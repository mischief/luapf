-- pf.dsl against the kernel: load a ruleset built with it, read it back,
-- and require every rule to render as pfctl prints it.
--
-- Guest only: it creates interfaces and replaces the ruleset.
local pf = require("pf")
local dsl = require("pf.dsl")

local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_dsl: not the disposable test guest; skipping")
	os.exit(0)
end
marker:close()

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>&1", "r"))
	local out = p:read("a")
	p:close()
	return out
end

local function must(cmd)
	local out = sh(cmd)
	assert(out == "", cmd .. ": " .. out)
end

-- An earlier test in the same guest can leave these behind.
for _, i in ipairs({ "pair1", "pair0", "vether0" }) do
	sh("ifconfig " .. i .. " destroy")
end
must("ifconfig pair0 create")
must("ifconfig pair1 create")
must("ifconfig pair0 patch pair1")
must("ifconfig pair1 rdomain 1")
must("ifconfig pair0 10.10.0.1/24 up")
must("ifconfig pair1 10.10.0.2/24 up")
must("ifconfig pair0 group testnet")
must("ifconfig vether0 create")
must("ifconfig vether0 192.168.77.1/24 up")

local h = assert(pf.open())

-- The rules of an anchor, as luapf renders them and as pfctl prints them.
local function compare(anchor)
	local theirs = {}
	local flag = anchor and ("-a " .. anchor .. " ") or ""
	local p = assert(io.popen("pfctl " .. flag .. "-s rules 2>/dev/null"))
	for line in p:lines() do
		-- The limiter definitions come first, and are not rules.
		if not line:match("^state limiter ") and
		    not line:match("^source limiter ") then
			theirs[#theirs + 1] = line
		end
	end
	p:close()
	local rules = h:rules(anchor)
	assert(#rules == #theirs, string.format(
	    "pfctl printed %d rules, the binding returned %d", #theirs, #rules))
	local wrong = {}
	for i, r in ipairs(rules) do
		if tostring(r) ~= theirs[i] then
			wrong[#wrong + 1] = string.format("[%d]\n  pfctl: %s\n  luapf: %s",
			    i, theirs[i], tostring(r))
		end
	end
	assert(#wrong == 0, "rules render differently from pfctl:\n" ..
	    table.concat(wrong, "\n"))
	return theirs
end

local pair0, vether0 = dsl.iface("pair0"), dsl.iface("vether0")
local hosts = dsl.table("hosts", { const = true,
    addrs = { "192.168.77.10", "192.168.77.11" } })
local overloaded = dsl.table("overloaded", { persist = true })
local blocked = dsl.table("blocked", { const = true,
    addrs = { "203.0.113.0/24", "198.51.100.7" } })

local flooders = dsl.table("flooders", { persist = true })
local dns = dsl.statelimiter("dns", { id = 3, limit = 1000 })
local scan = dsl.sourcelimiter("scan", { id = 7, entries = 100,
    limit = 10, rate = { 100, 10 }, inet_mask = 24, overload = flooders,
    above = 90, below = 10 })

local rs = dsl.ruleset()
rs:set{ skip = "lo0", block_policy = "return" }
rs:match{ dir = "out", on = pair0, af = "inet",
    from = dsl.NOT(vether0:network()), nat_to = pair0:addr0(),
    prio = { 3, 6 } }
rs:block{ policy = "drop", dir = "in", quick = true, on = pair0,
    from = blocked }
rs:block{ log = true }
rs:pass{ dir = "out", log = true }
rs:pass{ dir = "in", log = true, on = dsl.group("testnet"), af = "inet",
    proto = "icmp", icmp_type = "echoreq" }

local function forward(port, host, to)
	rs:pass{ dir = "in", log = true, quick = true, on = pair0,
	    proto = "tcp", to = pair0:addr0(), port = port,
	    rdr_to = dsl.pool(host, { port = to }) }
	rs:pass{ dir = "out", log = true, on = vether0, proto = "tcp",
	    to = host, port = to, received_on = vether0,
	    nat_to = vether0:addr() }
end
forward(2222, hosts, 22)
forward(2223, "192.168.77.12", 22)

rs:pass{ dir = "in", log = true, on = pair0, proto = { "tcp", "udp" },
    port = "domain", rdr_to = dsl.pool(vether0:addr(), { port = "domain" }) }
rs:pass{ dir = "in", log = true, on = pair0, proto = "tcp", port = 22,
    state = { max_src_conn_rate = { 1, 60 }, overload = overloaded,
    flush = "global" } }
rs:pass{ dir = "in", log = true, on = pair0, af = "inet", proto = "tcp",
    from = "10.10.0.0/24", port = { 80, 443 },
    rdr_to = dsl.pool("10.10.0.1", { port = 8080 }) }
rs:pass{ dir = "in", log = true, on = pair0, proto = "udp", port = 53,
    state_limiter = dns, source_limiter = { scan, action = "no-match" } }
rs:anchor("services", { dir = "in", on = pair0 })

local ok, out = rs:load()
assert(ok, "pf.dsl load failed:\n" .. tostring(out))

-- Each list of two doubles its rule.
local theirs = compare()
assert(#theirs == 16, "expected 16 rules, got " .. #theirs .. ":\n" ..
    table.concat(theirs, "\n"))

-- The tables went in with the rules.
local names = {}
for _, t in ipairs(h:tables()) do
	names[tostring(t.name or t)] = true
end
for _, want in ipairs({ "hosts", "overloaded", "blocked", "flooders" }) do
	assert(names[want], "table missing: " .. want)
end

-- The limiters went in with the rules, and a rule names them.
local sl, srcl = h:statelimiters(), h:sourcelimiters()
assert(#sl == 1 and sl[1].name == "dns" and sl[1].id == 3)
assert(#srcl == 1 and srcl[1].name == "scan" and srcl[1].inet_prefix == 24)
assert(srcl[1].overload and srcl[1].overload.table == "flooders")
local limited = h:rules()[15]
assert(limited.state_limiter == "dns" and
    limited.source_limiter_action == "no-match", tostring(limited))

-- An anchor loads on its own, under its own name.
local sub = dsl.ruleset()
sub:pass{ log = true, proto = "tcp", port = dsl.range(6000, 6010) }
sub:block{ log = true, proto = "udp", from_port = dsl.port("<", 1024) }
sub:pass{ log = true, proto = "udp", port = 5353, state_limiter = dns }
ok, out = sub:load({ anchor = "services" })
assert(ok, "anchor load failed:\n" .. tostring(out))
assert(#compare("services") == 3, "the anchor does not hold three rules")
assert(h:rules("services")[3].state_limiter == "dns",
    "the anchor rule lost its limiter")
assert(#h:rules() == 16, "an anchor load changed the main ruleset")

-- Lua out: a ruleset read from the kernel, written as Lua and run again,
-- loads to the same kernel rules.
local function texts(anchor)
	local out = {}
	for i, r in ipairs(h:rules(anchor)) do
		out[i] = tostring(r)
	end
	return out
end

local function roundtrip(anchor)
	local before = texts(anchor)
	local back = assert(dsl.read(h, anchor))
	local src = back:tolua()
	local again = assert(load(src, "=tolua"))()
	assert(again:render() == back:render(), "tolua changed the ruleset")
	ok, out = again:load({ anchor = anchor })
	assert(ok, "the read ruleset does not load:\n" .. tostring(out) ..
	    "\n" .. again:render())
	local after = texts(anchor)
	assert(#after == #before, "read back " .. #after .. " rules, not " ..
	    #before)
	for i = 1, #before do
		assert(before[i] == after[i], string.format(
		    "rule %d changed on the way through Lua:\n  was: %s\n  now: %s\n%s",
		    i, before[i], after[i], src))
	end
end
roundtrip(nil)
roundtrip("services")

-- pfctl's errors come back at the Lua line that made the bad rule, and a
-- refused ruleset leaves the loaded one in place.
local bad = dsl.ruleset()
bad:pass{ log = true }
bad:pass{ log = true, queue = "nosuchqueue" }
local badline = debug.getinfo(1, "l").currentline - 1
ok, out = bad:load()
assert(not ok, "pfctl took a rule naming a queue that does not exist")
assert(out:find("pf_test_dsl.lua:" .. badline .. ":", 1, true),
    "pfctl's error does not name the Lua line:\n" .. out)
assert(#h:rules() == 16, "a refused load changed the ruleset")

-- check only runs pfctl -n.
ok, out = bad:load({ check = true })
assert(not ok)
ok, out = sub:load({ check = true })
assert(ok, out)
assert(#h:rules() == 16, "a check changed the ruleset")

sh("pfctl -a services -F rules")
for _, i in ipairs({ "pair1", "pair0", "vether0" }) do
	sh("ifconfig " .. i .. " destroy")
end
sh("printf '%s\\n' 'pass log' | pfctl -f -")
print("pf_test_dsl: ok")
