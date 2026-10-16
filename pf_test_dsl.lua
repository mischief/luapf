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

-- pfctl is the reference: it loads the rendered text, and pf.dsl's own
-- load must leave the kernel the same.
local function pfctl(rs, anchor)
	local path = "/tmp/pf_test_dsl.conf"
	local f = assert(io.open(path, "w"))
	f:write(table.concat((rs:lines(anchor ~= nil)), "\n"), "\n")
	f:close()
	local out = sh("pfctl " .. (anchor and "-a " .. anchor .. " " or "") ..
	    "-f " .. path)
	os.remove(path)
	assert(out == "", "pfctl rejected the ruleset:\n" .. out ..
	    rs:render())
end

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

pfctl(rs)
local ok, out

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
pfctl(sub, "services")
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

-- Tables and limiters, as text that two loads can be compared by.
local function others(anchor)
	local out = {}
	for _, t in ipairs(h:tables(anchor or "")) do
		if (t.anchor or "") == (anchor or "") then
			local addrs = t:addresses()
			table.sort(addrs)
			out[#out + 1] = string.format("<%s> %s %s %s %s", t.name,
			    tostring(t.persist), tostring(t.const), tostring(t.counters),
			    table.concat(addrs, " "))
		end
	end
	for _, l in ipairs(h:statelimiters()) do
		out[#out + 1] = string.format("state %s %d %d %d/%d", l.name, l.id,
		    l.limit, l.rate.limit, l.rate.seconds)
	end
	for _, l in ipairs(h:sourcelimiters()) do
		out[#out + 1] = string.format("source %s %d %d %d %d/%d %d %d %s",
		    l.name, l.id, l.entries, l.limit, l.rate.limit, l.rate.seconds,
		    l.inet_prefix, l.inet6_prefix,
		    l.overload and l.overload.table .. l.overload.hwm ..
		    l.overload.lwm or "")
	end
	table.sort(out)
	return table.concat(out, "\n")
end

-- An automatic table gets a random name each load.
local function plain(s)
	return (s:gsub("__automatic_%x+_%d+", "__automatic"))
end

-- load leaves the kernel as pfctl left it: rules, tables and limiters.
local function native(rs, anchor, viapfctl)
	if viapfctl then
		pfctl(rs, anchor)
	end
	local before = texts(anchor)
	local beforeothers = plain(others(anchor))
	ok, out = rs:load({ anchor = anchor, pf = h })
	assert(ok, "load failed:\n" .. tostring(out))
	local after = texts(anchor)
	local wrong = {}
	for i = 1, math.max(#before, #after) do
		if plain(before[i] or "") ~= plain(after[i] or "") then
			wrong[#wrong + 1] = string.format("[%d]\n  pfctl: %s\n  load:  %s",
			    i, tostring(before[i]), tostring(after[i]))
		end
	end
	assert(#wrong == 0, "load differs from pfctl:\n" ..
	    table.concat(wrong, "\n"))
	local afterothers = plain(others(anchor))
	assert(afterothers == beforeothers, "tables or limiters differ:\n" ..
	    beforeothers .. "\n---\n" .. afterothers)
end
native(rs, nil)
native(sub, "services")
native(assert(dsl.read(h)), nil)

-- binat-to makes two rules, and a pool list makes a table.
local more = dsl.ruleset()
more:pass{ log = true, on = pair0, from = "10.10.0.5", binat_to = "192.168.77.5" }
more:pass{ log = true, dir = "in", on = pair0, proto = "tcp", port = 8000,
    rdr_to = { "192.168.77.20", "192.168.77.21" } }
more:pass{ log = true }
native(more, nil, true)

-- Options: the limits and timeouts pfctl -f sets, set and defaulted alike.
local function settings()
	return sh("pfctl -s timeouts") .. sh("pfctl -s memory") ..
	    sh("pfctl -s info | grep -i 'interface stats'")
end
local opts = dsl.ruleset()
opts:set{ limit = { states = 20000, src_nodes = 5000 },
    optimization = "aggressive", timeout = { tcp_first = 77, udp_single = 9 },
    loginterface = pair0, reassemble = true }
opts:pass{ log = true }
pfctl(opts)
local want = settings()
pfctl((function() local r = dsl.ruleset() r:pass{ log = true } return r end)())
assert(settings() ~= want, "a plain ruleset left the options set")
ok, out = opts:load({ pf = h })
assert(ok, out)
local got = settings()
assert(got == want, "options differ:\n" .. want .. "---\n" .. got)

native(rs, nil, true)

-- A refused rule is named by its Lua line, and the loaded ruleset stays.
local bad = dsl.ruleset()
bad:pass{ log = true }
bad:pass{ log = true, queue = "nosuchqueue" }
local badline = debug.getinfo(1, "l").currentline - 1
ok, out = bad:load()
assert(not ok, "the kernel took a rule naming a queue that does not exist")
assert(out:find("pf_test_dsl.lua:" .. badline .. ":", 1, true),
    "load's error does not name the Lua line:\n" .. out)
assert(#h:rules() == 16, "a refused load changed the ruleset")

-- check sends everything and keeps none of it.
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
