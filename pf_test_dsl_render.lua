-- pf.dsl without pf: what each rule renders to, and what each mistake
-- reports. Runs anywhere Lua runs.
local dsl = require("pf.dsl")

local function rendered(build)
	local rs = dsl.ruleset()
	build(rs)
	return rs:render()
end

local function same(build, want)
	local got = rendered(build)
	assert(got == want, "\nwant:\n" .. want .. "got:\n" .. got)
end

-- The error a build raises. It must name this file and the line that
-- defines build, plus offset.
local function refuses(build, pattern, offset)
	local line = debug.getinfo(build, "S").linedefined + (offset or 0)
	local ok, err = pcall(rendered, build)
	assert(not ok, "no error; wanted " .. pattern)
	local at = "pf_test_dsl_render.lua:" .. line .. ":"
	assert(err:find(at, 1, true), "error not at line " .. line .. ": " .. err)
	assert(err:find(pattern), "wanted " .. pattern .. ", got: " .. err)
end

local wan, lan = dsl.iface("em0"), dsl.iface("em1")

same(function(rs) rs:pass{} end, "pass\n")
same(function(rs) rs:block{ policy = "return", dir = "in", log = true,
    quick = true, on = wan } end,
    "block return in log quick on em0\n")
same(function(rs) rs:pass{ log = { all = true, to = dsl.iface("pflog1") } }
    end, "pass log (all, to pflog1)\n")
same(function(rs) rs:pass{ on = dsl.NOT(wan) } end, "pass on ! em0\n")
same(function(rs) rs:pass{ on = { wan, lan } } end, "pass on { em0, em1 }\n")
same(function(rs) rs:pass{ on = dsl.group("egress") } end,
    "pass on egress\n")

-- Addresses: strict literals, dynamic forms, lists and negation.
same(function(rs) rs:pass{ from = "10.0.0.0/8", to = "2001:db8::1" } end,
    "pass from 10.0.0.0/8 to 2001:db8::1\n")
same(function(rs) rs:pass{ from = { "192.0.2.1", dsl.NOT("192.0.2.0/24") } }
    end, "pass from { 192.0.2.1, ! 192.0.2.0/24 }\n")
same(function(rs) rs:pass{ to = { wan:addr(), wan:addr0(), wan:network(),
    wan:broadcast(), wan:peer() } } end,
    "pass from any to { (em0), (em0:0), (em0:network), (em0:broadcast), " ..
    "(em0:peer) }\n")
same(function(rs) rs:pass{ from = dsl.self } end, "pass from self\n")
same(function(rs) rs:pass{ to = "::" } end, "pass from any to ::\n")
same(function(rs) rs:pass{ to = "2001:db8:0:1::/64" } end,
    "pass from any to 2001:db8:0:1::/64\n")

-- Ports and protocols.
same(function(rs) rs:pass{ proto = { "tcp", "udp" }, port = "domain" } end,
    "pass proto { tcp, udp } from any to any port domain\n")
same(function(rs) rs:pass{ proto = "tcp", from_port = dsl.range(1024, 65535),
    port = { 22, dsl.port("!=", 23), dsl.port("><", 100, 200) } } end,
    "pass proto tcp from any port 1024:65535 to any port " ..
    "{ 22, != 23, 100 >< 200 }\n")
same(function(rs) rs:pass{ proto = "icmp", icmp_type = "echoreq" } end,
    "pass proto icmp icmp-type echoreq\n")

-- State, tags and the set actions.
same(function(rs) rs:pass{ state = false } end, "pass no state\n")
same(function(rs) rs:pass{ proto = "tcp", state = { kind = "modulate",
    source_track = "rule", max_src_nodes = 10, if_bound = true } } end,
    "pass proto tcp modulate state (max-src-nodes 10, source-track rule, " ..
    "if-bound)\n")
same(function(rs) rs:match{ tagged = "x", tag = "y", label = "l",
    prio = 3, queue = { "bulk", "ack" }, rtable = 1 } end,
    'match label "l" tag "y" tagged "x" rtable 1 set prio 3 ' ..
    'set queue (bulk, ack)\n')

-- Translation: a table defaults to round-robin.
local hosts = dsl.table("hosts", { const = true,
    addrs = { "192.0.2.10", dsl.NOT("192.0.2.11") } })
same(function(rs) rs:pass{ dir = "in", proto = "tcp", port = 80,
    rdr_to = dsl.pool(hosts, { port = 8080, sticky = true }) } end,
    "table <hosts> const { 192.0.2.10, !192.0.2.11 }\n" ..
    "pass in proto tcp from any to any port 80 " ..
    "rdr-to <hosts> port 8080 round-robin sticky-address\n")
same(function(rs) rs:match{ dir = "out", nat_to = dsl.pool(wan:addr(),
    { method = "source-hash" }) } end,
    "match out nat-to (em0) source-hash\n")

-- Options, tables and anchors.
same(function(rs)
	rs:set{ skip = { "lo0", wan }, limit = { states = 1000, src_nodes = 10 },
	    timeout = { tcp_established = 600 }, reassemble = false,
	    state_defaults = { pflow = true } }
	rs:table(dsl.table("unused", { persist = true, file = "/etc/x" }))
end, "set limit { src-nodes 10, states 1000 }\n" ..
    "set reassemble no\n" ..
    "set skip on { lo0, em0 }\n" ..
    "set state-defaults pflow\n" ..
    "set timeout { tcp.established 600 }\n" ..
    'table <unused> persist file "/etc/x"\n')
same(function(rs)
	local sub = dsl.ruleset()
	sub:pass{ dir = "in", proto = "tcp", port = 22 }
	rs:anchor("ward/*", { dir = "in", on = wan })
	rs:anchor("ssh", { rules = sub })
end, 'anchor "ward/*" in on em0\n' ..
    'anchor "ssh" {\n' ..
    "\tpass in proto tcp from any to any port 22\n" ..
    "}\n")

-- Limiters: defined in the main ruleset, named by id in rules.
local dns = dsl.statelimiter("dns", { id = 3, limit = 1000,
    rate = { 100, 10 } })
local flooders = dsl.table("flooders", { persist = true })
local scan = dsl.sourcelimiter("scan", { id = 7, entries = 10000,
    limit = 1000, inet_mask = 24, inet6_mask = 128, overload = flooders,
    above = 900, below = 100 })
same(function(rs)
	rs:pass{ dir = "in", state_limiter = dns,
	    source_limiter = { scan, action = "no-match" } }
	rs:limiter(dsl.statelimiter("idle", { id = 1, limit = 5 }))
end, "table <flooders> persist\n" ..
    'state limiter "idle" id 1 limit 5\n' ..
    'state limiter "dns" id 3 limit 1000 rate 100/10\n' ..
    'source limiter "scan" id 7 entries 10000 limit 1000 ' ..
    "table <flooders> above 900 below 100 inet mask 24\n" ..
    "pass in state limiter id 3 source limiter id 7 (no-match)\n")
do
	local rs = dsl.ruleset()
	rs:pass{ state_limiter = dns }
	local lines = rs:lines(true)
	assert(#lines == 1 and lines[1] == "pass state limiter id 3",
	    "an anchor defines limiters: " .. table.concat(lines, "\n"))
end
refuses(function(rs) rs:block{ state_limiter = dns } end, "not allowed")
refuses(function(rs) rs:pass{ state_limiter = scan } end,
    "must be a statelimiter")
refuses(function(rs) rs:pass{ source_limiter = { scan, action = "drop" } }
    end, "action must be block or no%-match")
refuses(function(rs) dsl.statelimiter("x", { id = 0, limit = 1 }) end,
    "id must be 1 to 255")
refuses(function(rs) dsl.sourcelimiter("x", { id = 1, limit = 1,
    entries = 1, above = 5 }) end, "above and below need overload")
refuses(function(rs) dsl.sourcelimiter("x", { id = 1, limit = 1,
    entries = 1, overload = flooders, above = 5, below = 5 }) end,
    "lower below")
refuses(function(rs)
	rs:pass{ state_limiter = dsl.statelimiter("a", { id = 4, limit = 1 }) }
	rs:pass{ state_limiter = dsl.statelimiter("b", { id = 4, limit = 1 }) }
end, "defined twice", 2)

-- Mistakes, each reported at the line that made it.
refuses(function(rs) rs:pass{ prot = "tcp" } end, "unknown option 'prot'")
refuses(function(rs) rs:block{ rdr_to = "192.0.2.1" } end,
    "'rdr_to' is not allowed")
refuses(function(rs) rs:pass{ from = wan } end,
    "use em0:addr%(%)")
refuses(function(rs) rs:pass{ from = "10.0.0.1/8" } end,
    "host bits set")
refuses(function(rs) rs:pass{ from = "2001:DB8::1" } end,
    "write 2001:DB8::1 as 2001:db8::1")
refuses(function(rs) rs:pass{ from = "2001:db8:0:0:1::1" } end,
    "as 2001:db8::1:0:0:1")
refuses(function(rs) rs:pass{ from = "fe80::1%em0" } end, "zone")
refuses(function(rs) rs:pass{ from = "010.0.0.1" } end,
    "not an address")
refuses(function(rs) rs:pass{ from = "www.example.com" } end,
    "not an address")
refuses(function(rs) rs:pass{ port = 22 } end, "needs proto tcp or udp")
refuses(function(rs) rs:pass{ proto = { "tcp", "icmp" }, port = 22 } end,
    "needs proto tcp or udp")
refuses(function(rs) rs:pass{ rdr_to = "192.0.2.1" } end,
    "needs dir = \"in\"")
refuses(function(rs) rs:pass{ dir = "out", nat_to = dsl.any } end,
    "cannot translate to any")
refuses(function(rs) rs:pass{ af = "inet6", to = "192.0.2.1" } end,
    "inet address in an af = \"inet6\" rule")
refuses(function(rs) rs:pass{ state = { flush = true } } end,
    "flush needs overload")
refuses(function(rs) rs:pass{ state = { max_src_conn_rate = 100 } } end,
    "max_src_conn_rate must be")
refuses(function(rs) rs:pass{ prio = 8 } end, "prio must be")
refuses(function(rs) rs:pass{ "quick" } end, "named, not positional")
refuses(function(rs) rs:set{ skip = "lo0" }; rs:set{ skip = "lo1" } end,
    "skip is already set")
refuses(function(rs) rs:anchor("../x") end, "bad name")
refuses(function(rs) rs:anchor("*") end, "bad name")
refuses(function(rs) rs:pass{ from = dsl.NOT({ "192.0.2.1" }) } end,
    "cannot negate a list")
refuses(function(rs) rs:pass{ proto = "udp", icmp_type = "echoreq" } end,
    "needs proto icmp")
refuses(function(rs) dsl.table("a b") end, "bad name")
refuses(function(rs) dsl.iface("em0; rm") end, "bad interface name")

-- A table defined twice must agree with itself.
refuses(function(rs)
	rs:pass{ from = dsl.table("t", { persist = true }) }
	rs:pass{ from = dsl.table("t", { const = true }) }
end, "defined twice", 2)

-- A mistake inside a helper names both the helper line and the caller.
local function helper(rs)
	rs:pass{ bogus = true }
end
do
	local ok, err = pcall(rendered, function(rs) helper(rs) end)
	assert(not ok)
	local at = debug.getinfo(helper, "S").linedefined + 1
	local from = debug.getinfo(1, "l").currentline - 3
	assert(err:find("pf_test_dsl_render.lua:" .. at .. ": .*via .*" ..
	    "pf_test_dsl_render.lua:" .. from), err)
end

-- pfctl's line numbers come back as the Lua lines that made them.
do
	local rs = dsl.ruleset()
	rs:pass{ dir = "in" }
	rs:block{ dir = "out" }
	local line = debug.getinfo(1, "l").currentline - 1
	local seen
	local ok, err = rs:load({ run = function(cmd)
		seen = cmd
		local path = cmd:match("-f '([^']+)'")
		return false, path .. ":2: syntax error\n"
	end, anchor = "ward/test" })
	assert(not ok)
	assert(seen:find("^pfctl %-a 'ward/test' %-n %-f '"), seen)
	assert(err:find("pf_test_dsl_render.lua:" .. line ..
	    ": block out: syntax error", 1, true), err)
end

-- check runs pfctl -n alone; a load runs it, then the real load.
do
	local rs = dsl.ruleset()
	rs:pass{}
	local cmds = {}
	local function run(cmd)
		cmds[#cmds + 1] = cmd
		return true, ""
	end
	assert(rs:load({ run = run, check = true }))
	assert(#cmds == 1 and cmds[1]:find(" %-n "), cmds[1])
	cmds = {}
	assert(rs:load({ run = run }))
	assert(#cmds == 2 and not cmds[2]:find(" %-n "), cmds[2])
end

print("pf_test_dsl_render: ok")
