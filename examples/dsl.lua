#!/usr/bin/env lua54
-- A small router ruleset written with pf.dsl. It prints the pf.conf text.
-- With -n it also checks the text with pfctl -n, and with -f it loads it.

local dsl = require("pf.dsl")

local lan, wan = dsl.iface("vport0"), dsl.iface("rge0")
local web = dsl.table("webabuse", { persist = true, counters = true })
local drop = dsl.table("spamhaus", { persist = true, counters = true })
local www = dsl.table("www", { persist = true })

local rs = dsl.ruleset()
rs:set{ skip = { "lo0" }, block_policy = "drop" }

rs:match{ dir = "out", on = wan, af = "inet", from = dsl.NOT(lan:network()),
	nat_to = wan:addr0(), prio = { 3, 6 } }

rs:block{ quick = true, dir = "in", on = wan, from = drop }

for _, port in ipairs({ 80, 443 }) do
	rs:pass{ quick = true, log = true, dir = "in", on = wan, proto = "tcp",
		to = wan:addr(), port = port,
		state = { max_src_conn = 64, max_src_conn_rate = { 100, 10 },
			overload = web, flush = "global", pflow = true } }
end

-- A port forward is a function, not a copied block of rules.
local function forward(port, host)
	rs:pass{ quick = true, log = true, dir = "in", on = wan, proto = "tcp",
		to = wan:addr0(), port = port, rdr_to = host }
	rs:pass{ dir = "in", on = lan, proto = "tcp", from = lan:network(),
		to = wan:addr0(), port = port, rdr_to = host }
	rs:pass{ dir = "out", on = lan, proto = "tcp", to = host, port = port,
		received_on = lan, nat_to = lan:addr() }
end
forward(2223, www)

rs:anchor("ward/*")

io.write(rs:render())

if arg[1] == "-n" or arg[1] == "-f" then
	local ok, out = rs:load({ check = arg[1] == "-n" })
	io.stderr:write(out)
	os.exit(ok and 0 or 1)
end
