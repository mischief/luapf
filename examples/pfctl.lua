#!/usr/bin/env lua54
-- A read-only pfctl(8), written against this binding.
--
-- It exists to be diffed: every modifier here is meant to print what
-- `pfctl -s` prints, so `pfctl.lua -s rules | diff - <(pfctl -s rules)`
-- is a test of whether the binding exposes enough to reproduce it. Where
-- the two disagree, one of them is wrong and the diff says which.
--
-- Only the show modifiers are implemented, and only those reachable
-- read-only. Nothing here writes.

local pf = require("pf")

local function die(fmt, ...)
	io.stderr:write("pfctl.lua: " .. string.format(fmt, ...) .. "\n")
	os.exit(1)
end

local function usage()
	io.stderr:write(
	    "usage: pfctl.lua [-vv] [-a anchor] -s modifier\n" ..
	    "modifiers: rules queue states Anchors Sources info " ..
	    "timeouts memory Tables Interfaces all\n")
	os.exit(1)
end

-- pfctl lets a modifier be abbreviated, so "ru" means rules.
local modifiers = {
	"rules", "queue", "states", "Anchors", "Sources", "info",
	"timeouts", "memory", "Tables", "Interfaces", "all",
}

local function resolve(arg)
	local hit
	for _, m in ipairs(modifiers) do
		if m == arg then
			return m
		end
		if m:sub(1, #arg) == arg then
			if hit then
				die("ambiguous modifier: %s", arg)
			end
			hit = m
		end
	end
	return hit or die("unknown modifier: %s", arg)
end

local opt = { verbose = 0, anchor = "" }
local want

local i = 1
while i <= #arg do
	local a = arg[i]
	if a == "-s" then
		i = i + 1
		want = arg[i] or usage()
	elseif a == "-a" then
		i = i + 1
		opt.anchor = arg[i] or usage()
	elseif a == "-v" then
		opt.verbose = opt.verbose + 1
	elseif a == "-vv" then
		opt.verbose = opt.verbose + 2
	else
		usage()
	end
	i = i + 1
end

if not want then
	usage()
end
want = resolve(want)

local h, err = pf.open("r")
if not h then
	die("open /dev/pf: %s", tostring(err))
end

local show = {}

function show.rules()
	for _, r in ipairs(h:rules(opt.anchor)) do
		print(tostring(r))
		if opt.verbose > 0 then
			-- Two spaces between the fields, and the packet
			-- and byte counts are the two directions summed:
			-- pfctl does not print the split this binding keeps.
			print(string.format(
			    "  [ Evaluations: %-8d  Packets: %-8d  " ..
			    "Bytes: %-10d  States: %-6d]",
			    r.evaluations, r.packets_in + r.packets_out,
			    r.bytes_in + r.bytes_out, r.states_cur))
			print(string.format(
			    "  [ Inserted: uid %u pid %u State Creations: %-6d]",
			    r.created_uid, r.created_pid, r.states_total))
		end
	end
end

function show.Anchors()
	for _, a in ipairs(h:anchors(opt.anchor)) do
		-- pfctl hides the inline anchors, whose names begin with an
		-- underscore, unless it is being verbose.
		local last = a:match("([^/]+)$")
		if opt.verbose > 0 or last:sub(1, 1) ~= "_" then
			print("  " .. a)
		end
	end
end

function show.Tables()
	for _, t in ipairs(h:tables(opt.anchor ~= "" and opt.anchor or nil)) do
		print("  " .. tostring(t.name))
	end
end

function show.Interfaces()
	for _, iface in ipairs(h:interfaces()) do
		print(iface.name)
	end
end

function show.memory()
	local limits = h:limits()
	-- pfctl walks its own list, so the order is fixed rather than
	-- whatever order the table happens to iterate in.
	for _, name in ipairs({"states", "src-nodes", "frags", "tables",
	    "table-entries", "pktdelay-pkts", "anchors"}) do
		local v = limits[name]
		if v then
			print(string.format("%-13s hard limit %8s", name,
			    v == 4294967295 and "unlimited" or tostring(v)))
		end
	end
end

function show.timeouts()
	local t = h:timeouts()
	local order = {
		"tcp.first", "tcp.opening", "tcp.established", "tcp.closing",
		"tcp.finwait", "tcp.closed", "tcp.tsdiff", "udp.first",
		"udp.single", "udp.multiple", "icmp.first", "icmp.error",
		"other.first", "other.single", "other.multiple",
		"frag", "interval", "adaptive.start", "adaptive.end",
		"src.track",
	}
	for _, name in ipairs(order) do
		if t[name] then
			-- The adaptive pair counts states, not seconds.
			local unit = name:sub(1, 9) == "adaptive." and " states"
			    or "s"
			print(string.format("%-20s %10d%s", name, t[name],
			    unit))
		end
	end
end

function show.Sources()
	for _, n in ipairs(h:srcnodes()) do
		print(string.format("%s -> %s ( states %d, connections %d )",
		    tostring(n.address), tostring(n.translation),
		    n.states or 0, n.connections or 0))
	end
end

-- pfctl prints the near end of the direction's own key first, then the
-- arrow, then the far end, with the other key's reading of each in
-- parentheses when it differs. An af-to state indexes like an outbound
-- one, which is why it also takes the outbound arrow.
-- This binding renders a v6 endpoint as [address]:port, the form a URL
-- uses. pfctl writes address[port]. Neither is wrong; only one of them is
-- what we are diffing against. A rdomain is shown only when it is not the
-- default, and belongs to the key the address came from.
local function host(addr, rdomain)
	local a, p = addr:match("^%[(.+)%]:(%d+)$")
	local out = a and (a .. "[" .. p .. "]") or addr

	if rdomain and rdomain ~= 0 then
		out = "(" .. rdomain .. ") " .. out
	end

	return out
end

local function stateline(s)
	local afto = (s.near_wire:sub(1, 1) == "[") ~=
	    (s.near_stack:sub(1, 1) == "[")
	local outward = s.direction == "out" or afto
	local near = outward and s.source or s.destination
	local far = outward and s.destination or s.source
	local otherfar = s.direction == "out" and s.far_stack or s.far_wire

	local rd, ord = s.rdomain, s.gateway_rdomain
	local out = { s.ifname, s.proto, host(near, rd) }
	if s.gateway ~= near or ord ~= rd then
		out[#out + 1] = "(" .. host(s.gateway, ord) .. ")"
	end
	out[#out + 1] = outward and "->" or "<-"
	out[#out + 1] = host(far, rd)
	if otherfar ~= far or ord ~= rd then
		out[#out + 1] = "(" .. host(otherfar, ord) .. ")"
	end

	-- The peers are ordered by direction alone. af-to moves the arrow
	-- and the index but not these, so outward is the wrong test here.
	local levels = s.direction == "out" and
	    (s.src_state .. ":" .. s.dst_state) or
	    (s.dst_state .. ":" .. s.src_state)

	return table.concat(out, " ") .. "       " .. levels
end

function show.states()
	for _, s in ipairs(h:states()) do
		print(stateline(s))
	end
end

function show.queue()
	local qs = h:queues()
	if #qs == 0 then
		return
	end
	for _, q in ipairs(qs) do
		local line = "queue " .. q.name
		if q.parent ~= "" then
			line = line .. " parent " .. q.parent
		else
			line = line .. " on " .. q.ifname
		end
		if q.default_queue then
			line = line .. " default"
		end
		print(line)
		if opt.verbose > 0 then
			print(string.format(
			    "  [ pkts: %10d  bytes: %10d  " ..
			    "dropped pkts: %6d bytes: %6d ]",
			    q.transmit_packets, q.transmit_bytes,
			    q.drop_packets, q.drop_bytes))
			print(string.format("  [ qlength: %3d/%3d ]",
			    q.queue_length, q.queue_limit))
		end
	end
end

function show.info()
	local st = h:status()
	print(string.format("Status: %s%s",
	    st.running and "Enabled" or "Disabled",
	    st.ifname ~= "" and ("  Interface: " .. st.ifname) or ""))
	print("")
	print("State Table                          Total             Rate")
	print(string.format("  %-24s%12d %14s", "current entries",
	    st.states, ""))
	for _, k in ipairs({"searches", "inserts", "removals"}) do
		print(string.format("  %-24s%12d %14s", k,
		    st.fcounters[k] or 0, ""))
	end
	print("Counters")
	local names = {}
	for k in pairs(st.counters) do
		names[#names + 1] = k
	end
	table.sort(names)
	for _, k in ipairs(names) do
		print(string.format("  %-24s%12d %14s", k, st.counters[k], ""))
	end
end

function show.all()
	for _, m in ipairs({"info", "rules", "states", "Tables", "Anchors"}) do
		show[m]()
	end
end

show[want]()
