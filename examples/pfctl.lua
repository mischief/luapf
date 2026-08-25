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

-- Clustered the way getopt(3) allows, because pfctl is used that way:
-- -vvsr is -v -v -s r, and an option's argument may be attached to it or
-- may be the next word.
local takesarg = { s = true, a = true }
local i = 1

while i <= #arg do
	local a = arg[i]

	if a:sub(1, 1) ~= "-" or a == "-" then
		usage()
	end

	local j = 2
	while j <= #a do
		local c = a:sub(j, j)

		if not takesarg[c] then
			if c ~= "v" then
				usage()
			end
			opt.verbose = opt.verbose + 1
			j = j + 1
		else
			local value = a:sub(j + 1)
			if value == "" then
				i = i + 1
				value = arg[i] or usage()
			end
			if c == "s" then
				want = value
			else
				opt.anchor = value
			end
			j = #a + 1
		end
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
		-- The inline anchors, whose names begin with an underscore,
		-- are never listed here. -v means recurse, not show these.
		if a:match("([^/]+)$"):sub(1, 1) ~= "_" then
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
		-- The skip marker is a verbose detail; plain output is
		-- names alone.
		print(iface.name ..
		    ((opt.verbose > 0 and iface.skip) and " (skip)" or ""))
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
local function hms(t)
	return string.format("%.2d:%.2d:%.2d", t // 3600, (t % 3600) // 60,
	    t % 60)
end

-- The window a peer is allowed, as pfctl writes it: where it starts and
-- how wide it is, with the modulation offset when one is in use.
local function seq(lo, hi, diff)
	if diff ~= 0 then
		return string.format("[%u + %u](+%u)", lo, hi - lo, diff)
	end
	return string.format("[%u + %u]", lo, hi - lo)
end

local function verbosestate(s)
	local out = {}

	if s.proto == "tcp" then
		-- Ordered by direction, the same way the peer levels are:
		-- an inbound state shows the far end's window first.
		local outward = s.direction == "out"
		local alo = outward and s.src_seqlo or s.dst_seqlo
		local ahi = outward and s.src_seqhi or s.dst_seqhi
		local ad = outward and s.src_seqdiff or s.dst_seqdiff
		local aw = outward and s.src_wscale or s.dst_wscale
		local blo = outward and s.dst_seqlo or s.src_seqlo
		local bhi = outward and s.dst_seqhi or s.src_seqhi
		local bd = outward and s.dst_seqdiff or s.src_seqdiff
		local bw = outward and s.dst_wscale or s.src_wscale
		-- A scale is only meaningful when both ends negotiated one.
		local scaled = s.src_wscale ~= 0 and s.dst_wscale ~= 0
		local line = "   " .. seq(alo, ahi, ad) ..
		    (scaled and (" wscale " .. aw) or "") ..
		    "  " .. seq(blo, bhi, bd) ..
		    (scaled and (" wscale " .. bw) or "")
		out[#out + 1] = line
	end

	-- The counters here are the kernel's own order, the state's
	-- direction first, which is not the in/out this binding names.
	local fwd, rev, fb, rb
	if s.direction == "out" then
		fwd, rev = s.packets_out, s.packets_in
		fb, rb = s.bytes_out, s.bytes_in
	else
		fwd, rev = s.packets_in, s.packets_out
		fb, rb = s.bytes_in, s.bytes_out
	end

	local line = string.format(
	    "   age %s, expires in %s, %d:%d pkts, %d:%d bytes",
	    hms(s.creation), hms(s.expire), fwd, rev, fb, rb)
	if s.anchor ~= -1 then
		line = line .. ", anchor " .. s.anchor
	end
	if s.rule ~= -1 then
		line = line .. ", rule " .. s.rule
	end
	for _, f in ipairs({"sloppy", "pflow", "source-track",
	    "sticky-address"}) do
		if (", " .. s.state_flag_names .. ","):find(",%s*" .. f .. ",") then
			line = line .. ", " .. f
		end
	end
	out[#out + 1] = line

	return table.concat(out, "\n")
end

function show.states()
	for _, s in ipairs(h:states()) do
		print(tostring(s))
		if opt.verbose > 0 then
			print(verbosestate(s))
		end
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

-- A failed ioctl is a message, not a traceback. pfctl says "Anchor does
-- not exist" and exits 0 for this one, so match that rather than
-- inventing a status of our own.
local ok, err = pcall(show[want])
if not ok then
	err = tostring(err):gsub("^.-:%d+: ", "")
	if err:find("DIOCGETRULES", 1, true) and opt.anchor ~= "" then
		io.stderr:write("pfctl.lua: Anchor does not exist\n")
		os.exit(0)
	end
	die("%s", err)
end
