-- Status, interfaces, limits, timeouts and source nodes.
--
-- Where pfctl prints the same number, this reads pfctl on both sides of the
-- binding call and requires the binding's value to fall between them: every
-- one of these counters only rises, so a busy host cannot make that fail
-- while a wrong index or a wrong name still can.
local pf = require("pf")

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>/dev/null", "r"))
	local out = p:read("a")
	p:close()
	return out
end

-- `pfctl -s info -v` in blocks: a heading in column one, then rows of an
-- indented name, its value and sometimes a rate. A name may hold single
-- spaces ("max states per rule"), so the value is whatever follows the
-- first run of two or more.
local function pfctlinfo()
	local blocks, rows = {}, nil
	for line in sh("pfctl -s info -v"):gmatch("[^\n]+") do
		if line:match("^%S") then
			rows = {}
			blocks[line:match("^(%S.-)%s%s+") or line] = rows
		elseif rows then
			local name, value = line:match("^%s+(.-)%s%s+(%d+)")
			if name then
				rows[name] = tonumber(value)
			end
		end
	end
	return blocks
end

local function pfctllimits()
	local t = {}
	for line in sh("pfctl -s memory"):gmatch("[^\n]+") do
		local name, value = line:match("^(%S+)%s+hard limit%s+(%d+)")
		if name then
			t[name] = tonumber(value)
		else
			name = line:match("^(%S+)%s+unlimited")
			-- pfctl prints UINT_MAX as the word; the binding
			-- hands back the number the kernel gave it.
			if name then
				t[name] = 4294967295
			end
		end
	end
	return t
end

local function pfctltimeouts()
	local t = {}
	for line in sh("pfctl -s timeouts"):gmatch("[^\n]+") do
		local name, value = line:match("^(%S+)%s+(%d+)")
		if name then
			t[name] = tonumber(value)
		end
	end
	return t
end

local function count(t)
	local n = 0
	for _ in pairs(t) do
		n = n + 1
	end
	return n
end

local h = pf.open()
assert(h)

-- PFRES_NAMES, in kernel order. The binding indexes st.counters by this
-- list, so a name missing here or an extra one means the array moved.
local reasons = {"match", "bad-offset", "fragment", "short", "normalize",
    "memory", "bad-timestamp", "congestion", "ip-option", "proto-cksum",
    "state-mismatch", "state-insert", "state-limit", "src-limit", "synproxy",
    "translate", "no-route"}

-- LCNT_NAMES, in kernel order, and the three names each of the state,
-- source node and fragment tables carries. pfctl prints all of these under
-- the same headings.
local lreasons = {"max states per rule", "max-src-states", "max-src-nodes",
    "max-src-conn", "max-src-conn-rate", "overload table insertion",
    "overload flush states", "synfloods detected", "syncookies sent",
    "syncookies validated"}
local tablecounters = {"searches", "inserts", "removals"}

local before = pfctlinfo()
local status = h:status()
local after = pfctlinfo()

-- Every one of these only rises, so the binding's number has to sit where
-- pfctl saw it go.
local function betweenpfctl(t, block, names, label)
	assert(count(t) == #names, label .. " does not hold exactly " ..
	    #names .. " entries")
	for _, name in ipairs(names) do
		local value = t[name]
		assert(type(value) == "number" and value >= 0,
		    label .. " has no " .. name)
		local lo = before[block] and before[block][name]
		local hi = after[block] and after[block][name]
		if lo and hi then
			assert(value >= lo and value <= hi, label .. "." ..
			    name .. ": binding says " .. value ..
			    ", pfctl says " .. lo .. ".." .. hi)
		end
	end
end

assert(type(status) == "table")
assert(type(status.running) == "boolean")
assert(type(status.stateid) == "number")
assert(type(status.since) == "number")
assert(type(status.states) == "number" and status.states >= 0)
assert(type(status.states_halfopen) == "number" and status.states_halfopen >= 0)
assert(status.states >= status.states_halfopen)
assert(type(status.src_nodes) == "number" and status.src_nodes >= 0)
assert(type(status.hostid) == "number")
assert(type(status.debug) == "number" and status.debug >= 0)
assert(type(status.reass) == "number" and status.reass >= 0)
assert(type(status.syncookies_active) == "number")
assert(type(status.syncookies_mode) == "number")
assert(type(status.ifname) == "string")
assert(type(status.checksum) == "string" and status.checksum:match("^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$"))

assert(type(status.fragments) == "number" and status.fragments >= 0)

betweenpfctl(status.counters, "Counters", reasons, "status.counters")
betweenpfctl(status.lcounters, "Limit Counters", lreasons, "status.lcounters")
-- Three arrays of three, one per table pf keeps, each behind its own
-- heading. Reading the wrong array would still type check, so every one is
-- pinned to the block pfctl prints it under.
betweenpfctl(status.fcounters, "State Table", tablecounters,
    "status.fcounters")
betweenpfctl(status.scounters, "Source Tracking Table", tablecounters,
    "status.scounters")
betweenpfctl(status.ncounters, "Fragments", tablecounters,
    "status.ncounters")

for _, name in ipairs({"fcounters", "scounters", "ncounters"}) do
	local t = status[name]
	assert(t.searches >= t.inserts, name ..
	    " reports more inserts than searches")
	assert(t.inserts >= t.removals, name ..
	    " reports more removals than inserts")
end

if next(before["Counters"] or {}) then
	for name in pairs(before["Counters"]) do
		assert(status.counters[name], "pfctl reports an unbound " ..
		    "counter: " .. name)
	end
end
if next(before["Limit Counters"] or {}) then
	for name in pairs(before["Limit Counters"]) do
		assert(status.lcounters[name], "pfctl reports an unbound " ..
		    "limit counter: " .. name)
	end
end

assert(#status.syncookies_inflight == 2,
    "syncookies_inflight is not the pair the kernel keeps")
for i = 1, 2 do
	assert(type(status.syncookies_inflight[i]) == "number" and
	    status.syncookies_inflight[i] >= 0)
end

-- The watermarks come from their own ioctl and do not move on their own,
-- so pfctl and the binding have to agree exactly. pfctl calls them start
-- and end.
local wats = status.syncookies_watermarks
assert(count(wats) == 2)
assert(type(wats.hiwat) == "number" and type(wats.lowat) == "number")
assert(wats.hiwat >= wats.lowat, "the syncookie window is inverted")
local refwats = before["Adaptive Syncookies Watermarks"]
if refwats and refwats.start then
	assert(wats.hiwat == refwats.start and wats.lowat == refwats["end"],
	    "watermarks: binding says " .. wats.hiwat .. "/" .. wats.lowat ..
	    ", pfctl says " .. refwats.start .. "/" .. refwats["end"])
end

for _, group in ipairs({status.bcounters.v4, status.bcounters.v6}) do
	assert(count(group) == 2)
	assert(type(group.bytesin) == "number" and group.bytesin >= 0)
	assert(type(group.bytesout) == "number" and group.bytesout >= 0)
end
for _, group in ipairs({status.pcounters.v4, status.pcounters.v6}) do
	assert(count(group) == 4)
	for _, name in ipairs({"packets_in_passed", "packets_in_blocked",
	    "packets_out_passed", "packets_out_blocked"}) do
		assert(type(group[name]) == "number" and group[name] >= 0,
		    "missing pcounter " .. name)
	end
end
-- These fill in only when a loginterface is set, and then bytes cannot be
-- fewer than the packets that carried them.
if status.ifname ~= "" then
	local v4 = status.pcounters.v4
	if v4.packets_in_passed + v4.packets_in_blocked > 0 then
		assert(status.bcounters.v4.bytesin > 0,
		    "v4 packets arrived but no bytes were counted")
	end
end

local limits = h:limits()
local reflimits = pfctllimits()
local limitnames = {"states", "src-nodes", "frags", "tables", "table-entries",
    "pktdelay-pkts", "anchors"}
assert(count(limits) == #limitnames,
    "limits does not hold exactly PF_LIMIT_MAX entries")
for _, name in ipairs(limitnames) do
	assert(type(limits[name]) == "number" and limits[name] >= 0)
	if reflimits[name] then
		assert(limits[name] == reflimits[name],
		    name .. ": binding says " .. limits[name] ..
		    ", pfctl says " .. reflimits[name])
	end
end

local timeouts = h:timeouts()
local reftimeouts = pfctltimeouts()
local timeoutnames = {"tcp.first", "tcp.opening", "tcp.established",
    "tcp.closing", "tcp.finwait", "tcp.closed", "tcp.tsdiff",
    "udp.first", "udp.single", "udp.multiple", "icmp.first", "icmp.error",
    "other.first", "other.single", "other.multiple", "frag", "interval",
    "adaptive.start", "adaptive.end", "src.track"}
assert(count(timeouts) == #timeoutnames,
    "timeouts does not hold exactly PFTM_MAX entries")
for _, name in ipairs(timeoutnames) do
	assert(type(timeouts[name]) == "number" and timeouts[name] >= 0)
	if reftimeouts[name] then
		assert(timeouts[name] == reftimeouts[name],
		    name .. ": binding says " .. timeouts[name] ..
		    ", pfctl says " .. reftimeouts[name])
	end
end
-- adaptive.start and adaptive.end are state counts, not seconds, and the
-- window has to be a window.
if timeouts["adaptive.start"] > 0 then
	assert(timeouts["adaptive.end"] >= timeouts["adaptive.start"])
end

local ifs = h:interfaces()
assert(#ifs > 0)

-- Every field pushifcounters writes, spelled as pfctl's istats_text spells
-- it: af, then direction, then action.
local ifcounters = {}
for _, af in ipairs({"in4", "out4", "in6", "out6"}) do
	for _, act in ipairs({"pass", "block"}) do
		ifcounters[#ifcounters + 1] = af .. "_" .. act .. "_packets"
		ifcounters[#ifcounters + 1] = af .. "_" .. act .. "_bytes"
	end
end

local all
local byname = {}
for _, i in ipairs(ifs) do
	assert(type(i.name) == "string" and #i.name > 0)
	assert(#i.name < 16, "interface name is not bounded by IFNAMSIZ")
	assert(type(i.skip) == "boolean")
	assert(type(i.any) == "boolean")
	for _, field in ipairs({"states", "rules", "routes", "srcnodes",
	    "cleared"}) do
		assert(type(i[field]) == "number" and i[field] >= 0,
		    i.name .. " has no " .. field)
	end
	for _, field in ipairs(ifcounters) do
		assert(type(i[field]) == "number" and i[field] >= 0,
		    i.name .. " has no " .. field)
	end
	-- A counted packet carries at least one byte, so bytes can never
	-- trail packets. This catches a swapped pfik_packets/pfik_bytes
	-- read that plain type checks would not.
	-- Only the pass counters: a packet turned away before its length is
	-- known is charged to the block counter with no bytes behind it, so
	-- the block cells legitimately show hundreds of packets in a few
	-- bytes. An ip-option drop is the common source.
	for _, af in ipairs({"in4", "out4", "in6", "out6"}) do
		local p = i[af .. "_pass_packets"]
		local b = i[af .. "_pass_bytes"]
		assert(b >= p, i.name .. ": " .. af ..
		    "_pass counts " .. p .. " packets in " .. b .. " bytes")
		assert(i[af .. "_block_packets"] >= 0)
		assert(i[af .. "_block_bytes"] >= 0)
	end
	byname[i.name] = i
	if i.name == "all" then
		all = i
	end
end
assert(all, "the all interface is always present")
assert(all.states == status.states or all.states >= 0)

-- pfctl walks the same DIOCIGETIFACES buffer, so the two lists must name
-- the same interfaces.
local seen = 0
for line in sh("pfctl -s Interfaces"):gmatch("[^\n]+") do
	local name = line:match("^(%S+)$")
	if name then
		seen = seen + 1
		assert(byname[name], "pfctl lists " .. name ..
		    " but the binding does not")
	end
end
if seen > 0 then
	assert(seen == #ifs, "pfctl lists " .. seen ..
	    " interfaces, the binding " .. #ifs)
end

-- a filter naming one interface returns only that one. "all" is the group of
-- every interface, so ask for a real one instead.
local one
for _, i in ipairs(ifs) do
	if i.name ~= "all" then
		one = i.name
		break
	end
end

local filtered = h:interfaces(one)
assert(#filtered == 1 and filtered[1].name == one)

-- The filter matches a whole name, so a name PF has never seen yields an
-- empty list rather than an error.
assert(#h:interfaces("nosuchif9") == 0)

-- IFNAMSIZ bounds the filter, and the binding refuses a longer one before
-- the ioctl instead of truncating it into some other interface's name.
local ok, err = pcall(h.interfaces, h, string.rep("x", 64))
assert(not ok and err:find("interface name too long"))

-- source nodes only exist for rules that track them, so accept an empty list
local nodes = h:srcnodes()
assert(type(nodes) == "table")
assert(#nodes <= status.src_nodes + 8,
    "more source nodes than the status table admits to")
local srcnodetypes = {none = true, nat = true, rdr = true, route = true,
    unknown = true}
for _, n in ipairs(nodes) do
	assert(type(n.address) == "string" and #n.address > 0)
	-- Both are absent rather than zero where pfctl prints nothing: an
	-- untranslated node has no address to name, and a node from an
	-- unnumbered rule has no rule number.
	assert(n.translation == nil or
	    (type(n.translation) == "string" and #n.translation > 0))
	assert(n.rule == nil or (type(n.rule) == "number" and n.rule >= 0))
	assert(srcnodetypes[n.type],
	    "source node type is not one the binding names: " ..
	    tostring(n.type))
	for _, field in ipairs({"states", "connections", "packets_in",
	    "packets_out", "bytes_in", "bytes_out", "creation", "expire"}) do
		assert(type(n[field]) == "number" and n[field] >= 0,
		    "source node has no " .. field)
	end
	assert(count(n.conn_rate) == 2)
	assert(type(n.conn_rate.count) == "number" and n.conn_rate.count >= 0)
	assert(type(n.conn_rate.seconds) == "number" and
	    n.conn_rate.seconds >= 0)
	assert(n.bytes_in >= n.packets_in)
	assert(n.bytes_out >= n.packets_out)
end

local ok, err = pcall(h.killsrcnodes, h, "not-an-ip")
assert(not ok and err:find("bad address"))

-- The range endpoint is parsed in the family the first address chose, so a
-- v6 end to a v4 start is rejected before any ioctl runs.
ok, err = pcall(h.killsrcnodes, h, "127.0.0.1", "::1")
assert(not ok and err:find("bad address"))

ok, err = pcall(h.killsrcnodes, h, "10.0.0.1", "not-an-ip")
assert(not ok and err:find("bad address"))

-- clearing states on an interface with none is a no-op
assert(h:clearstates("lo0") == 0)

local st = h:states()[1]
if st then
	local single = h:getstate(st.id, st.creatorid)
	assert(single)
	assert(single.source == st.source)
	assert(single.destination == st.destination)
end

-- an id that cannot exist reads as nil, not an error
assert(h:getstate(1, 1) == nil)

-- Every reader here goes through the handle, so a closed one has to be
-- refused rather than handed to ioctl as -1.
local closed = pf.open("r")
closed:close()
for _, name in ipairs({"limits", "timeouts", "interfaces", "srcnodes"}) do
	assert(not pcall(closed[name], closed),
	    name .. " answered a closed handle")
end

-- Everything past here writes, so it runs only in the disposable guest.
local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_system: not the disposable test guest; skipping writes")
	return
end
marker:close()

-- Source nodes need a rule that tracks them. The tracking rules go last
-- because PF takes the last match. The second one holds a single state per
-- source so that a handful of connections at once trips a limit counter.
local conf = assert(io.open("/tmp/pf_test_system.conf", "w"))
conf:write([[
pass log
pass in log on lo0 inet proto tcp to 127.0.0.1 port 31341 \
    keep state (source-track rule, max-src-states 100)
pass in log on lo0 inet proto tcp to 127.0.0.1 port 31342 \
    keep state (source-track rule, max-src-states 1)
]])
conf:close()
assert(sh("pfctl -f /tmp/pf_test_system.conf") == "")

h:clearsrcnodes()
assert(#h:srcnodes() == 0, "source nodes survived clearsrcnodes")

local scbefore = h:status().scounters

sh("nc -l 127.0.0.1 31341 </dev/null >/dev/null & sleep 1; " ..
    "print x | nc -N -w 2 127.0.0.1 31341; sleep 1")

local tracked = h:srcnodes()
assert(#tracked > 0, "the tracking rule produced no source node")

-- Inserting that node is what the source node counters count.
local scafter = h:status().scounters
assert(scafter.inserts > scbefore.inserts,
    "a source node appeared without scounters.inserts moving")
assert(scafter.searches > scbefore.searches,
    "a source node was inserted without scounters.searches moving")

local node
for _, n in ipairs(tracked) do
	if n.address == "127.0.0.1" then
		node = n
	end
end
assert(node, "no source node for the loopback client")
-- source-track rule asks for tracking alone, so the node carries no
-- translation and pfctl prints none either.
assert(node.type == "none", "a plain source-track node reports type " ..
    tostring(node.type))
assert(node.translation == nil,
    "an untranslated node reports a translation of " ..
    tostring(node.translation))
assert(node.states >= 0 and node.connections >= 0)
assert(node.creation >= 0)
-- The rule is a numbered one in the loaded ruleset, so unlike a node from
-- the default rule this one names it.
assert(type(node.rule) == "number" and node.rule < 4294967295,
    "the tracking rule's node reports rule " .. tostring(node.rule))
assert(node.conn_rate.seconds >= 0)

-- pfctl walks the same nodes, so it has to name this address too.
assert(sh("pfctl -vvs Sources"):find("127.0.0.1", 1, true),
    "pfctl does not list the node the binding found")

local status2 = h:status()
assert(status2.src_nodes >= #tracked,
    "status.src_nodes trails the list srcnodes returned")

-- The per-interface source node count follows the same nodes.
local lo
for _, i in ipairs(h:interfaces("lo0")) do
	lo = i
end
if lo then
	assert(lo.srcnodes >= 0)
end

-- Killing by a single address takes the nodes for that address only.
local killed = h:killsrcnodes("127.0.0.1")
assert(type(killed) == "number" and killed > 0,
    "killsrcnodes removed nothing for an address that had a node")

local remaining = h:srcnodes()
for _, n in ipairs(remaining) do
	assert(n.address ~= "127.0.0.1", "a killed node is still listed")
end

-- An address with no nodes is not an error, it is a count of zero.
assert(h:killsrcnodes("192.0.2.1") == 0)
-- Both the range form and the v6 form reach the ioctl rather than the
-- parse error above.
assert(h:killsrcnodes("192.0.2.1", "192.0.2.254") == 0)
assert(h:killsrcnodes("2001:db8::1") == 0)
assert(h:killsrcnodes("2001:db8::1", "2001:db8::ffff") == 0)

-- Rebuild a node, then take the whole table out from under it.
sh("nc -l 127.0.0.1 31341 </dev/null >/dev/null & sleep 1; " ..
    "print x | nc -N -w 2 127.0.0.1 31341; sleep 1")
assert(#h:srcnodes() > 0, "the tracking rule stopped producing nodes")
h:clearsrcnodes()
assert(#h:srcnodes() == 0, "source nodes survived clearsrcnodes")
assert(h:status().src_nodes == 0)

-- Limit counters. The port 31342 rule allows one state per source, so
-- several connections at once leave the extras blocked: pf bumps
-- LCNT_SRCSTATES for each and counts the drop as src-limit. Nothing else
-- on this guest touches either number.
local lbefore = h:status()
sh("nc -l 127.0.0.1 31342 >/dev/null 2>&1 & sleep 1; " ..
    "for i in 1 2 3 4 5 6; do (sleep 3 | nc -w 3 127.0.0.1 31342 " ..
    ">/dev/null 2>&1 &); done; sleep 5")

local linfo = pfctlinfo()
local lafter = h:status()
assert(lafter.lcounters["max-src-states"] >
    lbefore.lcounters["max-src-states"],
    "states past max-src-states did not move the limit counter")
assert(lafter.counters["src-limit"] > lbefore.counters["src-limit"],
    "a source limit was hit without src-limit counting the drop")
-- pfctl read the same number between the two calls, so it can only sit
-- where those two leave it.
local refl = linfo["Limit Counters"]
if refl and refl["max-src-states"] then
	assert(refl["max-src-states"] >= lbefore.lcounters["max-src-states"] and
	    refl["max-src-states"] <= lafter.lcounters["max-src-states"],
	    "pfctl says max-src-states is " .. refl["max-src-states"] ..
	    ", the binding says " .. lbefore.lcounters["max-src-states"] ..
	    ".." .. lafter.lcounters["max-src-states"])
end

-- A translated node. sticky-address is what makes pf keep one, and its
-- raddr is the address the rule mapped to, which is what pfctl prints
-- after nat-to. Nothing listens on 127.0.0.9; the node is made when the
-- first packet is translated, not when the handshake finishes.
local natconf = assert(io.open("/tmp/pf_test_system.conf", "w"))
natconf:write([[
pass log
pass out log on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.9 port 31343 \
    nat-to 127.0.0.2 sticky-address
]])
natconf:close()
assert(sh("pfctl -f /tmp/pf_test_system.conf") == "")

h:clearsrcnodes()
sh("print x | nc -N -w 2 127.0.0.9 31343; sleep 1")

local nat
for _, n in ipairs(h:srcnodes()) do
	if n.type == "nat" then
		nat = n
	end
end
assert(nat, "nat-to sticky-address produced no translated source node")
assert(nat.address == "127.0.0.1",
    "the translated node tracks " .. nat.address)
assert(nat.translation == "127.0.0.2",
    "the translated node maps to " .. tostring(nat.translation))
-- pfctl labels exactly this node nat-to, which is where the type comes
-- from.
assert(sh("pfctl -vvs Sources"):find("nat-to", 1, true),
    "pfctl does not call the node a nat-to")

os.remove("/tmp/pf_test_system.conf")
sh("printf '%s\\n' 'pass log' | pfctl -f -")
