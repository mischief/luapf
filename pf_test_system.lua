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

-- The Counters block of `pfctl -s info`. Without -v that block is last, so
-- nothing else can leak into it.
local function pfctlcounters()
	local t, inside = {}, false
	for line in sh("pfctl -s info"):gmatch("[^\n]+") do
		if line:match("^Counters") then
			inside = true
		elseif line:match("^%S") then
			inside = false
		elseif inside then
			local name, value = line:match("^%s+(%S+)%s+(%d+)")
			if name then
				t[name] = tonumber(value)
			end
		end
	end
	return t
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

local before = pfctlcounters()
local status = h:status()
local after = pfctlcounters()

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

assert(count(status.counters) == #reasons,
    "status.counters does not hold exactly PFRES_MAX entries")
for _, name in ipairs(reasons) do
	local value = status.counters[name]
	assert(type(value) == "number" and value >= 0,
	    "missing or negative counter " .. name)
	if before[name] and after[name] then
		assert(value >= before[name] and value <= after[name],
		    name .. ": binding says " .. value .. ", pfctl says " ..
		    before[name] .. ".." .. after[name])
	end
end
if next(before) then
	for name in pairs(before) do
		assert(status.counters[name], "pfctl reports an unbound " ..
		    "counter: " .. name)
	end
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
	for _, af in ipairs({"in4", "out4", "in6", "out6"}) do
		for _, act in ipairs({"pass", "block"}) do
			local p = i[af .. "_" .. act .. "_packets"]
			local b = i[af .. "_" .. act .. "_bytes"]
			assert(b >= p, i.name .. ": " .. af .. "_" .. act ..
			    " counts " .. p .. " packets in " .. b .. " bytes")
		end
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
for _, n in ipairs(nodes) do
	assert(type(n.address) == "string" and #n.address > 0)
	assert(type(n.translation) == "string" and #n.translation > 0)
	for _, field in ipairs({"states", "connections", "packets_in",
	    "packets_out", "bytes_in", "bytes_out", "creation", "expire",
	    "rule"}) do
		assert(type(n[field]) == "number" and n[field] >= 0,
		    "source node has no " .. field)
	end
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

-- Source nodes need a rule that tracks them. The tracking rule goes last
-- because PF takes the last match.
local conf = assert(io.open("/tmp/pf_test_system.conf", "w"))
conf:write([[
pass log
pass in log on lo0 inet proto tcp to 127.0.0.1 port 31341 \
    keep state (source-track rule, max-src-states 100)
]])
conf:close()
assert(sh("pfctl -f /tmp/pf_test_system.conf") == "")

h:clearsrcnodes()
assert(#h:srcnodes() == 0, "source nodes survived clearsrcnodes")

sh("nc -l 127.0.0.1 31341 </dev/null >/dev/null & sleep 1; " ..
    "print x | nc -N -w 2 127.0.0.1 31341; sleep 1")

local tracked = h:srcnodes()
assert(#tracked > 0, "the tracking rule produced no source node")

local node
for _, n in ipairs(tracked) do
	if n.address == "127.0.0.1" then
		node = n
	end
end
assert(node, "no source node for the loopback client")
assert(type(node.translation) == "string")
assert(node.states >= 0 and node.connections >= 0)
assert(node.creation >= 0)
-- pfctl prints rule.nr only when it is not -1; the binding hands the raw
-- u_int32_t across, so an untracked rule reads as UINT_MAX here.
assert(node.rule >= 0)

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

os.remove("/tmp/pf_test_system.conf")
sh("printf '%s\\n' 'pass log' | pfctl -f -")
