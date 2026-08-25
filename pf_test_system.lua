local pf = require("pf")

local h = pf.open()
assert(h)

local status = h:status()
assert(type(status) == "table")
assert(type(status.running) == "boolean")
assert(type(status.stateid) == "number")
assert(type(status.since) == "number")
assert(type(status.states) == "number" and status.states >= 0)
assert(type(status.states_halfopen) == "number" and status.states_halfopen >= 0)
assert(type(status.src_nodes) == "number" and status.src_nodes >= 0)
assert(type(status.hostid) == "number")
assert(type(status.ifname) == "string")
assert(type(status.checksum) == "string" and status.checksum:match("^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$"))
for _, group in ipairs({status.counters, status.bcounters.v4, status.bcounters.v6,
    status.pcounters.v4, status.pcounters.v6}) do
	assert(type(group) == "table")
	for _, value in pairs(group) do
		assert(type(value) == "number" and value >= 0)
	end
end

local limits = h:limits()
for _, name in ipairs({"states", "src-nodes", "frags", "tables", "table-entries",
    "pktdelay-pkts", "anchors"}) do
	assert(type(limits[name]) == "number" and limits[name] >= 0)
end

local timeouts = h:timeouts()
for _, name in ipairs({"tcp.first", "tcp.opening", "tcp.established",
    "tcp.closing", "tcp.finwait", "tcp.closed", "tcp.tsdiff",
    "udp.first", "udp.single", "udp.multiple", "icmp.first", "icmp.error",
    "other.first", "other.single", "other.multiple", "frag", "interval",
    "adaptive.start", "adaptive.end", "src.track"}) do
	assert(type(timeouts[name]) == "number" and timeouts[name] >= 0)
end

local ifs = h:interfaces()
assert(#ifs > 0)

local all
for _, i in ipairs(ifs) do
	assert(type(i.name) == "string" and #i.name > 0)
	assert(type(i.skip) == "boolean")
	assert(type(i.in4_pass_packets) == "number")
	assert(type(i.out6_block_bytes) == "number")
	assert(type(i.cleared) == "number")
	if i.name == "all" then
		all = i
	end
end
assert(all, "the all interface is always present")

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

-- source nodes only exist for rules that track them, so accept an empty list
local nodes = h:srcnodes()
assert(type(nodes) == "table")
for _, n in ipairs(nodes) do
	assert(type(n.address) == "string")
	assert(type(n.states) == "number")
	assert(type(n.rule) == "number")
end

local ok, err = pcall(h.killsrcnodes, h, "not-an-ip")
assert(not ok and err:find("bad address"))

-- clearing states on an interface with none is a no-op
assert(h:clearstates("lo0") == 0)

local st = h:states()[1]
if st then
	local one = h:getstate(st.id, st.creatorid)
	assert(one)
	assert(one.source == st.source)
	assert(one.destination == st.destination)
end

-- an id that cannot exist reads as nil, not an error
assert(h:getstate(1, 1) == nil)
