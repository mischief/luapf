local pf = require("pf")

local h = pf.open()
assert(h)

local limits = h:limits()
assert(type(limits.states) == "number" and limits.states > 0)
assert(type(limits["table-entries"]) == "number")

local timeouts = h:timeouts()
assert(timeouts["tcp.established"] > 0)
assert(type(timeouts["src.track"]) == "number")

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
