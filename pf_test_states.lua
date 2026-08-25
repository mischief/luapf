local pf = require('pf')
local h = pf.open()
assert(h)

local states = h:states()
assert(type(states) == "userdata")
local count = #states
assert(count >= 1)
assert(states[0] == nil)
assert(states[count + 1] == nil)
assert(states["not-an-index"] == nil)

for i = 1, count do
	local st = states[i]
	assert(st)
	assert(type(st.id) == "number" and st.id ~= 0)
	assert(type(st.creatorid) == "number" and st.creatorid >= 0)
	assert(type(st.ifname) == "string" and #st.ifname > 0)
	assert(st.proto == nil or type(st.proto) == "string")
	assert(type(st.direction) == "string" and
	    (st.direction == "in" or st.direction == "out"))
	assert(type(st.rule) == "number")
	assert(type(st.creation) == "number" and st.creation >= 0)
	assert(type(st.expire) == "number" and st.expire >= 0)
	assert(type(st.source) == "string" and #st.source > 0)
	assert(type(st.destination) == "string" and #st.destination > 0)
	assert(st.gateway == nil or type(st.gateway) == "string")
	assert(type(st.packets_in) == "number" and st.packets_in >= 0)
	assert(type(st.packets_out) == "number" and st.packets_out >= 0)
	assert(type(st.bytes_in) == "number" and st.bytes_in >= 0)
	assert(type(st.bytes_out) == "number" and st.bytes_out >= 0)

	local keys = 0
	for key, value in pairs(st) do
		assert(type(key) == "string")
		keys = keys + 1
	end
	assert(keys > 0)
end

local st1 = states[1]
local one = h:getstate(st1.id, st1.creatorid)
assert(one)
assert(one.id == st1.id)
assert(one.creatorid == st1.creatorid)
assert(one.source == st1.source)
assert(one.destination == st1.destination)

-- An id that cannot exist reads as nil, not an error.
assert(h:getstate(1, 1) == nil)

-- Clearing an interface with no matching states is a no-op.
assert(h:clearstates("lo0") == 0)
