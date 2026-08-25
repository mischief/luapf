local pf = require('pf')
local h = pf.open()
assert(h)

local rules = h:rules()
assert(type(rules) == "table")

for _, r in ipairs(rules) do
	assert(type(r.nr) == "number")
	assert(type(r.action) == "string" and #r.action > 0)
	assert(type(r.source) == "string" and #r.source > 0)
	assert(type(r.destination) == "string" and #r.destination > 0)
	assert(r.af == nil or r.af == "inet" or r.af == "inet6")
	assert(r.proto == nil or type(r.proto) == "string" or type(r.proto) == "number")
	assert(type(r.log) == "boolean")
	assert(type(r.keep_state) == "boolean")
	assert(type(r.interface) == "string")
	assert(type(r.label) == "string")
	assert(type(r.tag) == "string")
	assert(type(r.anchor) == "string")
	assert(type(r.anchor_call) == "string")
	assert(type(r.packets_in) == "number" and r.packets_in >= 0)
	assert(type(r.packets_out) == "number" and r.packets_out >= 0)
	assert(type(r.bytes_in) == "number" and r.bytes_in >= 0)
	assert(type(r.bytes_out) == "number" and r.bytes_out >= 0)
	assert(type(r.states_cur) == "number" and r.states_cur >= 0)
	assert(type(r.states_total) == "number" and r.states_total >= 0)
	assert(type(r.quick) == "boolean")
	assert(type(r.evaluations) == "number" and r.evaluations >= 0)
	assert(type(tostring(r)) == "string")

	local keys = 0
	for _ in pairs(r) do
		keys = keys + 1
	end
	assert(keys > 0)
end

local anchors = h:anchors()
assert(type(anchors) == "table")
for _, a in ipairs(anchors) do
	assert(type(a) == "string" and #a > 0)
	assert(type(h:rules(a)) == "table")
end

-- the kernel rejects an anchor that does not exist
local ok, err = pcall(h.rules, h, "nonexistent-anchor")
assert(not ok)
assert(err:find("DIOCGETRULES"))
