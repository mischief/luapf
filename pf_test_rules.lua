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
	assert(type(r.evaluations) == "number")
	assert(type(r.quick) == "boolean")
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
