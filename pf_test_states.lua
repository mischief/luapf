local pf = require('pf')
local h = pf.open()
assert(h)
local states = h:states()
--print(#states)


local st1 = states[1]
assert(st1)

assert(type(st1.id) == "number" and st1.id ~= 0)
assert(type(st1.ifname) == "string" and #st1.ifname > 0)
assert(type(st1.proto) == "string")
assert(type(st1.direction) == "string" and (st1.direction == "in" or st1.direction == "out"))
assert(type(st1.rule) == "number")

for _, st in ipairs(states) do
	local r = string.find(st.source, ":22$")
	local z = string.find(st.destination, ":22$")
	if r or z then
		for k,v in pairs(st) do
			if k == "id" then
				print(k, string.format("%x", v))
			else
				print(k,v)
			end
		end
	end
end

