local pf = require("pf")

local handle = pf.open()
assert(handle)

handle:addtables("test1")
handle:addtables({ "test2", "test3", "test4" })

handle:deletetables("test4")
handle:deletetables({ "test2", "test3" })

local tbls = handle:tables()
local found = false
for _, t in ipairs(tbls) do
	if t.anchor == "" and t.name == "test1" then
		found = true
	end
end

assert(found)

local t1 = handle:gettable("test1")
assert(t1)

t1:add("127.0.0.0/8")
assert(t1:test("127.0.0.1") == true)
t1:clear()

t1:add({"127.0.0.1", "127.0.0.2", "127.0.0.3"})

-- explicit refresh
t1 = handle:gettable("test1")

assert(#t1 == 3, "test1 len should be 3")
handle:deletetables("test1")

