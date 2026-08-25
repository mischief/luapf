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
t1:delete("127.0.0.2")
t1:refresh()
assert(#t1 == 2)
assert(t1:test("127.0.0.2") == false)
t1:add("127.0.0.2")
t1:refresh()
assert(#t1 == 3)

-- explicit refresh
t1 = handle:gettable("test1")

assert(#t1 == 3, "test1 len should be 3")

-- in place refresh sees what add did
t1:add("127.0.0.4")
assert(#t1 == 3)
assert(t1:refresh() == t1)
assert(#t1 == 4)
local addresses = t1:addresses()
assert(type(addresses) == "table" and #addresses == 4)
for _, address in ipairs(addresses) do
	assert(type(address) == "string")
end

assert(t1.counters == false)
-- a table that is neither persistent nor referenced is dropped when its
-- flags change, so keep it alive
assert(t1:setflags({ counters = true, persist = true }) == 1)
t1:refresh()
assert(t1.counters == true)

local stats = t1:addrstats()
assert(#stats == 4)
for _, a in ipairs(stats) do
	assert(type(a.address) == "string")
	assert(a.packets_in == 0 and a.bytes_out == 0)
	assert(type(a.cleared) == "number")
end

-- replace swaps the whole content in one step
local added, deleted = t1:replace({ "127.0.0.10", "127.0.0.11" })
assert(added == 2)
assert(deleted == 4)
t1:refresh()
assert(#t1 == 2)
assert(t1:test("127.0.0.10") == true)
assert(t1:test("127.0.0.1") == false)

assert(type(t1:clearaddrstats()) == "number")

-- IPv6 entries use the same address API.
t1:add("::1")
t1:refresh()
assert(t1:test("::1") == true)
assert(#t1 == 3)
t1:clear()

handle:deletetables("test1")

