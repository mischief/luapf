local pf = require("pf")

local h = assert(pf.open("rw"))

-- Every field the binding documents for a state limiter, and nothing else.
local statefields = {
	"id", "name", "limit", "rate",
	"inuse", "admitted", "hardlimited", "ratelimited",
}

-- overload is absent unless the limiter carries an overload table, so it
-- is checked separately rather than listed here.
local sourcefields = {
	"id", "name", "entries", "limit", "rate",
	"inet_prefix", "inet6_prefix",
	"nentries", "inuse", "addrallocs", "addrnomem",
	"admitted", "addrlimited", "hardlimited", "ratelimited",
}

local function checkrate(l)
	assert(type(l.rate) == "table", l.name .. ": rate is not a table")
	assert(type(l.rate.limit) == "number" and l.rate.limit >= 0,
	    l.name .. ": rate.limit")
	assert(type(l.rate.seconds) == "number" and l.rate.seconds >= 0,
	    l.name .. ": rate.seconds")
end

local function checkfields(l, fields, what)
	local want = {}
	for _, k in ipairs(fields) do
		assert(l[k] ~= nil, what .. " is missing " .. k)
		want[k] = true
	end
	want.overload = true
	for k in pairs(l) do
		assert(want[k], what .. " has unexpected field " .. k)
	end
end

local function checkstatelim(l)
	assert(type(l.id) == "number" and l.id >= 1 and l.id <= 255)
	assert(type(l.name) == "string" and #l.name > 0)
	assert(type(l.limit) == "number" and l.limit >= 1)
	checkrate(l)
	for _, k in ipairs({ "inuse", "admitted", "hardlimited",
	    "ratelimited" }) do
		assert(type(l[k]) == "number" and l[k] >= 0,
		    l.name .. ": " .. k)
	end
	assert(l.overload == nil, l.name .. ": state limiters have no overload")
	checkfields(l, statefields, "state limiter " .. l.name)
end

local function checksourcelim(l)
	assert(type(l.id) == "number" and l.id >= 1 and l.id <= 255)
	assert(type(l.name) == "string" and #l.name > 0)
	assert(type(l.entries) == "number" and l.entries >= 1)
	assert(type(l.limit) == "number" and l.limit >= 0)
	checkrate(l)
	assert(type(l.inet_prefix) == "number" and l.inet_prefix <= 32,
	    l.name .. ": inet_prefix")
	assert(type(l.inet6_prefix) == "number" and l.inet6_prefix <= 128,
	    l.name .. ": inet6_prefix")
	for _, k in ipairs({ "nentries", "inuse", "addrallocs", "addrnomem",
	    "admitted", "addrlimited", "hardlimited", "ratelimited" }) do
		assert(type(l[k]) == "number" and l[k] >= 0,
		    l.name .. ": " .. k)
	end
	if l.overload ~= nil then
		assert(type(l.overload) == "table")
		assert(type(l.overload.table) == "string" and
		    #l.overload.table > 0, l.name .. ": overload.table")
		assert(type(l.overload.hwm) == "number",
		    l.name .. ": overload.hwm")
		assert(type(l.overload.lwm) == "number",
		    l.name .. ": overload.lwm")
	end
	checkfields(l, sourcefields, "source limiter " .. l.name)
end

-- Ordered by id, with no id repeated.
local function checkorder(list, what)
	local last = 0
	for i, l in ipairs(list) do
		assert(l.id > last, what .. " entry " .. i .. " is out of order")
		last = l.id
	end
end

local function statelimiters()
	local list = h:statelimiters()
	assert(type(list) == "table")
	for _, l in ipairs(list) do
		checkstatelim(l)
	end
	checkorder(list, "statelimiters")
	return list
end

local function sourcelimiters()
	local list = h:sourcelimiters()
	assert(type(list) == "table")
	for _, l in ipairs(list) do
		checksourcelim(l)
	end
	checkorder(list, "sourcelimiters")
	return list
end

-- Whatever this machine is running, the shape has to hold. On a host with
-- no limiters configured both lists are simply empty.
statelimiters()
sourcelimiters()

-- A read-only handle answers both, which is what a caller that has dropped
-- privilege depends on.
do
	local ro = assert(pf.open("r"))
	assert(#ro:statelimiters() == #h:statelimiters())
	assert(#ro:sourcelimiters() == #h:sourcelimiters())
	ro:close()
end

-- A closed handle refuses both rather than reaching for a stale descriptor.
do
	local c = assert(pf.open("r"))
	c:close()
	assert(not pcall(function() return c:statelimiters() end))
	assert(not pcall(function() return c:sourcelimiters() end))
end

-- The rest needs limiters loaded, which means a ruleset of our own -- so it
-- runs only in the disposable guest.
local marker = io.open("/etc/luapf-test-vm")
if not marker then
	return
end
marker:close()

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>&1", "r"))
	local out = p:read("a")
	p:close()
	return out
end

local function byname(list)
	local m = {}
	for _, l in ipairs(list) do
		m[l.name] = l
	end
	return m
end

-- Two of each, so ordering and the walk over more than one entry are
-- exercised. The ids are deliberately not adjacent and not 1: the GETN
-- walk asks from one past the last id it saw, so a gap is what proves it
-- skips ahead rather than counting. "dns" carries no rate, "web" does;
-- "scan" carries an overload table and masks, "plain" neither.
local f = assert(io.open("/tmp/pf_test_limiters.conf", "w"))
f:write([[
table <flooders> persist

state limiter "dns" id 3 limit 1000
state limiter "web" id 9 limit 2000 rate 100/10

source limiter "plain" id 2 entries 500 limit 10
source limiter "scan" id 7 entries 10000 limit 1000 rate 100/10 \
	inet mask 24 inet6 mask 64 \
	table <flooders> above 900 below 100

pass in on lo0 state limiter "dns"
pass out on lo0 source limiter "scan"
]])
f:close()
local loaded = sh("pfctl -f /tmp/pf_test_limiters.conf")
assert(loaded == "", "pfctl rejected the limiter ruleset: " .. loaded)

local st = byname(statelimiters())

assert(st.dns ~= nil, "state limiter dns is missing")
assert(st.dns.id == 3, "dns id is " .. st.dns.id)
assert(st.dns.limit == 1000, "dns limit is " .. st.dns.limit)
assert(st.dns.rate.limit == 0 and st.dns.rate.seconds == 0,
    "dns has a rate it was not given")

assert(st.web ~= nil, "state limiter web is missing")
assert(st.web.id == 9, "web id is " .. st.web.id)
assert(st.web.limit == 2000, "web limit is " .. st.web.limit)
assert(st.web.rate.limit == 100, "web rate.limit is " .. st.web.rate.limit)
assert(st.web.rate.seconds == 10, "web rate.seconds is " ..
    st.web.rate.seconds)

local sr = byname(sourcelimiters())

assert(sr.plain ~= nil, "source limiter plain is missing")
assert(sr.plain.id == 2, "plain id is " .. sr.plain.id)
assert(sr.plain.entries == 500, "plain entries is " .. sr.plain.entries)
assert(sr.plain.limit == 10, "plain limit is " .. sr.plain.limit)
assert(sr.plain.rate.limit == 0 and sr.plain.rate.seconds == 0,
    "plain has a rate it was not given")
assert(sr.plain.overload == nil, "plain has an overload table")
assert(sr.plain.inet_prefix == 32, "plain inet_prefix is " ..
    sr.plain.inet_prefix)
assert(sr.plain.inet6_prefix == 128, "plain inet6_prefix is " ..
    sr.plain.inet6_prefix)

assert(sr.scan ~= nil, "source limiter scan is missing")
assert(sr.scan.id == 7, "scan id is " .. sr.scan.id)
assert(sr.scan.entries == 10000, "scan entries is " .. sr.scan.entries)
assert(sr.scan.limit == 1000, "scan limit is " .. sr.scan.limit)
assert(sr.scan.rate.limit == 100, "scan rate.limit is " ..
    sr.scan.rate.limit)
assert(sr.scan.rate.seconds == 10, "scan rate.seconds is " ..
    sr.scan.rate.seconds)
assert(sr.scan.inet_prefix == 24, "scan inet_prefix is " ..
    sr.scan.inet_prefix)
assert(sr.scan.inet6_prefix == 64, "scan inet6_prefix is " ..
    sr.scan.inet6_prefix)
assert(sr.scan.overload ~= nil, "scan has no overload table")
assert(sr.scan.overload.table == "flooders", "scan overload.table is " ..
    sr.scan.overload.table)
assert(sr.scan.overload.hwm == 900, "scan overload.hwm is " ..
    sr.scan.overload.hwm)
assert(sr.scan.overload.lwm == 100, "scan overload.lwm is " ..
    sr.scan.overload.lwm)

-- The read-only handle sees the same set once there is a set to see.
do
	local ro = assert(pf.open("r"))
	assert(#ro:statelimiters() == 2, "read-only handle sees " ..
	    #ro:statelimiters() .. " state limiters")
	assert(#ro:sourcelimiters() == 2, "read-only handle sees " ..
	    #ro:sourcelimiters() .. " source limiters")
	ro:close()
end

-- Counters move as traffic passes. PF is already running in the guest and
-- lo0 is up, so pinging it creates states under the "dns" pass rule.
local before = byname(statelimiters()).dns.admitted
sh("ping -c 2 -w 2 127.0.0.1")
local after = byname(statelimiters()).dns.admitted
assert(after >= before, "dns admitted went backwards")

-- Loading a ruleset without limiters empties both sets again, which is the
-- empty-list path the host also takes.
local g = assert(io.open("/tmp/pf_test_limiters_none.conf", "w"))
g:write("pass\n")
g:close()
assert(sh("pfctl -f /tmp/pf_test_limiters_none.conf") == "")

assert(#statelimiters() == 0, "state limiters survived a ruleset without any")
assert(#sourcelimiters() == 0,
    "source limiters survived a ruleset without any")

h:close()
