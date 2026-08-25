local pf = require("pf")

local handle = pf.open()
assert(handle)

-- A run that failed part way leaves its tables behind, and the counts
-- below are exact, so start from a known-empty set of these four names.
handle:deletetables({ "test1", "test2", "test3", "test4" })

assert(handle:addtables("test1") == 1)
assert(handle:addtables({ "test2", "test3", "test4" }) == 3)
-- The count is what changed, so a name that already exists adds nothing.
assert(handle:addtables("test1") == 0)

assert(handle:deletetables("test4") == 1)
assert(handle:deletetables({ "test2", "test3" }) == 2)
assert(handle:deletetables("test4") == 0)

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

-- pairs walks the read-only properties and nothing else: a method name
-- reaching the iterator would mean __index and __pairs disagree.
local props = {}
for k in pairs(t1) do
	props[k] = true
end
for _, name in ipairs({
	"anchor", "name", "persist", "const", "active", "inactive",
	"referenced", "refdanchor", "counters", "addresses_count",
	"match", "nomatch", "packets_in", "packets_out", "bytes_in",
	"bytes_out", "cleared", "refcnt_rule", "refcnt_anchor",
}) do
	assert(props[name], "pairs did not offer " .. name)
	props[name] = nil
end
assert(next(props) == nil, "pairs offered a key that is not a property")

assert(t1.name == "test1" and t1.anchor == "")
assert(t1.persist == true and t1.const == false)
assert(t1.active == true and t1.inactive == false)
-- No rule and no anchor names a table this test made, so both reference
-- counts stay at zero and the two reference flags stay false.
assert(t1.referenced == false and t1.refdanchor == false)
assert(t1.refcnt_rule == 0 and t1.refcnt_anchor == 0)
assert(t1.addresses_count == #t1)
assert(t1.match == 0 and t1.nomatch == 0)
assert(t1.packets_in == 0 and t1.packets_out == 0)
assert(t1.bytes_in == 0 and t1.bytes_out == 0)
assert(t1.cleared > 0 and t1.cleared <= os.time())

local stats = t1:addrstats()
assert(#stats == 4)
for _, a in ipairs(stats) do
	assert(type(a.address) == "string")
	assert(a.packets_in == 0 and a.packets_out == 0)
	assert(a.bytes_in == 0 and a.bytes_out == 0)
	assert(type(a.cleared) == "number")
	assert(a.cleared > 0 and a.cleared <= os.time())
end

-- replace swaps the whole content in one step
local added, deleted, changed = t1:replace({ "127.0.0.10", "127.0.0.11" })
assert(added == 2)
assert(deleted == 4)
-- changed counts entries kept but altered, and nothing here is kept.
assert(changed == 0)
t1:refresh()
assert(#t1 == 2)
assert(t1:test("127.0.0.10") == true)
assert(t1:test("127.0.0.1") == false)

-- The count is addresses zeroed. DIOCRCLRASTATS zeroes the addresses the
-- caller names in the request buffer, and the binding sends an empty one,
-- so today the call reaches the kernel, names nothing and reports nothing.
-- Fixing the binding to send the table's addresses turns this into 2.
assert(t1:clearaddrstats() == 0)

-- IPv6 entries use the same address API.
t1:add("::1")
t1:refresh()
assert(t1:test("::1") == true)
assert(#t1 == 3)

-- A name that does not exist in an anchor that does is a nil return. An
-- anchor that does not exist is not: DIOCRGETTSTATS fails with ENOENT and
-- that comes back as an error, so the two ways of missing do not look
-- alike to a caller.
assert(handle:gettable("luapfnosuchtable") == nil)
assert(not pcall(function()
	return handle:gettable("luapfnoanchor/luapfnosuchtable")
end))

-- Bad arguments are rejected before any ioctl runs.
assert(not pcall(function() return t1:add("not-an-address") end))
assert(not pcall(function() return t1:add({ {} }) end))
assert(not pcall(function() return t1:add(("1"):rep(60)) end))
assert(not pcall(function() return t1:setflags("persist") end))
assert(not pcall(function() return handle:addtables({ {} }) end))
-- DIOCRTSTADDRS takes a host, so a prefix is an error rather than false.
assert(not pcall(function() return t1:test("127.0.0.0/8") end))

assert(t1:clear() == 3)

assert(handle:deletetables("test1") == 1)


-- The rest needs a ruleset that names tables and traffic to count against
-- them, so it runs only in the disposable guest.
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

local function loadrules(text)
	local f = assert(io.open("/tmp/pf_test_tables.conf", "w"))
	f:write(text)
	f:close()
	local out = sh("pfctl -f /tmp/pf_test_tables.conf")
	assert(out == "" or not out:find("error", 1, true),
	    "pfctl rejected the ruleset: " .. out)
end

local function ip4(s)
	local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	return string.pack(">I1I1I1I1", a, b, c, d)
end

local function cksum(data)
	local sum = 0
	for i = 1, #data - 1, 2 do
		sum = sum + string.unpack(">I2", data, i)
	end
	if #data % 2 == 1 then
		sum = sum + data:byte(#data) * 256
	end
	while sum > 0xffff do
		sum = (sum & 0xffff) + (sum >> 16)
	end
	return (~sum) & 0xffff
end

-- One UDP datagram as it would arrive on the wire, so an inbound packet
-- can be injected on tun0 rather than sent: the far side of the
-- point-to-point link is this test. The UDP checksum is left zero, which
-- IPv4 permits and PF accepts.
local function udp4(src, sport, dst, dport, payload)
	local udp = string.pack(">I2I2I2I2", sport, dport, 8 + #payload, 0) ..
	    payload
	local hdr = string.pack(">I1I1I2I2I2I1I1I2", 0x45, 0, 20 + #udp,
	    0x1234, 0, 64, 17, 0) .. ip4(src) .. ip4(dst)
	hdr = hdr:sub(1, 10) .. string.pack(">I2", cksum(hdr)) .. hdr:sub(13)
	return hdr .. udp
end

-- Opening the device creates tun0 and is what keeps it running: the
-- interface goes down again on the last close.
local tun = assert(io.open("/dev/tun0", "r+b"))
tun:setvbuf("no")
assert(sh("ifconfig tun0 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up") == "")

-- PF matches an existing state before it reaches any rule, and only a rule
-- evaluation touches a table, so start with no states.
assert(handle:clearstates() >= 0)

-- <hit> is what the winning rule looks up, so it collects both the match
-- count and the packet counters. <miss> is looked up by an earlier rule
-- that never wins, so it collects nomatch and nothing else. The anchor is
-- loaded separately: a table inside an inline anchor block makes pfctl
-- fail the whole load with EBUSY.
loadrules([[
set skip on lo
table <hit> persist counters { 10.99.0.2 }
table <miss> persist counters { 10.99.0.9 }
pass log
anchor "audit" on tun0
block out log on tun0 inet proto udp to <miss>
pass out log on tun0 inet proto udp to <hit>
pass in log on tun0 inet proto udp from <hit>
]])

-- The anchor's own rule is TCP, so nothing this test sends reaches it and
-- <inner> stays a fixture for the naming and reference-count checks.
local af = assert(io.open("/tmp/pf_test_tables_anchor.conf", "w"))
af:write("table <inner> persist counters { 10.99.0.2 }\n" ..
    "pass in log on tun0 inet proto tcp to <inner>\n")
af:close()
assert(sh("pfctl -a audit -f /tmp/pf_test_tables_anchor.conf") == "")

local hit = assert(handle:gettable("hit"), "the ruleset defined no <hit>")
local miss = assert(handle:gettable("miss"), "the ruleset defined no <miss>")

-- A table the ruleset names carries the flags pf.conf asked for and one
-- rule reference for each rule that looks it up.
assert(hit.persist == true and hit.counters == true,
    "<hit> persist=" .. tostring(hit.persist) .. " counters=" ..
    tostring(hit.counters))
assert(hit.active == true and hit.inactive == false,
    "<hit> active=" .. tostring(hit.active) .. " inactive=" ..
    tostring(hit.inactive))
assert(hit.const == false, "<hit> came back const")
assert(hit.referenced == true, "<hit> is not marked referenced")
assert(hit.refdanchor == false, "<hit> is marked refdanchor")
assert(hit.refcnt_rule == 2, "<hit> rule references: " .. hit.refcnt_rule)
assert(hit.refcnt_anchor == 0, "<hit> anchor references: " ..
    hit.refcnt_anchor)
assert(miss.refcnt_rule == 1, "<miss> rule references: " .. miss.refcnt_rule)
assert(#hit == 1 and hit.addresses_count == 1,
    "<hit> holds " .. #hit .. " addresses")
assert(hit:addresses()[1] == "10.99.0.2")

-- An anchor's table is reachable by path, and its shadow in the main
-- ruleset is what carries the anchor reference.
local inner = assert(handle:gettable("audit/inner"),
    "no table inside the anchor")
assert(inner.anchor == "audit" and inner.name == "inner")
assert(#inner == 1, "<inner> holds " .. #inner .. " addresses")
-- pf:tables asks the kernel for the main ruleset only, so a table that
-- lives in an anchor never appears in the listing.
for _, t in ipairs(handle:tables()) do
	assert(t.anchor == "", "pf:tables returned an anchor's table")
end
local shadow = assert(handle:gettable("inner"),
    "the anchor's table has no shadow in the main ruleset")
assert(shadow.refdanchor == true, "the shadow is not marked refdanchor")
assert(shadow.refcnt_anchor >= 1, "the shadow has no anchor reference")
-- The shadow is the one table gettable hands back that is not active, and
-- the address ioctls refuse a table that is not active. pf:tables filters
-- these out; gettable does not.
assert(shadow.active == false, "the shadow is active")
assert(not pcall(function() return shadow:addrstats() end))
assert(not pcall(function() return shadow:addresses() end))

-- Outbound: the pass rule wins, so <hit> counts a match and a packet out.
-- The block rule ahead of it looks <miss> up and does not match.
sh("echo probe | nc -u -w 1 10.99.0.2 9999")

-- Inbound: the source address is what the winning rule looks up, so the
-- same table counts in the other direction.
tun:write(string.pack(">I4", 2) ..
    udp4("10.99.0.2", 40000, "10.99.0.1", 9999, "inprobe"))
tun:flush()
os.execute("sleep 1")

hit:refresh()
miss:refresh()

assert(hit.match >= 2, "<hit> matched " .. hit.match .. " times, wanted 2")
assert(hit.nomatch == 0, "<hit> counted a nomatch")
assert(hit.packets_out >= 1, "<hit> counted no outbound packet")
assert(hit.packets_in >= 1, "<hit> counted no inbound packet")
-- Every datagram here is at least an IPv4 header plus a UDP header.
assert(hit.bytes_out >= hit.packets_out * 28,
    "<hit> outbound bytes are short for the packet count")
assert(hit.bytes_in >= hit.packets_in * 28,
    "<hit> inbound bytes are short for the packet count")

assert(miss.nomatch >= 1, "<miss> counted no nomatch")
assert(miss.match == 0, "<miss> matched an address it does not hold")
-- A table only a losing rule looked up gets no packet or byte counters.
assert(miss.packets_out == 0 and miss.bytes_out == 0)
assert(miss.packets_in == 0 and miss.bytes_in == 0)

-- The per-address counters must account for the whole table: one address
-- holds every packet the table counted, in both directions.
local astats = hit:addrstats()
assert(#astats == 1)
local a = astats[1]
assert(a.address == "10.99.0.2")
assert(a.packets_out == hit.packets_out,
    "address packets out " .. a.packets_out .. " but table " ..
    hit.packets_out)
assert(a.packets_in == hit.packets_in,
    "address packets in " .. a.packets_in .. " but table " .. hit.packets_in)
assert(a.bytes_out == hit.bytes_out and a.bytes_in == hit.bytes_in,
    "address byte counters do not add up to the table's")

-- <miss> holds an address no packet ever reached, so its per-address
-- counters stay at zero while its nomatch count does not.
local mstats = miss:addrstats()
assert(#mstats == 1 and mstats[1].address == "10.99.0.9")
assert(mstats[1].packets_in == 0 and mstats[1].packets_out == 0)
assert(mstats[1].bytes_in == 0 and mstats[1].bytes_out == 0)

-- cleartables zeroes the table's own counters only. The kernel has a flag
-- for recursing into the addresses, the binding does not pass it, and so
-- the per-address counters are still there afterwards. `pfctl -T zero`
-- does ask for the recursion, so the two do not agree.
local tzero = hit.cleared
local addrpackets = a.packets_out
assert(addrpackets >= 1)
assert(handle:cleartables("hit") == 1)
hit:refresh()
assert(hit.match == 0 and hit.nomatch == 0)
assert(hit.packets_in == 0 and hit.packets_out == 0)
assert(hit.bytes_in == 0 and hit.bytes_out == 0)
assert(hit.cleared >= tzero, "cleartables did not move the cleared time")
assert(hit:addrstats()[1].packets_out == addrpackets,
    "cleartables zeroed the per-address counters too")

-- clearaddrstats should be the other half, and it is not. DIOCRCLRASTATS
-- zeroes the addresses named in the request buffer, and the binding sends
-- an empty one, so the call names nothing, reports nothing zeroed and
-- leaves the counters that survived cleartables in place.
assert(hit:clearaddrstats() == 0)
hit:refresh()
assert(hit:addrstats()[1].packets_out == addrpackets,
    "clearaddrstats zeroed an address it never named")

assert(handle:cleartables({ "hit", "miss" }) == 2)
assert(handle:cleartables("luapfnosuchtable") == 0)

-- A table lua creates is active but not persistent, which is why the
-- native part above sets persist before it changes any other flag.
-- pfctl -T add differs here: it always asks for a persistent table.
assert(handle:addtables("scratch") == 1)
local scratch = assert(handle:gettable("scratch"))
assert(scratch.active == true)
assert(scratch.persist == false, "addtables asked for persist")
assert(scratch.counters == false and scratch.const == false)
assert(scratch.referenced == false and scratch.refcnt_rule == 0)
assert(#scratch == 0 and #scratch:addrstats() == 0)

-- const rejects content changes, and setflags clears a flag as well as it
-- sets one. persist comes first so the table survives its own flag change.
assert(scratch:setflags({ persist = true }) == 1)
assert(scratch:add({ "10.99.0.20", "10.99.0.21" }) == 2)
assert(scratch:setflags({ const = true }) == 1)
scratch:refresh()
assert(scratch.const == true and scratch.persist == true)
assert(not pcall(function() return scratch:add("10.99.0.22") end),
    "a const table accepted an address")
assert(not pcall(function() return scratch:clear() end),
    "a const table let its addresses be cleared")
assert(scratch:setflags({ const = false }) == 1)
scratch:refresh()
assert(scratch.const == false, "setflags did not clear const")
assert(scratch:clear() == 2)
-- A repeat setflags changes nothing, so it reports nothing changed.
assert(scratch:setflags({ persist = true }) == 0)

-- clearalltables works per anchor, and an anchor that does not exist is an
-- error rather than a count of zero. The main ruleset goes back to what
-- the harness loaded first, so no rule holds a table reference when the
-- main ruleset is emptied.
assert(not pcall(function()
	return handle:clearalltables("luapfnosuchanchor")
end))
-- A table a rule still names keeps its reference and survives the clear,
-- so the rules go first, in both rulesets.
assert(sh("printf '%s\\n' 'pass log' | pfctl -f -") == "")
sh("pfctl -a audit -F rules")
assert(handle:clearalltables("audit") >= 1)
-- The anchor goes away with its last table, so asking for the table again
-- is now a missing anchor: an ENOENT error, not a nil return.
assert(not pcall(function() return handle:gettable("audit/inner") end))
assert(handle:clearalltables() >= 1)
assert(handle:gettable("scratch") == nil)
assert(#handle:tables() == 0, "clearalltables left a table behind")

os.remove("/tmp/pf_test_tables.conf")
os.remove("/tmp/pf_test_tables_anchor.conf")
tun:close()
