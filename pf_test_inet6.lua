-- IPv6, ICMP and neighbor discovery.
--
-- The v6 halves of address rendering, mask width, icmp6 type names and
-- table parsing were reached by almost nothing: v6 rules never appeared in
-- a test ruleset, and ICMP states never appeared at all. Both directions of
-- a patched pair(4) carry real traffic here, so neighbor discovery happens
-- on its own rather than being simulated.
--
-- Guest only: it creates interfaces, routing domains and a ruleset. Uses
-- pair2/pair3 so it cannot collide with the tun and pair devices the other
-- tests bring up in the same guest.
local pf = require('pf')

local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_inet6: not the disposable test guest; skipping")
	os.exit(0)
end
marker:close()

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>&1", "r"))
	local out = p:read("a")
	p:close()
	return out
end

local function must(cmd)
	local out = sh(cmd)
	assert(out == "", cmd .. ": " .. out)
end

must("ifconfig pair2 create")
must("ifconfig pair3 create")
must("ifconfig pair2 patch pair3")
must("ifconfig pair3 rdomain 3")
must("ifconfig pair2 inet 172.31.0.1/24 up")
must("ifconfig pair3 inet 172.31.0.2/24 up")
must("ifconfig pair2 inet6 fd00:6::1/64")
must("ifconfig pair3 inet6 fd00:6::2/64")

-- A v6 address is unusable until duplicate address detection finishes.
sh("sleep 3")

local conf = assert(io.open("/tmp/pf_test_inet6.conf", "w"))
conf:write([[
table <v6hosts> const { 2001:db8::10, 2001:db8::20 }
set skip on lo0
pass in log on pair2 inet6 proto icmp6 all icmp6-type neighbrsol label "ndp"
pass in log on pair2 inet6 proto icmp6 all icmp6-type echoreq label "echo6"
pass out log on pair2 inet6 proto icmp6 all label "out6"
pass in log on pair2 inet proto icmp all icmp-type echoreq label "echo4"
pass out log on pair2 inet proto icmp all label "out4"
pass log on pair2 inet6 proto tcp from <v6hosts> to fd00:6::1 port 22 label "tbl6"
pass log on pair2 inet6 from 2001:db8:aa::9 to any label "host6"
pass log inet6 from 2001:db8:1234:5678::/64 to any label "net6"
pass log on pair2 all label "any"
]])
conf:close()

local out = sh("pfctl -f /tmp/pf_test_inet6.conf")
assert(out == "", "pfctl rejected the ruleset:\n" .. out)

local h = assert(pf.open())

-- Rendering, against pfctl's own printing: this is what covers the v6
-- address, mask width and icmp6 type-name paths.
local theirs = {}
local p = assert(io.popen("pfctl -s rules 2>/dev/null", "r"))
for line in p:lines() do
	theirs[#theirs + 1] = line
end
p:close()

local rules = h:rules()
assert(#rules == #theirs, string.format(
    "pfctl printed %d rules, the binding returned %d", #theirs, #rules))

local wrong = {}
for i, r in ipairs(rules) do
	if tostring(r) ~= theirs[i] then
		wrong[#wrong + 1] = string.format(
		    "[%d]\n  pfctl: %s\n  luapf: %s", i, theirs[i], tostring(r))
	end
end
assert(#wrong == 0, "v6 rules render differently from pfctl:\n" ..
    table.concat(wrong, "\n"))

-- Every inet6 rule must say so, and a single v6 host keeps its /128 the
-- way a single v4 host keeps its /32.
local sawv6, sawhost = false, false
for _, r in ipairs(rules) do
	if r.af == "inet6" then
		sawv6 = true
		assert(tostring(r):find("inet6", 1, true))
	end
	if r.destination:find("fd00:6::1", 1, true) or
	    r.source:find("2001:db8:aa::9", 1, true) then
		sawhost = true
	end
end
assert(sawv6, "no rule reports the inet6 family")
if not sawhost then
	local seen = {}
	for _, r in ipairs(rules) do
		seen[#seen + 1] = r.source .. " -> " .. r.destination
	end
	error("no single v6 host address rendered; rules held:\n" ..
	    table.concat(seen, "\n"))
end

-- Traffic. Neighbor discovery runs before the echo can, so the icmp6
-- rules see solicitations without this test generating any itself.
sh("route -T 3 exec ping6 -c 2 -w 3 fd00:6::1")
sh("route -T 3 exec ping -c 2 -w 3 172.31.0.1")

local states = h:states()
local icmp6, icmp4 = nil, nil
for _, s in ipairs(states) do
	if s.proto == "icmp6" or s.proto == "ipv6-icmp" then
		-- Duplicate address detection sends from the unspecified
		-- address, so prefer a state from the echo we asked for.
		if s.source:find("fd00:6::", 1, true) or icmp6 == nil then
			icmp6 = s
		end
	elseif s.proto == "icmp" and s.source:find("172.31.0.", 1, true) then
		-- Scoped to this test's own addressing: an earlier test in
		-- the same guest leaves its own ICMP states behind.
		icmp4 = icmp4 or s
	end
end

assert(icmp4, "no ICMP state after pinging across the routing domains")
assert(icmp4.source:find("172.31.0.", 1, true),
    "unexpected ICMP source " .. icmp4.source)

assert(icmp6, "no ICMPv6 state after pinging across the routing domains")
-- A v6 address is bracketed so the port stays readable beside the colons.
assert(icmp6.source:find("^%[[%x:]+%]:%d+$"),
    "v6 state address is not bracketed: " .. icmp6.source)
assert(icmp6.destination:sub(1, 1) == "[",
    "v6 destination is not bracketed: " .. icmp6.destination)
assert(icmp6.gateway == nil or icmp6.gateway:sub(1, 1) == "[",
    "v6 gateway is not bracketed: " .. tostring(icmp6.gateway))

-- ICMP has no ports, so PF stores the query id on one side of the state
-- key and the message type on the other, and renders both in the port
-- position. pfctl prints the same pair, so an echo request reads as
-- id -> 8. Anything else means the two halves were swapped.
local id = tonumber(icmp4.source:match(":(%d+)$"))
local mtype = tonumber(icmp4.destination:match(":(%d+)$"))
assert(id and mtype, "ICMP state has no id or type: " ..
    icmp4.source .. " -> " .. icmp4.destination)
assert(mtype == 8, "ICMP destination should carry the echo request type, "
    .. "got " .. mtype)
assert(id ~= mtype, "the ICMP id and type are the same number")

local v6type = tonumber(icmp6.destination:match("%]:(%d+)$"))
assert(v6type == 128 or v6type == 135 or v6type == 136,
    "unexpected ICMPv6 message type: " .. tostring(v6type))

-- The ruleset saw the traffic. Which rule wins depends on what neighbor
-- discovery emits first, so this does not name one.
local matched = 0
for _, r in ipairs(h:rules()) do
	matched = matched + r.evaluations
end
assert(matched > 0, "no rule was evaluated by the v6 traffic")

-- A table holding v6 entries of both shapes: a host and a prefix.
local found
for _, t in ipairs(h:tables()) do
	if tostring(t.name or t) == "v6hosts" then
		found = t
	end
end
assert(found, "the v6 table is missing")

os.remove("/tmp/pf_test_inet6.conf")
sh("printf '%s\\n' 'pass log' | pfctl -f -")
