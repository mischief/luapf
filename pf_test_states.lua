-- The state table: the list object, every property of a state, and the
-- calls that read or remove one.
--
-- The read-only part runs anywhere and assumes no state exists. The
-- traffic and kill checks make a state of their own, so they need the
-- disposable guest.
local pf = require('pf')
local h = pf.open()
assert(h)

-- Every property the binding documents. The list is repeated here so that
-- one dropped or renamed property fails a test rather than passing quietly.
local properties = {
	"id", "creatorid", "ifname", "proto", "direction", "rule",
	"creation", "expire", "source", "destination", "gateway",
	"packets_in", "packets_out", "bytes_in", "bytes_out",
}

-- host:port for IPv4, [host]:port for IPv6.
local function ishostport(s)
	if type(s) ~= "string" then
		return false
	end
	local port = s:match("^%[[%x:.]+%]:(%d+)$")
	if not port then
		port = s:match("^%d+%.%d+%.%d+%.%d+:(%d+)$")
	end
	if not port then
		return false
	end
	return tonumber(port) <= 65535
end

local function checkstate(st)
	-- The kernel seeds the id counter from the clock in seconds, so a
	-- live id is well under the sign bit. A negative one would mean the
	-- 64-bit id lost its top bits on the way into a Lua integer.
	assert(type(st.id) == "number" and st.id > 0)
	assert(type(st.creatorid) == "number" and st.creatorid >= 0)
	-- Not every state is bound to an interface; unbound ones report the
	-- name of the catch-all kif. Either way the name is bounded and has
	-- no whitespace, because the kernel array is not NUL terminated.
	assert(type(st.ifname) == "string" and #st.ifname > 0)
	assert(#st.ifname < 16 and not st.ifname:find("%s"))
	assert(st.proto == nil or type(st.proto) == "string")
	assert(st.direction == "in" or st.direction == "out")
	-- A state made by no rule reports -1, the same as pfctl omitting it.
	assert(type(st.rule) == "number")
	assert(st.rule == -1 or st.rule >= 0)
	-- creation and expire are durations, not timestamps: age so far and
	-- seconds left. The kernel clamps an overdue state to zero, so expire
	-- may be zero while the state is still listed.
	assert(type(st.creation) == "number" and st.creation >= 0)
	assert(type(st.expire) == "number" and st.expire >= 0)
	assert(ishostport(st.source), "bad source " .. tostring(st.source))
	assert(ishostport(st.destination),
	    "bad destination " .. tostring(st.destination))
	assert(ishostport(st.gateway), "bad gateway " .. tostring(st.gateway))
	-- gateway is the same endpoint as the far side of translation sees
	-- it, so it shares an address family with the endpoint it mirrors.
	local mirrored = st.direction == "out" and st.source or st.destination
	assert((st.gateway:sub(1, 1) == "[") == (mirrored:sub(1, 1) == "["))

	assert(type(st.packets_in) == "number" and st.packets_in >= 0)
	assert(type(st.packets_out) == "number" and st.packets_out >= 0)
	assert(type(st.bytes_in) == "number" and st.bytes_in >= 0)
	assert(type(st.bytes_out) == "number" and st.bytes_out >= 0)
	-- The kernel counts whole IP packets, so a counted packet carries at
	-- least a minimal IPv4 header, and a state that moved nothing has
	-- nothing to show on either side.
	if st.packets_in > 0 then
		assert(st.bytes_in >= st.packets_in * 20)
	end
	if st.packets_out > 0 then
		assert(st.bytes_out >= st.packets_out * 20)
	end
	if st.packets_in + st.packets_out == 0 then
		assert(st.bytes_in + st.bytes_out == 0)
	end
end

local states = h:states()
assert(type(states) == "userdata")
local count = #states
assert(count >= 0)
assert(states[0] == nil)
assert(states[count + 1] == nil)
assert(states[-1] == nil)
assert(states["not-an-index"] == nil)
-- Only whole numbers index the list; a fraction is not rounded.
assert(states[1.5] == nil)

if count == 0 then
	print("pf_test_states: no states to inspect")
end

for i = 1, count do
	local st = states[i]
	assert(st)
	checkstate(st)

	-- __pairs must walk the documented set exactly once each, and agree
	-- with __index on every value.
	local seen = {}
	local keys = 0
	for key, value in pairs(st) do
		assert(type(key) == "string")
		assert(not seen[key], "pairs repeated " .. key)
		seen[key] = true
		keys = keys + 1
		assert(value == st[key], "pairs disagrees on " .. key)
	end
	assert(keys == #properties)
	for _, name in ipairs(properties) do
		assert(seen[name], "pairs omitted " .. name)
	end

	-- An unknown name reads as nil rather than raising, but a key that
	-- is not a string at all is an error.
	assert(st.nosuchproperty == nil)
	assert(not pcall(function()
		return st[true]
	end))
end

-- A second read of the whole table must describe the same states the same
-- way. Only the counters and the clock may have moved, and only forward.
local again = h:states()
local byid = {}
for i = 1, #again do
	local s = again[i]
	byid[string.format("%d:%d", s.id, s.creatorid)] = s
end
for i = 1, count do
	local s = states[i]
	local other = byid[string.format("%d:%d", s.id, s.creatorid)]
	if other then
		assert(other.ifname == s.ifname)
		assert(other.proto == s.proto)
		assert(other.direction == s.direction)
		assert(other.source == s.source)
		assert(other.destination == s.destination)
		assert(other.gateway == s.gateway)
		assert(other.rule == s.rule)
		assert(other.creation >= s.creation, "a state grew younger")
		assert(other.packets_in >= s.packets_in)
		assert(other.packets_out >= s.packets_out)
		assert(other.bytes_in >= s.bytes_in)
		assert(other.bytes_out >= s.bytes_out)
	end
end

if count > 0 then
	local st1 = states[1]
	-- A state may expire between the list and this read, so a miss here
	-- is not a failure; a hit must describe the same state.
	local one = h:getstate(st1.id, st1.creatorid)
	if one then
		checkstate(one)
		assert(one.id == st1.id)
		assert(one.creatorid == st1.creatorid)
		assert(one.ifname == st1.ifname)
		assert(one.proto == st1.proto)
		assert(one.direction == st1.direction)
		assert(one.source == st1.source)
		assert(one.destination == st1.destination)
		assert(one.gateway == st1.gateway)
		assert(one.rule == st1.rule)
		assert(one.creation >= st1.creation)
		assert(one.bytes_in >= st1.bytes_in)
		assert(one.bytes_out >= st1.bytes_out)
	end

	-- The lookup keys on the creator as well as the id, so the right id
	-- under the wrong creator is a miss.
	assert(h:getstate(st1.id, st1.creatorid ~ 1) == nil)
end

-- An id that cannot exist reads as nil, not an error.
assert(h:getstate(1, 1) == nil)
-- creatorid defaults to zero, which no live state carries.
assert(h:getstate(1) == nil)
assert(not pcall(h.getstate, h))
assert(not pcall(h.getstate, h, "not-an-id"))

-- An interface name too long to store is refused before any ioctl runs.
assert(not pcall(h.clearstates, h, string.rep("x", 32)))

local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_states: not the disposable test guest; " ..
	    "skipping the traffic checks")
	return
end
marker:close()

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>&1", "r"))
	local out = p:read("a")
	p:close()
	return out
end

-- Clearing an interface with no matching states is a no-op.
assert(h:clearstates("lo0") == 0)

-- tun(4) carries real packets across PF, and the guest already runs a
-- ruleset that keeps state on everything, so no rule needs to change
-- here. tun1, because pf_test_nat.lua owns tun0. Opening the device is
-- what creates the interface and keeps it alive.
local tun = io.open("/dev/tun1", "r+b")
if not tun then
	print("pf_test_states: no /dev/tun1; skipping the traffic checks")
	return
end
tun:setvbuf("no")
assert(sh("ifconfig tun1 10.99.1.1 10.99.1.2 netmask 255.255.255.255 up") ==
    "")
assert(sh("ifconfig tun1 inet6 fd00:99::1 fd00:99::2 prefixlen 128") == "")

local function findstate(proto, destination)
	local list = h:states()
	for i = 1, #list do
		local s = list[i]
		if s.proto == proto and s.destination == destination then
			return s
		end
	end
	return nil
end

-- One datagram, sent to a far side that is this process and never reads
-- it, so nothing answers and the reverse counters stay at zero.
local payload = string.rep("x", 40)
sh("printf '%s' '" .. payload .. "' | nc -u -w 1 10.99.1.2 9999")

local s4 = assert(findstate("udp", "10.99.1.2:9999"),
    "no state for the packet sent over tun1")
checkstate(s4)
-- ifname is the interface the state is bound to, which for a rule that
-- names no interface is the catch-all kif, not the wire the packet took.
assert(s4.ifname == "tun1" or s4.ifname == "all")
assert(s4.direction == "out")
assert(s4.source:match("^10%.99%.1%.1:%d+$"))
-- The counters index the state's own direction first, not the host's, so
-- an outbound state counts what it sent in packets_in.
assert(s4.packets_in == 1 and s4.packets_out == 0)
assert(s4.bytes_in == 20 + 8 + #payload)
assert(s4.bytes_out == 0)

-- An IPv6 address is tentative until duplicate address detection ends,
-- and a send from a tentative source fails outright, so wait for it.
sh("sleep 4")
local out6 = sh("printf '%s' '" .. payload .. "' | nc -u -w 1 fd00:99::2 9999")

local s6 = assert(findstate("udp", "[fd00:99::2]:9999"),
    "no state for the IPv6 packet sent over tun1: " .. out6)
checkstate(s6)
assert(s6.source:match("^%[fd00:99::1%]:%d+$"))
assert(s6.packets_in == 1 and s6.packets_out == 0)
assert(s6.bytes_in == 40 + 8 + #payload)

-- Killing a state this test made is the only safe way to check the count
-- the call reports: the id must be gone afterwards, and stay gone.
local killed = h:killstates(s4.id)
assert(killed == 1, "killstates removed " .. killed .. " states, not 1")
assert(h:getstate(s4.id, s4.creatorid) == nil)
assert(h:killstates(s4.id) == 0)

-- Killing one state leaves the rest alone.
assert(h:getstate(s6.id, s6.creatorid))
assert(h:killstates(s6.id) == 1)
assert(h:getstate(s6.id, s6.creatorid) == nil)

tun:close()
sh("ifconfig tun1 destroy")
