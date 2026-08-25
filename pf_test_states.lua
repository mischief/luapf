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
	"anchor", "creation", "expire", "timeout", "timeout_name",
	"source", "destination", "gateway", "rdomain", "gateway_rdomain",
	"near_wire", "far_wire", "near_stack", "far_stack",
	"route", "route_addr",
	"src_state", "dst_state", "connection_state",
	"state_flags", "state_flag_names",
	"packets_in", "packets_out", "bytes_in", "bytes_out",
	"src_seqlo", "src_seqhi", "src_seqdiff", "src_max_win",
	"src_mss", "src_wscale",
	"dst_seqlo", "dst_seqhi", "dst_seqdiff", "dst_max_win",
	"dst_mss", "dst_wscale",
}

-- The state flag bits, in the order the binding names them.
local stateflags = {
	{0x0001, "allowopts"}, {0x0002, "sloppy"}, {0x0004, "pflow"},
	{0x0008, "nosync"}, {0x0010, "ack"}, {0x0020, "nodf"},
	{0x0040, "settos"}, {0x0080, "randomid"}, {0x0100, "scrub-tcp"},
	{0x0200, "setprio"}, {0x0400, "inp-unlinked"},
}

-- The connection state levels each protocol has names for. A protocol with
-- no names, ICMP among them, reports the level as a number instead.
local levelnames = {
	tcp = {
		CLOSED = true, LISTEN = true, SYN_SENT = true,
		SYN_RCVD = true, ESTABLISHED = true, CLOSE_WAIT = true,
		FIN_WAIT_1 = true, CLOSING = true, LAST_ACK = true,
		FIN_WAIT_2 = true, TIME_WAIT = true,
		PROXY_SRC = true, PROXY_DST = true,
	},
	udp = {NO_TRAFFIC = true, SINGLE = true, MULTIPLE = true},
	other = {NO_TRAFFIC = true, SINGLE = true, MULTIPLE = true},
}

local function isuint(v, max)
	return type(v) == "number" and v >= 0 and v <= max and
	    v == math.floor(v)
end

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

	-- The four addresses a state holds: two ends, each in the view the
	-- wire has of it and the view the stack has. source, destination and
	-- gateway are three of those four read by direction.
	for _, name in ipairs({"near_wire", "far_wire", "near_stack",
	    "far_stack"}) do
		assert(ishostport(st[name]), "bad " .. name .. " " ..
		    tostring(st[name]))
	end
	if st.direction == "out" then
		assert(st.source == st.near_wire)
		assert(st.destination == st.far_wire)
		assert(st.gateway == st.near_stack)
	else
		assert(st.source == st.far_stack)
		assert(st.destination == st.near_stack)
		assert(st.gateway == st.near_wire)
	end

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

	-- A state made inside an anchor numbers its rule against that anchor,
	-- so neither number means anything without the other. Both report -1
	-- when there is none.
	assert(type(st.anchor) == "number")
	assert(st.anchor == -1 or st.anchor >= 0)

	-- An address carries no routing domain of its own, so two states in
	-- different domains may report the same source and destination.
	assert(isuint(st.rdomain, 65535))
	assert(isuint(st.gateway_rdomain, 65535))

	-- The bucket the state sits in is what sets expire.
	assert(isuint(st.timeout, 255))
	assert(st.timeout_name == nil or st.timeout_name:match("^%a[%a%.]*$"))

	assert(st.route == nil or st.route == "route-to" or
	    st.route == "dup-to" or st.route == "reply-to")
	assert(st.route_addr == nil or
	    (type(st.route_addr) == "string" and #st.route_addr > 0))
	if st.route_addr then
		assert(st.route, "a route target with no route")
	end

	-- src_state belongs to source and dst_state to destination, and the
	-- combined string joins the two the way pfctl does.
	assert(type(st.src_state) == "string" and #st.src_state > 0)
	assert(type(st.dst_state) == "string" and #st.dst_state > 0)
	assert(st.connection_state == st.src_state .. ":" .. st.dst_state)
	local known = levelnames[st.proto] or levelnames.other
	for _, level in ipairs({st.src_state, st.dst_state}) do
		assert(known[level] or level:match("^%d+$"),
		    "unknown level " .. level .. " for " ..
		    tostring(st.proto))
	end

	-- The names are the set bits, in bit order and nothing else.
	assert(isuint(st.state_flags, 65535))
	assert(type(st.state_flag_names) == "string")
	local want = {}
	for _, f in ipairs(stateflags) do
		if st.state_flags & f[1] ~= 0 then
			want[#want + 1] = f[2]
		end
	end
	assert(st.state_flag_names == table.concat(want, ","),
	    "flags " .. st.state_flags .. " read as " .. st.state_flag_names)

	-- Window tracking is per peer, and wscale is the shift alone: the
	-- flag bit above it is masked off.
	for _, name in ipairs({"seqlo", "seqhi", "seqdiff", "max_win",
	    "mss", "wscale"}) do
		assert(isuint(st["src_" .. name], 0xffffffff))
		assert(isuint(st["dst_" .. name], 0xffffffff))
	end
	assert(st.src_wscale <= 15 and st.dst_wscale <= 15)
	assert(st.src_mss <= 65535 and st.dst_mss <= 65535)
	assert(st.src_max_win <= 65535 and st.dst_max_win <= 65535)
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
		assert(other.rdomain == s.rdomain)
		assert(other.gateway_rdomain == s.gateway_rdomain)
		assert(other.rule == s.rule)
		assert(other.anchor == s.anchor)
		assert(other.route == s.route)
		assert(other.route_addr == s.route_addr)
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
		assert(one.anchor == st1.anchor)
		assert(one.rdomain == st1.rdomain)
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

-- What pfctl says about the states whose line contains needle: the
-- direction it renders as an arrow, and the pair of connection state
-- levels it prints last on the line.
local function pfctlstates(needle)
	local rows = {}
	for line in sh("pfctl -s states"):gmatch("[^\n]+") do
		local a, b = line:match("(%u[%u_%d]*):(%u[%u_%d]*)%s*$")
		if a and line:find(needle, 1, true) then
			rows[#rows + 1] = {
				direction = line:find(" %-> ") and "out" or
				    "in",
				pair = a .. ":" .. b,
			}
		end
	end
	return rows
end

-- pfctl orders the pair by the direction PF saw the packets in, while
-- src_state belongs to source and dst_state to destination. The two agree
-- outbound and are reversed inbound.
local function pfctlpair(st)
	if st.direction == "in" then
		return st.dst_state .. ":" .. st.src_state
	end
	return st.connection_state
end

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
-- in and out are the direction PF saw the packet in, the same as every
-- other counter pair in this binding, so the one datagram this host sent
-- counts as out however the kernel indexed it.
assert(s4.packets_out == 1 and s4.packets_in == 0)
assert(s4.bytes_out == 20 + 8 + #payload)
assert(s4.bytes_in == 0)

-- One datagram from the source, nothing back from the destination.
assert(s4.connection_state == "SINGLE:NO_TRAFFIC", s4.connection_state)
assert(s4.src_state == "SINGLE" and s4.dst_state == "NO_TRAFFIC")
assert(s4.timeout_name == "udp.first", tostring(s4.timeout_name))
assert(s4.rdomain == 0 and s4.gateway_rdomain == 0)
assert(s4.anchor == -1 and s4.rule >= 0)
assert(s4.route == nil and s4.route_addr == nil)
-- PF windows TCP and nothing else, so every peer field stays at zero.
for _, name in ipairs({"seqlo", "seqhi", "seqdiff", "max_win", "mss",
    "wscale"}) do
	assert(s4["src_" .. name] == 0 and s4["dst_" .. name] == 0,
	    "udp state carries a " .. name)
end

local rows = pfctlstates("10.99.1.2:9999")
assert(#rows == 1, "pfctl shows " .. #rows .. " states for the datagram")
assert(rows[1].direction == s4.direction)
assert(rows[1].pair == pfctlpair(s4),
    "pfctl reads " .. rows[1].pair .. ", the binding " ..
    s4.connection_state)

-- An IPv6 address is tentative until duplicate address detection ends,
-- and a send from a tentative source fails outright, so wait for it.
sh("sleep 4")
local out6 = sh("printf '%s' '" .. payload .. "' | nc -u -w 1 fd00:99::2 9999")

local s6 = assert(findstate("udp", "[fd00:99::2]:9999"),
    "no state for the IPv6 packet sent over tun1: " .. out6)
checkstate(s6)
assert(s6.source:match("^%[fd00:99::1%]:%d+$"))
assert(s6.packets_out == 1 and s6.packets_in == 0)
assert(s6.bytes_out == 40 + 8 + #payload)
assert(s6.connection_state == "SINGLE:NO_TRAFFIC")

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

-- The remaining properties need rules that set them. The guest ruleset is
-- restored below, so nothing after this test sees these.
local function loadrules(text)
	local f = assert(io.open("/tmp/pf_test_states.conf", "w"))
	f:write(text)
	f:close()
	local out = sh("pfctl -f /tmp/pf_test_states.conf")
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
	while sum > 0xffff do
		sum = (sum & 0xffff) + (sum >> 16)
	end
	return (~sum) & 0xffff
end

-- One packet as it would arrive on the wire, for a protocol nothing here
-- can send otherwise. The UDP checksum is left zero, which IPv4 permits.
local function ip4packet(proto, src, dst, payload)
	local hdr = string.pack(">I1I1I2I2I2I1I1I2", 0x45, 0, 20 + #payload,
	    0x1234, 0, 64, proto, 0) .. ip4(src) .. ip4(dst)
	hdr = hdr:sub(1, 10) .. string.pack(">I2", cksum(hdr)) .. hdr:sub(13)
	return hdr .. payload
end

sh("route -n add -net 10.99.2.0/24 10.99.1.2")
sh("route -n add -net 10.99.4.0/24 10.99.1.2")
sh("route -n add -net 10.99.5.0/24 10.99.1.2")
loadrules([[
pass log
pass out log on tun1 inet proto udp to 10.99.2.0/24 \
    route-to 10.99.1.2 nat-to 10.99.1.9 keep state (sloppy)
pass in log on tun1 inet proto udp from 10.99.3.1 \
    reply-to 10.99.1.2
pass out log on tun1 inet proto udp to 10.99.5.0/24 dup-to 10.99.1.2
anchor "luapf-states" out on tun1 inet proto udp to 10.99.4.0/24 {
	pass log
}
]])

sh("printf x | nc -u -w 1 10.99.2.5 9999")
local routed = assert(findstate("udp", "10.99.2.5:9999"),
    "no state for the route-to datagram")
checkstate(routed)
assert(routed.route == "route-to", tostring(routed.route))
assert(routed.route_addr == "10.99.1.2", tostring(routed.route_addr))
assert(routed.state_flag_names:find("sloppy"), routed.state_flag_names)
assert(routed.state_flags & 0x0002 ~= 0)
-- nat-to rewrote the near end, so its two views differ while the far end
-- reads the same either way.
assert(routed.near_wire:match("^10%.99%.1%.9:%d+$"), routed.near_wire)
assert(routed.near_stack:match("^10%.99%.1%.1:%d+$"), routed.near_stack)
assert(routed.far_wire == routed.far_stack)
assert(routed.far_wire == "10.99.2.5:9999")

sh("printf x | nc -u -w 1 10.99.5.5 9999")
local duped = assert(findstate("udp", "10.99.5.5:9999"),
    "no state for the dup-to datagram")
checkstate(duped)
assert(duped.route == "dup-to", tostring(duped.route))
assert(duped.route_addr == "10.99.1.2", tostring(duped.route_addr))

sh("printf x | nc -u -w 1 10.99.4.5 9999")
local inanchor = assert(findstate("udp", "10.99.4.5:9999"),
    "no state for the anchored datagram")
checkstate(inanchor)
-- A rule inside an anchor numbers itself against that anchor, so the two
-- are only meaningful together.
assert(inanchor.anchor >= 0, "anchored state reports anchor " ..
    inanchor.anchor)
assert(inanchor.rule >= 0)
-- The state holds the anchor open, and the kernel drops an anchor with
-- neither rules nor states in it. Leaving one behind would show up in
-- whatever reads the anchor list next.
assert(h:killstates(inanchor.id) == 1)

-- tun(4) prefixes each packet with its address family, network byte order.
tun:write(string.pack(">I4", 2) .. ip4packet(17, "10.99.3.1", "10.99.1.1",
    string.pack(">I2I2I2I2", 4444, 9997, 8, 0)))
tun:flush()
sh("sleep 1")
local replied = assert(findstate("udp", "10.99.1.1:9997"),
    "no state for the datagram written to tun1")
checkstate(replied)
assert(replied.direction == "in")
assert(replied.route == "reply-to", tostring(replied.route))
assert(replied.route_addr == "10.99.1.2", tostring(replied.route_addr))

-- A protocol PF has no names for reports the same three levels as UDP,
-- because everything that is not TCP, UDP or ICMP shares one table.
tun:write(string.pack(">I4", 2) ..
    ip4packet(47, "10.99.3.1", "10.99.1.1", "\0\0\0\0"))
tun:flush()
sh("sleep 1")
local other = assert(findstate("gre", "10.99.1.1:0"),
    "no state for the GRE packet written to tun1")
checkstate(other)
assert(other.connection_state == "SINGLE:NO_TRAFFIC",
    other.connection_state)
assert(other.timeout_name == "other.first", tostring(other.timeout_name))

-- ICMP has no state levels at all, so its pair reads as numbers.
sh("ping -c 1 -w 1 10.99.1.2")
local icmp
local afterping = h:states()
for i = 1, #afterping do
	if afterping[i].proto == "icmp" then
		icmp = afterping[i]
	end
end
assert(icmp, "no state for the echo request")
checkstate(icmp)
assert(icmp.connection_state:match("^%d+:%d+$"), icmp.connection_state)
assert(icmp.src_state:match("^%d+$") and icmp.dst_state:match("^%d+$"))

sh("printf '%s\\n' 'pass log' | pfctl -f -")
sh("pfctl -a luapf-states -F rules")

tun:close()
sh("ifconfig tun1 destroy")

-- Loopback carries the same datagram past PF twice, once outbound and once
-- inbound, which is the only place the two orderings of the pair differ.
sh("printf x | nc -u -w 1 127.0.0.1 9998")
local seen = {}
local list = h:states()
for i = 1, #list do
	local s = list[i]
	if s.proto == "udp" and s.destination == "127.0.0.1:9998" then
		checkstate(s)
		assert(s.connection_state == "SINGLE:NO_TRAFFIC",
		    s.direction .. " reads " .. s.connection_state)
		seen[s.direction] = s
	end
end
assert(seen.out, "no outbound state for the loopback datagram")
assert(seen["in"], "no inbound state for the loopback datagram")

for _, row in ipairs(pfctlstates("127.0.0.1:9998")) do
	local s = assert(seen[row.direction])
	assert(row.pair == pfctlpair(s),
	    "pfctl reads " .. row.pair .. " for the " .. row.direction ..
	    " state, the binding " .. s.connection_state)
end
assert(pfctlpair(seen["in"]) == "NO_TRAFFIC:SINGLE")

-- A connection is the only way to reach the TCP levels. The far side holds
-- it open long enough to be read, then both ends close.
local port = 31338
sh("nc -l 127.0.0.1 " .. port .. " >/dev/null 2>&1 &" ..
    " sleep 1; { sleep 8; echo x; } | nc -N 127.0.0.1 " .. port ..
    " >/dev/null 2>&1 & sleep 3")

local function findtcp()
	local found = {}
	local all = h:states()
	for i = 1, #all do
		local s = all[i]
		if s.proto == "tcp" and (s.source:find(":" .. port) or
		    s.destination:find(":" .. port)) then
			found[#found + 1] = s
		end
	end
	return found
end

local open = findtcp()
assert(#open > 0, "no state for the loopback connection")
for _, s in ipairs(open) do
	checkstate(s)
	assert(s.connection_state == "ESTABLISHED:ESTABLISHED",
	    "the open connection reads " .. s.connection_state)
	assert(s.timeout_name == "tcp.established", tostring(s.timeout_name))
	-- Both peers have sent something and allow something, so the window
	-- PF tracks for each of them is real. seqhi alone is not the window.
	assert(s.src_seqlo > 0 and s.dst_seqlo > 0)
	assert(s.src_seqhi - s.src_seqlo > 0)
	assert(s.dst_seqhi - s.dst_seqlo > 0)
	assert(s.src_max_win > 0 and s.dst_max_win > 0)
end

for _, row in ipairs(pfctlstates("127.0.0.1:" .. port)) do
	assert(row.pair == "ESTABLISHED:ESTABLISHED", row.pair)
end

-- Once both ends have closed, the levels move on and the state waits out
-- its new bucket rather than disappearing.
sh("sleep 9")
local closed = findtcp()
assert(#closed > 0, "the closed connection left no state")
for _, s in ipairs(closed) do
	checkstate(s)
	assert(s.connection_state:find("FIN_WAIT") or
	    s.connection_state:find("TIME_WAIT") or
	    s.connection_state:find("CLOSED"),
	    "the closed connection reads " .. s.connection_state)
	assert(s.timeout_name ~= "tcp.established", "still established")
end
