-- NAT and redirection, against a guest-local tun(4) point-to-point link.
--
-- lo0 is not a usable fixture for this: rules match and evaluate, but no
-- packet or state ever appears. tun(4) gives a real interface with a real
-- route whose far side is this process, so traffic genuinely crosses PF.
--
-- Guest only. It replaces the ruleset, so it must never run against a host.
local pf = require('pf')

local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_nat: not the disposable test guest; skipping")
	os.exit(0)
end
marker:close()

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>&1", "r"))
	local out = p:read("a")
	p:close()
	return out
end

local function loadrules(text)
	local f = assert(io.open("/tmp/pf_test_nat.conf", "w"))
	f:write(text)
	f:close()
	local out = sh("pfctl -f /tmp/pf_test_nat.conf")
	assert(out == "" or not out:find("error", 1, true),
	    "pfctl rejected the ruleset: " .. out)
end

-- The state whose destination is `hostport`, or nil.
local function findstate(h, proto, hostport)
	for _, s in ipairs(h:states()) do
		if s.proto == proto and s.destination == hostport then
			return s
		end
	end
	return nil
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

-- One UDP datagram as it would arrive on the wire. The UDP checksum is
-- left zero, which IPv4 permits and PF accepts.
local function udp4(src, sport, dst, dport, payload)
	local udp = string.pack(">I2I2I2I2", sport, dport, 8 + #payload, 0) ..
	    payload
	local hdr = string.pack(">I1I1I2I2I2I1I1I2", 0x45, 0, 20 + #udp,
	    0x1234, 0, 64, 17, 0) .. ip4(src) .. ip4(dst)
	hdr = hdr:sub(1, 10) .. string.pack(">I2", cksum(hdr)) .. hdr:sub(13)
	return hdr .. udp
end

-- Opening the device creates tun0 and is what keeps it running: the
-- interface goes down again on the last close, so this handle is held for
-- the whole test rather than opened per use.
local tun = assert(io.open("/dev/tun0", "r+b"))
tun:setvbuf("no")
assert(sh("ifconfig tun0 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up") == "")

local h = assert(pf.open())

-- An earlier test may have left a state for this pairing, and PF matches an
-- existing state before it ever reaches a translation rule.
assert(h:clearstates() >= 0)

-- Outbound: nat-to rewrites the source, and both halves of the translation
-- are visible on the state -- `source` is what goes on the wire, `gateway`
-- is what the stack asked for.
loadrules([[
set skip on lo
match out on tun0 inet proto udp from any to 10.99.0.2 nat-to 10.99.0.9
pass out log on tun0 inet proto udp
pass in log on tun0 inet proto udp
]])
sh("echo probe | nc -u -w 1 10.99.0.2 9999")

local s = findstate(h, "udp", "10.99.0.2:9999")
assert(s, "nat-to: no state for the outbound datagram")
assert(s.direction == "out", "nat-to: state is not outbound")
local natted = s.source:match("^([%d%.]+):")
local original = s.gateway and s.gateway:match("^([%d%.]+):")
assert(natted == "10.99.0.9",
    "nat-to: source is not the translated address: " .. tostring(s.source))
assert(original == "10.99.0.1",
    "nat-to: gateway is not the original address: " .. tostring(s.gateway))
assert(s.source ~= s.gateway, "nat-to: nothing was translated")

-- Inbound: rdr-to sends a datagram addressed to one port to another. The
-- packet is injected on tun0 rather than sent, because the far side of a
-- point-to-point link is this test.
assert(h:clearstates() >= 0)
loadrules([[
set skip on lo
match in on tun0 inet proto udp to 10.99.0.1 port 9999 rdr-to 10.99.0.1 port 9998
pass in log on tun0 inet proto udp
pass out log on tun0 inet proto udp
]])

os.execute("nc -u -l 10.99.0.1 9998 >/tmp/pf_test_nat.rdr 2>&1 &")
os.execute("sleep 1")
-- tun(4) prefixes each packet with its address family, network byte order.
tun:write(string.pack(">I4", 2) ..
    udp4("10.99.0.2", 40000, "10.99.0.1", 9999, "rdrprobe"))
tun:flush()
os.execute("sleep 1")
os.execute("pkill -f 'nc -u -l 10.99.0.1 9998'")

local got = assert(io.open("/tmp/pf_test_nat.rdr")):read("a")
assert(got:find("rdrprobe", 1, true),
    "rdr-to: the redirected listener received: " .. tostring(got))

local r = findstate(h, "udp", "10.99.0.1:9998")
assert(r, "rdr-to: no state for the injected datagram")
assert(r.direction == "in", "rdr-to: state is not inbound")
assert(r.source == "10.99.0.2:40000",
    "rdr-to: unexpected source " .. tostring(r.source))
-- Inbound, the gateway is the destination as it arrived, before the
-- redirect: the port the sender actually addressed.
assert(r.gateway == "10.99.0.1:9999",
    "rdr-to: gateway is not the original destination: " ..
    tostring(r.gateway))
assert(r.gateway ~= r.destination, "rdr-to: nothing was translated")

os.remove("/tmp/pf_test_nat.conf")
os.remove("/tmp/pf_test_nat.rdr")
tun:close()
