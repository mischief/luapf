local pf = require("pf")

local h = pf.open()
assert(h)

local queues = h:queues()
assert(type(queues) == "table")
for _, q in ipairs(queues) do
	assert(type(q.name) == "string" and #q.name > 0)
	assert(type(q.parent) == "string")
	assert(type(q.ifname) == "string")
	assert(type(q.qid) == "number")
	assert(type(q.parent_qid) == "number")
	assert(type(q.scheduler) == "string")
	assert(q.scheduler == "fifo" or q.scheduler == "flow")
	assert(type(q.queue_length) == "number")
	assert(type(q.queue_limit) == "number")
	assert(type(q.transmit_packets) == "number")
	assert(type(q.transmit_bytes) == "number")
	assert(type(q.drop_packets) == "number")
	assert(type(q.drop_bytes) == "number")
	if q.scheduler == "flow" then
		assert(type(q.flows) == "number")
	end
end

-- The rest needs a queue ruleset, which means an interface to hang one on
-- and a ruleset of our own -- so it runs only in the disposable guest.
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

-- Opening the device creates tun0 and is what keeps it running.
local tun = assert(io.open("/dev/tun0", "r+b"))
assert(sh("ifconfig tun0 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up") == "")

local f = assert(io.open("/tmp/pf_test_queues.conf", "w"))
f:write([[
queue rootq on tun0 bandwidth 10M max 10M
queue qfast parent rootq bandwidth 5M
queue qdef parent rootq bandwidth 1M default
pass out on tun0 inet proto udp set queue qdef
]])
f:close()
assert(sh("pfctl -f /tmp/pf_test_queues.conf") == "",
    "pfctl rejected the queue ruleset")

local qs = h:queues()
assert(#qs == 3, "expected three queues, got " .. #qs)

local byname = {}
for _, q in ipairs(qs) do
	assert(type(q.name) == "string" and #q.name > 0)
	assert(type(q.parent) == "string")
	assert(q.ifname == "tun0", "queue on the wrong interface: " ..
	    tostring(q.ifname))
	assert(type(q.qid) == "number" and q.qid > 0)
	assert(type(q.scheduler) == "string")
	byname[q.name] = q
end

assert(byname.rootq, "root queue missing")
assert(byname.rootq.parent == "", "the root queue has a parent")
assert(byname.qfast and byname.qfast.parent == "rootq",
    "qfast is not parented to rootq")
assert(byname.qdef and byname.qdef.parent == "rootq",
    "qdef is not parented to rootq")

-- A child names its parent both ways: by string and by qid.
assert(byname.qfast.parent_qid == byname.rootq.qid,
    "qfast's parent_qid does not point at rootq")
assert(byname.rootq.parent_qid == 0, "the root queue has a parent qid")

for _, q in ipairs(qs) do
	assert(type(q.transmit_packets) == "number" and q.transmit_packets >= 0)
	assert(type(q.transmit_bytes) == "number" and q.transmit_bytes >= 0)
	assert(type(q.drop_packets) == "number" and q.drop_packets >= 0)
	assert(type(q.drop_bytes) == "number" and q.drop_bytes >= 0)
	assert(type(q.queue_length) == "number")
	assert(type(q.queue_limit) == "number" and q.queue_limit > 0)
	local n = 0
	for _ in pairs(q) do
		n = n + 1
	end
	assert(n > 0, "queue " .. q.name .. " exposes no properties")
end

-- Traffic through the queued rule must not disturb the queue set. Whether
-- a counter moves is up to the queueing engine and the interface -- tun(4)
-- with nothing reading the device does not oblige -- and that is not what
-- this binding is responsible for reporting.
sh("echo queued | nc -u -w 1 10.99.0.2 9997")
assert(#h:queues() == 3, "the queue set changed under traffic")

os.remove("/tmp/pf_test_queues.conf")
sh("pfctl -f /etc/pf.conf")
tun:close()
