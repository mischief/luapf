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

-- Opening the device creates the tun interface and is what keeps it
-- running. Two interfaces are used so the binding has to report ifname
-- per queue rather than echo a single one.
local tun0 = assert(io.open("/dev/tun0", "r+b"))
local tun1 = assert(io.open("/dev/tun1", "r+b"))
assert(sh("ifconfig tun0 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up") == "")
assert(sh("ifconfig tun1 10.99.1.1 10.99.1.2 netmask 255.255.255.255 up") == "")

-- tun0 carries a three-level HFSC tree plus one leaf flow queue, tun1 a
-- root flow queue. That reaches both arms of the statistics union and
-- gives parent_qid something deeper than one level to point at.
local f = assert(io.open("/tmp/pf_test_queues.conf", "w"))
f:write([[
queue rootq on tun0 bandwidth 10M max 10M qlimit 100
queue qfast parent rootq bandwidth 5M burst 8M for 100ms
queue qdef parent rootq bandwidth 1M default
queue qmid parent rootq bandwidth 3M
queue qleaf parent qmid bandwidth 2M
queue qflow parent rootq bandwidth 1M flows 256 quantum 1500
queue fqroot on tun1 flows 512 qlimit 512 default
pass out on tun0 inet proto udp set queue qdef
]])
f:close()
local loaded = sh("pfctl -f /tmp/pf_test_queues.conf")
assert(loaded == "", "pfctl rejected the queue ruleset: " .. loaded)

-- pfctl -g -v prints, per queue, the same qid, parent_qid, ifname and
-- queue length that the binding reports. Parsing it gives an independent
-- reading of the very ioctls the binding calls.
local function pfctlqueues()
	local byname, order = {}, {}
	local cur
	for line in sh("pfctl -g -v -s queue"):gmatch("[^\n]+") do
		local name = line:match("^queue (%S+)")
		if name then
			cur = { name = name }
			byname[name] = cur
			order[#order + 1] = name
		elseif cur then
			local len, lim = line:match("qlength:%s*(%d+)/%s*(%d+)")
			if len then
				cur.queue_length = tonumber(len)
				cur.queue_limit = tonumber(lim)
			end
			local qid, pqid, ifname =
			    line:match("qid=(%d+) parent_qid=(%d+) ifname=(%S-)%]")
			if qid then
				cur.qid = tonumber(qid)
				cur.parent_qid = tonumber(pqid)
				cur.ifname = ifname
			end
		end
	end
	return byname, order
end

local ref, reforder = pfctlqueues()
local qs = h:queues()
assert(#qs == #reforder, "expected " .. #reforder ..
    " queues, the binding reported " .. #qs)

local byname, byqid = {}, {}
for _, q in ipairs(qs) do
	assert(type(q.name) == "string" and #q.name > 0)
	assert(type(q.parent) == "string")
	assert(type(q.qid) == "number" and q.qid > 0)
	assert(type(q.scheduler) == "string")
	assert(not byqid[q.qid], "two queues share qid " .. q.qid)
	byname[q.name] = q
	byqid[q.qid] = q
end

-- Every queue pfctl saw, with the same identity. A queue name is unique
-- across the whole set here, so name is a safe key for the comparison.
for name, r in pairs(ref) do
	local q = byname[name]
	assert(q, "the binding lost queue " .. name)
	assert(q.qid == r.qid, name .. ": qid " .. q.qid .. " but pfctl says " ..
	    r.qid)
	assert(q.parent_qid == r.parent_qid, name .. ": parent_qid " ..
	    q.parent_qid .. " but pfctl says " .. r.parent_qid)
	assert(q.ifname == r.ifname, name .. ": ifname " .. q.ifname ..
	    " but pfctl says " .. r.ifname)
	assert(q.queue_limit == r.queue_limit, name .. ": queue_limit " ..
	    q.queue_limit .. " but pfctl says " .. r.queue_limit)
	assert(q.queue_length == r.queue_length, name .. ": queue_length " ..
	    q.queue_length .. " but pfctl says " .. r.queue_length)
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

-- Three levels: qleaf -> qmid -> rootq. A one-level tree cannot tell a
-- parent_qid that is really the parent's from one that is always the
-- root's.
assert(byname.qmid and byname.qleaf, "the middle of the tree is missing")
assert(byname.qleaf.parent == "qmid", "qleaf is not parented to qmid")
assert(byname.qmid.parent == "rootq", "qmid is not parented to rootq")
assert(byname.qleaf.parent_qid == byname.qmid.qid,
    "qleaf's parent_qid does not point at qmid")
assert(byname.qmid.parent_qid == byname.rootq.qid,
    "qmid's parent_qid does not point at rootq")
assert(byname.qleaf.parent_qid ~= byname.rootq.qid,
    "qleaf's parent_qid points past qmid at the root")

-- The parent name and the parent qid must agree for every queue, not
-- only the ones named above.
for _, q in ipairs(qs) do
	if q.parent ~= "" then
		local p = byqid[q.parent_qid]
		assert(p, q.name .. ": parent_qid " .. q.parent_qid ..
		    " names no queue")
		assert(p.name == q.parent, q.name .. ": parent is " ..
		    q.parent .. " but parent_qid points at " .. p.name)
		assert(p.ifname == q.ifname,
		    q.name .. " and its parent sit on different interfaces")
	else
		assert(q.parent_qid == 0,
		    q.name .. " has no parent but a parent qid")
	end
end

-- Two interfaces, each with its own tree.
assert(byname.fqroot, "the tun1 queue is missing")
assert(byname.fqroot.ifname == "tun1", "fqroot is on " ..
    byname.fqroot.ifname)
assert(byname.rootq.ifname == "tun0", "rootq is on " ..
    byname.rootq.ifname)
assert(byname.fqroot.parent == "", "the tun1 root queue has a parent")

-- A root flow queue is the one case where the kernel fills the flow
-- queue arm of the statistics union, so flows is a real reading there.
assert(byname.fqroot.scheduler == "flow",
    "fqroot is reported as " .. byname.fqroot.scheduler)
assert(type(byname.fqroot.flows) == "number",
    "a flow queue reports no flows")
assert(byname.fqroot.flows >= 0)
assert(byname.fqroot.queue_limit == 512,
    "fqroot's configured qlimit did not survive: " ..
    byname.fqroot.queue_limit)

-- A flow queue with a parent is still a leaf the kernel serves with
-- HFSC, so its flows here is read out of the HFSC statistics at the
-- offset fq-codel keeps flows at. pfctl prints no flow count for such a
-- queue for that reason. The value is not meaningful; only its presence
-- and type are checked.
assert(byname.qflow, "the child flow queue is missing")
assert(byname.qflow.scheduler == "flow",
    "qflow is reported as " .. byname.qflow.scheduler)
assert(type(byname.qflow.flows) == "number")
assert(byname.qflow.parent == "rootq", "qflow is not parented to rootq")

-- The HFSC queues carry no flow count.
for _, name in ipairs({ "rootq", "qfast", "qdef", "qmid", "qleaf" }) do
	assert(byname[name].scheduler == "fifo", name ..
	    " is reported as " .. byname[name].scheduler)
	assert(byname[name].flows == nil, name .. " reports a flow count")
end

assert(byname.rootq.queue_limit == 100,
    "rootq's configured qlimit did not survive: " ..
    byname.rootq.queue_limit)
assert(byname.qdef.queue_limit == 50,
    "qdef did not get the default qlimit: " .. byname.qdef.queue_limit)

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
sh("echo queued | nc -u -w 1 10.99.1.2 9997")
local after = h:queues()
assert(#after == #qs, "the queue set changed under traffic")
for _, q in ipairs(after) do
	assert(byname[q.name], "a queue appeared under traffic: " .. q.name)
	assert(q.qid == byname[q.name].qid,
	    q.name .. " changed qid under traffic")
end

-- Reading twice in a row must give the same set: the ticket the first
-- read took must not disturb the second.
assert(#h:queues() == #qs, "a second read saw a different queue set")

os.remove("/tmp/pf_test_queues.conf")
sh("pfctl -f /etc/pf.conf")
tun0:close()
tun1:close()
