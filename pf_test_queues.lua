local pf = require("pf")

-- Every queue reports these; a queue that fq-codel served adds the
-- fq-codel statistics on top.
local common = {
	"name", "parent", "ifname", "qid", "parent_qid",
	"flags", "flowqueue_class", "default_queue", "root_class",
	"qlimit", "linkshare", "realtime", "upperlimit", "flowqueue",
	"scheduler", "queue_length", "queue_limit",
	"transmit_packets", "transmit_bytes", "drop_packets", "drop_bytes",
}
local fqonly = {
	"flows", "codel_target", "codel_interval",
	"delay_sum", "delay_sum_squared",
}

local function checkbwspec(q, path, bw)
	assert(type(bw) == "table", q.name .. ": " .. path .. " is not a table")
	assert(type(bw.absolute) == "number" and bw.absolute >= 0,
	    q.name .. ": " .. path .. ".absolute")
	-- pfctl rejects a percentage for a queue ("no bandwidth in % yet"),
	-- so the arm reads zero here. It is still reported, because the
	-- kernel keeps a percentage as a percentage and a caller reading
	-- only absolute would see zero for such a queue.
	assert(type(bw.percent) == "number" and bw.percent == 0,
	    q.name .. ": " .. path .. ".percent")
end

local function checkscspec(q, name)
	local sc = q[name]
	assert(type(sc) == "table", q.name .. ": " .. name .. " is not a table")
	checkbwspec(q, name .. ".m1", sc.m1)
	checkbwspec(q, name .. ".m2", sc.m2)
	assert(type(sc.d) == "number" and sc.d >= 0, q.name .. ": " .. name ..
	    ".d")
end

-- Every property the binding documents, and nothing else.
local function checkqueue(q)
	assert(type(q.name) == "string" and #q.name > 0)
	assert(type(q.parent) == "string")
	assert(type(q.ifname) == "string")
	assert(type(q.qid) == "number")
	assert(type(q.parent_qid) == "number")
	assert(type(q.flags) == "number" and q.flags >= 0)
	assert(type(q.flowqueue_class) == "boolean")
	assert(type(q.default_queue) == "boolean")
	assert(type(q.root_class) == "boolean")
	assert(type(q.qlimit) == "number" and q.qlimit >= 0)
	checkscspec(q, "linkshare")
	checkscspec(q, "realtime")
	checkscspec(q, "upperlimit")

	local fq = q.flowqueue
	assert(type(fq) == "table", q.name .. ": flowqueue is not a table")
	for _, k in ipairs({ "flows", "quantum", "target", "interval" }) do
		assert(type(fq[k]) == "number" and fq[k] >= 0,
		    q.name .. ": flowqueue." .. k)
	end

	assert(type(q.scheduler) == "string")
	assert(q.scheduler == "hfsc" or q.scheduler == "fqcodel",
	    q.name .. ": scheduler is " .. q.scheduler)
	assert(type(q.queue_length) == "number")
	assert(type(q.queue_limit) == "number")
	assert(type(q.transmit_packets) == "number")
	assert(type(q.transmit_bytes) == "number")
	assert(type(q.drop_packets) == "number")
	assert(type(q.drop_bytes) == "number")

	local want = {}
	for _, k in ipairs(common) do
		assert(q[k] ~= nil, q.name .. " is missing " .. k)
		want[k] = true
	end
	for _, k in ipairs(fqonly) do
		if q.scheduler == "fqcodel" then
			assert(type(q[k]) == "number" and q[k] >= 0,
			    q.name .. ": " .. k)
			want[k] = true
		else
			assert(q[k] == nil, q.name ..
			    " reports fq-codel's " .. k ..
			    " but HFSC served it")
		end
	end
	for k in pairs(q) do
		assert(want[k], q.name .. " reports an undocumented " ..
		    tostring(k))
	end
end

local h = pf.open()
assert(h)

local queues = h:queues()
assert(type(queues) == "table")
for _, q in ipairs(queues) do
	checkqueue(q)
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
-- gives parent_qid something deeper than one level to point at. The
-- shaping keywords are spread across the tree so that each service curve
-- and each flow queue parameter is set on at least one queue and left
-- alone on another.
local f = assert(io.open("/tmp/pf_test_queues.conf", "w"))
f:write([[
queue rootq on tun0 bandwidth 10M max 10M qlimit 100
queue qfast parent rootq bandwidth 5M burst 9M for 100ms
queue qdef parent rootq bandwidth 1M default
queue qmid parent rootq bandwidth 3M min 2M max 4M
queue qleaf parent qmid bandwidth 2M qlimit 77
queue qflow parent rootq bandwidth 1M flows 256 quantum 1500
queue fqroot on tun1 flows 512 qlimit 512 default
pass out on tun0 inet proto udp set queue qdef
]])
f:close()
local loaded = sh("pfctl -f /tmp/pf_test_queues.conf")
assert(loaded == "", "pfctl rejected the queue ruleset: " .. loaded)

-- pfctl prints a bandwidth through the same formatter for every queue, so
-- a suffix and a decimal fraction are all it can produce.
local mult = { [""] = 1, K = 1000, M = 1000 * 1000, G = 1000 * 1000 * 1000 }
local function rate(s)
	local n, suffix = s:match("^([%d%.]+)([KMG]?)$")
	assert(n, "pfctl printed an unreadable bandwidth: " .. s)
	return math.floor(tonumber(n) * mult[suffix] + 0.5)
end

-- pfctl -g -v prints, per queue, the same qid, parent_qid, ifname, queue
-- length and shaping parameters that the binding reports. Parsing it gives
-- an independent reading of the very ioctls the binding calls.
local function pfctlqueues()
	local byname, order = {}, {}
	local cur
	for line in sh("pfctl -g -v -s queue"):gmatch("[^\n]+") do
		local name = line:match("^queue (%S+)")
		if name then
			cur = { name = name }
			byname[name] = cur
			order[#order + 1] = name
			cur.bandwidth = line:match("bandwidth ([%d%.]+[KMG]?)")
			cur.max = line:match("max ([%d%.]+[KMG]?)")
			cur.min = line:match("min ([%d%.]+[KMG]?)")
			cur.burst, cur.burstd =
			    line:match("burst ([%d%.]+[KMG]?) for (%d+)ms")
			cur.qlimit = line:match("qlimit (%d+)")
			cur.flows = line:match("flows (%d+)")
			cur.quantum = line:match("quantum (%d+)")
			cur.default = line:match(" default") ~= nil
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
	checkqueue(q)
	assert(q.qid > 0)
	assert(not byqid[q.qid], "two queues share qid " .. q.qid)
	byname[q.name] = q
	byqid[q.qid] = q
end

-- Every queue pfctl saw, with the same identity and the same shaping.
-- A queue name is unique across the whole set here, so name is a safe key
-- for the comparison.
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

	-- pf.conf's bandwidth, max and min are the second slope of the
	-- link share, upper limit and real time curves in that order.
	local curve = {
		bandwidth = q.linkshare, max = q.upperlimit, min = q.realtime,
	}
	for key, sc in pairs(curve) do
		local want = r[key] and rate(r[key]) or 0
		assert(sc.m2.absolute == want, name .. ": " .. key .. " is " ..
		    sc.m2.absolute .. " but pfctl says " .. want)
	end

	-- A burst is the first slope of whichever curve it followed, and
	-- pfctl prints it beside that curve. A curve with no burst is flat:
	-- d is zero and the first slope repeats the second, so d is what
	-- tells a burst from a plain bandwidth.
	local burst, d = 0, 0
	for _, sc in pairs(curve) do
		if sc.d ~= 0 then
			burst = burst + sc.m1.absolute
			d = d + sc.d
		else
			assert(sc.m1.absolute == sc.m2.absolute,
			    name .. ": a curve with no burst time has two "
			    .. "different slopes")
		end
	end
	assert(burst == (r.burst and rate(r.burst) or 0), name ..
	    ": burst is " .. burst .. " but pfctl says " .. tostring(r.burst))
	assert(d == (tonumber(r.burstd) or 0), name .. ": burst time is " ..
	    d .. " but pfctl says " .. tostring(r.burstd))

	-- pfctl prints a queue's own qlimit only when the ruleset set one.
	-- The scheduler's queue_limit fills in the default of 50; the spec's
	-- qlimit stays zero.
	assert(q.qlimit == (tonumber(r.qlimit) or 0), name .. ": qlimit " ..
	    q.qlimit .. " but pfctl says " .. tostring(r.qlimit))
	assert(q.flowqueue.flows == (tonumber(r.flows) or 0),
	    name .. ": flowqueue.flows " .. q.flowqueue.flows ..
	    " but pfctl says " .. tostring(r.flows))
	assert(q.flowqueue.quantum == (tonumber(r.quantum) or 0),
	    name .. ": flowqueue.quantum " .. q.flowqueue.quantum ..
	    " but pfctl says " .. tostring(r.quantum))
	assert(q.default_queue == r.default, name .. ": default_queue is " ..
	    tostring(q.default_queue) .. " but pfctl says " ..
	    tostring(r.default))
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

-- A root flow queue is the one case where the kernel fills the flow queue
-- arm of the statistics union: the queue asked for flows, has no parent
-- and is not an HFSC root class. Only there is a flow count a real
-- reading, and only there does the delay sum exist.
assert(byname.fqroot.scheduler == "fqcodel",
    "fqroot is served by " .. byname.fqroot.scheduler)
assert(byname.fqroot.flowqueue_class, "fqroot is not a flow queue")
assert(not byname.fqroot.root_class, "fqroot is an HFSC root class")
assert(byname.fqroot.flows >= 0)
assert(byname.fqroot.flowqueue.flows == 512,
    "fqroot's configured flow count did not survive: " ..
    byname.fqroot.flowqueue.flows)
assert(byname.fqroot.qlimit == 512,
    "fqroot's configured qlimit did not survive: " .. byname.fqroot.qlimit)
assert(byname.fqroot.queue_limit == 512,
    "fqroot's scheduler qlimit did not survive: " ..
    byname.fqroot.queue_limit)

-- A flow queue with a parent is a leaf that HFSC serves, so the kernel
-- filled the HFSC arm. Reading flows there would really read
-- hfsc_class_stats.period, and pfctl prints no flow count for such a
-- queue for the same reason. The configured flow count still stands.
assert(byname.qflow, "the child flow queue is missing")
assert(byname.qflow.parent == "rootq", "qflow is not parented to rootq")
assert(byname.qflow.flowqueue_class, "qflow is not a flow queue")
assert(byname.qflow.scheduler == "hfsc",
    "qflow is served by " .. byname.qflow.scheduler)
assert(byname.qflow.flows == nil,
    "qflow reports a flow count read out of the HFSC statistics")
assert(byname.qflow.delay_sum == nil, "qflow reports an fq-codel delay sum")
assert(byname.qflow.flowqueue.flows == 256,
    "qflow's configured flow count did not survive: " ..
    byname.qflow.flowqueue.flows)
assert(byname.qflow.flowqueue.quantum == 1500,
    "qflow's quantum did not survive: " .. byname.qflow.flowqueue.quantum)

-- The HFSC queues are neither flow queues nor served by one.
for _, name in ipairs({ "rootq", "qfast", "qdef", "qmid", "qleaf" }) do
	local q = byname[name]
	assert(q.scheduler == "hfsc", name .. " is served by " .. q.scheduler)
	assert(not q.flowqueue_class, name .. " is a flow queue")
	assert(q.flows == nil, name .. " reports a flow count")
	assert(q.flowqueue.flows == 0, name .. " has a configured flow count")
end

-- Only the queue at the top of an HFSC tree is the root class, and only
-- the queue the ruleset marked default absorbs unmatched packets.
assert(byname.rootq.root_class, "rootq is not the HFSC root class")
-- The booleans are the flag word taken apart, so they must agree with it.
for _, q in ipairs(qs) do
	local want = 0
	if q.flowqueue_class then want = want + 0x0001 end
	if q.root_class then want = want + 0x0002 end
	if q.default_queue then want = want + 0x1000 end
	assert(q.flags == want, q.name .. ": flags " .. q.flags ..
	    " does not match the flags reported one by one")
end
for _, name in ipairs({ "qfast", "qdef", "qmid", "qleaf", "qflow" }) do
	assert(not byname[name].root_class, name .. " is a root class")
end
assert(byname.qdef.default_queue, "qdef is not the default queue")
assert(byname.fqroot.default_queue, "fqroot is not the default queue")
for _, name in ipairs({ "rootq", "qfast", "qmid", "qleaf", "qflow" }) do
	assert(not byname[name].default_queue, name .. " is a default queue")
end

-- The shaping the ruleset asked for, curve by curve.
assert(byname.rootq.linkshare.m2.absolute == 10 * 1000 * 1000,
    "rootq's bandwidth is " .. byname.rootq.linkshare.m2.absolute)
assert(byname.rootq.upperlimit.m2.absolute == 10 * 1000 * 1000,
    "rootq's max is " .. byname.rootq.upperlimit.m2.absolute)
assert(byname.rootq.realtime.m2.absolute == 0, "rootq has a min")
assert(byname.qmid.realtime.m2.absolute == 2 * 1000 * 1000,
    "qmid's min is " .. byname.qmid.realtime.m2.absolute)
assert(byname.qmid.upperlimit.m2.absolute == 4 * 1000 * 1000,
    "qmid's max is " .. byname.qmid.upperlimit.m2.absolute)

-- A burst is the first slope of the curve it was written beside, so
-- "bandwidth 5M burst 9M for 100ms" lands in the link share curve.
assert(byname.qfast.linkshare.m2.absolute == 5 * 1000 * 1000,
    "qfast's bandwidth is " .. byname.qfast.linkshare.m2.absolute)
assert(byname.qfast.linkshare.m1.absolute == 9 * 1000 * 1000,
    "qfast's burst is " .. byname.qfast.linkshare.m1.absolute)
assert(byname.qfast.linkshare.d == 100,
    "qfast's burst time is " .. byname.qfast.linkshare.d)
assert(byname.qdef.linkshare.d == 0, "qdef has a burst time")
assert(byname.qdef.linkshare.m1.absolute == byname.qdef.linkshare.m2.absolute,
    "qdef has no burst but a first slope of its own")

-- The ruleset's qlimit and the scheduler's are two different numbers.
-- They agree where the ruleset set one, and the scheduler fills in its
-- own default of 50 where it did not.
assert(byname.rootq.qlimit == 100,
    "rootq's configured qlimit did not survive: " .. byname.rootq.qlimit)
assert(byname.rootq.queue_limit == 100,
    "rootq's scheduler qlimit did not survive: " .. byname.rootq.queue_limit)
assert(byname.qleaf.qlimit == 77,
    "qleaf's configured qlimit did not survive: " .. byname.qleaf.qlimit)
assert(byname.qleaf.queue_limit == 77,
    "qleaf's scheduler qlimit did not survive: " .. byname.qleaf.queue_limit)
assert(byname.qdef.qlimit == 0, "qdef asked for a qlimit: " ..
    byname.qdef.qlimit)
assert(byname.qdef.queue_limit == 50,
    "qdef did not get the default qlimit: " .. byname.qdef.queue_limit)

for _, q in ipairs(qs) do
	assert(q.transmit_packets >= 0)
	assert(q.transmit_bytes >= 0)
	assert(q.drop_packets >= 0)
	assert(q.drop_bytes >= 0)
	assert(q.queue_limit > 0)
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
	local before = byname[q.name]
	assert(before, "a queue appeared under traffic: " .. q.name)
	assert(q.qid == before.qid, q.name .. " changed qid under traffic")
	assert(q.scheduler == before.scheduler,
	    q.name .. " changed scheduler under traffic")
	assert(q.linkshare.m2.absolute == before.linkshare.m2.absolute,
	    q.name .. " changed bandwidth under traffic")
end

-- Reading twice in a row must give the same set: the ticket the first
-- read took must not disturb the second.
assert(#h:queues() == #qs, "a second read saw a different queue set")

os.remove("/tmp/pf_test_queues.conf")
sh("pfctl -f /etc/pf.conf")
tun0:close()
tun1:close()
