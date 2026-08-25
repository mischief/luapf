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
