-- Collects pf metrics in prometheus exposition format.

local pf = require("pf")

local M = {}

local handle

-- Adopts a descriptor already open on /dev/pf, for a caller that opens it
-- while privileged and then drops.
function M.usefd(fd)
	handle = pf.openfd(fd)
end

-- Reuses one /dev/pf descriptor across calls.
function M.collect()
	local out = {}

	local function emit(s)
		out[#out + 1] = s
	end

	local function escape(v)
		return (tostring(v):gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"))
	end

	local function labels(t)
		if not t or #t == 0 then
			return ""
		end

		local parts = {}
		for _, pair in ipairs(t) do
			parts[#parts + 1] = string.format('%s="%s"', pair[1], escape(pair[2]))
		end

		return "{" .. table.concat(parts, ",") .. "}"
	end

	local declared = {}

	local function metric(name, kind, help, value, lbls)
		if not declared[name] then
			declared[name] = true
			emit(string.format("# HELP %s %s", name, help))
			emit(string.format("# TYPE %s %s", name, kind))
		end

		if type(value) == "boolean" then
			value = value and 1 or 0
		end

		emit(string.format("%s%s %d", name, labels(lbls), value))
	end

	if not handle then
		handle = pf.open()
	end

	local h = handle

	-- status

	local st = h:status()

	metric("pf_enabled", "gauge", "Whether pf is enabled.", st.running)
	metric("pf_since_seconds", "gauge", "Seconds since pf was started.", st.since)
	metric("pf_states", "gauge", "Number of states.", st.states)
	metric("pf_states_halfopen", "gauge", "Number of half open states.", st.states_halfopen)
	metric("pf_src_nodes", "gauge", "Number of source tracking nodes.", st.src_nodes)
	metric("pf_syncookies_active", "gauge", "Whether syncookies are active.", st.syncookies_active)

	for name, value in pairs(st.counters) do
		metric("pf_counters_total", "counter", "pf status counters.", value, { { "counter", name } })
	end

	for _, af in ipairs({ "v4", "v6" }) do
		local b = st.bcounters[af]
		local p = st.pcounters[af]

		metric("pf_bytes_total", "counter", "Bytes seen by the log interface.",
			b.bytesin, { { "af", af }, { "dir", "in" } })
		metric("pf_bytes_total", "counter", "Bytes seen by the log interface.",
			b.bytesout, { { "af", af }, { "dir", "out" } })

		metric("pf_packets_total", "counter", "Packets seen by the log interface.",
			p.packets_in_passed, { { "af", af }, { "dir", "in" }, { "action", "pass" } })
		metric("pf_packets_total", "counter", "Packets seen by the log interface.",
			p.packets_in_blocked, { { "af", af }, { "dir", "in" }, { "action", "block" } })
		metric("pf_packets_total", "counter", "Packets seen by the log interface.",
			p.packets_out_passed, { { "af", af }, { "dir", "out" }, { "action", "pass" } })
		metric("pf_packets_total", "counter", "Packets seen by the log interface.",
			p.packets_out_blocked, { { "af", af }, { "dir", "out" }, { "action", "block" } })
	end

	-- interfaces

	for _, i in ipairs(h:interfaces()) do
		local l = { { "interface", i.name } }

		metric("pf_interface_states", "gauge", "States referencing an interface.", i.states, l)
		metric("pf_interface_rules", "gauge", "Rules referencing an interface.", i.rules, l)
		metric("pf_interface_skip", "gauge", "Whether pf skips an interface.", i.skip, l)

		for _, af in ipairs({ "4", "6" }) do
			for _, dir in ipairs({ "in", "out" }) do
				for _, act in ipairs({ "pass", "block" }) do
					local key = dir .. af .. "_" .. act
					local al = {
						{ "interface", i.name },
						{ "af", "v" .. af },
						{ "dir", dir },
						{ "action", act },
					}

					metric("pf_interface_packets_total", "counter",
						"Packets per interface.", i[key .. "_packets"], al)
					metric("pf_interface_bytes_total", "counter",
						"Bytes per interface.", i[key .. "_bytes"], al)
				end
			end
		end
	end

	-- tables

	for _, t in ipairs(h:tables()) do
		local l = { { "table", t.name }, { "anchor", t.anchor } }

		metric("pf_table_addresses", "gauge", "Addresses in a table.", t.addresses_count, l)
		metric("pf_table_matches_total", "counter", "Table lookups that matched.", t.match, l)
		metric("pf_table_nomatches_total", "counter", "Table lookups that did not match.", t.nomatch, l)
		metric("pf_table_packets_total", "counter", "Packets matched by a table.",
			t.packets_in, { { "table", t.name }, { "anchor", t.anchor }, { "dir", "in" } })
		metric("pf_table_packets_total", "counter", "Packets matched by a table.",
			t.packets_out, { { "table", t.name }, { "anchor", t.anchor }, { "dir", "out" } })
		metric("pf_table_bytes_total", "counter", "Bytes matched by a table.",
			t.bytes_in, { { "table", t.name }, { "anchor", t.anchor }, { "dir", "in" } })
		metric("pf_table_bytes_total", "counter", "Bytes matched by a table.",
			t.bytes_out, { { "table", t.name }, { "anchor", t.anchor }, { "dir", "out" } })
	end

	-- rules, in every anchor

	local anchors = { "" }
	for _, a in ipairs(h:anchors()) do
		anchors[#anchors + 1] = a
	end

	for _, anchor in ipairs(anchors) do
		for _, r in ipairs(h:rules(anchor)) do
			local l = {
				{ "anchor", anchor },
				{ "nr", r.nr },
				{ "action", r.action },
				{ "label", r.label },
			}

			metric("pf_rule_evaluations_total", "counter", "Rule evaluations.", r.evaluations, l)
			metric("pf_rule_states", "gauge", "States created by a rule.", r.states_cur, l)
			metric("pf_rule_states_total", "counter", "States ever created by a rule.", r.states_total, l)
			metric("pf_rule_packets_total", "counter", "Packets matched by a rule.",
				r.packets_in, { { "anchor", anchor }, { "nr", r.nr }, { "dir", "in" } })
			metric("pf_rule_packets_total", "counter", "Packets matched by a rule.",
				r.packets_out, { { "anchor", anchor }, { "nr", r.nr }, { "dir", "out" } })
			metric("pf_rule_bytes_total", "counter", "Bytes matched by a rule.",
				r.bytes_in, { { "anchor", anchor }, { "nr", r.nr }, { "dir", "in" } })
			metric("pf_rule_bytes_total", "counter", "Bytes matched by a rule.",
				r.bytes_out, { { "anchor", anchor }, { "nr", r.nr }, { "dir", "out" } })
		end
	end

	-- queues

	for _, q in ipairs(h:queues()) do
		local l = { { "queue", q.name }, { "interface", q.ifname } }

		metric("pf_queue_length", "gauge", "Packets waiting in a queue.", q.queue_length, l)
		metric("pf_queue_limit", "gauge", "Queue capacity in packets.", q.queue_limit, l)
		metric("pf_queue_transmit_packets_total", "counter", "Packets sent from a queue.",
			q.transmit_packets, l)
		metric("pf_queue_transmit_bytes_total", "counter", "Bytes sent from a queue.",
			q.transmit_bytes, l)
		metric("pf_queue_drop_packets_total", "counter", "Packets dropped by a queue.",
			q.drop_packets, l)
		metric("pf_queue_drop_bytes_total", "counter", "Bytes dropped by a queue.", q.drop_bytes, l)
	end

	-- source nodes are counted, not listed; one series per host is too many

	local nodes, states, conns = 0, 0, 0
	for _, n in ipairs(h:srcnodes()) do
		nodes = nodes + 1
		states = states + n.states
		conns = conns + n.connections
	end

	metric("pf_srcnodes", "gauge", "Source tracking nodes.", nodes)
	metric("pf_srcnode_states", "gauge", "States held by source tracking nodes.", states)
	metric("pf_srcnode_connections", "gauge", "Connections held by source tracking nodes.", conns)

	-- tunables

	for name, value in pairs(h:limits()) do
		metric("pf_limit", "gauge", "Configured pf limits.", value, { { "limit", name } })
	end

	for name, value in pairs(h:timeouts()) do
		metric("pf_timeout_seconds", "gauge", "Configured pf timeouts.", value, { { "timeout", name } })
	end

	return table.concat(out, "\n") .. "\n"
end

return M
