local pf = require('pf')
local h = pf.open()
assert(h)

-- Every action name rule.c can produce. A rule whose action byte is out of
-- range renders as "?", which means the kernel grew an action the binding
-- does not know about.
local actions = {
	["pass"] = true, ["block"] = true, ["scrub"] = true,
	["no scrub"] = true, ["nat"] = true, ["no nat"] = true,
	["binat"] = true, ["no binat"] = true, ["rdr"] = true,
	["no rdr"] = true, ["synproxy drop"] = true, ["defer"] = true,
	["match"] = true, ["divert"] = true, ["route-to"] = true,
	["af-to"] = true,
}

-- The complete property set of a rule, in the order rule.c lists it.
-- __pairs must yield exactly these, no more and no fewer.
local properties = {
	"nr", "action", "direction", "af", "proto", "quick", "log",
	"keep_state", "interface", "interface_not", "label", "tag", "anchor",
	"anchor_call",
	"source", "destination", "evaluations", "packets_in", "packets_out",
	"bytes_in", "bytes_out", "states_cur", "states_total",
}

local function isuint(v)
	return type(v) == "number" and v >= 0 and v % 1 == 0
end

-- Checks one rule against everything that holds for any ruleset, including
-- an empty one on a machine that has never passed a packet.
local function checkrule(r, anchor)
	local text = tostring(r)

	assert(isuint(r.nr))
	assert(type(r.action) == "string" and actions[r.action],
	    "unknown action: " .. tostring(r.action))
	assert(r.direction == nil or r.direction == "in" or
	    r.direction == "out", "bad direction: " .. tostring(r.direction))
	assert(r.af == nil or r.af == "inet" or r.af == "inet6")
	assert(r.proto == nil or type(r.proto) == "string" or
	    (isuint(r.proto) and r.proto > 0 and r.proto <= 255))
	assert(type(r.log) == "boolean")
	assert(type(r.keep_state) == "boolean")
	assert(type(r.quick) == "boolean")
	assert(type(r.source) == "string" and #r.source > 0)
	assert(type(r.destination) == "string" and #r.destination > 0)

	-- The kernel hands back fixed-size arrays it need not terminate, so a
	-- string longer than its array means the binding read past the end.
	assert(type(r.interface) == "string" and #r.interface < 16)
	-- The name alone cannot say whether the rule matches that interface
	-- or every other one, so the flag has to travel beside it.
	assert(type(r.interface_not) == "boolean")
	assert(not r.interface_not or r.interface ~= "",
	    "a negated interface with no name")
	assert(type(r.label) == "string" and #r.label < 64)
	assert(type(r.tag) == "string" and #r.tag < 64)
	assert(type(r.anchor) == "string" and #r.anchor < 1024)
	assert(type(r.anchor_call) == "string" and #r.anchor_call < 1024)

	-- DIOCGETRULE never writes pr->anchor, so the anchor a rule reports is
	-- the anchor it was asked for.
	assert(r.anchor == anchor,
	    "rule claims anchor " .. r.anchor .. ", asked for " .. anchor)

	-- __tostring has to agree with the properties it renders from.
	assert(type(text) == "string" and #text > 0)
	if r.anchor_call ~= "" then
		assert(text:find('"' .. r.anchor_call .. '"', 1, true),
		    "anchor call missing from: " .. text)
	else
		assert(text:sub(1, #r.action) == r.action,
		    "text does not open with the action: " .. text)
	end
	if r.direction == "in" then
		assert(text:find(" in", 1, true), "no direction in: " .. text)
	elseif r.direction == "out" then
		assert(text:find(" out", 1, true), "no direction in: " .. text)
	end
	if r.quick then
		assert(text:find(" quick", 1, true), "no quick in: " .. text)
	end
	if r.log then
		assert(text:find(" log", 1, true), "no log in: " .. text)
	end
	if r.af then
		assert(text:find(" " .. r.af, 1, true), "no af in: " .. text)
	end
	if r.interface ~= "" then
		assert(text:find(r.interface, 1, true),
		    "no interface in: " .. text)
		assert(text:find("on ! " .. r.interface, 1, true) ~= nil ==
		    r.interface_not,
		    "negation not rendered as pfctl writes it: " .. text)
	end
	if r.label ~= "" then
		assert(text:find('label "' .. r.label .. '"', 1, true),
		    "no label in: " .. text)
	end

	-- Counters. A live host keeps incrementing these, so nothing here
	-- compares two separate reads; every check is within one snapshot.
	assert(isuint(r.evaluations))
	assert(isuint(r.packets_in))
	assert(isuint(r.packets_out))
	assert(isuint(r.bytes_in))
	assert(isuint(r.bytes_out))
	assert(isuint(r.states_cur))
	assert(isuint(r.states_total))

	-- PF counts the whole IP packet, so bytes and packets move together
	-- and a byte count can never be the smaller of the two.
	assert((r.bytes_in > 0) == (r.packets_in > 0),
	    "bytes_in and packets_in disagree on rule " .. r.nr)
	assert((r.bytes_out > 0) == (r.packets_out > 0),
	    "bytes_out and packets_out disagree on rule " .. r.nr)
	assert(r.bytes_in >= r.packets_in)
	assert(r.bytes_out >= r.packets_out)

	-- Every state a rule holds is one it created, and each creation cost
	-- an evaluation. `pfctl -vsr -z` zeroes states_total and evaluations
	-- but leaves states_cur alone, so this test never clears counters.
	assert(r.states_total >= r.states_cur,
	    "rule " .. r.nr .. " holds more states than it ever created")
	assert(r.evaluations >= r.states_total,
	    "rule " .. r.nr .. " created states it never evaluated")

	-- A rule that has demonstrably done work must have been evaluated.
	if r.states_total > 0 then
		assert(r.evaluations > 0,
		    "rule " .. r.nr .. " created states without an evaluation")
	end

	-- __pairs must cover the properties exactly, with the same values
	-- __index gives. A property whose value is nil still yields its key.
	local seen = {}
	for k, v in pairs(r) do
		assert(type(k) == "string")
		assert(not seen[k], "duplicate key from pairs: " .. k)
		seen[k] = true
		assert(v == r[k], "pairs disagrees with index on " .. k)
	end
	for _, k in ipairs(properties) do
		assert(seen[k], "pairs never yielded " .. k)
		seen[k] = nil
	end
	assert(next(seen) == nil,
	    "pairs yielded an undocumented key: " .. tostring(next(seen)))

	-- Unknown keys read as nil rather than raising.
	assert(r.no_such_property == nil)
end

local rules = h:rules()
assert(type(rules) == "table")

local hit = false
local prev

for i, r in ipairs(rules) do
	checkrule(r, "")

	-- The kernel walks the ruleset in order and numbers it as it goes.
	if prev then
		assert(r.nr > prev, "rule numbers are not increasing at " .. i)
	end
	prev = r.nr

	if r.evaluations > 0 then
		hit = true
	end
end

-- PF evaluates the first rule of an active ruleset against every packet, so
-- on a machine that has moved any traffic some rule has been hit. A guest
-- that just loaded its ruleset may genuinely be at zero, which is why this
-- reports rather than asserts.
if #rules > 0 and not hit then
	print("pf_test_rules: no rule has been evaluated yet")
end

local anchors = h:anchors()
assert(type(anchors) == "table")
for _, a in ipairs(anchors) do
	assert(type(a) == "string" and #a > 0)
	local sub = h:rules(a)
	assert(type(sub) == "table")
	for _, r in ipairs(sub) do
		checkrule(r, a)
	end
end

-- the kernel rejects an anchor that does not exist
local ok, err = pcall(h.rules, h, "nonexistent-anchor")
assert(not ok)
assert(err:find("DIOCGETRULES"))
