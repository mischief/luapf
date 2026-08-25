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
	"user", "group", "flags",
	"redirect", "redirect_address", "redirect_port", "redirect_port_end",
	"pool_type", "sticky_address", "static_port",
	"rdomain", "rtable",
	"return_policy", "return_ttl", "return_icmp", "return_icmp6",
	"fragment", "no_sync", "source_track", "if_bound", "sloppy", "pflow",
	"once", "expired", "af_to", "delay",
	"probability", "allow_opts", "min_ttl", "max_mss", "tos", "set_tos",
	"no_df", "random_id", "reassemble_tcp",
	"match_tag", "match_tag_not", "os_fingerprint",
	"anchor_relative", "anchor_wildcard",
	"divert", "divert_address", "divert_port",
	"source_addresses", "destination_addresses", "src_nodes",
	"max_pkt_rate", "max_pkt_rate_seconds", "pkt_rate_count",
	"pkt_rate_last", "created_uid", "created_pid", "expires",
}

-- Every state-keeping mode rule.c can name, and every divert and return
-- keyword beside them.
local states = {
	["normal"] = true, ["modulate"] = true, ["synproxy"] = true,
}

local diverts = {
	["divert-to"] = true, ["divert-reply"] = true,
	["divert-packet"] = true,
}

local returns = {
	["drop"] = true, ["return"] = true, ["return-rst"] = true,
	["return-icmp"] = true,
}

-- Every pool type rule.c can name.
local pooltypes = {
	["bitmask"] = true, ["random"] = true, ["source-hash"] = true,
	["round-robin"] = true, ["least-states"] = true,
}

-- Every translation keyword rule.c can name.
local redirects = {
	["nat-to"] = true, ["af-to"] = true, ["rdr-to"] = true,
	["route-to"] = true, ["reply-to"] = true, ["dup-to"] = true,
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
	assert(r.keep_state == nil or states[r.keep_state],
	    "unknown state mode: " .. tostring(r.keep_state))
	assert(type(r.quick) == "boolean")
	assert(type(r.source) == "string" and #r.source > 0)
	assert(type(r.destination) == "string" and #r.destination > 0)

	-- The kernel hands back fixed-size arrays it need not terminate, so a
	-- string longer than its array means the binding read past the end.
	assert(type(r.interface) == "string" and #r.interface < 16)
	-- The name alone cannot say whether the rule matches that interface
	-- or every other one, so the flag has to travel beside it.
	assert(type(r.interface_not) == "boolean")
	assert(not r.interface_not or r.interface ~= "" or r.rdomain ~= nil,
	    "a negated interface with nothing to negate")
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

	-- A rule that constrains a user or a group renders the comparison the
	-- same way in the text and in the property.
	assert(r.user == nil or type(r.user) == "string")
	assert(r.group == nil or type(r.group) == "string")
	if r.user then
		assert(text:find(" user " .. r.user, 1, true),
		    "no user in: " .. text)
	end
	if r.group then
		assert(text:find(" group " .. r.group, 1, true),
		    "no group in: " .. text)
	end

	-- pf stores the flags a packet must have and the flags it looks at,
	-- so a flag the rule requires must be one it inspects.
	if r.flags then
		assert(type(r.flags) == "string")
		local want, mask = r.flags:match("^([FSRPAUEW]*)/([FSRPAUEW]*)$")
		assert(mask, "malformed flags: " .. r.flags)
		for c in want:gmatch(".") do
			assert(mask:find(c, 1, true),
			    "rule requires flag " .. c .. " it never reads")
		end
		assert(text:find(" flags " .. r.flags, 1, true),
		    "no flags in: " .. text)
	end

	-- The translation pool. Every part of it is absent together.
	assert(type(r.sticky_address) == "boolean")
	assert(type(r.static_port) == "boolean")
	assert(r.pool_type == nil or pooltypes[r.pool_type],
	    "unknown pool type: " .. tostring(r.pool_type))
	if r.redirect == nil then
		assert(r.redirect_address == nil)
		assert(r.redirect_port == nil)
		assert(r.redirect_port_end == nil)
		assert(r.pool_type == nil)
		assert(not r.sticky_address and not r.static_port)
	else
		assert(redirects[r.redirect],
		    "unknown redirect: " .. tostring(r.redirect))
		assert(type(r.redirect_address) == "string" and
		    #r.redirect_address > 0)
		assert(text:find(" " .. r.redirect .. " " ..
		    r.redirect_address, 1, true),
		    "no " .. r.redirect .. " in: " .. text)
		-- A pool that reports no first port cannot report a last one,
		-- and a range that has a top has it above the bottom.
		if r.redirect_port == nil then
			assert(r.redirect_port_end == nil)
		else
			assert(isuint(r.redirect_port) and
			    r.redirect_port <= 65535)
			if r.redirect_port_end then
				assert(isuint(r.redirect_port_end) and
				    r.redirect_port_end <= 65535)
				assert(r.redirect_port_end ~=
				    r.redirect_port)
			end
		end
		if r.pool_type then
			assert(text:find(" " .. r.pool_type, 1, true),
			    "no pool type in: " .. text)
		end
		assert(r.sticky_address ==
		    (text:find(" sticky-address", 1, true) ~= nil))
		assert(r.static_port ==
		    (text:find(" static-port", 1, true) ~= nil))
	end

	-- The routing domain the rule is confined to and the table it looks
	-- packets up in. Both are absent on an ordinary rule, and neither can
	-- be told from a global rule by any other property.
	assert(r.rdomain == nil or isuint(r.rdomain))
	assert(r.rtable == nil or isuint(r.rtable))
	if r.rdomain then
		local written = r.interface_not and " on ! rdomain " or
		    " on rdomain "
		assert(text:find(written .. r.rdomain, 1, true),
		    "no rdomain in: " .. text)
	end
	if r.rtable then
		assert(text:find(" rtable " .. r.rtable, 1, true),
		    "no rtable in: " .. text)
	end

	-- A label is free text, so a keyword inside one is not evidence the
	-- rule carries that keyword. Only a rule without a label can be read
	-- backwards, from the rendering to the property.
	local plain = r.label == ""

	-- What a block rule answers with. Only a block rule answers at all.
	assert(r.return_policy == nil or returns[r.return_policy],
	    "unknown return policy: " .. tostring(r.return_policy))
	assert((r.return_policy ~= nil) == (r.action == "block"),
	    "return policy on a " .. r.action .. " rule")
	assert(r.return_ttl == nil or
	    (isuint(r.return_ttl) and r.return_ttl <= 255))
	assert(r.return_ttl == nil or r.return_policy == "return-rst")
	assert((r.return_icmp ~= nil) == (r.return_policy == "return-icmp"))
	assert((r.return_icmp6 ~= nil) == (r.return_policy == "return-icmp"))
	if r.return_policy and r.return_policy ~= "drop" then
		assert(text:find(" " .. r.return_policy, 1, true),
		    "no return policy in: " .. text)
	end

	-- The rule_flag bits. Each one changes what the rule does, so each
	-- has to be readable on its own rather than only in the text.
	for _, k in ipairs({"fragment", "no_sync", "if_bound", "sloppy",
	    "pflow", "once", "expired", "af_to", "allow_opts",
	    "match_tag_not", "no_df", "random_id", "reassemble_tcp",
	    "anchor_wildcard"}) do
		assert(type(r[k]) == "boolean",
		    k .. " is not a boolean: " .. tostring(r[k]))
	end
	assert(r.source_track == nil or r.source_track == "global" or
	    r.source_track == "rule",
	    "unknown source-track scope: " .. tostring(r.source_track))
	-- A keyword opens its group or follows another, so it is preceded by
	-- a paren or a space depending on what else the rule asked for. The
	-- sole option of a group is the case a built ruleset rarely has.
	for _, k in ipairs({{"fragment", "fragment"}, {"once", "once"},
	    {"allow_opts", "allow-opts"}, {"pflow", "pflow"},
	    {"sloppy", "sloppy"}, {"if_bound", "if-bound"},
	    {"no_sync", "no-sync"}, {"no_df", "no-df"},
	    {"random_id", "random-id"},
	    {"reassemble_tcp", "reassemble tcp"}}) do
		local present = text:find(" " .. k[2], 1, true) ~= nil or
		    text:find("(" .. k[2], 1, true) ~= nil
		if r[k[1]] then
			assert(present, "no " .. k[2] .. " in: " .. text)
		elseif plain then
			assert(not present,
			    k[2] .. " rendered but not reported: " .. text)
		end
	end
	if r.redirect == "af-to" then
		assert(r.af_to, "an af-to pool without the af-to flag")
	end
	assert(r.delay == nil or isuint(r.delay))

	-- Match criteria that carry a value.
	assert(r.probability == nil or (type(r.probability) == "number" and
	    r.probability > 0 and r.probability <= 100),
	    "bad probability: " .. tostring(r.probability))
	for _, k in ipairs({"min_ttl", "max_mss", "tos", "set_tos"}) do
		assert(r[k] == nil or isuint(r[k]), k .. " is not a count")
	end
	assert(r.tos == nil or r.tos <= 255)
	assert(r.set_tos == nil or r.set_tos <= 255)
	assert(r.min_ttl == nil or r.min_ttl <= 255)
	assert(r.max_mss == nil or r.max_mss <= 65535)
	if r.tos then
		assert(text:find(string.format(" tos 0x%2.2x", r.tos), 1, true),
		    "no tos in: " .. text)
	end

	-- The tag a rule matches on, which is not the tag it sets.
	assert(type(r.match_tag) == "string" and #r.match_tag < 64)
	assert(not r.match_tag_not or r.match_tag ~= "",
	    "a negated tag match with no tag")
	if r.match_tag ~= "" then
		local written = r.match_tag_not and " ! tagged " or " tagged "
		assert(text:find(written .. r.match_tag, 1, true),
		    "no tagged in: " .. text)
	end
	if r.tag ~= "" then
		assert(text:find(" tag " .. r.tag, 1, true),
		    "no tag in: " .. text)
	end

	-- A rule that tests an OS fingerprint cannot collapse to "all": the
	-- fingerprint is written between the two endpoints.
	assert(r.os_fingerprint == nil or isuint(r.os_fingerprint))
	if r.os_fingerprint then
		assert(not text:find(" all", 1, true),
		    "a fingerprint rule rendered as all: " .. text)
	end

	assert(isuint(r.anchor_relative))

	-- Divert. Only divert-to names an address, and only a divert that
	-- moves packets names a port.
	assert(r.divert == nil or diverts[r.divert],
	    "unknown divert: " .. tostring(r.divert))
	assert((r.divert_address ~= nil) == (r.divert == "divert-to"))
	assert((r.divert_port ~= nil) ==
	    (r.divert ~= nil and r.divert ~= "divert-reply"))
	if r.divert then
		assert(text:find(" " .. r.divert, 1, true),
		    "no divert in: " .. text)
	end
	assert(r.divert_port == nil or
	    (isuint(r.divert_port) and r.divert_port <= 65535))

	-- How many addresses each endpoint resolves to. A table pf has not
	-- resolved yet reports -1, so this is not a plain count.
	for _, k in ipairs({"source_addresses", "destination_addresses"}) do
		assert(r[k] == nil or (type(r[k]) == "number" and
		    r[k] % 1 == 0 and r[k] >= -1), k .. " is not a count")
	end
	local src = r.source:gsub("^! ", "")
	assert((r.source_addresses ~= nil) ==
	    (src:find("^%(") ~= nil or src:find("^<") ~= nil),
	    "a count on an endpoint that resolves nothing: " .. r.source)

	-- The packet rate cap and how close the rule stands to it. The limit
	-- and its window are set together or not at all.
	assert((r.max_pkt_rate ~= nil) == (r.max_pkt_rate_seconds ~= nil))
	if r.max_pkt_rate then
		assert(isuint(r.max_pkt_rate) and isuint(r.max_pkt_rate_seconds))
		assert(text:find(" max-pkt-rate " .. r.max_pkt_rate .. "/" ..
		    r.max_pkt_rate_seconds, 1, true),
		    "no max-pkt-rate in: " .. text)
	end
	assert(isuint(r.pkt_rate_count))
	assert(isuint(r.pkt_rate_last))

	-- Who loaded the rule, which pfctl prints on its Inserted line, and
	-- when a once rule went away.
	assert(isuint(r.created_uid))
	assert(isuint(r.created_pid))
	assert(isuint(r.src_nodes))
	assert(r.expires == nil or isuint(r.expires))

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

	-- A rule holds states it did not create: a match rule with a
	-- translation is charged the current count while the pass rule that
	-- follows it is charged the creations, so a live firewall shows
	-- states_cur in the hundreds against states_total of zero. Only the
	-- creations are bounded by the evaluations that produced them.
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


-- Guest only: everything below creates interfaces and a routing domain, and
-- loads a ruleset over whatever the machine is running.
local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_rules: not the disposable test guest; skipping the rest")
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

-- A rule confined to one routing domain needs a second domain to exist,
-- and pair4/pair5 are the pair this test owns in a guest it shares.
must("ifconfig pair4 create")
must("ifconfig pair5 create")
must("ifconfig pair4 patch pair5")
must("ifconfig pair5 rdomain 5")
must("ifconfig pair4 192.168.88.1/24 up")

-- Nothing sends traffic to pair4, which keeps the `once` rules from being
-- hit and removed while the test is reading them.
local conf = assert(io.open("/tmp/pf_test_rules.conf", "w"))
conf:write([[
table <cnt> const { 192.168.99.1, 192.168.99.2 }

block return-rst(ttl 64) in on pair4 proto tcp all
block return-icmp(host-prohib) in on pair4 inet all
block return-icmp6(admin-unr) in on pair4 inet6 all
block return-icmp in on pair4 all
block return in on pair4 all
block drop in on pair4 all
pass in on rdomain 5 all
pass in on ! rdomain 5 all
pass in on pair4 inet all rtable 0
pass in on pair4 inet all probability 12.5%
pass in on pair4 inet all allow-opts
pass in on pair4 inet all tos 0x10 set (tos 0x08, delay 20)
pass in on pair4 inet all scrub (no-df, random-id, min-ttl 4, reassemble tcp)
pass in on pair4 inet proto tcp all scrub (max-mss 1400)
pass in on pair4 inet all tag mytag
pass in on pair4 inet all tagged othertag
pass in on pair4 inet all ! tagged othertag
pass in on pair4 inet all fragment
pass in on pair4 inet all once
pass in on pair4 inet all max-pkt-rate 100/10
pass in on pair4 inet all divert-packet port 700
pass in on pair4 inet all divert-to 127.0.0.1 port 88
pass out on pair4 inet all divert-reply
pass in on pair4 inet proto tcp all modulate state
pass in on pair4 inet proto tcp all synproxy state
pass in on pair4 inet all no state
pass in on pair4 inet all keep state (sloppy, if-bound, no-sync, pflow, source-track rule, max 100)
pass in on pair4 inet all label "the-label" once tag t2 tagged t3 rtable 0
pass in on pair4 inet from <cnt> to any
pass in on pair4 inet from (pair4) to any
pass in on pair4 inet proto icmp all icmp-type unreach code port-unr
]])
conf:close()

local out = sh("pfctl -f /tmp/pf_test_rules.conf")
assert(out == "", "pfctl rejected the ruleset:\n" .. out)

local theirs = {}
local pipe = assert(io.popen("pfctl -s rules 2>/dev/null", "r"))
for line in pipe:lines() do
	theirs[#theirs + 1] = line
end
pipe:close()

local loaded = h:rules()
assert(#loaded == #theirs, string.format(
    "pfctl printed %d rules, the binding returned %d", #theirs, #loaded))

-- A qualifier the renderer drops changes what the rule means, and only a
-- comparison with pfctl catches that.
local wrong = {}
local byname = {}
for i, r in ipairs(loaded) do
	checkrule(r, "")
	byname[tostring(r)] = r
	if tostring(r) ~= theirs[i] then
		wrong[#wrong + 1] = string.format(
		    "[%d]\n  pfctl: %s\n  luapf: %s", i, theirs[i], tostring(r))
	end
end
assert(#wrong == 0, "rules render differently from pfctl:\n" ..
    table.concat(wrong, "\n"))

local function rule(text)
	return assert(byname[text], "no rule rendered as: " .. text)
end

-- A nil in a table constructor is indistinguishable from a key that was
-- never written, so an expected nil is spelled NONE.
local NONE = setmetatable({}, {__tostring = function() return "nil" end})

local function want(r, fields)
	for k, v in pairs(fields) do
		if v == NONE then
			v = nil
		end
		assert(r[k] == v, string.format("%s is %s, expected %s: %s",
		    k, tostring(r[k]), tostring(v), tostring(r)))
	end
end

want(rule("block return-rst(ttl 64) in on pair4 proto tcp all"),
    {return_policy = "return-rst", return_ttl = 64, return_icmp = NONE})
-- A rule with an address family carries a default in the other family's
-- field, and that default has no type byte, so it has no name either.
want(rule("block return-icmp(host-prohib) in on pair4 inet all"),
    {return_policy = "return-icmp", return_icmp = "host-prohib",
     return_icmp6 = "3", return_ttl = NONE})
want(rule("block return-icmp6(admin-unr) in on pair4 inet6 all"),
    {return_policy = "return-icmp", return_icmp6 = "admin-unr"})
want(rule("block return-icmp(port-unr, port-unr) in on pair4 all"),
    {return_icmp = "port-unr", return_icmp6 = "port-unr"})
want(rule("block return in on pair4 all"), {return_policy = "return"})
want(rule("block drop in on pair4 all"),
    {return_policy = "drop", return_ttl = NONE, return_icmp = NONE})

-- The two rdomain forms differ only in the flag they share with the
-- interface negation, so both have to be read back.
want(rule("pass in on rdomain 5 all flags S/SA"),
    {rdomain = 5, interface = "", interface_not = false})
want(rule("pass in on ! rdomain 5 all flags S/SA"),
    {rdomain = 5, interface = "", interface_not = true})

want(rule("pass in on pair4 inet all flags S/SA rtable 0"),
    {rtable = 0, rdomain = NONE})

local prob = rule("pass in on pair4 inet all flags S/SA probability 12.5%")
assert(math.abs(prob.probability - 12.5) < 0.01,
    "probability is " .. tostring(prob.probability))

want(rule("pass in on pair4 inet all flags S/SA allow-opts"),
    {allow_opts = true})
want(rule("pass in on pair4 inet all flags S/SA tos 0x10 " ..
    "set (tos 0x08, delay 20)"),
    {tos = 0x10, set_tos = 0x08, delay = 20})
want(rule("pass in on pair4 inet all flags S/SA " ..
    "scrub (no-df random-id min-ttl 4 reassemble tcp)"),
    {no_df = true, random_id = true, min_ttl = 4, reassemble_tcp = true,
     max_mss = NONE})
want(rule("pass in on pair4 inet proto tcp all flags S/SA " ..
    "scrub (max-mss 1400)"), {max_mss = 1400, no_df = false})

want(rule("pass in on pair4 inet all flags S/SA tag mytag"),
    {tag = "mytag", match_tag = ""})
want(rule("pass in on pair4 inet all flags S/SA tagged othertag"),
    {match_tag = "othertag", match_tag_not = false, tag = ""})
want(rule("pass in on pair4 inet all flags S/SA ! tagged othertag"),
    {match_tag = "othertag", match_tag_not = true})

want(rule("pass in on pair4 inet all fragment"), {fragment = true})
want(rule("pass in on pair4 inet all flags S/SA once"),
    {once = true, expired = false, expires = NONE})

-- The kernel divides the stored limit down again on copyout, so the number
-- the rule reports is the number pf.conf asked for.
want(rule("pass in on pair4 inet all flags S/SA max-pkt-rate 100/10"),
    {max_pkt_rate = 100, max_pkt_rate_seconds = 10})

want(rule("pass in on pair4 inet all flags S/SA scrub (reassemble tcp) " ..
    "divert-packet port 700"),
    {divert = "divert-packet", divert_port = 700, divert_address = NONE})
want(rule("pass in on pair4 inet all flags S/SA divert-to 127.0.0.1 port 88"),
    {divert = "divert-to", divert_address = "127.0.0.1", divert_port = 88})
want(rule("pass out on pair4 inet all flags S/SA divert-reply"),
    {divert = "divert-reply", divert_port = NONE, divert_address = NONE})

-- keep_state is a string because "modulate" and "synproxy" are neither
-- "keep state" nor "no state", and a boolean cannot say which.
want(rule("pass in on pair4 inet proto tcp all flags S/SA modulate state"),
    {keep_state = "modulate"})
want(rule("pass in on pair4 inet proto tcp all flags S/SA synproxy state"),
    {keep_state = "synproxy"})
want(rule("pass in on pair4 inet all no state"), {keep_state = NONE})
want(rule("pass in on pair4 inet all flags S/SA keep state (max 100, " ..
    "no-sync, source-track rule, if-bound, sloppy, pflow, " ..
    "adaptive.start 60, adaptive.end 120)"),
    {keep_state = "normal", no_sync = true, source_track = "rule",
     if_bound = true, sloppy = true, pflow = true})

want(rule('pass in on pair4 inet all flags S/SA label "the-label" once ' ..
    "tag t2 tagged t3 rtable 0"),
    {label = "the-label", once = true, tag = "t2", match_tag = "t3",
     rtable = 0})

-- The address counts pfctl shows under -vv, which it leaves out of the
-- rendering this test compares against.
want(rule("pass in on pair4 inet from <cnt> to any flags S/SA"),
    {source_addresses = 2, destination_addresses = NONE})
local dyn = rule("pass in on pair4 inet from (pair4) to any flags S/SA")
assert(dyn.source_addresses >= 1,
    "pair4 resolves to " .. tostring(dyn.source_addresses) .. " addresses")

want(rule("pass in on pair4 inet proto icmp all icmp-type unreach " ..
    "code port-unr"), {return_policy = NONE})

-- Every rule was loaded by this process's pfctl, running as root.
for _, r in ipairs(loaded) do
	assert(r.created_uid == 0, "rule " .. r.nr .. " was not loaded by root")
	assert(r.created_pid > 0, "rule " .. r.nr .. " records no loader")
end

-- An OS fingerprint has no name here, so the rendering leaves it out. It
-- must still stop the rule from collapsing to "all", which would claim the
-- rule matches traffic it never sees.
local fp = assert(io.open("/tmp/pf_test_rules_os.conf", "w"))
fp:write('pass in on pair4 inet proto tcp from any os "Linux" to any\n')
fp:close()
out = sh("pfctl -f /tmp/pf_test_rules_os.conf")
assert(out == "", "pfctl rejected the fingerprint rule:\n" .. out)

local osrule = h:rules()[1]
assert(osrule.os_fingerprint ~= nil and osrule.os_fingerprint > 0,
    "no fingerprint on the rule: " .. tostring(osrule.os_fingerprint))
assert(tostring(osrule):find("from any to any", 1, true),
    "a fingerprint rule did not spell its endpoints out: " ..
    tostring(osrule))

os.remove("/tmp/pf_test_rules.conf")
os.remove("/tmp/pf_test_rules_os.conf")
sh("printf '%s\\n' 'pass log' | pfctl -f -")
