-- A ruleset with the shape of a real one, and a topology to hang it on.
--
-- The other tests load two or three rules, which leaves most of the rule
-- renderer unreached and lets a wrong rendering pass unnoticed. This builds
-- something closer to a working firewall -- tables of several kinds, a queue
-- tree, translation with dynamic addresses, state options, anchors, an
-- interface group -- and then requires every rule to render exactly as pfctl
-- prints it.
--
-- Guest only: it creates interfaces, routing domains and a ruleset.
local pf = require('pf')

local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_ruleset: not the disposable test guest; skipping")
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
	return out
end

-- Two routing domains joined by a patched pair(4): traffic sent into one
-- end arrives at the other through the kernel, so PF sees genuine routed
-- packets rather than anything this test hands it.
must("ifconfig pair0 create")
must("ifconfig pair1 create")
must("ifconfig pair0 patch pair1")
must("ifconfig pair1 rdomain 1")
must("ifconfig pair0 10.10.0.1/24 up")
must("ifconfig pair1 10.10.0.2/24 up")
must("ifconfig pair0 group testnet")
must("ifconfig vether0 create")
must("ifconfig vether0 192.168.77.1/24 up")

local zone = assert(io.open("/tmp/pf_test_ruleset.zone", "w"))
zone:write("203.0.113.0/24\n198.51.100.7\n")
zone:close()

local conf = assert(io.open("/tmp/pf_test_ruleset.conf", "w"))
conf:write([[
table <hosts> const { 192.168.77.10, 192.168.77.11 }
table <firewall> const { self }
table <blocked> const file "/tmp/pf_test_ruleset.zone"
table <overloaded>

set block-policy return
set loginterface pair0
set optimization aggressive
set skip on lo0
set state-defaults pflow

queue top on pair0 bandwidth 100M max 100M qlimit 256
queue main parent top bandwidth 90M default
queue bulk parent top bandwidth 10M

match out on pair0 inet from !(vether0:network) to any nat-to (pair0:0) set prio (3, 6)

block drop in quick on pair0 from <blocked>
block return out log proto tcp all user = 55
block all

pass from <firewall>
pass out

pass in on testnet inet proto icmp all icmp-type echoreq
pass in on ! pair0 proto tcp from any to any port 6000:6010
pass in log quick on pair0 proto tcp from any to (pair0:0) port 2222 rdr-to <hosts> port 22
pass in on vether0 proto { tcp, udp } from any to any port domain rdr-to (vether0) port domain
pass out on vether0 proto tcp to <hosts> port 22 received-on vether0 nat-to vether0
pass out on pair0 proto { tcp, udp } from any to any port 4001 set queue bulk keep state
pass in on pair0 proto tcp from any to any port 22 keep state (max-src-conn-rate 1/60, overload <overloaded> flush global)
pass in on pair0 inet proto tcp from 10.10.0.0/24 to any port { 80, 443 } rdr-to 10.10.0.1 port 8080
anchor "services"
]])
conf:close()

local out = sh("pfctl -f /tmp/pf_test_ruleset.conf")
assert(out == "", "pfctl rejected the ruleset:\n" .. out)

local h = assert(pf.open())

-- Every rule, rendered against pfctl's own printing of the same ruleset.
-- This is the assertion the whole fixture exists for: a renderer that
-- drops a qualifier changes what the rule means, and only a comparison
-- with pfctl catches that.
local theirs = {}
local p = assert(io.popen("pfctl -s rules 2>/dev/null", "r"))
for line in p:lines() do
	theirs[#theirs + 1] = line
end
p:close()

local rules = h:rules()
assert(#rules == #theirs, string.format(
    "pfctl printed %d rules, the binding returned %d", #theirs, #rules))

local wrong = {}
for i, r in ipairs(rules) do
	if tostring(r) ~= theirs[i] then
		wrong[#wrong + 1] = string.format(
		    "[%d]\n  pfctl: %s\n  luapf: %s", i, theirs[i], tostring(r))
	end
end
assert(#wrong == 0, "rules render differently from pfctl:\n" ..
    table.concat(wrong, "\n"))

-- The tables the ruleset declared, of each kind it declared them in.
local names = {}
for _, t in ipairs(h:tables()) do
	names[tostring(t.name or t)] = true
end
for _, want in ipairs({"hosts", "firewall", "blocked", "overloaded"}) do
	assert(names[want], "table missing: " .. want)
end

-- An anchor the ruleset calls, and the call recorded on the calling rule.
local anchors = h:anchors()
local seen = false
for _, a in ipairs(anchors) do
	if a == "services" then
		seen = true
	end
end
assert(seen, "the services anchor is not listed")

local called = false
for _, r in ipairs(rules) do
	if r.anchor_call == "services" then
		called = true
	end
end
assert(called, "no rule records the anchor call")

-- The queue tree, on the interface it was declared on.
local queues = h:queues()
assert(#queues == 3, "expected three queues, got " .. #queues)
for _, q in ipairs(queues) do
	assert(q.ifname == "pair0", "queue on the wrong interface: " ..
	    tostring(q.ifname))
end

-- Traffic across the routing domains, so the translation rules run against
-- packets the kernel actually forwarded.
sh("route -T 1 exec ping -c 1 -w 2 10.10.0.1")
sh("echo probe | route -T 1 exec nc -u -w 1 10.10.0.1 4001")
assert(#h:rules() == #rules, "the ruleset changed under traffic")

local evaluated = false
for _, r in ipairs(h:rules()) do
	if r.evaluations > 0 then
		evaluated = true
	end
end
assert(evaluated, "no rule was evaluated by the traffic")

os.remove("/tmp/pf_test_ruleset.conf")
os.remove("/tmp/pf_test_ruleset.zone")
sh("printf '%s\\n' 'pass log' | pfctl -f -")
