-- The anchor tree: the walk that lists it, the root argument that starts
-- the walk part way down, the rule count of each anchor, and the anchor
-- call in the parent that ties a nested anchor back to its caller.
--
-- Building the tree means loading a ruleset, so the whole test runs only
-- in the disposable guest.
local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_anchors: not the disposable test guest; skipping")
	os.exit(0)
end
marker:close()

local pf = require("pf")

local h = pf.open()
assert(h)

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>&1", "r"))
	local out = p:read("a")
	p:close()
	return out
end

local function writefile(path, text)
	local f = assert(io.open(path, "w"))
	f:write(text)
	f:close()
end

local function same(got, want, what)
	assert(#got == #want, what .. ": expected " .. #want ..
	    " anchors, got " .. #got .. " (" .. table.concat(got, " ") .. ")")
	for i, v in ipairs(want) do
		assert(got[i] == v, what .. ": entry " .. i .. " is " ..
		    tostring(got[i]) .. ", expected " .. v)
	end
end

-- The tree is three deep under "a" and two deep under "z", with two
-- siblings under a/b. A flat set never reaches the code that joins a
-- parent path to a child name and never revisits the pending list. The
-- block with no anchor name is an inline anchor: pfctl names it "_1" and
-- keeps such names out of the plain listing, so the binding reports one
-- anchor more than pfctl -s Anchors does.
writefile("/tmp/pf_test_anchors.conf", [[
set skip on lo
anchor "a"
anchor "m"
anchor "z"
anchor {
	pass in log proto tcp to port 25
}
pass out log all
]])

-- Each anchor is loaded on its own with pfctl -a rather than as an inline
-- block, because a block that carries a table fails the whole load.
writefile("/tmp/pf_test_anchors_a.conf", [[
anchor "b"
pass in log proto tcp to port 22
]])
writefile("/tmp/pf_test_anchors_ab.conf", [[
anchor "c"
anchor "x"
block in log proto icmp
]])
writefile("/tmp/pf_test_anchors_abc.conf", [[
pass in log proto udp to port 53
pass in log proto udp to port 123
block in log from 198.51.100.0/24
]])
writefile("/tmp/pf_test_anchors_abx.conf", [[
pass in log proto tcp to port 80
]])
writefile("/tmp/pf_test_anchors_z.conf", [[
anchor "y"
]])
writefile("/tmp/pf_test_anchors_zy.conf", [[
pass in log proto tcp to port 443
pass in log proto tcp to port 8443
]])

local function load(anchor, file)
	local at = anchor == "" and "" or ("-a " .. anchor .. " ")
	local out = sh("pfctl " .. at .. "-f " .. file)
	assert(out == "", "pfctl rejected " .. file .. ": " .. out)
end

load("", "/tmp/pf_test_anchors.conf")
load("a", "/tmp/pf_test_anchors_a.conf")
load("a/b", "/tmp/pf_test_anchors_ab.conf")
load("a/b/c", "/tmp/pf_test_anchors_abc.conf")
load("a/b/x", "/tmp/pf_test_anchors_abx.conf")
load("z", "/tmp/pf_test_anchors_z.conf")
load("z/y", "/tmp/pf_test_anchors_zy.conf")

-- Sorted, which is not the order the tree is walked in: a/b and its two
-- children sit below the whole first level in the walk but between "a"
-- and "m" here.
local expected = {
	"a", "a/b", "a/b/c", "a/b/x", "m", "z", "z/y",
}

local function hidden(path)
	return path:match("^_") ~= nil or path:match("/_") ~= nil
end

local anchors = h:anchors()
assert(type(anchors) == "table")

local visible, inline = {}, {}
for _, a in ipairs(anchors) do
	assert(type(a) == "string" and #a > 0)
	if hidden(a) then
		inline[#inline + 1] = a
	else
		visible[#visible + 1] = a
	end
end

same(visible, expected, "pf:anchors()")
assert(#inline == 1, "expected one inline anchor, got " ..
    table.concat(inline, " "))

-- pfctl walks the same tree through the same two ioctls and prints full
-- paths, so its listing is an independent reading of the path joining. The
-- recursive listing prints the inline anchor as well.
local ref = {}
for line in sh("pfctl -s Anchors -v"):gmatch("[^\n]+") do
	ref[#ref + 1] = line:match("^%s*(%S+)%s*$")
end
same(ref, anchors, "pfctl -s Anchors -v")

-- Without -v, pfctl prints the same paths but leaves the inline anchor
-- out. That difference is pfctl's, not the kernel's: the binding reports
-- every anchor that exists.
local plain = {}
for line in sh("pfctl -s Anchors"):gmatch("[^\n]+") do
	local name = line:match("^%s*(%S+)%s*$")
	assert(not hidden(name), "pfctl printed the inline anchor " .. name)
	plain[#plain + 1] = name
end
same(plain, visible, "pfctl -s Anchors")
assert(#h:rules(inline[1]) == 1, "the inline anchor lost its rule")

-- A root starts the walk below the top. The root itself is not part of
-- its own listing, and nothing outside it is either.
same(h:anchors("a"), { "a/b", "a/b/c", "a/b/x" }, 'pf:anchors("a")')
same(h:anchors("a/b"), { "a/b/c", "a/b/x" }, 'pf:anchors("a/b")')
same(h:anchors("m"), {}, 'pf:anchors("m")')

local ok, err = pcall(h.anchors, h, "nosuchanchor")
assert(not ok, "a nonexistent root was accepted")
assert(tostring(err):match("DIOCGETRULESETS"),
    "unexpected error for a nonexistent root: " .. tostring(err))

ok, err = pcall(h.anchors, h, string.rep("deep/", 1000))
assert(not ok, "an oversized root was accepted")
assert(tostring(err):match("anchor path too long"),
    "unexpected error for an oversized root: " .. tostring(err))

-- Every anchor's own rule count, and the count read the expensive way.
-- The two must agree for every anchor in the tree, including the empty
-- one: an anchor with no rules of its own still exists.
local wantcounts = {
	["a"] = 2,
	["a/b"] = 3,
	["a/b/c"] = 3,
	["a/b/x"] = 1,
	["m"] = 0,
	["z"] = 1,
	["z/y"] = 2,
}

local counted = {}
for _, a in ipairs(h:anchors("", true)) do
	assert(type(a) == "table", "counts entry is not a table")
	assert(type(a.path) == "string")
	assert(type(a.rules) == "number" and a.rules >= 0)
	assert(a.rules == #h:rules(a.path), a.path .. ": count says " ..
	    a.rules .. " but pf:rules gives " .. #h:rules(a.path))
	if not hidden(a.path) then
		assert(wantcounts[a.path], "unexpected anchor " .. a.path)
		assert(a.rules == wantcounts[a.path], a.path .. ": counted " ..
		    a.rules .. " rules, expected " .. wantcounts[a.path])
	end
	counted[#counted + 1] = a.path
end

same(counted, anchors, "pf:anchors with counts")
local rootcounted = {}
for _, a in ipairs(h:anchors("a/b", true)) do
	rootcounted[#rootcounted + 1] = a.path
end
same(rootcounted, { "a/b/c", "a/b/x" }, "a root with counts")

-- pfctl reads the same anchor by path and prints one line per rule.
local n = 0
for _ in sh("pfctl -a a/b/c -s rules"):gmatch("[^\n]+") do
	n = n + 1
end
assert(n == 3, "pfctl printed " .. n .. " rules for a/b/c")

-- The rules of a nested anchor are its own, not its parent's.
local abc = h:rules("a/b/c")
assert(#abc == 3, "a/b/c holds " .. #abc .. " rules")
for _, r in ipairs(abc) do
	assert(r.anchor == "a/b/c", "a rule of a/b/c reports anchor " ..
	    tostring(r.anchor))
	assert(r.anchor_call == "", "a rule of a/b/c calls an anchor")
end

-- The two halves meet here: the anchors under a/b are exactly the
-- anchors its rules call. The call records the child's name, not the
-- full path, so the path has to be rebuilt to match the listing.
local calls = {}
for _, r in ipairs(h:rules("a/b")) do
	assert(r.anchor == "a/b", "a rule of a/b reports anchor " ..
	    tostring(r.anchor))
	if r.anchor_call ~= "" then
		calls[#calls + 1] = "a/b/" .. r.anchor_call
	end
end
same(calls, { "a/b/c", "a/b/x" }, "the anchor calls in a/b")

local parentcalls = {}
for _, r in ipairs(h:rules("a")) do
	if r.anchor_call ~= "" then
		parentcalls[#parentcalls + 1] = "a/" .. r.anchor_call
	end
end
same(parentcalls, { "a/b" }, "the anchor calls in a")

-- Reading twice must give the same tree: the walk must not leave a
-- ruleset ticket or a pending path behind.
same(h:anchors(), anchors, "a second walk")

for _, f in ipairs({ "", "_a", "_ab", "_abc", "_abx", "_z", "_zy" }) do
	os.remove("/tmp/pf_test_anchors" .. f .. ".conf")
end
sh("pfctl -f /etc/pf.conf")
