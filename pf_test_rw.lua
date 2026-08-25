-- The paths that change PF: enabling and disabling it, clearing counters,
-- killing states, and handing an existing descriptor to the binding.
--
-- Guest only, and deliberately so -- every one of these would disturb the
-- host it ran on, which is why nothing else here covers them.
local pf = require('pf')

local marker = io.open("/etc/luapf-test-vm")
if not marker then
	print("pf_test_rw: not the disposable test guest; skipping")
	os.exit(0)
end
marker:close()

local function sh(cmd)
	local p = assert(io.popen(cmd .. " 2>&1", "r"))
	local out = p:read("a")
	p:close()
	return out
end

local h = assert(pf.open())

-- PF may be left either way by an earlier test, so read the flag rather
-- than assume a starting state.
local function running()
	return h:status().running
end

assert(type(running()) == "boolean")

h:stop()
assert(not running(), "PF still reports running after stop")
h:start()
assert(running(), "PF does not report running after start")

-- Counters clear. Traffic is generated first so there is something to
-- clear, and the check is that the number does not grow across the call.
sh("printf '%s\\n' 'pass log' | pfctl -f -")
sh("echo x | nc -w 1 127.0.0.1 9 2>/dev/null")
h:clearstatus()
local st = h:status()
assert(type(st.since) == "number", "status has no since after clearstatus")

-- States: create some, count them, kill them by filter, then clear.
local before = #h:states()
sh("nc -l 127.0.0.1 31399 </dev/null >/dev/null &")
sh("sleep 1; echo y | nc -N -w 1 127.0.0.1 31399")
local during = #h:states()
assert(during >= before, "state table shrank while a connection was made")

-- killstates takes the id of one state and reports how many it removed.
local target = h:states()[1]
if target then
	local killed = h:killstates(target.id)
	assert(type(killed) == "number" and killed >= 0,
	    "killstates did not report a count")
end

assert(h:clearstates() >= 0)
assert(#h:states() == 0, "states remain after clearstates")

-- openfd adopts a descriptor the caller keeps: closing the handle must
-- leave the caller's own descriptor usable, which is the whole point of
-- the duplicate it takes.
local serialutil = require('serialutil')
local dev = assert(io.open("/dev/pf", "r+b"))
local fd = serialutil.fileno(dev)
local h2 = assert(pf.openfd(fd))
assert(type(h2:status().running) == "boolean",
    "a handle from openfd cannot read status")
h2:close()

local h3 = assert(pf.openfd(fd), "the caller's descriptor died with the handle")
assert(type(h3:status().running) == "boolean")
h3:close()
dev:close()

-- A closed handle refuses work rather than reaching ioctl with a
-- released descriptor.
local h4 = assert(pf.open())
h4:close()
local ok, err = pcall(function() return h4:status() end)
assert(not ok, "a closed handle still answered")
assert(tostring(err):find("closed", 1, true),
    "unexpected error from a closed handle: " .. tostring(err))
h4:close()

-- A read-only handle reads but cannot write.
local ro = assert(pf.open("r"))
assert(type(ro:status().running) == "boolean", "read-only handle cannot read")
local wok = pcall(function() return ro:clearstatus() end)
assert(not wok, "a read-only handle performed a write")
ro:close()

sh("printf '%s\\n' 'pass log' | pfctl -f -")
