-- luapf_console.lua: drive the luapf disposable-guest serial console
-- like a human at a terminal -- log in, run shell commands, move files
-- -- rather than a bespoke line protocol.
--
-- serialutil.so (examples/serialutil/serialutil.c, built as part of this
-- project's own meson build -- see meson.build) does the actual tty work:
-- raw serial open and readable() poll instead of a blocking read. It is
-- a small vendored-in trim of nlos's test/hostutil.c, not a dependency on
-- that project's tree: this repo's VM-building machinery has to build
-- and run on its own.
--
-- Reached through LUA_CPATH, which meson.build's devenv/default test
-- setup sets to the build root -- run under `meson devenv` (or
-- `eval "$(meson devenv -C build --dump)"`), require("serialutil")
-- just finds it. Outside one, the module is not on the path and
-- require says so.
--
-- push() does NOT use ZMODEM, despite lrzsz being installed in the
-- guest for it (see build_test_vm_base.sh). vmd(8)'s emulated com0 is
-- a from-scratch ns8250 with no FIFO and no flow control -- see
-- /usr/src/usr.sbin/vmd/ns8250.c: com_rcv() reads one byte off the host
-- pty straight into the (single-byte) receive register with nothing
-- behind it, so a byte arriving before the guest's IRQ handler drains
-- the last one is simply gone, with no overrun indication either side
-- can see. Measured directly: lrzsz transfers climbed to ~100% then
-- desynced and looped forever on ZCAN, independent of window size,
-- baud, or CRC width. exec()'s line-at-a-time protocol tolerates this
-- because ksh's own line editor already assumes a lossy, echoing tty
-- and reads a whole line before acting on it; push() reuses exec() and
-- moves data as base64 lines instead.
--
-- Every action here assumes it owns the whole session: opening,
-- logging in, and closing are the caller's job (see run_pf_vm_tests.sh),
-- because a second opener of the same vmd tty steals bytes the first is
-- waiting for.

local M = {}

local Console = {}
Console.__index = Console

local function escape_transcript(data)
	return data:gsub("\r", "\\r"):gsub("\t", "\\t")
end

local function transcript(c, direction, data)
	if not c.transcript or not data then
		return
	end
	-- Reads are one byte at a time, so buffer each direction and emit one
	-- record per newline rather than one record per byte.
	local buffers = c.transcript_buffers
	local buf = (buffers[direction] or "") .. data
	while true do
		local newline = buf:find("\n", 1, true)
		if not newline then
			break
		end
		c.transcript:write(direction, " ",
		    escape_transcript(buf:sub(1, newline - 1)), "\n")
		buf = buf:sub(newline + 1)
	end
	buffers[direction] = buf
	c.transcript:flush()
end

local function flush_transcript(c)
	if not c.transcript then
		return
	end
	for _, direction in ipairs({"TX", "RX"}) do
		local buf = c.transcript_buffers[direction]
		if buf and #buf > 0 then
			c.transcript:write(direction, " ", escape_transcript(buf), "\n")
		end
	end
	c.transcript:flush()
end

local function tx(c, ...)
	local parts = {...}
	local data = table.concat(parts)
	if c.transcript_redact then
		data = "<redacted>\r\n"
	end
	transcript(c, "TX", data)
	return c.f:write(...)
end

local function rx(c, data)
	transcript(c, "RX", data)
	return data
end

local function serialutil()
	return require("serialutil")
end

-- open(port, baud, transcript_path) -> console
-- Password input is recorded as <redacted>.
function M.open(port, baud, transcript_path)
	local hu = serialutil()
	local f, err = hu.serial(port, baud or 115200)

	if not f then
		return nil, err
	end
	local transcript_file
	if transcript_path then
		transcript_file, err = io.open(transcript_path, "a")
		if not transcript_file then
			f:close()
			return nil, err
		end
	end
	return setmetatable({ hu = hu, f = f, fd = hu.fileno(f),
	    transcript = transcript_file,
	    transcript_buffers = { TX = "", RX = "" } }, Console)
end

local napper = nil

local function nap(seconds)
	if not napper then
		napper = serialutil().sleep
	end
	napper(seconds)
end

M.nap = nap

-- say(line, settle) -- type one line at whatever prompt currently has
-- the console (login, password, or shell). Flush matters: the stream
-- is read/write and C wants the direction change separated by a flush,
-- else a later read can block forever on a line that went out fine.
function Console:say(line, settle)
	tx(self, line, "\r\n")
	self.f:flush()
	nap(settle or 0.4)
	return self
end

-- drain(limit, quiet) -- read and discard until `quiet` seconds of
-- silence or `limit` total seconds, whichever comes first. For
-- clearing whatever a prompt printed before the caller cares, or the
-- line after a transfer that timed out.
function Console:drain(limit, quiet)
	local deadline = os.time() + (limit or 3)
	local n = 0

	while os.time() < deadline do
		if not self.hu.readable(self.fd, quiet or 0.4) then
			break
		end
		if not rx(self, self.f:read(1)) then
			break
		end
		n = n + 1
	end
	return n
end

-- ask(line, quiet) -- type a line and collect what comes back until
-- `quiet` seconds of silence. Lines rather than a prompt match: the
-- shell's PS1 prints without a trailing newline, and there is no fixed
-- transcript shape to parse against, so gathering until the guest goes
-- quiet is what actually works, same as hostpanel.lua's ask().
function Console:ask(line, quiet, max_seconds)
	tx(self, line, "\r\n")
	self.f:flush()

	local out = {}
	local deadline = os.time() + (max_seconds or 10)

	while os.time() < deadline do
		if not self.hu.readable(self.fd, quiet or 0.6) then
			break
		end
		local c = rx(self, self.f:read(1))
		if not c then
			break
		end
		out[#out + 1] = c
	end
	return (table.concat(out):gsub("\r", ""))
end

-- expect(needle, limit) -- read until `needle` (a plain string, not a
-- pattern) appears, or give up after `limit` seconds. Ported from
-- nlos's hostpanel.lua: ask()/drain() stop at a *gap* in output and
-- call that the end, which is wrong for a boot -- a pause between one
-- rc(8) service and the next reads as a guest with nothing left to
-- say. Waiting for a specific word is not a race; waiting for silence
-- is, and login: showing up late (slow disk, first boot) is exactly
-- what silence-based waiting gets wrong.
function Console:expect(needle, limit)
	local out = {}
	local deadline = os.time() + (limit or 30)
	local seen = ""

	while os.time() <= deadline do
		if self.hu.readable(self.fd, 0.5) then
			local c = rx(self, self.f:read(1))

			if not c then
				break
			end
			out[#out + 1] = c
			-- tail only: a whole-buffer find per byte is
			-- quadratic, and a boot is thousands of them
			seen = (seen .. c):sub(-#needle)
			if seen == needle then
				return (table.concat(out):gsub("\r", "")), true
			end
		end
	end
	return (table.concat(out):gsub("\r", "")), false
end

-- login(user, password) -- assumes a getty is showing "login:" (the
-- ordinary OpenBSD console, no custom agent). Sends a blank line
-- first: the console may be mid-line from a previous session or from
-- boot output racing the first read, and a stray prompt beats joining
-- onto whatever was half-typed.
function Console:login(user, password, timeout)
	self:say("")

	local deadline = os.time() + (timeout or 60)
	local _, got_login = self:expect("login: ", timeout)
	if not got_login then
		return nil, "timed out waiting for login prompt"
	end

	self:say(user, 0.3)

	local remaining = deadline - os.time()
	local _, got_password = self:expect("Password:", remaining > 0 and remaining or 1)
	if not got_password then
		return nil, "timed out waiting for password prompt"
	end

	self.transcript_redact = true
	self:say(password, 0.5)
	self.transcript_redact = false

	-- login(1) says nothing on success, so the only proof the password
	-- was taken is a shell answering a command. A wrong password instead
	-- prints "Login incorrect" and hands the line back to getty, and
	-- whatever we typed at that getty comes back echoed -- so treat a
	-- fresh login prompt as failure too, not as a slow shell.
	while true do
		local remaining = deadline - os.time()
		if remaining <= 0 then
			break
		end
		local probe = "LUAPF_SHELL_" .. math.random(1, 1e9)
		local status, out = self:exec("echo " .. probe,
		    remaining < 8 and remaining or 8)

		out = tostring(out)
		if status == 0 and out:find(probe, 1, true) then
			return self
		end
		if out:find("Login incorrect", 1, true) then
			return nil, "login incorrect for user " .. tostring(user)
		end
		-- Start of a line only: login(1) greets a *successful* login
		-- with "Last login: ...", which a plain substring test would
		-- read as a getty prompt.
		if out:match("^login: ") or out:match("[\r\n]login: ") then
			return nil, "back at the login prompt after sending " ..
			    "the password for user " .. tostring(user)
		end
	end
	return nil, "logged in but no shell answered within " ..
	    tostring(timeout or 60) .. "s"
end

-- ready(timeout) -- proves the guest is actually up and the shell will
-- answer, rather than assuming a successful login means the shell is
-- live yet. Marker files, not merely a shell prompt: run_pf_vm_tests.sh
-- wants to know rc.firsttime (package install, provisioning) finished,
-- and a shell that answers a command earlier than that is answering
-- from a guest still installing packages underneath it.
function Console:ready(timeout)
	local out = self:ask(
	    "test -f /etc/luapf-test-vm && test -f /etc/luapf-test-vm-ready " ..
	    "&& echo LUAPF_READY || echo LUAPF_NOT_READY",
	    0.6, timeout or 10)

	return out:find("LUAPF_READY", 1, true) ~= nil
end

-- base64, for push() below. hostutil doesn't provide one and stock Lua
-- has none; small and self-contained since this is the one place the
-- console driver needs it.
local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function b64encode(data)
	local out = {}

	for i = 1, #data, 3 do
		local a, b, c = data:byte(i, i + 2)
		b = b or 0
		local n = a * 65536 + b * 256 + (c or 0)
		local o1, o2 = (n >> 18) & 0x3f, (n >> 12) & 0x3f
		local o3, o4 = (n >> 6) & 0x3f, n & 0x3f
		local chunk = b64chars:sub(o1 + 1, o1 + 1) ..
		    b64chars:sub(o2 + 1, o2 + 1) ..
		    b64chars:sub(o3 + 1, o3 + 1) ..
		    b64chars:sub(o4 + 1, o4 + 1)

		if not data:byte(i + 2) then
			chunk = chunk:sub(1, 3) .. "="
		end
		if not data:byte(i + 1) then
			chunk = chunk:sub(1, 2) .. "=="
		end
		out[#out + 1] = chunk
	end
	return table.concat(out)
end

-- push(file, dest) -- send a local file to the guest, landing at
-- `dest`/basename(file).
--
-- ZMODEM (lrzsz) was tried first and works up to roughly 16-32KB, then
-- desyncs indefinitely: vmd's emulated com0 is a software ns8250 with
-- no FIFO (see dmesg: "com0 ... ns8250, no fifo"), and lrz/lsz retry
-- forever rather than giving up when it can't keep up. exec() over the
-- same tty has proven solid under the same conditions (used for every
-- other guest interaction here), so push() reuses it: base64 lines
-- through the guest's own shell, appended with dd. Slower than ZMODEM
-- would be if ZMODEM worked, but it actually finishes.
function Console:push(file, dir)
	local fh, err = io.open(file, "rb")

	if not fh then
		return nil, "cannot read " .. tostring(file) .. ": " .. tostring(err)
	end

	local name = file:match("([^/]+)$")
	local dest = dir and (dir .. "/" .. name) or name

	local status, out = self:exec("rm -f " .. dest, 10)
	if status ~= 0 then
		fh:close()
		return nil, "cannot clear destination: " .. tostring(out)
	end

	-- One base64 line per exec() round trip. 900 bytes in -> 1200
	-- base64 chars out, safely under ksh's LINE_MAX (2048, see
	-- getconf LINE_MAX) alongside the "print -rn -- " and
	-- "| base64 -d >>path" wrapping exec() adds; a line that hits
	-- LINE_MAX gets silently truncated by the shell's line editor
	-- with no error, which looked exactly like "it worked" until the
	-- destination file came back short.
	while true do
		local chunk = fh:read(900)
		if not chunk then
			break
		end

		-- openssl base64 -d, not base64(1) (OpenBSD has no such
		-- command) and not b64decode(1) (wants a uuencode-style
		-- begin/end wrapper, or -r for raw input plus -m -- more
		-- moving parts than the one tool every OpenBSD install
		-- already has for this).
		local encoded = b64encode(chunk)
		local cmd = "print -rn -- " .. encoded ..
		    " | openssl base64 -d -A >>" .. dest

		status, out = self:exec(cmd, 20)
		if status ~= 0 then
			fh:close()
			return nil, "append failed: " .. tostring(out)
		end
	end
	fh:close()
	return true
end

-- exec(cmd, timeout) -> status, output -- run a shell command line and
-- collect its output, using a sentinel to know the command actually
-- finished (as opposed to merely going quiet for `quiet` seconds, which
-- a slow command could do too).
function Console:exec(cmd, timeout)
	local sentinel = ("LUAPF_DONE_%d"):format(math.random(1, 1e9))

	tx(self, cmd, "\necho ", sentinel, " $?\r\n")
	self.f:flush()

	local out = {}
	local deadline = os.time() + (timeout or 60)
	-- Room for the sentinel, its status and the newline ending it, and
	-- no more: this is rescanned for every chunk that arrives.
	local window = #sentinel + 16
	local seen = ""

	while os.time() < deadline do
		if not self.hu.readable(self.fd, 1.0) then
			goto continue
		end
		-- Whatever has arrived, not one byte of it: a test that
		-- prints its output, or a pflog dump, is tens of kilobytes
		-- through a 115200 line, and a byte at a time cost one
		-- read(2) and one rescan of the whole transcript each.
		local c = rx(self, self.hu.readsome(self.fd, 4096))
		if not c then
			return nil, table.concat(out), "console closed"
		end
		out[#out + 1] = c
		-- Search the carried tail joined to the whole new chunk,
		-- then trim. Trimming first would drop the sentinel whenever
		-- the shell's next prompt arrived in the same chunk, timing
		-- out a command that had in fact finished.
		local hay = seen .. c
		seen = hay:sub(-window)
		-- Anchored on the end of the sentinel's own line: a chunk
		-- that split the status would otherwise report a prefix of
		-- it and treat the command as finished early.
		local status = hay:match(sentinel .. " (%-?%d+)[\r\n]")
		if status then
			local full = table.concat(out):gsub("\r", "")
			-- strip the echoed command line and the sentinel
			-- line itself, leaving only what the command wrote.
			local body = full:match("^[^\n]*\n(.-)\n?" ..
			    sentinel .. " %-?%d+%s*\n?$") or full
			return tonumber(status), body
		end
		::continue::
	end
	return nil, table.concat(out):gsub("\r", ""), "timed out"
end

function Console:close()
	flush_transcript(self)
	self.f:close()
	if self.transcript then
		self.transcript:close()
		self.transcript = nil
	end
end

return M
