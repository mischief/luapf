-- Serves pf metrics over HTTP: exporter_server.lua [address] [port] [user].
--
-- A collector holds /dev/pf; the network process drops privilege and pledges.
-- The "pf" promise covers rule writers only, so reading rules under it aborts.

package.path = (arg[0]:match("^(.*)/") or ".") .. "/?.lua;" .. package.path

local fcntl = require("posix.fcntl")
local pwd = require("posix.pwd")
local signal = require("posix.signal")
local socket = require("posix.sys.socket")
local unistd = require("posix.unistd")
local wait = require("posix.sys.wait")

local pf = require("pf")
local pfmetrics = require("pfmetrics")

local address = arg[1] or "127.0.0.1"
local port = tonumber(arg[2]) or 9107
local user = arg[3] or "_pfexp"

local function die(msg)
	io.stderr:write("exporter: ", msg, "\n")
	os.exit(1)
end

local function readall(fd, want)
	local buf = ""

	while #buf < want do
		local chunk = unistd.read(fd, want - #buf)
		if not chunk or #chunk == 0 then
			return nil
		end
		buf = buf .. chunk
	end

	return buf
end

local function writeall(fd, s)
	local off = 0

	while off < #s do
		local n = unistd.write(fd, s:sub(off + 1))
		if not n or n <= 0 then
			return false
		end
		off = off + n
	end

	return true
end

-- collector: one byte in, a length prefixed document out

local function collector(sock, listenfd, pffd)
	unistd.close(listenfd)
	pfmetrics.usefd(pffd)

	pf.privsep.setproctitle("collector")

	while true do
		if not readall(sock, 1) then
			os.exit(0)
		end

		local ok, body = pcall(pfmetrics.collect)
		if not ok then
			io.stderr:write("collect: ", tostring(body), "\n")
			body = ""
		end

		if not writeall(sock, string.pack("<I4", #body) .. body) then
			os.exit(1)
		end
	end
end

local function ask(sock)
	if not writeall(sock, "?") then
		return nil
	end

	local head = readall(sock, 4)
	if not head then
		return nil
	end

	local len = string.unpack("<I4", head)
	if len == 0 then
		return nil
	end

	return readall(sock, len)
end

-- http

local function respond(fd, status, ctype, body)
	local head = string.format(
		"HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, ctype, #body)

	local off = 0
	local text = head .. body

	while off < #text do
		local n = socket.send(fd, text:sub(off + 1))
		if not n or n <= 0 then
			return
		end
		off = off + n
	end
end

-- Only the request line matters; the socket closes after one response, so
-- whatever else the client sent can be discarded.
local function requestline(fd)
	local buf = ""

	while #buf < 8192 do
		local chunk = socket.recv(fd, 1024)
		if not chunk or #chunk == 0 then
			return nil
		end

		buf = buf .. chunk

		local line = buf:match("^([^\r\n]*)\r?\n")
		if line then
			return line
		end
	end

	return nil
end

local function serve(sock, listenfd)
	pf.privsep.setproctitle("http")

	while true do
		local fd = socket.accept(listenfd)

		if fd then
			local line = requestline(fd)
			local method, path

			if line then
				method, path = line:match("^(%u+)%s+(%S+)")
			end

			if method ~= "GET" and method ~= "HEAD" then
				respond(fd, "405 Method Not Allowed", "text/plain", "method not allowed\n")
			elseif path == "/metrics" then
				local body = ask(sock)

				if body then
					respond(fd, "200 OK", "text/plain; version=0.0.4", body)
				else
					respond(fd, "503 Service Unavailable", "text/plain", "collector gone\n")
				end
			elseif path == "/" then
				respond(fd, "200 OK", "text/html",
					'<html><body><a href="/metrics">metrics</a></body></html>\n')
			else
				respond(fd, "404 Not Found", "text/plain", "not found\n")
			end

			unistd.close(fd)
		end
	end
end

-- setup, while still privileged

if unistd.geteuid() ~= 0 then
	die("must start as root to open /dev/pf")
end

local pw = pwd.getpwnam(user) or die("no such user: " .. user)
local pffd = fcntl.open("/dev/pf", fcntl.O_RDWR) or die("cannot open /dev/pf")

signal.signal(signal.SIGPIPE, signal.SIG_IGN)

local listenfd = assert(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))

assert(socket.setsockopt(listenfd, socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
assert(socket.bind(listenfd, { family = socket.AF_INET, addr = address, port = port }))
assert(socket.listen(listenfd, 8))

local parentsock, childsock = assert(socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0))

local pid = assert(unistd.fork())

if pid == 0 then
	unistd.close(parentsock)
	collector(childsock, listenfd, pffd)
	os.exit(0)
end

unistd.close(childsock)
unistd.close(pffd)

assert(pf.privsep.setgroups(pw.pw_gid))
assert(pf.privsep.setresgid(pw.pw_gid, pw.pw_gid, pw.pw_gid))
assert(pf.privsep.setresuid(pw.pw_uid, pw.pw_uid, pw.pw_uid))

if unistd.geteuid() == 0 or unistd.getuid() == 0 then
	die("still root after the drop")
end

assert(pf.privsep.pledge("stdio inet", nil))

serve(parentsock, listenfd)

wait.wait(pid)
