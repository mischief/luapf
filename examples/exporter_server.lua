-- Serves pf metrics over HTTP for prometheus to scrape.
--
--   exporter_server.lua [address] [port] [user]   default 127.0.0.1 9107
--
-- Given a user it opens /dev/pf, binds the port, then becomes that user.

package.path = (arg[0]:match("^(.*)/") or ".") .. "/?.lua;" .. package.path

local fcntl = require("posix.fcntl")
local pwd = require("posix.pwd")
local signal = require("posix.signal")
local socket = require("posix.sys.socket")
local unistd = require("posix.unistd")

local pf = require("pf")
local pfmetrics = require("pfmetrics")

local address = arg[1] or "127.0.0.1"
local port = tonumber(arg[2]) or 9107
local user = arg[3]

-- A client that hangs up mid-write must not take the server with it.
signal.signal(signal.SIGPIPE, signal.SIG_IGN)

local listenfd = assert(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))

assert(socket.setsockopt(listenfd, socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
assert(socket.bind(listenfd, { family = socket.AF_INET, addr = address, port = port }))
assert(socket.listen(listenfd, 8))

-- Everything that needs privilege happens before the drop: the pf descriptor
-- and the listening socket both outlive it.
if user then
	local pw = assert(pwd.getpwnam(user), "no such user: " .. tostring(user))

	pfmetrics.usefd(assert(fcntl.open("/dev/pf", fcntl.O_RDWR)))

	assert(unistd.setpid("g", pw.pw_gid))
	assert(unistd.setpid("u", pw.pw_uid))

	if unistd.geteuid() == 0 or unistd.getuid() == 0 then
		error("still running as root after the drop")
	end
end

local function writeall(fd, s)
	local off = 0

	while off < #s do
		local n = socket.send(fd, s:sub(off + 1))
		if not n or n <= 0 then
			return false
		end
		off = off + n
	end

	return true
end

local function respond(fd, status, ctype, body)
	local head = string.format(
		"HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, ctype, #body)

	writeall(fd, head .. body)
end

-- Reads just the request line; headers are not used and the socket is closed
-- after one response, so anything else the client sent can be discarded.
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

while true do
	local fd = socket.accept(listenfd)

	if fd then
		local line = requestline(fd)
		local method, path = nil, nil

		if line then
			method, path = line:match("^(%u+)%s+(%S+)")
		end

		if method ~= "GET" and method ~= "HEAD" then
			respond(fd, "405 Method Not Allowed", "text/plain", "method not allowed\n")
		elseif path == "/metrics" then
			local ok, body = pcall(pfmetrics.collect)

			if ok then
				respond(fd, "200 OK", "text/plain; version=0.0.4", body)
			else
				io.stderr:write("collect: ", tostring(body), "\n")
				respond(fd, "500 Internal Server Error", "text/plain", "collect failed\n")
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
