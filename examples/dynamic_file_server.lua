-- Serve a directory tree over a small HTTP/1.1 endpoint, rendering any
-- small text file containing the literal token @ADDRESS@ by substituting
-- the address the client actually used to reach us -- read off the
-- request's Host: header -- before sending it.
--
-- Usage: dynamic_file_server.lua port directory [bind-address]
--
-- This exists for OpenBSD's netboot autoinstall(8): with vmctl start -B
-- net -L, vmd's own built-in DHCP server (see /usr/src/usr.sbin/vmd/dhcp.c)
-- answers the guest's PXE request with next-server/filename pointing back
-- at the host, and the installer fetches its response file over HTTP from
-- there entirely on its own -- no serial console interaction, and no need
-- to bake an /auto_install.conf into the boot ramdisk. But at the point
-- install.conf is generated (before any VM has started), the host-side
-- tap address that answer has to point back at isn't known yet -- it's
-- assigned per the numeric vmid vmd happens to hand out, which isn't
-- ours to pick or predict on a host that may already have other VMs
-- running. Binding 0.0.0.0 and reading the client's own idea of our
-- address off its Host: header sidesteps needing to know that address
-- ahead of time at all: whatever the guest actually used to reach us is
-- necessarily reachable, and is also the right thing to hand back for
-- every URL install.conf itself contains (the disklabel template, the
-- set server, etc).
--
-- Only files below TEMPLATE_MAX are ever read whole and searched for
-- @ADDRESS@ -- large files (release sets, potentially hundreds of MB)
-- are always streamed unchanged, both because reading them whole would
-- be wasteful and because none of them ever contain the token.

local socket = require("posix.sys.socket")
local unistd = require("posix.unistd")

local port = tonumber(arg[1])
local root = arg[2]
local address = arg[3] or "0.0.0.0"

local TEMPLATE_MAX = 65536

local function die(msg)
	io.stderr:write("dynamic-file-server: ", msg, "\n")
	os.exit(1)
end

if not port or not root then
	die("usage: " .. arg[0] .. " port directory [bind-address]")
end

if port < 1 or port > 65535 or port % 1 ~= 0 then
	die("port must be an integer from 1 through 65535")
end

local rootfd = io.open(root, "rb")
if rootfd then
	rootfd:close()
else
	die("cannot read directory: " .. root)
end

local function writeall(fd, text)
	local off = 0

	while off < #text do
		local n = socket.send(fd, text:sub(off + 1))
		if not n or n <= 0 then
			return false
		end
		off = off + n
	end

	return true
end

local function respond(fd, status, ctype, length, body)
	local head = string.format(
		"HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, ctype, length)

	return writeall(fd, head) and (not body or writeall(fd, body))
end

-- Reads the request line and headers (up to the blank line that ends
-- them), and returns the request line plus a table of headers keyed by
-- lowercased name. Any body is neither read nor needed: every request
-- this serves is a GET or HEAD.
local function read_request(fd)
	local buf = ""

	while not buf:find("\r\n\r\n", 1, true) do
		if #buf > 65536 then
			return nil
		end

		local chunk = socket.recv(fd, 4096)
		if not chunk or #chunk == 0 then
			return nil
		end
		buf = buf .. chunk
	end

	local head = buf:match("^(.-)\r\n\r\n")
	local lines = {}

	for line in (head .. "\r\n"):gmatch("(.-)\r\n") do
		lines[#lines + 1] = line
	end

	local headers = {}
	for i = 2, #lines do
		local k, v = lines[i]:match("^([^:]+):%s*(.*)$")
		if k then
			headers[k:lower()] = v
		end
	end

	return lines[1], headers
end

local function decode_path(path)
	path = path:gsub("%%(%x%x)", function(hex)
		return string.char(tonumber(hex, 16))
	end)

	if path:find("%%", 1, true) or path:find("\0", 1, true) or
		path:sub(1, 1) ~= "/" then
		return nil
	end

	local parts = {}
	for part in path:gmatch("[^/]+") do
		if part == "." or part == ".." then
			return nil
		end
		parts[#parts + 1] = part
	end

	if #parts == 0 then
		return nil
	end

	return table.concat(parts, "/")
end

local function content_type(name)
	if name:sub(-4) == ".txt" or name:sub(-5) == ".conf" then
		return "text/plain; charset=utf-8"
	end
	return "application/octet-stream"
end

-- The address the guest used to reach us, per its own Host: header --
-- not anything we look up locally, since under vmd -L there's no single
-- "our address" to look up: the answer is whichever tap address this
-- particular VM instance was handed, and the guest already knows it
-- (it's what it just connected to).
local function address_from_host(headers)
	local host = headers and headers.host
	if not host then
		return nil
	end

	-- The value is attacker-controlled, so accept only what can name
	-- this server: a hostname, an IPv4 literal, or a bracketed IPv6
	-- literal, with an optional :port. Anything else takes the same
	-- 400 path as a missing Host, since guessing at what a malformed
	-- header meant would only hand the guest an unreachable address.
	local literal = host:match("^(%[[%x:%.]+%])") or host:match("^([%w%-%.]+)")
	if not literal or #literal > 255 then
		return nil
	end

	local rest = host:sub(#literal + 1)
	if rest ~= "" and not rest:match("^:%d+$") then
		return nil
	end

	return literal
end

local function serve_file(fd, method, path, headers)
	local relative = decode_path(path)
	if not relative then
		respond(fd, "403 Forbidden", "text/plain; charset=utf-8", #"forbidden\n",
			method == "GET" and "forbidden\n" or nil)
		return
	end

	local file = io.open(root .. "/" .. relative, "rb")
	if not file then
		respond(fd, "404 Not Found", "text/plain; charset=utf-8", #"not found\n",
			method == "GET" and "not found\n" or nil)
		return
	end

	local length = file:seek("end")
	file:seek("set")
	if not length then
		file:close()
		respond(fd, "500 Internal Server Error", "text/plain; charset=utf-8",
			#"cannot read file\n", method == "GET" and "cannot read file\n" or nil)
		return
	end

	if length <= TEMPLATE_MAX then
		local body = file:read(length)
		file:close()

		if body and body:find("@ADDRESS@", 1, true) then
			local address_ = address_from_host(headers)
			if not address_ then
				local msg = "no usable Host header to render @ADDRESS@ in " ..
					relative .. "\n"
				respond(fd, "400 Bad Request", "text/plain; charset=utf-8",
					#msg, method == "GET" and msg or nil)
				return
			end
			-- gsub reads % in a replacement string as a capture
			-- reference, so escape it here as well: the substituted
			-- text must be exactly what the guest connected to,
			-- whatever address_from_host is taught to accept later.
			body = (body:gsub("@ADDRESS@", (address_:gsub("%%", "%%%%"))))
		end

		respond(fd, "200 OK", content_type(relative), #body,
			method == "GET" and body or nil)
		return
	end

	-- Larger than TEMPLATE_MAX: stream unchanged. Release sets run into
	-- the hundreds of megabytes; reading one whole just to check it for
	-- a token it will never contain would be pure waste.
	if not respond(fd, "200 OK", content_type(relative), length) or method == "HEAD" then
		file:close()
		return
	end

	while true do
		local chunk = file:read(65536)
		if not chunk then
			break
		end
		if not writeall(fd, chunk) then
			break
		end
	end
	file:close()
end

local listenfd = assert(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
assert(socket.setsockopt(listenfd, socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
assert(socket.bind(listenfd, { family = socket.AF_INET, addr = address, port = port }))
assert(socket.listen(listenfd, 8))

io.stderr:write(string.format("serving %s on http://%s:%d/ (rendering @ADDRESS@ from Host:)\n",
	root, address, port))

while true do
	local fd = socket.accept(listenfd)
	if fd then
		local line, headers = read_request(fd)
		local method, path, version

		if line then
			method, path, version = line:match("^(%u+)%s+(%S+)%s+(HTTP/1%.[01])$")
		end

		if not method then
			respond(fd, "400 Bad Request", "text/plain; charset=utf-8", #"bad request\n", "bad request\n")
		elseif method ~= "GET" and method ~= "HEAD" then
			respond(fd, "405 Method Not Allowed", "text/plain; charset=utf-8",
				#"method not allowed\n", method == "HEAD" and nil or "method not allowed\n")
		else
			-- autoinstall(8) appends "?path=<setdir>" to every fetch it
			-- makes for the response file itself; strip the query
			-- string before path validation rather than teach
			-- decode_path about it.
			local raw_path = path:match("^([^?]*)")
			serve_file(fd, method, raw_path, headers or {})
		end

		unistd.close(fd)
	end
end
