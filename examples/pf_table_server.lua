-- Read-only local PF table-membership service.
--
-- This is an experimental demo. It serves requests over /var/run/pfd.sock;
-- change the socket ownership and mode before using it outside a controlled
-- local environment. It only calls read-only PF table operations.

local imsg = require("imsg")
local posix = require("posix")
local poll = require("posix.poll")
local socket = require("posix.sys.socket")
local stat = require("posix.sys.stat")
local unistd = require("posix.unistd")
local pf = require("pf")

local IMSG_PF_TABLE_TEST = 1
local IMSG_PF_TABLE_FAIL = 2
local IMSG_PF_TABLE_REPLY = 3

local socket_path = "/var/run/pfd.sock"

os.remove(socket_path)

local handle = assert(pf.open())
local listener, err = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
assert(listener, err)

local ok
ok, err = socket.bind(listener, {
	family = socket.AF_UNIX,
	path = socket_path,
})
assert(ok == 0, err)

-- Restrict this to the account that runs the demo. Deployments should use a
-- dedicated group and 0660 rather than making PF table queries world-readable.
ok, err = stat.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR)
assert(ok == 0, err)

ok, err = socket.listen(listener, 10)
assert(ok == 0, err)

local descriptors = {
	[listener] = { events = { IN = true } },
}
local channels = {}

local function table_named(name)
	for _, table in ipairs(handle:tables()) do
		if table.name == name then
			return table
		end
	end
end

local function reply(channel, kind, id, data)
	channel:compose(kind, id, 0, -1, data)
	channel:flush()
end

local function handle_message(channel, message)
	if message:type() ~= IMSG_PF_TABLE_TEST then
		return
	end

	local ok, table_name, address = pcall(string.unpack, "=ss", message:data())
	if not ok then
		reply(channel, IMSG_PF_TABLE_FAIL, message:id(), "bad request")
		return
	end

	local table = table_named(table_name)
	if not table then
		reply(channel, IMSG_PF_TABLE_FAIL, message:id(), "table not found")
		return
	end

	local tested, present = pcall(table.test, table, address)
	if not tested then
		reply(channel, IMSG_PF_TABLE_FAIL, message:id(), "bad address")
		return
	end

	reply(channel, IMSG_PF_TABLE_REPLY, message:id(),
	      string.pack("=B", present and 1 or 0))
end

while true do
	local ready, poll_error = poll.poll(descriptors, -1)
	assert(ready, poll_error)

	for fd, events in pairs(descriptors) do
		if fd == listener then
			if events.revents.IN then
				local client, accept_error = posix.accept(listener)
				if client then
					descriptors[client] = { events = { IN = true } }
					channels[client] = imsg.new(client)
				else
					io.stderr:write("accept: ", accept_error, "\n")
				end
			end
		else
			local channel = channels[fd]
			if not channel:read() then
				unistd.close(fd)
				descriptors[fd] = nil
				channels[fd] = nil
			else
				while true do
					local message = channel:get()
					if not message then
						break
					end
					handle_message(channel, message)
				end
			end
		end
	end
end
