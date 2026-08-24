-- Query the read-only PF table demo service.
-- Usage: lua pf_table_client.lua [table] [address]

local imsg = require("imsg")
local socket = require("posix.sys.socket")

local IMSG_PF_TABLE_TEST = 1
local IMSG_PF_TABLE_FAIL = 2
local IMSG_PF_TABLE_REPLY = 3

local socket_path = "/var/run/pfd.sock"
local table_name = arg[1] or "firewall"
local address = arg[2] or "127.0.0.1"

local fd, err = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
assert(fd, err)

local ok
ok, err = socket.connect(fd, {
	family = socket.AF_UNIX,
	path = socket_path,
})
assert(ok == 0, err)

local channel = imsg.new(fd)
channel:compose(IMSG_PF_TABLE_TEST, 1, 0, -1,
                string.pack("=ss", table_name, address))
channel:flush()
assert(channel:read())

local message = assert(channel:get())
local kind, data = message:type(), message:data()

if kind == IMSG_PF_TABLE_FAIL then
	io.stderr:write(data, "\n")
elseif kind == IMSG_PF_TABLE_REPLY then
	local present = string.unpack("=B", data) ~= 0
	print(string.format("table %s has %s? %s", table_name, address, present))
else
	error("unexpected reply")
end
