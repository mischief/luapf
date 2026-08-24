-- Print the number of active PF states involving each RFC 1918 IPv4 host.
-- This only performs read-only PF ioctls.

local pf = require("pf")

local h = pf.open()
local counts = {}

local function host(endpoint)
	-- PF state endpoints are IPv4 "address:port" or IPv6 "[address]:port".
	return endpoint:match("^%[([^]]+)%]:%d+$") or
	       endpoint:match("^([^:]+):%d+$")
end

local function is_private_ipv4(address)
	local a, b = address:match("^(%d+)%.(%d+)%.%d+%.%d+$")
	a, b = tonumber(a), tonumber(b)

	return a == 10 or
	       (a == 172 and b and b >= 16 and b <= 31) or
	       (a == 192 and b == 168)
end

local function count(endpoint)
	local address = host(endpoint)

	if address and is_private_ipv4(address) then
		counts[address] = (counts[address] or 0) + 1
	end
end

for _, state in ipairs(h:states()) do
	count(state.source)
	count(state.destination)
end

local sorted = {}
for address, count in pairs(counts) do
	sorted[#sorted + 1] = { address = address, count = count }
end

table.sort(sorted, function(a, b)
	return a.count > b.count
end)

for _, entry in ipairs(sorted) do
	print(entry.address, entry.count)
end
