--- Build a pf ruleset as Lua data, check it, and load it.
--
-- Each constructor checks its arguments when it is called. An error names
-- the Lua file and line of the call, and of the function call around it.
-- load writes it to the kernel the way pfctl -f does, with no program.
-- read and tolua turn a loaded ruleset back into Lua. See examples/dsl.lua.
-- @module pf.dsl

local M = {}

local SELF = debug.getinfo(1, "S").source

-- The call sites outside this module, innermost first. The walk stops at
-- a main chunk.
local function where()
	local sites = {}
	local level = 2
	while #sites < 3 do
		local info = debug.getinfo(level, "Sl")
		if not info then
			break
		end
		if info.source ~= SELF and info.currentline > 0 then
			sites[#sites + 1] = info.short_src .. ":" .. info.currentline
			if info.what == "main" then
				break
			end
		end
		level = level + 1
	end
	return sites
end

local function sitestr(sites)
	return sites and sites[1] or "?"
end

local function via(sites)
	if sites and sites[2] then
		return " (via " .. table.concat(sites, ", ", 2) .. ")"
	end
	return ""
end

local function fail(sites, fmt, ...)
	error(sitestr(sites) .. ": " .. string.format(fmt, ...) .. via(sites), 0)
end

local function isint(v, lo, hi)
	return math.type(v) == "integer" and v >= lo and v <= hi
end

-- A plain Lua array: no metatable, keys 1..n, at least one entry.
local function isarray(v)
	if type(v) ~= "table" or getmetatable(v) ~= nil then
		return false
	end
	local n = 0
	for _ in pairs(v) do
		n = n + 1
	end
	return n > 0 and n == #v
end

-- A string pf can take between double quotes.
local function quotable(v)
	return type(v) == "string" and v ~= "" and not v:find('["\n\\]')
end

local Value = {}
Value.__index = Value

local function value(kind, t)
	t.kind = kind
	return setmetatable(t, Value)
end

local function isvalue(v, kind)
	return getmetatable(v) == Value and (kind == nil or v.kind == kind)
end

--
-- Literal addresses
--

local function parse4(s)
	local bytes = {}
	for p in (s .. "."):gmatch("([^.]*)%.") do
		if not p:match("^%d%d?%d?$") or (#p > 1 and p:sub(1, 1) == "0") then
			return nil
		end
		local v = tonumber(p)
		if v > 255 then
			return nil
		end
		bytes[#bytes + 1] = v
	end
	if #bytes ~= 4 then
		return nil
	end
	return bytes
end

local function groups6(s)
	local g = {}
	if s == "" then
		return g
	end
	for p in (s .. ":"):gmatch("([^:]*):") do
		if not p:match("^%x%x?%x?%x?$") then
			return nil
		end
		g[#g + 1] = tonumber(p, 16)
	end
	return g
end

local function parse6(s)
	local all
	local head, tail = s:match("^(.-)::(.*)$")
	if head then
		if tail:find("::", 1, true) then
			return nil
		end
		local h, t = groups6(head), groups6(tail)
		if not h or not t or #h + #t > 7 then
			return nil
		end
		all = {}
		for _, v in ipairs(h) do
			all[#all + 1] = v
		end
		for _ = 1, 8 - #h - #t do
			all[#all + 1] = 0
		end
		for _, v in ipairs(t) do
			all[#all + 1] = v
		end
	else
		all = groups6(s)
		if not all or #all ~= 8 then
			return nil
		end
	end
	return all
end

-- RFC 5952 text: lower case, no leading zeros, the longest run of two or
-- more zero groups (the first on a tie) written as "::".
local function format6(g)
	local best, bestlen = nil, 1
	local i = 1
	while i <= 8 do
		if g[i] == 0 then
			local j = i
			while j <= 8 and g[j] == 0 do
				j = j + 1
			end
			if j - i > bestlen then
				best, bestlen = i, j - i
			end
			i = j
		else
			i = i + 1
		end
	end
	local function hex(from, to)
		local out = {}
		for k = from, to do
			out[#out + 1] = string.format("%x", g[k])
		end
		return table.concat(out, ":")
	end
	if best then
		return hex(1, best - 1) .. "::" .. hex(best + bestlen, 8)
	end
	return hex(1, 8)
end

-- Parse an address or prefix strictly: no host bits, no zone, no host
-- names, and only the normal text form.
local function parseaddr(s)
	if s:find("%", 1, true) then
		return nil, "a zone is not allowed: " .. s
	end
	local a, plen = s:match("^([^/]*)/(.*)$")
	if not a then
		a = s
	end
	local af, bits, bytes
	if a:find(":", 1, true) then
		local g = parse6(a)
		if not g then
			return nil, "not an address: " .. s
		end
		local canon = format6(g)
		if canon ~= a then
			return nil, string.format("write %s as %s", a, canon)
		end
		af, bits, bytes = "inet6", 128, {}
		for _, v in ipairs(g) do
			bytes[#bytes + 1] = v >> 8
			bytes[#bytes + 1] = v & 0xff
		end
	else
		bytes = parse4(a)
		if not bytes then
			return nil, "not an address: " .. s
		end
		af, bits = "inet", 32
	end
	local n = bits
	if plen then
		if not plen:match("^%d+$") or (#plen > 1 and plen:sub(1, 1) == "0") then
			return nil, "bad prefix length: " .. s
		end
		n = tonumber(plen)
		if n > bits then
			return nil, "bad prefix length: " .. s
		end
	end
	for i, b in ipairs(bytes) do
		local keep = n - (i - 1) * 8
		local mask = keep >= 8 and 0xff or keep <= 0 and 0 or
		    (0xff << (8 - keep)) & 0xff
		if b & mask ~= b then
			return nil, "host bits set: " .. s
		end
	end
	return { af = af, text = s }
end

--
-- Interfaces and dynamic addresses
--

local Iface = {}
Iface.__index = Iface

local function ifname(name, sites, what)
	if type(name) ~= "string" or #name > 15 or
	    not name:match("^[%a_][%w_%.%-]*$") then
		fail(sites, "%s: bad interface name: %s", what, tostring(name))
	end
	return name
end

--- An interface. Its addresses are dynamic: they follow the interface.
-- @string name interface name
-- @treturn Iface
function M.iface(name)
	return setmetatable({ name = ifname(name, where(), "iface") }, Iface)
end

--- An interface group, such as egress. Membership can change at run time.
-- @string name group name
-- @treturn Iface
function M.group(name)
	return setmetatable({ name = ifname(name, where(), "group"),
	    group = true }, Iface)
end

local function dyn(self, mod, what)
	if getmetatable(self) ~= Iface then
		fail(where(), "%s: call it as iface:%s()", what, what)
	end
	return value("dyn", { name = self.name, mod = mod, group = self.group })
end

--- An interface or group, from iface or group. Use it as on or
-- received_on, or take an address from it.
-- @type Iface

--- All addresses of the interface, as (name).
-- @return address
function Iface:addr() return dyn(self, "", "addr") end
--- The first address of the interface, as (name:0).
-- @return address
function Iface:addr0() return dyn(self, ":0", "addr0") end
--- The networks of the interface, as (name:network).
-- @return address
function Iface:network() return dyn(self, ":network", "network") end
--- The broadcast addresses of the interface, as (name:broadcast).
-- @return address
function Iface:broadcast() return dyn(self, ":broadcast", "broadcast") end
--- The peer address of a point-to-point interface, as (name:peer).
-- @return address
function Iface:peer() return dyn(self, ":peer", "peer") end

Iface.__tostring = function(self) return self.name end

--- @section end

--- Any address.
M.any = value("any", {})
--- Every address of this host, dynamic, as (self).
M.self = value("self", {})

--
-- Tables
--

local function tablename(name, sites)
	if type(name) ~= "string" or #name > 31 or
	    not name:match("^[%w_%-]+$") then
		fail(sites, "table: bad name: %s", tostring(name))
	end
	return name
end

local tableopts = { persist = true, const = true, counters = true,
    file = true, addrs = true }

--- A table. Rules that name it define it in the loaded ruleset.
-- @string name table name
-- @tab[opt] opts persist, const, counters (booleans), file (a path or a
-- list of paths), addrs (a list of literal addresses, or NOT of one)
-- @return table
function M.table(name, opts)
	local sites = where()
	local t = value("table", { name = tablename(name, sites),
	    sites = sites, files = {}, addrs = {} })
	opts = opts or {}
	for k, v in pairs(opts) do
		if not tableopts[k] then
			fail(sites, "table: unknown option '%s'", tostring(k))
		end
	end
	for _, k in ipairs({ "persist", "const", "counters" }) do
		if opts[k] ~= nil and type(opts[k]) ~= "boolean" then
			fail(sites, "table: %s must be true or false", k)
		end
		t[k] = opts[k] or false
	end
	local files = opts.file
	if type(files) == "string" then
		files = { files }
	end
	if files ~= nil then
		if not isarray(files) then
			fail(sites, "table: file must be a path or a list of paths")
		end
		for _, f in ipairs(files) do
			if not quotable(f) then
				fail(sites, "table: bad file name: %s", tostring(f))
			end
			t.files[#t.files + 1] = f
		end
	end
	if opts.addrs ~= nil then
		if not isarray(opts.addrs) then
			fail(sites, "table: addrs must be a list")
		end
		for _, a in ipairs(opts.addrs) do
			local s, neg = a, ""
			if isvalue(a, "not") and a.inner.kind == "addr" then
				s, neg = a.inner.text, "!"
			end
			if type(s) ~= "string" then
				fail(sites, "table: entries must be literal addresses")
			end
			local p, err = parseaddr(s)
			if not p then
				fail(sites, "table: %s", err)
			end
			t.addrs[#t.addrs + 1] = neg .. p.text
		end
	end
	return t
end

local function tabledef(t)
	local w = { "table <" .. t.name .. ">" }
	for _, k in ipairs({ "persist", "const", "counters" }) do
		if t[k] then
			w[#w + 1] = k
		end
	end
	for _, f in ipairs(t.files) do
		w[#w + 1] = 'file "' .. f .. '"'
	end
	if #t.addrs > 0 then
		w[#w + 1] = "{ " .. table.concat(t.addrs, ", ") .. " }"
	end
	return table.concat(w, " ")
end

--
-- Limiters
--

local function limiterrate(v, sites, what)
	if not (isarray(v) and #v == 2 and isint(v[1], 1, 0xffffffff) and
	    isint(v[2], 1, 0xffffffff)) then
		fail(sites, "%s: rate must be { states, seconds }", what)
	end
	return " rate " .. v[1] .. "/" .. v[2]
end

local function limiter(kind, name, opts, known, sites)
	local what = kind .. "limiter"
	if not quotable(name) or #name > 15 then
		fail(sites, "%s: bad name: %s", what, tostring(name))
	end
	if type(opts) ~= "table" or getmetatable(opts) ~= nil then
		fail(sites, "%s: takes a table of options", what)
	end
	for k in pairs(opts) do
		if not known[k] then
			fail(sites, "%s: unknown option '%s'", what, tostring(k))
		end
	end
	if not isint(opts.id, 1, 255) then
		fail(sites, "%s: id must be 1 to 255", what)
	end
	if not isint(opts.limit, 1, 1 << 24) then
		fail(sites, "%s: limit must be 1 to %d", what, 1 << 24)
	end
	local copy = {}
	for k, v in pairs(opts) do
		copy[k] = v
	end
	return value("limiter", { which = kind, name = name, id = opts.id,
	    opts = copy, sites = sites })
end

--- A state limiter: it caps the states the rules that name it create.
-- @string name limiter name
-- @tab opts id (1 to 255), limit, rate ({ states, seconds })
-- @return limiter
function M.statelimiter(name, opts)
	local sites = where()
	local l = limiter("state", name, opts,
	    { id = true, limit = true, rate = true }, sites)
	l.text = 'state limiter "' .. name .. '" id ' .. opts.id ..
	    " limit " .. opts.limit
	if opts.rate ~= nil then
		l.text = l.text .. limiterrate(opts.rate, sites, "statelimiter")
	end
	return l
end

--- A source limiter: it caps the states each source address creates.
-- @string name limiter name
-- @tab opts id (1 to 255), entries, limit, rate ({ states, seconds }),
-- `inet_mask`, `inet6_mask`, overload (a table), above, below
-- @return limiter
function M.sourcelimiter(name, opts)
	local sites = where()
	local l = limiter("source", name, opts, { id = true, entries = true,
	    limit = true, rate = true, inet_mask = true, inet6_mask = true,
	    overload = true, above = true, below = true }, sites)
	if not isint(opts.entries, 1, 0xffffffff) then
		fail(sites, "sourcelimiter: entries must be a count")
	end
	local w = { 'source limiter "' .. name .. '" id ' .. opts.id ..
	    " entries " .. opts.entries .. " limit " .. opts.limit }
	if opts.rate ~= nil then
		w[1] = w[1] .. limiterrate(opts.rate, sites, "sourcelimiter")
	end
	if opts.overload ~= nil then
		if not isvalue(opts.overload, "table") then
			fail(sites, "sourcelimiter: overload must be a table")
		end
		if not isint(opts.above, 1, 0xffffffff) or
		    not isint(opts.below, 0, opts.above - 1) then
			fail(sites, "sourcelimiter: overload needs above and a " ..
			    "lower below")
		end
		w[#w + 1] = "table <" .. opts.overload.name .. "> above " ..
		    opts.above .. " below " .. opts.below
		l.overload = opts.overload
	elseif opts.above ~= nil or opts.below ~= nil then
		fail(sites, "sourcelimiter: above and below need overload")
	end
	for _, m in ipairs({ { "inet_mask", 32 }, { "inet6_mask", 128 } }) do
		local k, max = m[1], m[2]
		if opts[k] ~= nil then
			if not isint(opts[k], 1, max) then
				fail(sites, "sourcelimiter: %s must be 1 to %d", k, max)
			end
			if opts[k] ~= max then
				w[#w + 1] = k:gsub("_mask", " mask") .. " " .. opts[k]
			end
		end
	end
	l.text = table.concat(w, " ")
	return l
end

--
-- Addresses in rules
--

local address

--- The negation of an address or an interface.
-- @param x an address, or an Iface for on and received_on
-- @return negated address or interface
function M.NOT(x)
	local sites = where()
	if getmetatable(x) == Iface then
		return value("not", { inner = x })
	end
	local inner = address(x, sites, "NOT")
	if inner.kind == "list" then
		fail(sites, "NOT: pf cannot negate a list; negate each entry")
	elseif inner.kind == "not" then
		fail(sites, "NOT: double negation")
	elseif inner.kind == "any" then
		fail(sites, "NOT: 'not any' matches nothing")
	end
	return value("not", { inner = inner })
end

-- Check an address and return it as a Value. A string is a literal
-- address, and a plain array is a list.
function address(v, sites, what)
	if type(v) == "string" then
		local p, err = parseaddr(v)
		if not p then
			fail(sites, "%s: %s", what, err)
		end
		return value("addr", p)
	end
	if getmetatable(v) == Iface then
		fail(sites, "%s: %s is an interface, not an address; " ..
		    "use %s:addr(), :addr0() or :network()", what, v.name, v.name)
	end
	if isvalue(v) then
		local k = v.kind
		if k == "addr" or k == "dyn" or k == "table" or k == "any" or
		    k == "self" or k == "list" then
			return v
		end
		if k == "not" and getmetatable(v.inner) ~= Iface then
			return v
		end
	end
	if isarray(v) then
		local items = {}
		for i, x in ipairs(v) do
			local a = address(x, sites, what)
			if a.kind == "list" or a.kind == "any" then
				fail(sites, "%s: a list cannot hold %s", what, a.kind)
			end
			items[i] = a
		end
		return value("list", { items = items })
	end
	fail(sites, "%s: not an address: %s", what, tostring(v))
end

local function raddr(v)
	local k = v.kind
	if k == "addr" then
		return v.text
	elseif k == "dyn" then
		return "(" .. v.name .. v.mod .. ")"
	elseif k == "table" then
		return "<" .. v.name .. ">"
	elseif k == "any" then
		return k
	elseif k == "self" then
		-- Dynamic, unlike a bare self, which pfctl expands at load time.
		return "(self)"
	elseif k == "not" then
		return "! " .. raddr(v.inner)
	elseif k == "list" then
		local out = {}
		for i, x in ipairs(v.items) do
			out[i] = raddr(x)
		end
		return "{ " .. table.concat(out, ", ") .. " }"
	end
	error("raddr: " .. tostring(k))
end

-- Call fn on every table and every literal an address names.
local function walkaddr(v, fn)
	if v.kind == "not" then
		walkaddr(v.inner, fn)
	elseif v.kind == "list" then
		for _, x in ipairs(v.items) do
			walkaddr(x, fn)
		end
	else
		fn(v)
	end
end

--
-- Ports
--

local portops = { ["="] = true, ["!="] = true, ["<"] = true, ["<="] = true,
    [">"] = true, [">="] = true, ["<>"] = true, ["><"] = true }

local function portnum(v)
	return isint(v, 0, 65535) or
	    (type(v) == "string" and v:match("^%a[%w%-]*$") ~= nil)
end

--- A port range, lo:hi inclusive.
-- @int lo first port
-- @int hi last port
-- @return port
function M.range(lo, hi)
	local sites = where()
	if not isint(lo, 0, 65535) or not isint(hi, 0, 65535) or lo > hi then
		fail(sites, "range: need two ports, low first")
	end
	return value("port", { text = lo .. ":" .. hi, op = ":", a = lo, b = hi })
end

--- A port with an operator.
-- @string op =, !=, <, <=, >, >=, >< or <>
-- @int a port
-- @int[opt] b second port, for >< and <>
-- @return port
-- @usage dsl.port("<", 1024)
function M.port(op, a, b)
	local sites = where()
	if not portops[op] then
		fail(sites, "port: unknown operator %s", tostring(op))
	end
	local two = op == "<>" or op == "><"
	if not isint(a, 0, 65535) or (two and not isint(b, 0, 65535)) or
	    (not two and b ~= nil) then
		fail(sites, "port: bad port for %s", op)
	end
	if two then
		return value("port", { text = a .. " " .. op .. " " .. b, op = op,
		    a = a, b = b })
	end
	return value("port", { text = op .. " " .. a, op = op, a = a })
end

local function port(v, sites, what)
	if portnum(v) then
		return tostring(v)
	elseif isvalue(v, "port") then
		return v.text
	elseif isarray(v) then
		local out = {}
		for i, x in ipairs(v) do
			if isarray(x) then
				fail(sites, "%s: a list cannot hold a list", what)
			end
			out[i] = port(x, sites, what)
		end
		return "{ " .. table.concat(out, ", ") .. " }"
	end
	fail(sites, "%s: not a port: %s", what, tostring(v))
end

--
-- Address pools
--

local poolmethods = { ["round-robin"] = true, random = true,
    ["source-hash"] = true, bitmask = true, ["least-states"] = true }

--- A translation target with options, for `nat_to`, `rdr_to` and
-- `binat_to`.
-- @param addr address
-- @tab[opt] opts port (a port or a range), method (round-robin, random,
-- source-hash, bitmask, least-states), sticky (boolean)
-- @return pool
function M.pool(addr, opts)
	local sites = where()
	local p = value("pool", { addr = address(addr, sites, "pool"),
	    opts = {} })
	opts = opts or {}
	for k, v in pairs(opts) do
		p.opts[k] = v
	end
	for k, v in pairs(opts) do
		if k == "port" then
			if not (portnum(v) or isvalue(v, "port")) then
				fail(sites, "pool: not a port: %s", tostring(v))
			end
			p.port = portnum(v) and tostring(v) or v.text
		elseif k == "method" then
			if not poolmethods[v] then
				fail(sites, "pool: unknown method %s", tostring(v))
			end
			p.method = v
		elseif k == "sticky" then
			if type(v) ~= "boolean" then
				fail(sites, "pool: sticky must be true or false")
			end
			p.sticky = v
		else
			fail(sites, "pool: unknown option '%s'", tostring(k))
		end
	end
	if p.sticky and p.method == "bitmask" then
		fail(sites, "pool: bitmask cannot be sticky")
	end
	return p
end

local function pool(v, sites, what)
	if not isvalue(v, "pool") then
		v = value("pool", { addr = address(v, sites, what), opts = {} })
	end
	if v.addr.kind == "any" or v.addr.kind == "not" or
	    v.addr.kind == "self" then
		fail(sites, "%s: cannot translate to %s", what, raddr(v.addr))
	end
	return v
end

local function rpool(p)
	local w = { raddr(p.addr) }
	if p.port then
		w[#w + 1] = "port " .. p.port
	end
	local method = p.method
	if not method and (p.addr.kind == "table" or p.addr.kind == "list") then
		method = "round-robin"
	end
	if method then
		w[#w + 1] = method
	end
	if p.sticky then
		w[#w + 1] = "sticky-address"
	end
	return table.concat(w, " ")
end

--
-- State options
--

local function stateopts(v, sites, what, kinds)
	local out = {}
	local function want(ok, fmt, ...)
		if not ok then
			fail(sites, what .. ": " .. fmt, ...)
		end
	end
	for k in pairs(v) do
		want(type(k) == "string", "options are named, not positional")
	end
	local kind = v.kind or "keep"
	want(not kinds or kind == "keep" or kind == "modulate" or
	    kind == "synproxy", "kind must be keep, modulate or synproxy")
	want(kinds or v.kind == nil, "kind is not allowed here")
	local counts = { "max", "max_src_states", "max_src_nodes",
	    "max_src_conn" }
	for _, k in ipairs(counts) do
		if v[k] ~= nil then
			want(isint(v[k], 1, 0xffffffff), "%s must be a count", k)
			out[#out + 1] = k:gsub("_", "-") .. " " .. v[k]
		end
	end
	if v.max_src_conn_rate ~= nil then
		local r = v.max_src_conn_rate
		want(isarray(r) and #r == 2 and isint(r[1], 1, 0xffffffff) and
		    isint(r[2], 1, 0xffffffff),
		    "max_src_conn_rate must be { connections, seconds }")
		out[#out + 1] = "max-src-conn-rate " .. r[1] .. "/" .. r[2]
	end
	if v.overload ~= nil then
		want(isvalue(v.overload, "table"), "overload must be a table")
		local s = "overload <" .. v.overload.name .. ">"
		if v.flush == "global" then
			s = s .. " flush global"
		elseif v.flush == true then
			s = s .. " flush"
		else
			want(v.flush == nil, "flush must be true or \"global\"")
		end
		out[#out + 1] = s
	else
		want(v.flush == nil, "flush needs overload")
	end
	if v.source_track ~= nil then
		local st = v.source_track
		want(st == true or st == "rule" or st == "global",
		    "source_track must be true, \"rule\" or \"global\"")
		out[#out + 1] = st == true and "source-track" or
		    "source-track " .. st
	end
	want(not (v.if_bound and v.floating), "if_bound or floating, not both")
	for _, k in ipairs({ "if_bound", "floating", "sloppy", "no_sync",
	    "pflow" }) do
		if v[k] ~= nil then
			want(type(v[k]) == "boolean", "%s must be true or false", k)
			if v[k] then
				out[#out + 1] = k:gsub("_", "-")
			end
		end
	end
	local known = { kind = true, max_src_conn_rate = true, overload = true,
	    flush = true, source_track = true, if_bound = true,
	    floating = true, sloppy = true, no_sync = true, pflow = true }
	for _, k in ipairs(counts) do
		known[k] = true
	end
	for k in pairs(v) do
		want(known[k], "unknown state option '%s'", k)
	end
	return kind, out
end

--
-- Rules
--

local function oneof(v, ...)
	for _, x in ipairs({ ... }) do
		if v == x then
			return true
		end
	end
	return false
end

local function protos(v, sites)
	local list = isarray(v) and v or { v }
	local names = {}
	for i, p in ipairs(list) do
		if not (isint(p, 0, 255) or
		    (type(p) == "string" and p:match("^%a[%w%-]*$"))) then
			fail(sites, "proto: not a protocol: %s", tostring(p))
		end
		names[i] = tostring(p)
	end
	return names
end

local function rif(v, sites, what)
	if getmetatable(v) == Iface then
		return v.name
	elseif isvalue(v, "not") and getmetatable(v.inner) == Iface then
		return "! " .. v.inner.name
	elseif isarray(v) then
		local out = {}
		for i, x in ipairs(v) do
			if getmetatable(x) ~= Iface then
				fail(sites, "%s: a list holds interfaces only", what)
			end
			out[i] = x.name
		end
		return "{ " .. table.concat(out, ", ") .. " }"
	end
	fail(sites, "%s: not an interface: %s; use dsl.iface()", what,
	    tostring(v))
end

-- Options each rule takes, with the actions that allow them.
local ALL = { pass = true, block = true, match = true, anchor = true }
local FILTER = { pass = true, block = true, match = true }
local TRANSLATE = { pass = true, match = true }
local ruleopts = {
	dir = ALL, quick = ALL, on = ALL, af = ALL, proto = ALL, from = ALL,
	to = ALL, port = ALL, from_port = ALL, log = FILTER, policy =
	{ block = true }, flags = FILTER, icmp_type = FILTER,
	icmp6_type = FILTER, state = { pass = true }, label = FILTER,
	state_limiter = { pass = true }, source_limiter = { pass = true },
	tag = TRANSLATE, tagged = ALL, received_on = ALL, prio = TRANSLATE,
	user = FILTER,
	queue = TRANSLATE, rtable = TRANSLATE, once = FILTER,
	allow_opts = { pass = true }, nat_to = TRANSLATE,
	rdr_to = TRANSLATE, binat_to = TRANSLATE,
}

local function bool(r, opts, k, sites)
	if opts[k] ~= nil and type(opts[k]) ~= "boolean" then
		fail(sites, "%s: %s must be true or false", r.action, k)
	end
	return opts[k]
end

local function word(v)
	return type(v) == "string" and v:match("^[%w_%.%-]+$") ~= nil
end

-- Check rule options and return the rule as pf.conf words.
local function rule(action, opts, sites)
	local r = { action = action, sites = sites, tables = {}, af = {},
	    limiters = {}, opts = opts }
	if type(opts) ~= "table" or getmetatable(opts) ~= nil then
		fail(sites, "%s: takes a table of options", action)
	end
	for k in pairs(opts) do
		if type(k) ~= "string" then
			fail(sites, "%s: options are named, not positional", action)
		end
		if not ruleopts[k] then
			fail(sites, "%s: unknown option '%s'", action, k)
		end
		if not ruleopts[k][action] then
			fail(sites, "%s: option '%s' is not allowed here", action, k)
		end
	end

	local function seen(v)
		if v.kind == "table" then
			r.tables[#r.tables + 1] = v
		elseif v.kind == "addr" then
			r.af[v.af] = true
		end
	end

	local w = {}
	if action == "block" and opts.policy ~= nil then
		if not oneof(opts.policy, "drop", "return", "return-rst",
		    "return-icmp") then
			fail(sites, "block: unknown policy %s", tostring(opts.policy))
		end
		w[#w + 1] = "block " .. opts.policy
	else
		w[#w + 1] = action
	end
	if opts.dir ~= nil then
		if not oneof(opts.dir, "in", "out") then
			fail(sites, "%s: dir must be \"in\" or \"out\"", action)
		end
		w[#w + 1] = opts.dir
	end
	if opts.log ~= nil then
		local l = opts.log
		if l == true then
			w[#w + 1] = "log"
		elseif type(l) == "table" and getmetatable(l) == nil then
			local lw = {}
			for k, v in pairs(l) do
				if oneof(k, "all", "matches", "user") and v == true then
					lw[#lw + 1] = k
				elseif k == "to" and getmetatable(v) == Iface then
					lw[#lw + 1] = "to " .. v.name
				else
					fail(sites, "%s: bad log option '%s'", action,
					    tostring(k))
				end
			end
			table.sort(lw)
			w[#w + 1] = "log (" .. table.concat(lw, ", ") .. ")"
		elseif l ~= false then
			fail(sites, "%s: log must be true or a table", action)
		end
	end
	if bool(r, opts, "quick", sites) then
		w[#w + 1] = "quick"
	end
	if opts.on ~= nil then
		w[#w + 1] = "on " .. rif(opts.on, sites, action .. ": on")
	end
	if opts.af ~= nil then
		if not oneof(opts.af, "inet", "inet6") then
			fail(sites, "%s: af must be \"inet\" or \"inet6\"", action)
		end
		w[#w + 1] = opts.af
	end
	local names
	if opts.proto ~= nil then
		names = protos(opts.proto, sites)
		w[#w + 1] = "proto " .. (#names == 1 and names[1] or
		    "{ " .. table.concat(names, ", ") .. " }")
	end
	if opts.port ~= nil or opts.from_port ~= nil then
		local ok = names ~= nil
		for _, p in ipairs(names or {}) do
			ok = ok and oneof(p, "tcp", "udp", "6", "17")
		end
		if not ok then
			fail(sites, "%s: a port needs proto tcp or udp", action)
		end
	end
	if opts.from ~= nil or opts.from_port ~= nil then
		local a = address(opts.from or M.any, sites, action .. ": from")
		walkaddr(a, seen)
		w[#w + 1] = "from " .. raddr(a)
		if opts.from_port ~= nil then
			w[#w + 1] = "port " .. port(opts.from_port, sites,
			    action .. ": from_port")
		end
	end
	if opts.to ~= nil or opts.port ~= nil then
		local a = address(opts.to or M.any, sites, action .. ": to")
		walkaddr(a, seen)
		if opts.from == nil and opts.from_port == nil then
			w[#w + 1] = "from any"
		end
		w[#w + 1] = "to " .. raddr(a)
		if opts.port ~= nil then
			w[#w + 1] = "port " .. port(opts.port, sites, action .. ": port")
		end
	end
	if opts.user ~= nil then
		-- pf matches the owner of a socket, so only tcp and udp.
		local u = opts.user
		if not names or #names == 0 then
			fail(sites, "%s: user needs proto tcp or udp", action)
		end
		for _, n in ipairs(names) do
			if n ~= "tcp" and n ~= "udp" then
				fail(sites, "%s: user needs proto tcp or udp", action)
			end
		end
		if not (isint(u, 0, 0xfffffffe) or
		    (type(u) == "string" and u:match("^[%a_][%w_.%-]*$"))) then
			fail(sites, "%s: bad user %s", action, tostring(u))
		end
		w[#w + 1] = "user " .. u
	end
	if opts.flags ~= nil then
		if opts.flags ~= "any" and
		    not tostring(opts.flags):match("^[FSRPAUEW]*/[FSRPAUEW]+$") then
			fail(sites, "%s: bad flags %s", action, tostring(opts.flags))
		end
		w[#w + 1] = "flags " .. opts.flags
	end
	for _, k in ipairs({ "icmp_type", "icmp6_type" }) do
		if opts[k] ~= nil then
			local p = k == "icmp_type" and "icmp" or "ipv6-icmp"
			if not names or #names ~= 1 or
			    (names[1] ~= p and not (k == "icmp6_type" and
			    names[1] == "icmp6")) then
				fail(sites, "%s: %s needs proto %s", action, k, p)
			end
			if not (word(opts[k]) or isint(opts[k], 0, 255)) then
				fail(sites, "%s: bad %s", action, k)
			end
			w[#w + 1] = k:gsub("_", "-") .. " " .. opts[k]
		end
	end
	if bool(r, opts, "allow_opts", sites) then
		w[#w + 1] = "allow-opts"
	end
	if bool(r, opts, "once", sites) then
		w[#w + 1] = "once"
	end
	if opts.state == false then
		w[#w + 1] = "no state"
	elseif opts.state ~= nil then
		if type(opts.state) ~= "table" or getmetatable(opts.state) then
			fail(sites, "%s: state must be false or a table", action)
		end
		local kind, so = stateopts(opts.state, sites, action .. ": state",
		    true)
		local s = kind .. " state"
		if #so > 0 then
			s = s .. " (" .. table.concat(so, ", ") .. ")"
		end
		w[#w + 1] = s
		if opts.state.overload then
			seen(opts.state.overload)
		end
	end
	-- By id: pfctl only knows limiter names in the main ruleset.
	for _, k in ipairs({ "state_limiter", "source_limiter" }) do
		local v = opts[k]
		if v ~= nil then
			local kind = k:match("^(%a+)_")
			local l, act = v, nil
			if type(v) == "table" and getmetatable(v) == nil then
				l, act = v[1], v.action
				for x in pairs(v) do
					if x ~= 1 and x ~= "action" then
						fail(sites, "%s: %s: unknown option '%s'", action, k,
						    tostring(x))
					end
				end
				if not oneof(act, "block", "no-match") then
					fail(sites, "%s: %s: action must be block or no-match",
					    action, k)
				end
			end
			if not isvalue(l, "limiter") or l.which ~= kind then
				fail(sites, "%s: %s must be a %slimiter", action, k, kind)
			end
			r.limiters[#r.limiters + 1] = l
			w[#w + 1] = kind .. " limiter id " .. l.id ..
			    (act and " (" .. act .. ")" or "")
		end
	end
	for _, k in ipairs({ "label", "tag", "tagged" }) do
		if opts[k] ~= nil then
			if not quotable(opts[k]) then
				fail(sites, "%s: bad %s", action, k)
			end
			w[#w + 1] = k .. ' "' .. opts[k] .. '"'
		end
	end
	if opts.received_on ~= nil then
		w[#w + 1] = "received-on " .. rif(opts.received_on, sites,
		    action .. ": received_on")
	end
	if opts.rtable ~= nil then
		if not isint(opts.rtable, 0, 255) then
			fail(sites, "%s: rtable must be 0 to 255", action)
		end
		w[#w + 1] = "rtable " .. opts.rtable
	end
	if opts.prio ~= nil then
		local p = opts.prio
		if isint(p, 0, 7) then
			w[#w + 1] = "set prio " .. p
		elseif isarray(p) and #p == 2 and isint(p[1], 0, 7) and
		    isint(p[2], 0, 7) then
			w[#w + 1] = "set prio (" .. p[1] .. ", " .. p[2] .. ")"
		else
			fail(sites, "%s: prio must be 0 to 7, or two of them", action)
		end
	end
	if opts.queue ~= nil then
		local q = opts.queue
		if word(q) then
			w[#w + 1] = "set queue " .. q
		elseif isarray(q) and #q == 2 and word(q[1]) and word(q[2]) then
			w[#w + 1] = "set queue (" .. q[1] .. ", " .. q[2] .. ")"
		else
			fail(sites, "%s: queue must be a name, or two names", action)
		end
	end
	local xdir = { nat_to = "out", rdr_to = "in" }
	for _, k in ipairs({ "nat_to", "rdr_to", "binat_to" }) do
		if opts[k] ~= nil then
			if k == "binat_to" and opts.dir ~= nil then
				fail(sites, "%s: binat_to takes no dir; it makes both", action)
			elseif xdir[k] and opts.dir ~= xdir[k] then
				fail(sites, "%s: %s needs dir = \"%s\"", action, k, xdir[k])
			end
			local p = pool(opts[k], sites, action .. ": " .. k)
			walkaddr(p.addr, seen)
			w[#w + 1] = k:gsub("_", "-") .. " " .. rpool(p)
		end
	end
	if opts.af ~= nil then
		for af in pairs(r.af) do
			if af ~= opts.af then
				fail(sites, "%s: an %s address in an af = \"%s\" rule",
				    action, af, opts.af)
			end
		end
	end
	r.text = table.concat(w, " ")
	return r
end

--
-- Rulesets
--

local Ruleset = {}
Ruleset.__index = Ruleset

--- A new empty ruleset.
-- @treturn Ruleset
function M.ruleset()
	return setmetatable({ items = {}, options = {}, declared = {},
	    limiters = {},
	    sites = where() }, Ruleset)
end

--- A list of rules with the tables, limiters and options they need.
-- @type Ruleset

--- Append a pass rule. Every option is checked now.
--
-- Filter: `dir quick log on af proto from to port from_port flags
-- icmp_type icmp6_type user label tagged received_on once`. log is true
-- or { all, matches, user, to }. Pass only: `allow_opts state_limiter
-- source_limiter state`, where state is false or a table of `kind max
-- max_src_states max_src_nodes max_src_conn max_src_conn_rate overload
-- flush source_track if_bound floating sloppy no_sync pflow`. Pass and
-- match: `tag prio queue rtable nat_to rdr_to binat_to`.
-- @tab opts rule options
-- @treturn Ruleset self
function Ruleset:pass(opts)
	self.items[#self.items + 1] = rule("pass", opts, where())
	return self
end

--- Append a block rule. It takes the filter options of pass, and policy:
-- drop, return, return-rst or return-icmp.
-- @tab opts rule options
-- @treturn Ruleset self
function Ruleset:block(opts)
	self.items[#self.items + 1] = rule("block", opts, where())
	return self
end

--- Append a match rule. It takes the options pass and match share.
-- @tab opts rule options
-- @treturn Ruleset self
function Ruleset:match(opts)
	self.items[#self.items + 1] = rule("match", opts, where())
	return self
end

local function anchorname(name, sites)
	if type(name) ~= "string" or #name > 1023 or name == "" then
		fail(sites, "anchor: bad name: %s", tostring(name))
	end
	local parts = {}
	for p in (name .. "/"):gmatch("([^/]*)/") do
		parts[#parts + 1] = p
	end
	for i, p in ipairs(parts) do
		if not (p:match("^[%w_%-%.]+$") or (p == "*" and i == #parts and
		    i > 1)) or p == "." or p == ".." then
			fail(sites, "anchor: bad name: %s", name)
		end
	end
	return name
end

--- Call an anchor.
-- @string name anchor name; a last component of * calls every child
-- @tab[opt] opts `dir quick on af proto from to port from_port tagged
-- received_on`, and rules: a Ruleset to load inline
-- @treturn Ruleset self
function Ruleset:anchor(name, opts)
	local sites = where()
	anchorname(name, sites)
	opts = opts or {}
	local inline = opts.rules
	local copy = {}
	for k, v in pairs(opts) do
		if k ~= "rules" then
			copy[k] = v
		end
	end
	if inline ~= nil then
		if getmetatable(inline) ~= Ruleset then
			fail(sites, "anchor: rules must be a ruleset")
		end
		if next(inline.options) then
			fail(sites, "anchor: an inline ruleset cannot set options")
		end
		if name:find("*", 1, true) then
			fail(sites, "anchor: a wildcard anchor cannot hold rules")
		end
	end
	local r = rule("anchor", copy, sites)
	r.text = r.text:gsub("^anchor", 'anchor "' .. name .. '"')
	r.name = name
	r.inline = inline
	self.items[#self.items + 1] = r
	return self
end

--- Declare a table the rules do not name, such as one only pfctl -T fills.
-- @param t a table from dsl.table
-- @treturn Ruleset self
function Ruleset:table(t)
	if not isvalue(t, "table") then
		fail(where(), "table: not a table")
	end
	self.declared[#self.declared + 1] = t
	return self
end

--- Declare a limiter the rules do not name, such as one only anchors use.
-- @param l a limiter from dsl.statelimiter or dsl.sourcelimiter
-- @treturn Ruleset self
function Ruleset:limiter(l)
	if not isvalue(l, "limiter") then
		fail(where(), "limiter: not a limiter")
	end
	self.limiters[#self.limiters + 1] = l
	return self
end

local setnames = { skip = true, block_policy = true, optimization = true,
    loginterface = true, state_policy = true, limit = true, timeout = true,
    reassemble = true, state_defaults = true }
local limits = { states = true, frags = true, src_nodes = true,
    tables = true, table_entries = true }
local timeouts = {}
for _, k in ipairs({ "tcp.first", "tcp.opening", "tcp.established",
    "tcp.closing", "tcp.finwait", "tcp.closed", "udp.first", "udp.single",
    "udp.multiple", "icmp.first", "icmp.error", "other.first",
    "other.single", "other.multiple", "frag", "interval", "src.track",
    "adaptive.start", "adaptive.end", "tcp.tsdiff" }) do
	timeouts[k] = true
end

local function setline(k, v, sites)
	local function want(ok, fmt, ...)
		if not ok then
			fail(sites, "set: " .. fmt, ...)
		end
	end
	if k == "skip" then
		local list = isarray(v) and v or { v }
		local out = {}
		for i, x in ipairs(list) do
			if getmetatable(x) == Iface then
				x = x.name
			end
			out[i] = ifname(x, sites, "set: skip")
		end
		return "set skip on " .. (#out == 1 and out[1] or
		    "{ " .. table.concat(out, ", ") .. " }")
	elseif k == "block_policy" then
		want(oneof(v, "drop", "return"), "block_policy must be drop or return")
		return "set block-policy " .. v
	elseif k == "optimization" then
		want(oneof(v, "normal", "high-latency", "satellite", "aggressive",
		    "conservative"), "unknown optimization %s", tostring(v))
		return "set optimization " .. v
	elseif k == "loginterface" then
		if getmetatable(v) == Iface then
			v = v.name
		end
		return "set loginterface " .. ifname(v, sites, "set: loginterface")
	elseif k == "state_policy" then
		want(oneof(v, "if-bound", "floating"),
		    "state_policy must be if-bound or floating")
		return "set state-policy " .. v
	elseif k == "reassemble" then
		want(type(v) == "boolean", "reassemble must be true or false")
		return "set reassemble " .. (v and "yes" or "no")
	elseif k == "limit" or k == "timeout" then
		want(type(v) == "table" and next(v) ~= nil, "%s takes a table", k)
		local out = {}
		for name, n in pairs(v) do
			local pfname = tostring(name):gsub("_", k == "limit" and "-" or ".")
			want(k == "limit" and limits[name] or timeouts[pfname],
			    "unknown %s %s", k, tostring(name))
			want(isint(n, 0, 0xffffffff), "%s %s must be a count", k, name)
			out[#out + 1] = pfname .. " " .. n
		end
		table.sort(out)
		return "set " .. k .. " { " .. table.concat(out, ", ") .. " }"
	elseif k == "state_defaults" then
		want(type(v) == "table" and getmetatable(v) == nil,
		    "state_defaults takes a table")
		local _, out = stateopts(v, sites, "set: state_defaults", false)
		want(#out > 0, "state_defaults is empty")
		return "set state-defaults " .. table.concat(out, ", ")
	end
end

--- Set ruleset options. Each option can be set once.
-- @tab opts `skip block_policy optimization loginterface state_policy
-- reassemble limit timeout state_defaults`
-- @treturn Ruleset self
function Ruleset:set(opts)
	local sites = where()
	if type(opts) ~= "table" then
		fail(sites, "set: takes a table of options")
	end
	for k, v in pairs(opts) do
		if not setnames[k] then
			fail(sites, "set: unknown option '%s'", tostring(k))
		end
		if self.options[k] then
			fail(sites, "set: %s is already set at %s", k,
			    sitestr(self.options[k].sites))
		end
		self.options[k] = { line = setline(k, v, sites), sites = sites,
		    value = v }
	end
	return self
end

-- Every limiter the ruleset and its inline anchors name, in id order.
local function limiters(rs, out, byid)
	local function add(l, sites)
		local have = byid[l.id]
		if have and have ~= l and have.text ~= l.text then
			fail(sites, "limiter id %d is defined twice, differently " ..
			    "(the other at %s)", l.id, sitestr(have.sites))
		end
		if not have then
			for _, o in ipairs(out) do
				if o.name == l.name and o.which == l.which then
					fail(sites, "%s limiter \"%s\" has two ids " ..
					    "(the other at %s)", l.which, l.name, sitestr(o.sites))
				end
			end
			byid[l.id] = l
			out[#out + 1] = l
		end
	end
	for _, l in ipairs(rs.limiters) do
		add(l, l.sites)
	end
	for _, r in ipairs(rs.items) do
		for _, l in ipairs(r.limiters) do
			add(l, r.sites)
		end
		if r.inline then
			limiters(r.inline, out, byid)
		end
	end
	table.sort(out, function(a, b)
		if a.which ~= b.which then
			return a.which == "state"
		end
		return a.id < b.id
	end)
end

-- Every table the ruleset and its inline anchors name, first use first.
local function collect(rs, out, byname, lims)
	local function add(t, sites)
		local have = byname[t.name]
		if have and have ~= t and tabledef(have) ~= tabledef(t) then
			fail(sites, "table <%s> is defined twice, differently " ..
			    "(the other at %s)", t.name, sitestr(have.sites))
		end
		if not have then
			byname[t.name] = t
			out[#out + 1] = t
		end
	end
	for _, t in ipairs(rs.declared) do
		add(t, t.sites)
	end
	for _, l in ipairs(lims or {}) do
		if l.overload then
			add(l.overload, l.sites)
		end
	end
	for _, r in ipairs(rs.items) do
		for _, t in ipairs(r.tables) do
			add(t, r.sites)
		end
		if r.inline then
			collect(r.inline, out, byname)
		end
	end
end

local function emit(rs, lines, map, indent)
	for _, r in ipairs(rs.items) do
		if r.inline then
			lines[#lines + 1] = indent .. r.text .. " {"
			map[#lines] = r.sites
			emit(r.inline, lines, map, indent .. "\t")
			lines[#lines + 1] = indent .. "}"
			map[#lines] = r.sites
		else
			lines[#lines + 1] = indent .. r.text
			map[#lines] = r.sites
		end
	end
end

--- The ruleset as pf.conf lines, and the Lua call site of each line.
-- @bool[opt] anchor leave out what only the main ruleset can hold
-- @treturn {string,...} lines
-- @treturn table call sites by line number
function Ruleset:lines(anchor)
	local lines, map = {}, {}
	local keys = {}
	for k in pairs(self.options) do
		keys[#keys + 1] = k
	end
	table.sort(keys)
	for _, k in ipairs(keys) do
		lines[#lines + 1] = self.options[k].line
		map[#lines] = self.options[k].sites
	end
	local lims = {}
	if not anchor then
		limiters(self, lims, {})
	end
	local tables = {}
	collect(self, tables, {}, lims)
	for _, t in ipairs(tables) do
		lines[#lines + 1] = tabledef(t)
		map[#lines] = t.sites
	end
	for _, l in ipairs(lims) do
		lines[#lines + 1] = l.text
		map[#lines] = l.sites
	end
	emit(self, lines, map, "")
	return lines, map
end

--- The ruleset as pf.conf text.
-- @treturn string
function Ruleset:render()
	local lines = self:lines()
	return table.concat(lines, "\n") .. "\n"
end

--
-- Loading: the ruleset into the kernel, expanded the way pfctl does
--

local tcpflags = { F = 0x01, S = 0x02, R = 0x04, P = 0x08, A = 0x10,
    U = 0x20, E = 0x40, W = 0x80 }

local function flagbits(s)
	local n = 0
	for ch in s:gmatch(".") do
		n = n | tcpflags[ch]
	end
	return n
end

local function items(v)
	if v.kind == "list" then
		return v.items
	end
	return { v }
end

-- An address as h:load() takes it, and its family when it has one.
local function nativeaddr(v, sites, what)
	local neg = false
	if v.kind == "not" then
		v, neg = v.inner, true
	end
	local a
	if v.kind == "any" then
		a = { type = "any" }
	elseif v.kind == "addr" then
		local text, bits = v.text:match("^([^/]+)/?(%d*)$")
		a = { type = "addr", addr = text, af = v.af,
		    bits = tonumber(bits) or (v.af == "inet" and 32 or 128) }
	elseif v.kind == "dyn" then
		a = { type = "dyn", name = v.name, network = v.mod == ":network",
		    broadcast = v.mod == ":broadcast", peer = v.mod == ":peer",
		    first = v.mod == ":0" }
	elseif v.kind == "self" then
		a = { type = "dyn", name = "self" }
	elseif v.kind == "table" then
		a = { type = "table", name = v.name }
	else
		fail(sites, "%s: cannot load %s", what, v.kind)
	end
	a.neg = neg
	return a, v.af
end

-- Every port a port option names, for one protocol.
local function nativeports(v, proto, sites, what, pf)
	if v == nil then
		return { false }
	end
	local list = isarray(v) and v or { v }
	local out = {}
	for _, p in ipairs(list) do
		if math.type(p) == "integer" then
			out[#out + 1] = { op = "=", lo = p, hi = 0 }
		elseif type(p) == "string" then
			local n = pf.servicenumber(p, proto or "tcp")
			if not n then
				fail(sites, "%s: unknown service %s/%s", what, p, proto or "tcp")
			end
			out[#out + 1] = { op = "=", lo = n, hi = 0 }
		else
			out[#out + 1] = { op = p.op, lo = p.a, hi = p.b or 0 }
		end
	end
	return out
end

-- A pool given as a list becomes a const table, the way pfctl does it.
local function autotable(ctx, list, sites, what)
	local addrs = {}
	for _, v in ipairs(list.items) do
		if v.kind ~= "addr" then
			fail(sites, "%s: a pool list holds addresses only", what)
		end
		addrs[#addrs + 1] = v.text
	end
	ctx.ntables = ctx.ntables + 1
	local t = value("table", { name = string.format("__automatic_%x_%d",
	    ctx.tableid, ctx.ntables - 1), const = true, persist = false,
	    counters = false, files = {}, addrs = addrs, sites = sites })
	ctx.autotables[#ctx.autotables + 1] = t
	return t
end

local function nativepool(ctx, v, proto, sites, what)
	local pf = ctx.pf
	local p = isvalue(v, "pool") and v or
	    value("pool", { addr = address(v, sites, what), opts = {} })
	local addr = p.addr
	if addr.kind == "list" then
		addr = autotable(ctx, addr, sites, what)
	end
	local a, paf = nativeaddr(addr, sites, what)
	if addr ~= p.addr then
		-- A list decides the family only when all of it shares one.
		paf = p.addr.items[1].af
		for _, v in ipairs(p.addr.items) do
			if v.af ~= paf then
				paf = nil
			end
		end
	end
	local port = p.opts.port
	if type(port) == "string" then
		port = pf.servicenumber(port, proto or "tcp") or
		    fail(sites, "%s: unknown service %s/%s", what, port, proto or "tcp")
	end
	if what == "binat_to" then
		a.port_lo, a.port_hi = 0, 0
	elseif what == "nat_to" then
		if port == nil then
			a.port_lo, a.port_hi = 50001, 65535
		elseif isvalue(port, "port") then
			a.port_lo, a.port_hi = port.a, port.b
		else
			a.port_lo, a.port_hi = port, port
		end
	elseif port ~= nil then
		if isvalue(port, "port") then
			a.port_lo, a.port_hi, a.port_op = port.a, port.b, port.op
		else
			a.port_lo, a.port_hi = port, 0
		end
	end
	a.method = p.opts.method
	if not a.method and (a.type == "table" or (a.type == "dyn" and not a.first)) then
		a.method = "round-robin"
	end
	a.sticky = p.opts.sticky
	return a, paf
end

-- The state a pass rule keeps, the way pfctl fills it in.
local function nativestate(opts, rsopts, proto, out)
	local st = opts.state
	if st == false then
		return 0
	end
	local defaults = st == nil
	if defaults then
		st = rsopts.state_defaults and rsopts.state_defaults.value or {}
	end
	local keep = st.kind == "modulate" and 2 or st.kind == "synproxy" and 3 or 1
	if keep > 1 and proto and proto ~= 6 then
		keep = 1
	end
	local s = { keep = keep, timeouts = {} }
	for _, k in ipairs({ "max", "max_src_states", "max_src_nodes",
	    "max_src_conn" }) do
		s[k] = st[k]
	end
	local track, rule = st.source_track, false
	if st.max_src_conn_rate then
		s.max_src_conn_rate = { limit = st.max_src_conn_rate[1],
		    seconds = st.max_src_conn_rate[2] }
	end
	if st.max_src_states then
		track = track or true
	end
	if st.max_src_conn or st.max_src_conn_rate or st.max_src_nodes then
		track, rule = track or true, true
	end
	if track then
		out.source_track = (rule or track == "rule") and "rule" or "global"
		local secs = s.max_src_conn_rate and s.max_src_conn_rate.seconds or 0
		if secs > 0 then
			s.timeouts["src.track"] = secs
		end
	end
	if st.max then
		s.timeouts["adaptive.start"] = st.max // 10 * 6
		s.timeouts["adaptive.end"] = st.max // 10 * 12
	end
	if st.overload then
		s.overload = st.overload.name
		s.flush = st.flush
	end
	if st.if_bound then
		out.if_bound = true
	elseif not st.floating and rsopts.state_policy and
	    rsopts.state_policy.value == "if-bound" then
		out.if_bound = true
	end
	out.sloppy, out.no_sync, out.pflow = st.sloppy, st.no_sync, st.pflow
	out.state = s
	return keep
end

-- One dsl rule as the kernel rules pfctl would expand it to.
local function nativerule(ctx, r, out)
	local rsopts, pf = ctx.rsopts, ctx.pf
	local opts, sites, action = r.opts, r.sites, r.action
	local anchor = action == "anchor"
	local base = { where = sitestr(sites), action = anchor and "pass" or action,
	    anchor_call = r.name, direction = opts.dir, quick = opts.quick,
	    label = opts.label, tag = opts.tag, tagged = opts.tagged,
	    rtable = opts.rtable, once = opts.once, allow_opts = opts.allow_opts }
	if action == "block" then
		base.policy = opts.policy or (rsopts.block_policy and
		    rsopts.block_policy.value == "return" and "return") or nil
		if base.policy == "drop" then
			base.policy = nil
		end
	end
	if opts.log == true then
		base.log = {}
	elseif type(opts.log) == "table" then
		base.log = { all = opts.log.all, matches = opts.log.matches,
		    user = opts.log.user }
		if opts.log.to then
			base.log.to = tonumber(opts.log.to.name:match("^pflog(%d+)$"))
		end
	end
	if opts.prio then
		base.prio = math.type(opts.prio) == "integer" and
		    { opts.prio, opts.prio } or opts.prio
	end
	if opts.queue then
		base.queue = type(opts.queue) == "string" and { opts.queue } or opts.queue
	end
	if opts.received_on then
		local v = opts.received_on
		base.received_on = getmetatable(v) == Iface and { name = v.name } or
		    { name = v.inner.name, neg = true }
	end
	if opts.user ~= nil then
		base.uid = math.type(opts.user) == "integer" and opts.user or
		    pf.uidnumber(opts.user) or
		    fail(sites, "%s: unknown user %s", action, opts.user)
	end
	for _, k in ipairs({ "state_limiter", "source_limiter" }) do
		local v = opts[k]
		if v then
			local l = isvalue(v) and v or v[1]
			base[k] = { id = l.id, action = not isvalue(v) and v.action or nil }
		end
	end
	if opts.binat_to then
		local b = isvalue(opts.binat_to, "pool") and opts.binat_to.addr or
		    opts.binat_to
		for _, v in ipairs({ address(opts.from or M.any, sites, "from"),
		    address(b, sites, "binat_to") }) do
			if not (v.kind == "addr" or (v.kind == "dyn" and v.mod == ":0")) then
				fail(sites, "%s: binat_to needs an address or (if:0) on " ..
				    "both sides", action)
			end
		end
	end

	local ifs = { false }
	if opts.on then
		local v = opts.on
		if getmetatable(v) == Iface then
			ifs = { { name = v.name } }
		elseif isvalue(v, "not") then
			ifs = { { name = v.inner.name, neg = true } }
		else
			ifs = {}
			for i, x in ipairs(v) do
				ifs[i] = { name = x.name }
			end
		end
	end
	local protos = { false }
	if opts.proto then
		protos = {}
		for i, p in ipairs(isarray(opts.proto) and opts.proto or { opts.proto }) do
			local n = math.type(p) == "integer" and p or pf.protonumber(p)
			if not n then
				fail(sites, "%s: unknown protocol %s", action, p)
			end
			protos[i] = { n = n, name = tostring(p) }
		end
	end
	local srcs = items(address(opts.from or M.any, sites, "from"))
	local dsts = items(address(opts.to or M.any, sites, "to"))

	-- A list whose literals all share one family decides the rule's.
	local af0 = opts.af
	for _, list in ipairs({ srcs, dsts }) do
		if not af0 then
			local seen
			for _, v in ipairs(list) do
				local x = v.kind == "not" and v.inner or v
				if x.kind ~= "addr" or (seen and seen ~= x.af) then
					seen = false
					break
				end
				seen = x.af
			end
			af0 = seen or nil
		end
	end

	local added = 0
	for _, i in ipairs(ifs) do
	for _, p in ipairs(protos) do
	for _, src in ipairs(srcs) do
	for _, dst in ipairs(dsts) do
	local pname = p and p.name or nil
	for _, sp in ipairs(nativeports(opts.from_port, pname, sites, "from_port", pf)) do
	for _, dp in ipairs(nativeports(opts.port, pname, sites, "port", pf)) do
		local x = {}
		for k, v in pairs(base) do
			x[k] = v
		end
		local af = af0
		for _, k in ipairs({ "nat_to", "rdr_to", "binat_to" }) do
			if opts[k] then
				local pool, paf = nativepool(ctx, opts[k], pname, sites, k)
				if af and paf and af ~= paf then
					fail(sites, "%s: %s address in an %s rule", action, paf, af)
				end
				af = af or paf
				x[k == "rdr_to" and "rdr" or "nat"] = pool
			end
		end
		if opts.binat_to then
			x.direction = "out"
		end
		local s, saf = nativeaddr(src, sites, "from")
		local d, daf = nativeaddr(dst, sites, "to")
		if not ((af and saf and af ~= saf) or (af and daf and af ~= daf) or
		    (saf and daf and saf ~= daf)) then
			af = af or saf or daf
			x.af = af
			s.port = sp or nil
			d.port = dp or nil
			x.from, x.to = s, d
			if i then
				x.ifname, x.ifnot = i.name, i.neg
			end
			x.proto = p and p.n or nil
			local tcp = not p or p.n == 6
			for _, k in ipairs({ "icmp_type", "icmp6_type" }) do
				local t = opts[k]
				if t ~= nil then
					x.icmp_type = math.type(t) == "integer" and t or
					    pf.icmptype(t, k == "icmp6_type" and "inet6" or "inet") or
					    fail(sites, "%s: unknown %s %s", action, k, t)
				end
			end
			local keep = 0
			if action == "pass" then
				keep = nativestate(opts, rsopts, p and p.n, x)
			end
			if opts.flags == "any" then
				x.flags, x.flagset = 0, 0
			elseif opts.flags then
				local a, b = opts.flags:match("^(.*)/(.*)$")
				x.flags, x.flagset = flagbits(a), flagbits(b)
			elseif action == "pass" and keep ~= 0 then
				x.flags, x.flagset = tcpflags.S, tcpflags.S | tcpflags.A
			end
			if not tcp then
				x.flags, x.flagset = nil, nil
			end
			out[#out + 1] = x
			added = added + 1
			-- binat-to adds the inbound rule that maps the target back.
			if opts.binat_to then
				local y = {}
				for k, v in pairs(x) do
					y[k] = v
				end
				y.direction, y.nat = "in", nil
				y.from = nativeaddr(dst, sites, "to")
				y.from.port = dp or nil
				local b = isvalue(opts.binat_to, "pool") and
				    opts.binat_to.addr or opts.binat_to
				y.to = nativeaddr(address(b, sites, "binat_to"), sites,
				    "binat_to")
				y.to.port = sp or nil
				y.rdr = nativeaddr(src, sites, "from")
				y.rdr.port_lo, y.rdr.port_hi = 0, 0
				if y.rdr.type == "dyn" and not y.rdr.first then
					y.rdr.method = "round-robin"
				end
				out[#out + 1] = y
			end
		end
	end end end end end end
	if added == 0 then
		fail(sites, "%s: rule expands to no valid combination", action)
	end
end

local function tableaddrs(t, sites)
	local out = {}
	local function add(s)
		local neg = s:sub(1, 1) == "!"
		if neg then
			s = s:sub(2)
		end
		local p, err = parseaddr(s)
		if not p then
			fail(sites, "table <%s>: %s", t.name, err)
		end
		local text, bits = s:match("^([^/]+)/?(%d*)$")
		out[#out + 1] = { addr = text, af = p.af, neg = neg,
		    bits = tonumber(bits) or (p.af == "inet" and 32 or 128) }
	end
	for _, a in ipairs(t.addrs) do
		add(a)
	end
	for _, f in ipairs(t.files) do
		local fh, err = io.open(f)
		if not fh then
			fail(sites, "table <%s>: %s", t.name, err)
		end
		for line in fh:lines() do
			line = line:gsub("#.*", "")
			for word in line:gmatch("%S+") do
				add(word)
			end
		end
		fh:close()
	end
	return (#t.addrs > 0 or #t.files > 0) and out or nil
end

-- The timeouts each set optimization stands for, as pfctl has them.
local hints = {
	normal = { 120, 30, 86400, 900, 45, 90, 30 },
	satellite = { 180, 35, 86400, 905, 50, 95, 60 },
	conservative = { 3600, 900, 432000, 3600, 600, 180, 60 },
	aggressive = { 30, 5, 18000, 60, 30, 30, 10 },
}
hints["high-latency"] = hints.satellite
local hintnames = { "tcp.first", "tcp.opening", "tcp.established",
    "tcp.closing", "tcp.finwait", "tcp.closed", "tcp.tsdiff" }

local function nativeoptions(rs)
	local o = rs.options
	local out = {}
	if o.limit then
		out.limits = {}
		for k, v in pairs(o.limit.value) do
			out.limits[(k:gsub("_", "-"))] = v
		end
	end
	if o.optimization or o.timeout then
		out.timeouts = {}
		if o.optimization then
			for i, v in ipairs(hints[o.optimization.value]) do
				out.timeouts[hintnames[i]] = v
			end
		end
		for k, v in pairs(o.timeout and o.timeout.value or {}) do
			out.timeouts[(k:gsub("_", "."))] = v
		end
	end
	if o.loginterface then
		local v = o.loginterface.value
		out.loginterface = getmetatable(v) == Iface and v.name or v
	end
	if o.reassemble then
		out.reassemble = o.reassemble.value
	end
	return out
end

-- The argument h:load() takes.
local function nativespec(rs, anchor, pf)
	if anchor ~= "" then
		for k, v in pairs(rs.options) do
			if k == "skip" or k == "limit" or k == "timeout" or
			    k == "optimization" or k == "loginterface" or
			    k == "reassemble" then
				fail(v.sites, "set: %s belongs to the main ruleset", k)
			end
		end
	end
	local spec = { rulesets = {} }
	local ctx = { pf = pf, rsopts = rs.options, autotables = {},
	    ntables = 0, tableid = math.random(0, 0x7fffffff) }
	local lims = {}
	if anchor == "" then
		limiters(rs, lims, {})
	end
	local tables = {}
	collect(rs, tables, {}, lims)
	local function ruleset(r, path, tbls)
		local entry = { anchor = path, rules = {}, tables = {} }
		spec.rulesets[#spec.rulesets + 1] = entry
		for _, t in ipairs(tbls) do
			entry.tables[#entry.tables + 1] = { name = t.name,
			    persist = t.persist, const = t.const, counters = t.counters,
			    addrs = tableaddrs(t, t.sites) }
		end
		for _, item in ipairs(r.items) do
			nativerule(ctx, item, entry.rules)
			if item.inline then
				ruleset(item.inline, path == "" and item.name or
				    path .. "/" .. item.name, {})
			end
		end
	end
	ruleset(rs, anchor, tables)
	for _, t in ipairs(ctx.autotables) do
		local e = spec.rulesets[1].tables
		e[#e + 1] = { name = t.name, const = true,
		    addrs = tableaddrs(t, t.sites) }
	end
	if anchor == "" then
		spec.options = nativeoptions(rs)
	end
	spec.statelimiters, spec.sourcelimiters = {}, {}
	for _, l in ipairs(lims) do
		local o = l.opts
		local e = { name = l.name, id = l.id, limit = o.limit,
		    entries = o.entries, inet_mask = o.inet_mask,
		    inet6_mask = o.inet6_mask, above = o.above, below = o.below,
		    overload = o.overload and o.overload.name }
		if o.rate then
			e.rate_limit, e.rate_seconds = o.rate[1], o.rate[2]
		end
		local list = l.which == "state" and spec.statelimiters or
		    spec.sourcelimiters
		list[#list + 1] = e
	end
	if rs.options.skip and anchor == "" then
		local v = rs.options.skip.value
		spec.skip = {}
		for i, x in ipairs(isarray(v) and v or { v }) do
			spec.skip[i] = getmetatable(x) == Iface and x.name or x
		end
	end
	return spec
end

--- Load the ruleset into the kernel in one transaction, the way pfctl -f
-- does: rules, tables, limiters, and on the main ruleset its options. It
-- runs no program; rules are expanded and filled in here.
-- @tab[opt] opts anchor (load into this anchor), check (send it all,
-- then roll back), pf (a handle from pf.open; one is opened otherwise),
-- names (the name lookups, for tests; the pf module by default)
-- @treturn[1] boolean true
-- @return[2] nil
-- @treturn[2] string error that names the Lua line of the rule
function Ruleset:load(opts)
	opts = opts or {}
	local sites = where()
	local ok, err = pcall(function()
		local names = opts.names or require("pf")
		local anchor = opts.anchor and anchorname(opts.anchor, sites) or ""
		local spec = nativespec(self, anchor, names)
		spec.check = opts.check
		local h = opts.pf or assert(require("pf").open())
		local done = h:load(spec)
		if not opts.pf then
			h:close()
		end
		return done
	end)
	if not ok then
		return nil, err
	end
	return true
end

--
-- Lua out
--

local methods = { [""] = "addr", [":0"] = "addr0", [":network"] = "network",
    [":broadcast"] = "broadcast", [":peer"] = "peer" }

local function key(k)
	if type(k) == "string" and k:match("^[%a_][%w_]*$") then
		return k
	end
	return "[" .. string.format("%q", k) .. "]"
end

-- Lua source for a value. ctx maps tables and limiters to the names
-- that hold them.
local function ser(v, ctx)
	local t = type(v)
	if t == "string" then
		return string.format("%q", v)
	elseif t == "number" or t == "boolean" then
		return tostring(v)
	elseif getmetatable(v) == Iface then
		return (v.group and "dsl.group(" or "dsl.iface(") ..
		    ser(v.name) .. ")"
	elseif getmetatable(v) == Ruleset then
		return assert(ctx[v], "no name for an inline ruleset")
	elseif isvalue(v) then
		local k = v.kind
		if k == "addr" then
			return ser(v.text)
		elseif k == "dyn" then
			return (v.group and "dsl.group(" or "dsl.iface(") ..
			    ser(v.name) .. "):" .. methods[v.mod] .. "()"
		elseif k == "table" or k == "limiter" then
			return assert(ctx[v], "no name for " .. k .. " " .. v.name)
		elseif k == "any" or k == "self" then
			return "dsl." .. k
		elseif k == "not" then
			return "dsl.NOT(" .. ser(v.inner, ctx) .. ")"
		elseif k == "list" then
			return ser(v.items, ctx)
		elseif k == "port" then
			if v.op == ":" then
				return "dsl.range(" .. v.a .. ", " .. v.b .. ")"
			end
			return "dsl.port(" .. ser(v.op) .. ", " .. v.a ..
			    (v.b and ", " .. v.b or "") .. ")"
		elseif k == "pool" then
			if next(v.opts) == nil then
				return "dsl.pool(" .. ser(v.addr, ctx) .. ")"
			end
			return "dsl.pool(" .. ser(v.addr, ctx) .. ", " ..
			    ser(v.opts, ctx) .. ")"
		end
	elseif t == "table" then
		local parts = {}
		for i = 1, #v do
			parts[#parts + 1] = ser(v[i], ctx)
		end
		local keys = {}
		for k in pairs(v) do
			if not (math.type(k) == "integer" and k >= 1 and k <= #v) then
				keys[#keys + 1] = k
			end
		end
		table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
		for _, k in ipairs(keys) do
			parts[#parts + 1] = key(k) .. " = " .. ser(v[k], ctx)
		end
		if #parts == 0 then
			return "{}"
		end
		return "{ " .. table.concat(parts, ", ") .. " }"
	end
	error("cannot write " .. tostring(v) .. " as Lua")
end

local function tableopts_of(t)
	local o = {}
	for _, k in ipairs({ "persist", "const", "counters" }) do
		if t[k] then
			o[k] = true
		end
	end
	if #t.files > 0 then
		o.file = #t.files == 1 and t.files[1] or t.files
	end
	if #t.addrs > 0 then
		o.addrs = {}
		for i, a in ipairs(t.addrs) do
			o.addrs[i] = a:sub(1, 1) == "!" and
			    value("not", { inner = value("addr", { text = a:sub(2) }) }) or a
		end
	end
	return o
end

--- The ruleset as Lua source. Running the source returns an equal
-- ruleset.
-- @treturn string
function Ruleset:tolua()
	local out = { 'local dsl = require("pf.dsl")', "local T, L = {}, {}" }
	local ctx = {}
	local lims = {}
	limiters(self, lims, {})
	local tables = {}
	collect(self, tables, {}, lims)
	for _, t in ipairs(tables) do
		ctx[t] = "T[" .. ser(t.name) .. "]"
		local o = tableopts_of(t)
		out[#out + 1] = ctx[t] .. " = dsl.table(" .. ser(t.name) ..
		    (next(o) and ", " .. ser(o, ctx) or "") .. ")"
	end
	for _, l in ipairs(lims) do
		ctx[l] = "L[" .. l.id .. "]"
		out[#out + 1] = ctx[l] .. " = dsl." .. l.which .. "limiter(" ..
		    ser(l.name) .. ", " .. ser(l.opts, ctx) .. ")"
	end
	-- Equal tables under other names resolve to the one written out.
	local byname = {}
	for _, t in ipairs(tables) do
		byname[t.name] = ctx[t]
	end
	setmetatable(ctx, { __index = function(_, v)
		if isvalue(v, "table") then
			return byname[v.name]
		end
	end })

	local n = 0
	local function body(rs, var)
		out[#out + 1] = "local " .. var .. " = dsl.ruleset()"
		local keys = {}
		for k in pairs(rs.options) do
			keys[#keys + 1] = k
		end
		table.sort(keys)
		if #keys > 0 then
			local o = {}
			for _, k in ipairs(keys) do
				o[k] = rs.options[k].value
			end
			out[#out + 1] = var .. ":set" .. ser(o, ctx)
		end
		for _, t in ipairs(rs.declared) do
			out[#out + 1] = var .. ":table(" .. ctx[t] .. ")"
		end
		for _, l in ipairs(rs.limiters) do
			out[#out + 1] = var .. ":limiter(" .. ctx[l] .. ")"
		end
		for _, r in ipairs(rs.items) do
			if r.action == "anchor" then
				local o = {}
				for k, v in pairs(r.opts) do
					o[k] = v
				end
				if r.inline then
					n = n + 1
					local sub = "a" .. n
					body(r.inline, sub)
					ctx[r.inline] = sub
					o.rules = r.inline
				end
				local args = ser(r.name)
				if next(o) then
					args = args .. ", " .. ser(o, ctx)
				end
				out[#out + 1] = var .. ":anchor(" .. args .. ")"
			else
				out[#out + 1] = var .. ":" .. r.action .. ser(r.opts, ctx)
			end
		end
	end
	body(self, "rs")
	out[#out + 1] = "return rs"
	return table.concat(out, "\n") .. "\n"
end

--
-- Lua in from the kernel
--

local dynmod = function(a)
	local mods = {}
	if a.network then mods[#mods + 1] = ":network" end
	if a.broadcast then mods[#mods + 1] = ":broadcast" end
	if a.peer then mods[#mods + 1] = ":peer" end
	if a.first then mods[#mods + 1] = ":0" end
	if #mods > 1 then
		return nil
	end
	return mods[1] or ""
end

local function readaddr(a, af, tables, sites, what)
	local v
	if a.type == "any" then
		v = M.any
	elseif a.type == "addr" then
		local max = (af == "inet6" or a.addr:find(":", 1, true)) and 128 or 32
		local text = a.addr .. (a.bits < max and "/" .. a.bits or "")
		local p, err = parseaddr(text)
		if not p then
			fail(sites, "%s: %s", what, err)
		end
		v = value("addr", p)
	elseif a.type == "dyn" then
		if a.name == "self" then
			v = M.self
		else
			local mod = dynmod(a)
			if not mod then
				fail(sites, "%s: (%s) has more than one modifier", what, a.name)
			end
			v = value("dyn", { name = a.name, mod = mod })
		end
	elseif a.type == "table" then
		v = tables[a.name] or M.table(a.name)
		tables[a.name] = v
	else
		fail(sites, "%s: pf.dsl has no %s address", what, a.type)
	end
	if a.neg then
		v = value("not", { inner = v })
	end
	return v
end

local function readport(p)
	if p.op == "=" then
		return p.lo
	elseif p.op == ":" then
		return value("port", { text = p.lo .. ":" .. p.hi, op = ":",
		    a = p.lo, b = p.hi })
	elseif p.op == "<>" or p.op == "><" then
		return value("port", { text = p.lo .. " " .. p.op .. " " .. p.hi,
		    op = p.op, a = p.lo, b = p.hi })
	end
	return value("port", { text = p.op .. " " .. p.lo, op = p.op, a = p.lo })
end

-- Properties pf.dsl has no option for. A rule with one cannot be read.
local unsupported = { "group", "os_fingerprint", "probability",
    "tos", "set_tos", "divert", "rdomain", "delay", "max_pkt_rate",
    "min_ttl", "max_mss", "return_ttl" }
local unsupportedflags = { "af_to", "fragment", "no_df", "random_id",
    "reassemble_tcp", "match_tag_not", "sloppy", "no_sync" }

local function readpool(p, af, tables, sites, what)
	if p.ifname then
		fail(sites, "%s: pf.dsl has no pool bound to an interface", what)
	end
	if p.static_port then
		fail(sites, "%s: pf.dsl has no static-port", what)
	end
	local addr = readaddr(p, af, tables, sites, what)
	local o = {}
	if p.port_lo then
		o.port = p.port_lo == p.port_hi and p.port_lo or
		    value("port", { text = p.port_lo .. ":" .. p.port_hi, op = ":",
		    a = p.port_lo, b = p.port_hi })
	end
	-- A table pool is round-robin unless it says otherwise.
	if p.method and not (p.method == "round-robin" and addr.kind == "table") then
		o.method = p.method
	end
	if p.sticky then
		o.sticky = true
	end
	if next(o) == nil then
		return addr
	end
	return value("pool", { addr = addr, opts = o, port = o.port and
	    (type(o.port) == "number" and tostring(o.port) or o.port.text),
	    method = o.method, sticky = o.sticky })
end

-- The options of one kernel rule, with what pfctl adds by default taken
-- back out.
local function readrule(r, tables, lims, sites)
	for _, k in ipairs(unsupported) do
		if r[k] ~= nil then
			fail(sites, "pf.dsl has no %s option", k)
		end
	end
	for _, k in ipairs(unsupportedflags) do
		if r[k] then
			fail(sites, "pf.dsl has no %s option", k)
		end
	end
	local spec = r.spec
	if spec.route then
		fail(sites, "pf.dsl has no route-to")
	end
	if spec.icmp_code then
		fail(sites, "pf.dsl has no icmp-code")
	end
	local o = {}
	o.dir = r.direction
	if r.quick then
		o.quick = true
	end
	if spec.log then
		local l = {}
		for _, k in ipairs({ "all", "matches", "user" }) do
			l[k] = spec.log[k]
		end
		if spec.log.to then
			l.to = M.iface("pflog" .. spec.log.to)
		end
		o.log = next(l) and l or true
	end
	if r.interface ~= "" then
		local i = M.iface(r.interface)
		o.on = r.interface_not and value("not", { inner = i }) or i
	end
	o.af = r.af
	if r.proto then
		o.proto = tonumber(r.proto) or r.proto
	end
	local function side(a, addrkey, portkey)
		if a.type ~= "any" or a.neg then
			o[addrkey] = readaddr(a, r.af, tables, sites, addrkey)
		end
		if a.port then
			o[portkey] = readport(a.port)
		end
	end
	side(spec.from, "from", "from_port")
	side(spec.to, "to", "port")
	local keep = spec.state.keep
	if r.flags and not (r.action == "pass" and keep ~= 0 and
	    r.flags == "S/SA") then
		o.flags = r.flags
	end
	if spec.icmp_type then
		local p = o.proto
		o[(p == "ipv6-icmp" or p == "icmp6" or p == 58) and "icmp6_type" or
		    "icmp_type"] = spec.icmp_type
	end
	if r.allow_opts then
		o.allow_opts = true
	end
	if r.once then
		o.once = true
	end
	if r.action == "pass" then
		local st = spec.state
		if keep == 0 then
			o.state = false
		else
			local so = {}
			so.kind = keep == 2 and "modulate" or keep == 3 and "synproxy" or nil
			for _, k in ipairs({ "max", "max_src_states", "max_src_nodes",
			    "max_src_conn" }) do
				so[k] = st[k]
			end
			local tm = st.timeouts
			if st.max_src_conn_rate then
				so.max_src_conn_rate = { st.max_src_conn_rate.limit,
				    st.max_src_conn_rate.seconds }
				if tm["src.track"] == st.max_src_conn_rate.seconds then
					tm["src.track"] = nil
				end
			end
			if st.max and tm["adaptive.start"] == st.max // 10 * 6 and
			    tm["adaptive.end"] == st.max // 10 * 12 then
				tm["adaptive.start"], tm["adaptive.end"] = nil, nil
			end
			local k = next(tm)
			if k then
				fail(sites, "pf.dsl has no state timeout %s", k)
			end
			if st.overload then
				so.overload = tables[st.overload] or M.table(st.overload)
				tables[st.overload] = so.overload
				if st.flush then
					so.flush = st.flush
				end
			end
			-- Any max-src option turns on source-track rule.
			local tracked = st.max_src_states or st.max_src_nodes or
			    st.max_src_conn or st.max_src_conn_rate
			if r.source_track and not (tracked and r.source_track == "rule") then
				so.source_track = r.source_track
			end
			if r.if_bound then
				so.if_bound = true
			end
			if r.pflow then
				so.pflow = true
			end
			if next(so) then
				o.state = so
			end
		end
	end
	if r.user then
		local uid = r.user:match("^= (%d+)$")
		if not uid then
			fail(sites, "pf.dsl has no user %s", r.user)
		end
		uid = tonumber(uid)
		o.user = uid == 0xffffffff and "unknown" or uid
	end
	if r.label ~= "" then
		o.label = r.label
	end
	if r.tag ~= "" then
		o.tag = r.tag
	end
	if r.match_tag ~= "" then
		o.tagged = r.match_tag
	end
	if spec.received_on then
		local i = M.iface(spec.received_on.name)
		o.received_on = spec.received_on.neg and
		    value("not", { inner = i }) or i
	end
	o.rtable = r.rtable
	if spec.prio then
		o.prio = spec.prio[1] == spec.prio[2] and spec.prio[1] or spec.prio
	end
	if spec.queue then
		o.queue = #spec.queue == 1 and spec.queue[1] or spec.queue
	end
	if spec.nat and spec.rdr then
		fail(sites, "pf.dsl cannot read a rule with two pools")
	end
	if spec.nat then
		o.nat_to = readpool(spec.nat, r.af, tables, sites, "nat_to")
	end
	if spec.rdr then
		o.rdr_to = readpool(spec.rdr, r.af, tables, sites, "rdr_to")
	end
	for _, k in ipairs({ "state_limiter", "source_limiter" }) do
		local l = spec[k]
		if l then
			local lim = lims[k:match("^%a+")][l.id]
			if not lim then
				fail(sites, "%s id %d does not exist", k, l.id)
			end
			o[k] = l.action == "no-match" and { lim, action = "no-match" } or
			    lim
		end
	end
	if r.action == "block" then
		o.policy = r.return_policy
	end
	return o
end

--- @section end

--- Read a ruleset back from the kernel. Tables keep their flags; only
-- const tables keep their addresses, since others hold data.
-- @param h a handle from pf.open
-- @string[opt] anchor the ruleset to read; the main one when nil
-- @treturn[1] Ruleset
-- @return[2] nil
-- @treturn[2] string error that names the first rule pf.dsl cannot express
function M.read(h, anchor)
	local ok, rs = pcall(function()
		local tables = {}
		local declared = {}
		for _, t in ipairs(h:tables(anchor or "")) do
			if (t.anchor or "") == (anchor or "") then
				local o = { persist = t.persist or nil, const = t.const or nil,
				    counters = t.counters or nil }
				if t.const then
					o.addrs = {}
					for _, e in ipairs(t:entries()) do
						local a = e.address
						o.addrs[#o.addrs + 1] = e.negated and
						    value("not", { inner = value("addr", { text = a }) }) or a
					end
				end
				tables[t.name] = M.table(t.name, o)
				if not t.referenced then
					declared[#declared + 1] = tables[t.name]
				end
			end
		end
		local lims = { state = {}, source = {} }
		for _, l in ipairs(h:statelimiters()) do
			local o = { id = l.id, limit = l.limit }
			if l.rate.limit ~= 0 then
				o.rate = { l.rate.limit, l.rate.seconds }
			end
			lims.state[l.id] = M.statelimiter(l.name, o)
		end
		for _, l in ipairs(h:sourcelimiters()) do
			local o = { id = l.id, entries = l.entries, limit = l.limit }
			if l.rate.limit ~= 0 then
				o.rate = { l.rate.limit, l.rate.seconds }
			end
			if l.inet_prefix ~= 32 then
				o.inet_mask = l.inet_prefix
			end
			if l.inet6_prefix ~= 128 then
				o.inet6_mask = l.inet6_prefix
			end
			if l.overload then
				local name = l.overload.table
				tables[name] = tables[name] or M.table(name)
				o.overload = tables[name]
				o.above, o.below = l.overload.hwm, l.overload.lwm
			end
			lims.source[l.id] = M.sourcelimiter(l.name, o)
		end

		local rs = M.ruleset()
		for _, t in ipairs(declared) do
			rs:table(t)
		end
		if not anchor or anchor == "" then
			for _, kind in ipairs({ "state", "source" }) do
				for _, l in pairs(lims[kind]) do
					rs:limiter(l)
				end
			end
		end
		for _, r in ipairs(h:rules(anchor)) do
			local sites = { string.format("pf rule %s%d",
			    anchor and anchor ~= "" and anchor .. "/" or "", r.nr) }
			local o = readrule(r, tables, lims, sites)
			local item
			if r.anchor_call ~= "" then
				for k in pairs(o) do
					if not ruleopts[k].anchor then
						o[k] = nil
					end
				end
				item = rule("anchor", o, sites)
				item.text = item.text:gsub("^anchor",
				    'anchor "' .. r.anchor_call .. '"')
				item.name = r.anchor_call
			else
				item = rule(r.action, o, sites)
			end
			rs.items[#rs.items + 1] = item
		end
		return rs
	end)
	if not ok then
		return nil, rs
	end
	return rs
end

return M
