# luapf

Lua bindings for the OpenBSD packet filter, pf(4).

- `pf` reads and controls pf through `/dev/pf`: status, states, rules,
  anchors, tables, queues, limiters, timeouts and source nodes.
- `pf.dsl` builds a ruleset as Lua data, renders it as pf.conf text, and
  loads it the way `pfctl -f` does, without running pfctl.

Lua 5.3 and 5.4 on OpenBSD are supported.

## Install

    luarocks install pf

Or build with meson:

    meson setup build
    ninja -C build
    doas ninja -C build install

## Use

```lua
local pf = require("pf")

local h = pf.open()
for _, r in ipairs(h:rules()) do
	print(tostring(r))
end
h:close()
```

```lua
local dsl = require("pf.dsl")

local wan = dsl.iface("em0")
local rs = dsl.ruleset()
rs:set{ skip = { "lo0" }, block_policy = "drop" }
rs:block{ dir = "in", on = wan }
rs:pass{ dir = "in", on = wan, proto = "tcp", to = wan:addr(), port = 22 }
rs:pass{ dir = "out" }

io.write(rs:render())
assert(rs:load({ check = true }))
```

Opening `/dev/pf` needs root. A descriptor opened read-only keeps working
after a privilege drop. Every call raises a Lua error on failure.

More programs are in `examples/`, such as a pfctl clone (`pfctl.lua`) and
a Prometheus exporter (`exporter.lua`). With ldoc installed, the build
writes the API reference to `build/index.html`.

## pf.dsl and pfctl

`pf.dsl` does not run the pfctl optimizer, does not read `/etc/pf.os`,
and cannot define queues.

## Tests

See `TESTING.md`.

## License

ISC. See `LICENSE`.
