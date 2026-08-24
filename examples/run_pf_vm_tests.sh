#!/bin/ksh -e
# Run luapf PF tests in a disposable vmd overlay, controlled only over serial.
# The host PF is never opened or changed by this script.
#
# Usage: run_pf_vm_tests.sh [base.qcow2] [overlay.qcow2] [isolated|uplink]

selfdir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$selfdir/.." && pwd)
base=${1:-/home/mischief/vmd/luapf/luapf-pf-test-base.qcow2}
overlay=${2:-/home/mischief/vmd/luapf/luapf-pf-test-run.qcow2}
network=${3:-isolated}
name=luapf-pf-test-run
archive="$overlay.source.tgz"
tty=
started=false

# serialutil.so is this repo's own (examples/serialutil/serialutil.c,
# built by this project's own meson build -- see meson.build), reached
# through LUA_CPATH the same way meson's own devenv/test setup do
# (require("serialutil"), not an *_SO environment variable). No external
# tree needs to be checked out beside luapf for this to run.
build=${LUAPF_BUILD_DIR:-"$root/build"}
export LUA_CPATH="$build/?.so;;"
root_password=${LUAPF_ROOT_PASSWORD:-13ZU8cJXvLK58O4cUiVJbvY4}

fail() { print -u2 -r -- "run-pf-vm-tests: $*"; exit 1; }
cleanup() {
	if $started; then
		doas vmctl stop -f "$name" >/dev/null 2>&1 || true
	fi
	rm -f "$archive"
}
trap cleanup EXIT HUP INT TERM

[[ -f $base ]] || fail "base image is not a regular file: $base"
[[ ! -e $overlay ]] || fail "overlay already exists: $overlay"
[[ -r $build/serialutil.so ]] || fail "$build/serialutil.so is not readable " \
    "(build it: cd $root && meson setup build && ninja -C build serialutil.so)"
case $network in
isolated) use_uplink=false ;;
uplink) use_uplink=true ;;
*) fail "network must be isolated or uplink" ;;
esac

git -C "$root" archive --format=tar.gz HEAD >"$archive"
doas vmctl create -b "$base" "$overlay"
if $use_uplink; then
	doas vmctl start -m 1G -d "$overlay" -n uplink "$name"
else
	doas vmctl start -m 1G -d "$overlay" "$name"
fi
started=true

tty=$(doas vmctl status -r | awk -v name="$name" '$NF == name {print $6}')
[[ -n $tty && -c /dev/$tty ]] || fail "cannot discover serial tty for $name"
tty=/dev/$tty

# One lua5.4 process drives the whole session -- login, readiness poll, the
# file push, and every test command -- because a second opener of the same
# vmd tty steals bytes the first is waiting for (see luapf_console.lua).
# guest_script below is what actually builds and runs the tests inside the
# guest; it's handed to that one process's Console:exec(), so its failures
# come back as this process's exit status without a second connection to
# the tty.
guest_script=$(mktemp)
cat >"$guest_script" <<'GUEST'
cd /root
rm -rf luapf
mkdir luapf
cd luapf
tar -xzhf source.tgz
meson setup build
ninja -C build
pfctl -ef - <<'PF'
set skip on lo
pass quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 keep state
PF
nc -l 127.0.0.1 31337 >/dev/null &
listener=$!
sleep 1
print x | nc -N 127.0.0.1 31337 || true
kill "$listener" 2>/dev/null || true
export LUA_CPATH="$PWD/build/?.so"
for test in pf_test_tables.lua pf_test_states.lua pf_test_rules.lua pf_test_system.lua; do
	lua54 "$test"
done
GUEST

driver=$(mktemp)
cat >"$driver" <<'LUAEOF'
package.path = arg[1] .. "/?.lua;" .. package.path
local console = require("luapf_console")

local tty, password, archive, guest_script = arg[2], arg[3], arg[4], arg[5]

local c, err = console.open(tty, 115200)
if not c then
	io.stderr:write("run-pf-vm-tests: cannot open " .. tty .. ": " .. tostring(err) .. "\n")
	os.exit(1)
end

io.stderr:write("run-pf-vm-tests: waiting for login prompt\n")
local ok, lerr = c:login("root", password, 120)
if not ok then
	io.stderr:write("run-pf-vm-tests: login failed: " .. tostring(lerr) .. "\n")
	os.exit(1)
end

-- build_test_vm_base.sh writes the readiness marker only after package
-- install finished on the base image, but poll it anyway rather than
-- assume a successful login means the guest is otherwise ready: this
-- is a routine guard on the same Console:ready() build_test_vm_base.sh
-- itself uses, not a sign this particular boot is still provisioning.
io.stderr:write("run-pf-vm-tests: waiting for guest to finish provisioning\n")
local deadline = os.time() + 180
local isready = false
while os.time() < deadline do
	if c:ready(5) then
		isready = true
		break
	end
end
if not isready then
	io.stderr:write("run-pf-vm-tests: guest did not become ready\n")
	os.exit(1)
end

io.stderr:write("run-pf-vm-tests: pushing source archive\n")
local pushed, perr = c:push(archive, "/root")
if not pushed then
	io.stderr:write("run-pf-vm-tests: push failed: " .. tostring(perr) .. "\n")
	os.exit(1)
end

-- source.tgz is what the guest_script's tar line expects; the archive
-- itself may be named anything on the host side.
local archive_name = archive:match("([^/]+)$")
if archive_name ~= "source.tgz" then
	local status, out = c:exec("mv " .. archive_name .. " source.tgz", 10)
	if status ~= 0 then
		io.stderr:write("run-pf-vm-tests: rename failed: " .. tostring(out) .. "\n")
		os.exit(1)
	end
end

io.stderr:write("run-pf-vm-tests: building and running tests in the guest\n")
local script = assert(io.open(guest_script, "rb")):read("a")
local status, out = c:exec(script, 300)
io.write(out)
if status ~= 0 then
	io.stderr:write("run-pf-vm-tests: guest tests failed: exit " .. tostring(status) .. "\n")
	c:say("halt -p", 0.3)
	os.exit(1)
end

c:say("halt -p", 0.3)
c:close()
os.exit(0)
LUAEOF

doas env LUA_CPATH="$LUA_CPATH" lua5.4 "$driver" "$root/examples" "$tty" \
    "$root_password" "$archive" "$guest_script"
status=$?
rm -f "$driver" "$guest_script"
(( status == 0 )) || fail "guest driver failed (exit $status)"

started=false
print -r -- "run-pf-vm-tests: all tests passed in disposable overlay: $overlay"
