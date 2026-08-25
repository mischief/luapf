#!/bin/ksh -e
# Run luapf PF tests in a disposable vmd overlay, controlled only over serial.
# The host PF is never opened or changed by this script.
#
# Usage: run_pf_vm_tests.sh [base.qcow2] [overlay.qcow2] [isolated|uplink]

selfdir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$selfdir/.." && pwd)
base=${1:-"$root/.vm/luapf-pf-test-base.qcow2"}
overlay=${2:-"$root/.vm/luapf-pf-test-run.qcow2"}
network=${3:-isolated}
name=luapf-pf-test-run
transcript=${LUAPF_VM_TRANSCRIPT:-"$root/.vm/$name-console.log"}

# qcow2 stores the backing filename as supplied to vmctl create.  vmd may
# resolve that filename from a different working directory, so make both
# paths absolute before creating the overlay.
base_dir=$(cd "$(dirname "$base")" && pwd)
base="$base_dir/$(basename "$base")"
overlay_dir=$(cd "$(dirname "$overlay")" && pwd)
overlay="$overlay_dir/$(basename "$overlay")"
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

git -C "$root" ls-files -co --exclude-standard | tar -C "$root" -czf "$archive" -I -
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
mkdir -p "$(dirname "$transcript")"
: >"$transcript"

# One lua5.4 process drives the whole session -- login, readiness poll, the
# file push, and every test command -- because a second opener of the same
# vmd tty steals bytes the first is waiting for (see luapf_console.lua).
# guest_script below is what actually builds and runs the tests inside the
# guest; it's handed to that one process's Console:exec(), so its failures
# come back as this process's exit status without a second connection to
# the tty.
guest_script=$(mktemp)
cat >"$guest_script" <<'GUEST'
set -e; cd /root; rm -rf luapf; mkdir luapf; tar -xzhf /root/source.tgz -C luapf; cd luapf; meson setup build; ninja -C build; printf '%s\n' 'pass' | pfctl -f -; nc -l 127.0.0.1 31337 </dev/null >/dev/null & listener=$!; sleep 1; print x | nc -N 127.0.0.1 31337 || true; kill "$listener" 2>/dev/null || true; export LUA_CPATH="$PWD/build/?.so"; for test in pf_test_tables.lua pf_test_states.lua pf_test_rules.lua pf_test_queues.lua pf_test_system.lua; do lua54 "$test"; done
GUEST

driver=$(mktemp)
cat >"$driver" <<'LUAEOF'
package.path = arg[1] .. "/?.lua;" .. package.path
local console = require("luapf_console")

local tty, password, archive, guest_script, transcript_path =
    arg[2], arg[3], arg[4], arg[5], arg[6]

local c, err = console.open(tty, 115200, transcript_path)
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
	local status, out = c:exec("mv /root/" .. archive_name .. " source.tgz", 10)
	if status ~= 0 then
		io.stderr:write("run-pf-vm-tests: rename failed: " .. tostring(out) .. "\n")
		os.exit(1)
	end
end

io.stderr:write("run-pf-vm-tests: pushing guest test script\n")
local script_pushed, serr = c:push(guest_script, "/root")
if not script_pushed then
	io.stderr:write("run-pf-vm-tests: script push failed: " .. tostring(serr) .. "\n")
	os.exit(1)
end
local script_name = guest_script:match("([^/]+)$")
local renamed, rout = c:exec("mv /root/" .. script_name .. " /root/run-tests.ksh", 10)
if renamed ~= 0 then
	io.stderr:write("run-pf-vm-tests: script rename failed: " .. tostring(rout) .. "\n")
	os.exit(1)
end

io.stderr:write("run-pf-vm-tests: building and running tests in the guest\n")
local status, out = c:exec("ksh /root/run-tests.ksh", 300)
io.write(out or "")
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
    "$root_password" "$archive" "$guest_script" "$transcript"
status=$?
rm -f "$driver" "$guest_script"
(( status == 0 )) || fail "guest driver failed (exit $status)"

started=false
print -r -- "run-pf-vm-tests: all tests passed in disposable overlay: $overlay"
