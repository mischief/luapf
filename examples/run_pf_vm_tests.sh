#!/bin/ksh -e
# Run luapf PF tests in a disposable vmd overlay, controlled only over serial.
# The host PF is never opened or changed by this script.
#
# Usage: run_pf_vm_tests.sh [base.qcow2] [overlay.qcow2] [isolated|uplink]
#
# Runs are independent: the guest is named after its own overlay, so several
# may run at once as long as each is given its own overlay. LUAPF_VM_TESTS
# picks which guest-side tests run, for working on one of them without
# editing this file.

selfdir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$selfdir/.." && pwd)
base=${1:-"$root/.vm/luapf-pf-test-base.qcow2"}
overlay=${2:-"$root/.vm/luapf-pf-test-run.qcow2"}
network=${3:-isolated}
# Named after the overlay, not a fixed string: two runs sharing a VM name
# would collide in vmctl, and the second would read the first's serial tty
# out from under it (the tty is discovered by name below).
name=${LUAPF_VM_NAME:-$(basename "${overlay%.qcow2}")}
transcript=${LUAPF_VM_TRANSCRIPT:-"$root/.vm/$name-console.log"}
tests=${LUAPF_VM_TESTS:-"pf_test_tables.lua pf_test_states.lua \
pf_test_rules.lua pf_test_queues.lua pf_test_system.lua pf_test_nat.lua"}
# Every guest rule carries `log`, and pflog0 is captured for the whole run,
# so a failed test comes back with the packets that reached PF rather than
# only rule counters. The dump is bounded because it returns over the same
# 115200 serial console as everything else.
pflog_lines=${LUAPF_VM_PFLOG_LINES:-120}

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
created_overlay=false
passed=false
driver=
guest_script=

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
	if [[ -n $driver ]]; then
		rm -f "$driver"
	fi
	if [[ -n $guest_script ]]; then
		rm -f "$guest_script"
	fi
	# A successful run's overlay is kept on purpose so its disk can be
	# inspected afterwards. A failed one is not: the script refuses to
	# start when the overlay exists, so leaving it behind would wedge
	# every later run under the same overlay name.
	if ! $passed && $created_overlay; then
		rm -f "$overlay"
	fi
	return 0
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
created_overlay=true
if $use_uplink; then
	doas vmctl start -m 1G -d "$overlay" -n uplink "$name"
else
	doas vmctl start -m 1G -d "$overlay" "$name"
fi
started=true

# vmctl start returns once vmd accepted the guest, which is before vmd has
# published the guest's serial tty, so poll instead of reading status once.
tty=
waited=0
while (( waited < 10 )); do
	tty=$(doas vmctl status -r | awk -v name="$name" '$NF == name {print $6}')
	if [[ -n $tty && -c /dev/$tty ]]; then
		break
	fi
	sleep 1
	waited=$((waited + 1))
done
[[ -n $tty && -c /dev/$tty ]] ||
    fail "cannot discover serial tty for $name after ${waited}s"
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
cat >"$guest_script" <<GUEST
set -e; cd /root; rm -rf luapf; mkdir luapf; tar -xzhf /root/source.tgz -C luapf; cd luapf; meson setup build; ninja -C build; printf '%s\n' 'pass log' | pfctl -f -; ifconfig pflog0 up; tcpdump -n -i pflog0 -w /tmp/pflog.pcap >/dev/null 2>&1 & pflog=\$!; sleep 1; nc -l 127.0.0.1 31337 </dev/null >/dev/null & listener=\$!; sleep 1; print x | nc -N 127.0.0.1 31337 || true; kill "\$listener" 2>/dev/null || true; export LUA_CPATH="\$PWD/build/?.so"; status=0; for test in $tests; do lua54 "\$test" || { status=\$?; break; }; done; sleep 1; kill "\$pflog" 2>/dev/null || true; sleep 1; print -- "--- pflog (last $pflog_lines of \$(tcpdump -n -r /tmp/pflog.pcap 2>/dev/null | wc -l) packets) ---"; tcpdump -n -e -ttt -r /tmp/pflog.pcap 2>&1 | tail -n $pflog_lines || true; exit \$status
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

# `set -e` would abort here before the exit status could be reported, so keep
# the driver in a list whose failure is handled. cleanup removes the temp files.
status=0
doas env LUA_CPATH="$LUA_CPATH" lua5.4 "$driver" "$root/examples" "$tty" \
    "$root_password" "$archive" "$guest_script" "$transcript" || status=$?
(( status == 0 )) || fail "guest driver failed (exit $status)"

started=false
passed=true
print -r -- "run-pf-vm-tests: all tests passed in disposable overlay: $overlay"
