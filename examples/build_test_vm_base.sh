#!/bin/ksh -e
# Build a powered-off OpenBSD base image for disposable luapf PF tests.
#
# This intentionally destroys the target disk.  The guest finds its own way
# to an autoinstall over the network -- see below -- so nothing is ever
# embedded into bsd.rd itself; the unmodified release installer is used
# as-is.  Package installation (lua54, meson, ninja) is driven from the
# host over the serial console after the post-install reboot, not from an
# rc.firsttime baked into the image -- see the comment above that decision
# in examples/autoinstall/install.site for why: rc(8) runs rc.firsttime
# right after starting dhcpleased/resolvd, not after they've actually
# converged, and racing pkg_add against that asynchronously-provisioned
# resolv.conf failed often enough in practice (pkg_add erroring "no
# address associated with name" while the guest's own root shell, minutes
# later, resolves fine) to be worth avoiding rather than patching around
# with a sleep/retry loop baked into the ramdisk. Driving it from the host
# means this script can simply wait until the network actually works
# before running pkg_add, the same way a human at the console would.
#
# How the guest finds its autoinstall response file, with no serial
# console poking and no /auto_install.conf baked into the ramdisk:
#
#   vmctl start -B net -L tells vmd to mark the guest's vio0 as the boot
#   device (see vionet.pxeboot in /usr/src/usr.sbin/vmd/virtio.c).  vmd's
#   own built-in DHCP responder (dhcp.c) then answers the installer's
#   normal initial DHCP request with next-server = the host-side tap
#   address and filename = "auto_install" -- exactly the two DHCP options
#   /usr/src/distrib/miniroot/install.sub's get_responsefile() looks for to
#   behave "as if the machine is netbooted" (autoinstall(8)) and fetch its
#   response file over HTTP entirely on its own, all before the installer
#   would otherwise have prompted at the serial console.  bsd.rd itself is
#   used completely unmodified.
#
# Usage:
#   build_test_vm_base.sh [stage] [release-bsd.rd] [target.qcow2] [vm-name]

selfdir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$selfdir/.." && pwd)
stage=${1:-"$root/build/autoinstall-httpd"}
release_rd=${2:-/home/mischief/vmd/luapf/bsd.rd-7.9}
disk=${3:-/home/mischief/vmd/luapf/luapf-pf-test-base.qcow2}
name=${4:-luapf-pf-test-bootstrap}
port=80
timeout=${LUAPF_VM_BOOTSTRAP_TIMEOUT:-1800}
setdir="$stage/pub/OpenBSD/7.9/amd64"
lock="$stage/.build-test-vm-base.lock"
site_src="$selfdir/autoinstall"
server_pid=
vm_started=false
lock_held=false
cleaned_up=false

# serialutil.so is this repo's own (examples/serialutil/serialutil.c,
# built by this project's own meson build -- see meson.build), reached
# through LUA_CPATH the same way meson's own devenv/test setup do
# (require("serialutil"), not an *_SO environment variable). No external
# tree needs to be checked out beside luapf for this to run.
build=${LUAPF_BUILD_DIR:-"$root/build"}
export LUA_CPATH="$build/?.so;;"
root_password=${LUAPF_ROOT_PASSWORD:-13ZU8cJXvLK58O4cUiVJbvY4}

fail() {
	echo "build-test-vm-base: $*" >&2
	exit 1
}

cleanup() {
	$cleaned_up && return
	cleaned_up=true
	if [[ -n $server_pid ]]; then
		doas kill "$server_pid" >/dev/null 2>&1 || true
		# Do not wait here: signal cleanup must never wait indefinitely for it.
		server_pid=
	fi
	if $lock_held; then
		rmdir "$lock" >/dev/null 2>&1 || true
	fi
}

terminate() {
	cleanup
	exit 1
}
trap cleanup EXIT
trap terminate HUP INT TERM

[[ -r $release_rd ]] || fail "release installer is not readable: $release_rd (run fetch_release_sets.sh first)"
[[ -r $build/serialutil.so ]] || fail "$build/serialutil.so is not readable " \
    "(build it: cd $root && meson setup build && ninja -C build serialutil.so)"

# Stage the tracked response file, disklabel template and site tarball into
# the (untracked, regenerable) HTTP stage dir.  These are small and authored
# by hand, so they live under examples/autoinstall/ in git rather than
# build/, which fetch_release_sets.sh otherwise populates with hundreds of
# megabytes of downloaded release sets that have no business in version
# control.  install.conf keeps the literal token @ADDRESS@ everywhere it
# needs to name this server -- dynamic_file_server.lua renders it per
# request from the client's own Host: header, since the host-side tap
# address a -L guest sees isn't known (or even ours to predict, on a host
# that may have other VMs already running) until vmd has actually started
# it.
mkdir -p "$setdir"
install -m 644 "$site_src/install.conf" "$stage/install.conf"
install -m 644 "$site_src/luapf-root-only.disklabel" "$stage/luapf-root-only.disklabel"
tar -C "$site_src" -czf "$setdir/site79.tgz" install.site

# The builder has one fixed target VM/disk and listener; reject concurrent
# invocations before creating or removing any generated resource.
mkdir "$lock" 2>/dev/null || fail "another build-test-vm-base run holds $lock"
lock_held=true
for file in SHA256 SHA256.sig BUILDINFO INSTALL.amd64 bsd base79.tgz comp79.tgz site79.tgz index.txt; do
	[[ -r $setdir/$file ]] || fail "missing staged file: $setdir/$file"
done
[[ ! -e $disk ]] || fail "target disk already exists: $disk"

# Release artifacts are acquired and verified when the persistent stage is
# populated.  Do not repeat expensive signature verification for every
# disposable-image build; this builder only checks that the expected staged
# files exist, then ensures its local source bsd.rd is the staged installer.
cmp "$release_rd" "$setdir/bsd.rd" || fail "release bsd.rd differs from staged bsd.rd"

# Bound to 0.0.0.0:80 (not a specific tap address), so it can start before
# the VM exists at all -- nothing about it depends on which vmid vmd ends
# up assigning.  Port 80 needs root, hence doas; vmctl needs it anyway.
doas lua54 "$root/examples/dynamic_file_server.lua" "$port" "$stage" &
server_pid=$!
sleep 1
curl -fsS "http://127.0.0.1:$port/install.conf" | grep -qv '@ADDRESS@' ||
	fail "dynamic file server did not render install.conf"
curl -fsSI "http://127.0.0.1:$port/pub/OpenBSD/7.9/amd64/SHA256.sig" >/dev/null

# A fresh qcow2 is the base image; the guest can alter only this disk.
# bsd.rd is used exactly as staged/verified -- no embedding step at all.
doas vmctl create -s 20G "$disk"
doas vmctl start -m 1G -B net -b "$release_rd" -d "$disk" -L "$name"
vm_started=true

tty=$(doas vmctl status -r | awk -v name="$name" '$NF == name {print $6}')
[[ -n $tty && -c /dev/$tty ]] || fail "cannot discover serial tty for $name"
tty=/dev/$tty

# The installer fetches its response file, sets, and reboots into the
# installed system entirely on its own (see the file header comment).
# Everything from here on drives that installed system's console directly,
# the same way run_pf_vm_tests.sh drives a disposable test overlay: one
# lua5.4 process owns the tty from first login through shutdown, because a
# second opener of the same vmd tty steals bytes the first is waiting for.
driver=$(mktemp)
cat >"$driver" <<'LUAEOF'
package.path = arg[1] .. "/?.lua;" .. package.path
local console = require("luapf_console")

local tty, password = arg[2], arg[3]

local c, err = console.open(tty, 115200)
if not c then
	io.stderr:write("build-test-vm-base: cannot open " .. tty .. ": " .. tostring(err) .. "\n")
	os.exit(1)
end

-- Autoinstall (fetching sets, extracting, installing bootblocks) plus the
-- reboot back to a login prompt is the slow part; give it most of the
-- overall timeout.
io.stderr:write("build-test-vm-base: waiting for post-install login prompt\n")
local ok, lerr = c:login("root", password, 1500)
if not ok then
	io.stderr:write("build-test-vm-base: login failed: " .. tostring(lerr) .. "\n")
	os.exit(1)
end

-- rc(8) has only just started dhcpleased/resolvd asynchronously at this
-- point; a shell prompt answering does not mean the network is up yet.
-- Poll for an actual working resolver rather than assume any fixed delay
-- is long enough, since that is exactly the race rc.firsttime lost.
io.stderr:write("build-test-vm-base: waiting for network\n")
local network_ok = false
local deadline = os.time() + 120
while os.time() < deadline do
	local status = c:exec(
	    "/usr/bin/ftp -o /dev/null -w 5 https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64/SHA256.sig",
	    10)
	if status == 0 then
		network_ok = true
		break
	end
end
if not network_ok then
	io.stderr:write("build-test-vm-base: network did not come up in time\n")
	os.exit(1)
end

io.stderr:write("build-test-vm-base: installing packages\n")
local status, out = c:exec(
    "PKG_PATH=https://cdn.openbsd.org/pub/OpenBSD/7.9/packages/amd64/ " ..
    "pkg_add -I lua54 meson ninja", 300)
io.write(out)
if status ~= 0 then
	io.stderr:write("build-test-vm-base: pkg_add failed: exit " .. tostring(status) .. "\n")
	os.exit(1)
end

-- Deliberately last: run_pf_vm_tests.sh's Console:ready() treats this
-- file's presence as proof provisioning actually completed, not merely
-- that the guest booted.
status, out = c:exec("touch /etc/luapf-test-vm-ready", 10)
if status ~= 0 then
	io.stderr:write("build-test-vm-base: could not write ready marker: " .. tostring(out) .. "\n")
	os.exit(1)
end

c:say("halt -p", 0.5)
c:close()
os.exit(0)
LUAEOF

doas env LUA_CPATH="$LUA_CPATH" lua5.4 "$driver" "$root/examples" "$tty" "$root_password"
status=$?
rm -f "$driver"
(( status == 0 )) || fail "guest driver failed (exit $status)"

# vmctl returns a non-running VM only after the halt -p above completes an
# orderly guest poweroff.
deadline=$((SECONDS + timeout))
while doas vmctl status -r | awk '{print $NF}' | grep -qx "$name"; do
	(( SECONDS < deadline )) || fail "timed out waiting for guest poweroff"
	sleep 5
done

echo "build-test-vm-base: guest powered off; base image is ready: $disk"
