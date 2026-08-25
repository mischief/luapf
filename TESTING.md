# Running the PF tests

There are two ways to run them, and they cover different ground.

**Natively**, `meson test` runs the read-only tests against whatever PF
the machine is already running. It needs `doas` and a real `/dev/pf`. A
developer's own ruleset has far more shape than anything built for a
test, so this is what exercises the rule renderer hardest -- but nothing
here may change PF, so the write paths stay untested.

**In a disposable guest**, `examples/run_pf_vm_tests.sh` boots a vmd(8)
VM from a throwaway overlay and runs everything, including the tests that
enable and disable PF, kill states, load rulesets and build interfaces.
Disturbing PF is the point, and the overlay is discarded afterwards.

    meson test -C build --print-errorlogs
    ./examples/run_pf_vm_tests.sh .vm/luapf-pf-test-base-vmd.qcow2 .vm/run.qcow2 isolated

Guests are named after their overlay, so several may run at once as long
as each is given its own.

## Host configuration

The guest reaches the network only for `pkg_add` while the base image is
being built. Everything after that runs isolated. What the host needs:

**vmd(8)**, enabled and running, with a switch for the guests:

    # /etc/vm.conf
    switch "uplink" {
            interface veb0
    }

    # rcctl enable vmd && rcctl start vmd

**The bridge the switch names.** vmd hands guests addresses out of
100.64.0.0/10 and routes them through this:

    # /etc/hostname.veb0
    add vport0
    up

    # /etc/hostname.vport0
    inet 10.0.0.1 255.255.255.0
    up

**Forwarding**, or nothing leaves the guest:

    # /etc/sysctl.conf
    net.inet.ip.forwarding=1

**PF rules for the guest network.** Guests need their traffic translated
on the way out, and their DNS answered:

    match out on egress inet from 100.64.0.0/10 to any nat-to (egress)
    pass in inet proto { tcp, udp } from 100.64.0.0/10 to any port 53 \
        rdr-to 127.0.0.1 port 53

**A resolver on 127.0.0.1** for that redirect to reach -- unwind(8) is
what the default install runs:

    # rcctl enable unwind && rcctl start unwind

Neither the test runner nor the base image builder touches host PF. The
builder does need to bind port 80 while it serves the release sets, so
nothing else may hold it.

## Rebuilding the base image

The base is an OpenBSD guest with lua54, meson and ninja installed, and
nothing else. Tests never boot it directly; each run takes a qcow2
overlay of it. Rebuild it when the release moves, or when it breaks.

Fetch and verify the release artifacts. The third argument overrides the
mirror, which is worth doing if you run one:

    ./examples/fetch_release_sets.sh "$PWD/build/autoinstall-httpd" 7.9 \
        https://mirror.offblast.org

Every signed artifact is checked against `/etc/signify/openbsd-79-base.pub`,
so a missing or wrong signify key stops this before anything is staged.

Then build the image. It boots the release installer with vmd's own DHCP
pointing at a file server this script runs, so the install is unattended
and needs no console interaction:

    ./examples/build_test_vm_base.sh "$PWD/build/autoinstall-httpd" \
        "$PWD/build/autoinstall-httpd/pub/OpenBSD/7.9/amd64/bsd.rd" \
        "$PWD/.vm/luapf-pf-test-base-vmd.qcow2" luapf-pf-test-bootstrap

Two messages during the build are expected and not failures: the
`site79.tgz` checksum warning, because that set is generated here rather
than signed, and a failure to relink a unique kernel.

Then run the suite against it, as above.

Timings on a 16-core machine, from nothing:

    fetch      16s      from a mirror on the same network
    base    5m 12s
    suite   3m 18s      ten test files

## Knobs

    LUAPF_VM_TESTS       which guest-side tests to run
    LUAPF_VM_COVERAGE    build the guest copy instrumented and report
                         what the run reached
    LUAPF_VM_KERNEL      boot a kernel of your own, for testing a change
                         to pf(4) against these tests
    LUAPF_VM_PFLOG_LINES how much of the pflog dump to bring back
    LUAPF_BUILD_DIR      where serialutil.so is
    LUAPF_ROOT_PASSWORD  the guest's root password

Every guest rule carries `log`, and pflog0 is captured for the whole run,
so a failing test comes back with the packets that reached PF rather than
rule counters alone. The dump is bounded because it returns over the same
115200 serial console as everything else.
