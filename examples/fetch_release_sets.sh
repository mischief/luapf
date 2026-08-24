#!/bin/ksh -e
# Fetch and signify(1)-verify the OpenBSD release artifacts
# build_test_vm_base.sh needs to autoinstall a 7.9 guest, into a stage
# directory suitable for serving with dynamic_file_server.lua.
#
# Idempotent: files already present are not re-fetched, so re-running
# after an interrupted download only fills in what is missing. Re-run
# with a stage that already has everything and it just re-verifies.
#
# Usage: fetch_release_sets.sh [stage] [release] [mirror]

selfdir=$(cd "$(dirname "$0")" && pwd)
stage=${1:-"$selfdir/../build/autoinstall-httpd"}
release=${2:-7.9}
mirror=${3:-https://cdn.openbsd.org}

setdir="$stage/pub/OpenBSD/$release/amd64"
pubkey="/etc/signify/openbsd-${release%.*}${release#*.}-base.pub"

fail() { print -u2 -r -- "fetch-release-sets: $*"; exit 1; }

[[ -r $pubkey ]] || fail "signify pubkey not found: $pubkey " \
    "(wrong release, or signify-* package missing)"

mkdir -p "$setdir"
cd "$setdir"

for file in SHA256 SHA256.sig BUILDINFO INSTALL.amd64 bsd bsd.rd \
    base79.tgz comp79.tgz index.txt; do
	# base79.tgz/comp79.tgz are named for the two-digit release
	# (79 == 7.9); this only targets 7.9 today, same as the rest of
	# this example -- generalizing the version substitution isn't
	# worth it for a fixture that pins one release throughout.
	[[ -f $file ]] && continue
	echo "fetching $file"
	ftp -o "$file" "$mirror/pub/OpenBSD/$release/amd64/$file"
done

echo "verifying signed release artifacts"
signify -C -p "$pubkey" -x SHA256.sig \
    bsd bsd.rd base79.tgz comp79.tgz INSTALL.amd64

echo "fetch-release-sets: staged and verified under $setdir"
