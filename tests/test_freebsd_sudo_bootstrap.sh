#!/bin/sh
# Tests the FreeBSD sudo-bootstrap logic in tpm_setup.sh's "freebsd") case
# arm: FreeBSD's base system doesn't ship sudo, and everything from the
# tpm2-tools install onward assumes it's already present. Covers all four
# branches (already root / needs su, install succeeds / fails) using fake
# id/pkg/su stubs on a PATH that excludes the real sudo, so this doesn't
# touch the real system.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

TESTS_RUN=0
TESTS_FAILED=0
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
FAKEBIN="$TMPDIR/fakebin"
mkdir -p "$FAKEBIN"

SNIPPET="$TMPDIR/snippet.sh"
awk '/^        if ! command -v sudo/,/^        fi$/' "$REPO_ROOT/tpm_setup.sh" > "$SNIPPET"
if [ ! -s "$SNIPPET" ]; then
    fail "could not extract the sudo-bootstrap snippet from tpm_setup.sh (did it move/change shape?)"
    printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
    exit 1
fi

cat > "$FAKEBIN/pkg" <<EOF
#!/bin/sh
if [ "\$FAKE_PKG_FAIL" = "1" ]; then
    echo "pkg: install failed (simulated)" >&2
    exit 1
fi
if [ "\$1" = "install" ]; then
    printf '#!/bin/sh\nexec "\$@"\n' > "$FAKEBIN/sudo"
    chmod +x "$FAKEBIN/sudo"
fi
exit 0
EOF
cat > "$FAKEBIN/su" <<EOF
#!/bin/sh
if [ "\$FAKE_SU_FAIL" = "1" ]; then
    echo "su: Sorry (simulated)" >&2
    exit 1
fi
"$FAKEBIN/pkg" install -y sudo
EOF
chmod +x "$FAKEBIN/pkg" "$FAKEBIN/su"

# Real sh/printf/etc still need to be reachable; only sudo itself is
# excluded, by pointing PATH at fakebin + the real base-system dirs
# instead of wherever the real sudo binary happens to live.
TESTPATH="$FAKEBIN:/bin:/usr/bin"

run_case() {
    LABEL="$1"
    FAKE_UID="$2"
    FAKE_SU_FAIL="$3"
    FAKE_PKG_FAIL="$4"
    EXPECT_SUCCESS="$5"
    rm -f "$FAKEBIN/sudo" "$FAKEBIN/id"
    printf '#!/bin/sh\n[ "$1" = "-u" ] && echo "%s"\n' "$FAKE_UID" > "$FAKEBIN/id"
    chmod +x "$FAKEBIN/id"
    OUT=$(env -i PATH="$TESTPATH" FAKE_SU_FAIL="$FAKE_SU_FAIL" FAKE_PKG_FAIL="$FAKE_PKG_FAIL" sh -c ". $SNIPPET" 2>&1)
    CODE=$?
    if [ "$EXPECT_SUCCESS" = "1" ]; then
        if [ "$CODE" -eq 0 ] && [ -x "$FAKEBIN/sudo" ]; then
            pass "$LABEL"
        else
            fail "$LABEL (exit=$CODE): $OUT"
        fi
    else
        if [ "$CODE" -ne 0 ] && printf '%s' "$OUT" | grep -q "pkg install -y sudo"; then
            pass "$LABEL"
        else
            fail "$LABEL (exit=$CODE, missing actionable guidance): $OUT"
        fi
    fi
}

run_case "already root, install succeeds"     0    0 0 1
run_case "already root, install fails"        0    0 1 0
run_case "not root, su succeeds"              1000 0 0 1
run_case "not root, su fails"                 1000 1 0 0

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
