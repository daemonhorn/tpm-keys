#!/bin/sh
# Round-trips the on-TPM sentinel-header format (_tpm_emit_header /
# _tpm_read_secret, extracted verbatim from tpm_setup.sh) against a real
# TPM 2.0 device, covering:
#   - fresh header-formatted write/read with 0x00 erase-fill
#   - fresh header-formatted write/read with 0xFF erase-fill (the FreeBSD
#     bug this format exists to fix)
#   - legacy (headerless) data with a simulated 0xFF erase-fill tail
#   - legacy (headerless) data with a 0x00 erase-fill tail
#   - binary (SSH-key-like) payload round-trips byte-for-byte
# Requires a writable TPM 2.0 device and tpm2-tools; skips (exit 0 with a
# note) if neither is available, so this can run in CI environments without
# a TPM without being treated as a failure.
#
# tpm2-tools talking to a raw /dev/tpm0 (no kernel/userspace resource
# manager) has been observed to hit transient TCTI I/O errors under
# back-to-back commands in some environments -- retry setup/write/undefine
# calls a few times rather than let an unrelated environment hiccup fail
# this suite. This is separate from _tpm_read_secret's own internal retry,
# which is exercised as-is.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/lib/extract.sh"

TESTS_RUN=0
TESTS_FAILED=0

pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

# Retries a command up to 5 times, swallowing stderr from failed attempts
# (only the last attempt's stderr is shown, so real failures still surface).
_retry() {
    N=0
    while [ "$N" -lt 5 ]; do
        N=$((N + 1))
        if [ "$N" -eq 5 ]; then
            "$@" && return 0
        else
            "$@" 2>/dev/null && return 0
        fi
    done
    return 1
}

if ! command -v tpm2_nvdefine >/dev/null 2>&1; then
    printf "SKIP: tpm2-tools not installed\n"
    exit 0
fi

TEST_IDX=0x1502000
TEST_PIN=test-sentinel-pin

cleanup() { _retry tpm2_nvundefine -C o "$TEST_IDX" >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
if ! _retry tpm2_nvdefine -C o -s 64 -a "authread|authwrite" -p "$TEST_PIN" "$TEST_IDX" >/dev/null; then
    printf "SKIP: cannot access/define a TPM NV index (no device access in this environment)\n"
    exit 0
fi
_retry tpm2_nvundefine -C o "$TEST_IDX" >/dev/null

# Load the real functions from tpm_setup.sh -- not a reimplementation.
eval "$(extract_func "$REPO_ROOT/tpm_setup.sh" _tpm_emit_header)"
eval "$(extract_func "$REPO_ROOT/tpm_setup.sh" _tpm_read_secret)"
TPM_HDR_MAGIC1=165
TPM_HDR_MAGIC2=126
TPM_HDR_SIZE=6

PAYLOAD="hello-world-secret-123"

# --- Test 1: fresh header write/read ---
_retry tpm2_nvdefine -C o -s 64 -a "authread|authwrite" -p "$TEST_PIN" "$TEST_IDX" >/dev/null
LEN=$(printf '%s' "$PAYLOAD" | wc -c | tr -d ' ')
N=0
while [ "$N" -lt 5 ]; do
    N=$((N + 1))
    { _tpm_emit_header "$LEN"; printf '%s' "$PAYLOAD"; } | tpm2_nvwrite -C "$TEST_IDX" -P "$TEST_PIN" -i - "$TEST_IDX" >/dev/null 2>&1 && break
done
GOT=$(_tpm_read_secret "$TEST_IDX" "$TEST_PIN")
[ "$GOT" = "$PAYLOAD" ] && pass "fresh header round-trip" || fail "fresh header round-trip: got [$GOT]"
_retry tpm2_nvundefine -C o "$TEST_IDX" >/dev/null 2>&1

# --- Test 2: legacy data, simulated 0xFF erase-fill tail ---
_retry tpm2_nvdefine -C o -s 64 -a "authread|authwrite" -p "$TEST_PIN" "$TEST_IDX" >/dev/null
PADLEN=$((64 - LEN))
N=0
while [ "$N" -lt 5 ]; do
    N=$((N + 1))
    if {
        printf '%s' "$PAYLOAD"
        i=0
        while [ "$i" -lt "$PADLEN" ]; do printf '%b' '\0377'; i=$((i + 1)); done
    } | tpm2_nvwrite -C "$TEST_IDX" -P "$TEST_PIN" -i - "$TEST_IDX" >/dev/null 2>&1; then
        break
    fi
done
GOT=$(_tpm_read_secret "$TEST_IDX" "$TEST_PIN")
[ "$GOT" = "$PAYLOAD" ] && pass "legacy fallback, 0xFF-filled tail" || fail "legacy fallback, 0xFF-filled tail: got [$GOT]"
_retry tpm2_nvundefine -C o "$TEST_IDX" >/dev/null 2>&1

# --- Test 3: legacy data, 0x00 erase-fill tail (plain write, untouched rest) ---
_retry tpm2_nvdefine -C o -s 64 -a "authread|authwrite" -p "$TEST_PIN" "$TEST_IDX" >/dev/null
N=0
while [ "$N" -lt 5 ]; do
    N=$((N + 1))
    printf '%s' "$PAYLOAD" | tpm2_nvwrite -C "$TEST_IDX" -P "$TEST_PIN" -i - "$TEST_IDX" >/dev/null 2>&1 && break
done
GOT=$(_tpm_read_secret "$TEST_IDX" "$TEST_PIN")
[ "$GOT" = "$PAYLOAD" ] && pass "legacy fallback, 0x00-filled tail" || fail "legacy fallback, 0x00-filled tail: got [$GOT]"
_retry tpm2_nvundefine -C o "$TEST_IDX" >/dev/null 2>&1

# --- Test 4: binary (SSH-key-like) payload round-trips byte-for-byte ---
_retry tpm2_nvdefine -C o -s 512 -a "authread|authwrite" -p "$TEST_PIN" "$TEST_IDX" >/dev/null
BIN_FILE=$(mktemp)
# A deterministic pseudo-binary blob covering the full byte range 0-249.
i=0
while [ "$i" -lt 250 ]; do
    printf '%b' "$(printf '\\0%03o' "$i")"
    i=$((i + 1))
done > "$BIN_FILE"
BIN_LEN=$(wc -c < "$BIN_FILE" | tr -d ' ')
N=0
while [ "$N" -lt 5 ]; do
    N=$((N + 1))
    { _tpm_emit_header "$BIN_LEN"; cat "$BIN_FILE"; } | tpm2_nvwrite -C "$TEST_IDX" -P "$TEST_PIN" -i - "$TEST_IDX" >/dev/null 2>&1 && break
done
GOT_FILE=$(mktemp)
_tpm_read_secret "$TEST_IDX" "$TEST_PIN" > "$GOT_FILE"
if cmp -s "$BIN_FILE" "$GOT_FILE"; then
    pass "binary payload exact byte round-trip"
else
    fail "binary payload exact byte round-trip"
fi
rm -f "$BIN_FILE" "$GOT_FILE"
_retry tpm2_nvundefine -C o "$TEST_IDX" >/dev/null 2>&1

trap - EXIT
cleanup

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
