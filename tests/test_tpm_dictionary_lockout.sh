#!/bin/sh
# Regression test for a real incident found debugging a live account
# (dhorn@freebsd-test): a raw hardware TPM's dictionary-attack lockout
# tripped (TPM_RC_LOCKOUT, 0x921 -- "authorizations for objects subject to
# DA protection are not allowed at this time because the TPM is in DA
# lockout mode") from earlier wrong-PIN attempts (the bug fixed separately
# in test_agent_pin_no_wrong_attempt.sh). Once locked, the TPM refuses
# EVERY authorization -- including a subsequently-correct PIN -- and
# _tpm_read_secret used to swallow the real reason (stderr redirected to
# a temp file only inspected for the unrelated 0x903 pattern), surfacing
# only as a generic "Failed to load SSH key" / "Failed to load API
# secret." with no hint that the TPM itself needed to be unlocked.
#
# _tpm_read_secret now detects 0x921/"lockout mode" specifically, and
# (since this TPM never had a lockout password set) clears it
# automatically with `tpm2_dictionarylockout --clear-lockout` and retries
# once. If the clear command itself fails (a lockout password IS set, or
# the caller lacks permission) or the TPM is still locked after clearing,
# it stops retrying immediately (further identical attempts won't help)
# and prints a clear, actionable message instead of the generic failure.
#
# Separately: a raw hardware TPM's DA counter is shared across the whole
# chip, not per-index, and the header-peek loop alone retries up to 3
# times -- enough by itself to turn a genuinely WRONG PIN into a lockout
# mid-call (MAX_AUTH_FAIL is commonly 3). Confirmed directly on
# dhorn@freebsd-test: typing a deliberately wrong PIN produced "[TPM]
# Note: the TPM was in dictionary-attack lockout from prior failed
# attempts (not a wrong PIN) -- cleared automatically, retrying." --
# which is actively misleading (it WAS this PIN) -- followed by the SSH
# key failing as expected, but then "[TPM] Secrets loaded." for the API
# key, because the auto-clear-and-retry used the separately-derived
# agent PIN, which happened to still be valid from an earlier session.
# _tpm_read_secret now tracks, within a single call, whether THIS PIN
# already produced a genuine wrong-PIN failure (0x98E, "the authorization
# HMAC check failed") before any lockout is seen. If so, a subsequent
# lockout is attributed to this PIN, not treated as a leftover, and it is
# not retried.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/lib/extract.sh"

TESTS_RUN=0
TESTS_FAILED=0
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
FAKEBIN="$TMPDIR/fakebin"
mkdir -p "$FAKEBIN"

SNIPPET="$TMPDIR/read_secret.sh"
extract_func "$REPO_ROOT/tpm_setup.sh" "_tpm_read_secret" > "$SNIPPET"
if [ ! -s "$SNIPPET" ]; then
    fail "could not extract _tpm_read_secret from tpm_setup.sh -- did it move/change shape?"
    printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
    exit 1
fi

# FAKE_LOCKOUT_FAIL_COUNT calls fail with the real 0x921 lockout error text
# before succeeding. FAKE_LOCKOUT_CLEAR_OK controls whether the fake
# tpm2_dictionarylockout succeeds (mirrors the real "no lockout password
# set" case) or fails (mirrors "a lockout password is set" / no permission).
cat > "$FAKEBIN/tpm2_nvread" <<'EOF'
#!/bin/sh
COUNT_FILE="$FAKE_CALL_COUNT_FILE"
N=0
[ -f "$COUNT_FILE" ] && N=$(cat "$COUNT_FILE")
N=$((N + 1))
echo "$N" > "$COUNT_FILE"
if [ "$N" -le "${FAKE_LOCKOUT_FAIL_COUNT:-0}" ]; then
    echo "WARNING:esys:src/tss2-esys/api/Esys_NV_Read.c:315:Esys_NV_Read_Finish() Received TPM Error" >&2
    echo "ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode (0x00000921)" >&2
    echo "ERROR: Esys_NV_Read(0x921) - tpm:warn(2.0): authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode" >&2
    exit 1
fi
OFFSET=0
for ARG in "$@"; do
    case "$ARG" in --offset=*) OFFSET="${ARG#--offset=}" ;; esac
done
if [ "$OFFSET" = "0" ]; then
    printf '%b' "$FAKE_HDR_BYTES"
else
    printf '%s' "$FAKE_PAYLOAD"
fi
EOF
chmod +x "$FAKEBIN/tpm2_nvread"

cat > "$FAKEBIN/tpm2_dictionarylockout" <<EOF
#!/bin/sh
echo "clear-lockout" >> "$TMPDIR/lockout.log"
[ "\${FAKE_LOCKOUT_CLEAR_OK:-1}" = "1" ]
EOF
chmod +x "$FAKEBIN/tpm2_dictionarylockout"

cat > "$FAKEBIN/tpm2_flushcontext" <<EOF
#!/bin/sh
echo "flush \$1" >> "$TMPDIR/flush.log"
EOF
chmod +x "$FAKEBIN/tpm2_flushcontext"

run_case() {
    : > "$TMPDIR/callcount"
    : > "$TMPDIR/lockout.log"
    : > "$TMPDIR/flush.log"
    env "$@" PATH="$FAKEBIN:/bin:/usr/bin" FAKE_CALL_COUNT_FILE="$TMPDIR/callcount" \
        TPM_HDR_SIZE=6 TPM_HDR_MAGIC1=165 TPM_HDR_MAGIC2=126 \
        sh -c ". '$SNIPPET'; RAW=\$(_tpm_read_secret 0x1502000 testpin); printf '%s' \"\$RAW\"" 2>"$TMPDIR/stderr"
}

echo "=== locked out on the first call, no lockout password set -- clears automatically and recovers ==="
OUT=$(run_case FAKE_LOCKOUT_FAIL_COUNT=1 FAKE_LOCKOUT_CLEAR_OK=1 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello")
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE unexpectedly recovering from a single lockout"
else
    case "$OUT" in *"hello"*) pass "recovers the secret after auto-clearing a lockout" ;; *) fail "did not recover the secret: $OUT" ;; esac
fi
if [ "$(cat "$TMPDIR/lockout.log" 2>/dev/null | wc -l)" -eq 1 ]; then
    pass "calls tpm2_dictionarylockout --clear-lockout exactly once"
else
    fail "expected exactly one clear-lockout call, got: $(cat "$TMPDIR/lockout.log" 2>/dev/null)"
fi
if grep -q "dictionary-attack lockout" "$TMPDIR/stderr" && grep -q "cleared automatically" "$TMPDIR/stderr"; then
    pass "tells the user plainly that a lockout was cleared (not a silent retry)"
else
    fail "did not print a note about the lockout auto-clear: $(cat "$TMPDIR/stderr")"
fi

echo "=== locked out, and the clear command itself fails (e.g. a lockout password is set) -- stops immediately, clear message ==="
OUT=$(run_case FAKE_LOCKOUT_FAIL_COUNT=99 FAKE_LOCKOUT_CLEAR_OK=0 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello")
CODE=$?
case "$OUT" in
    "") pass "fails cleanly (empty output) when the lockout cannot be cleared" ;;
    *) fail "expected empty output when clearing fails, got: $OUT" ;;
esac
CALLS=$(cat "$TMPDIR/callcount")
if [ "$CALLS" -eq 1 ]; then
    pass "stops after the first attempt instead of burning further retries against a still-locked TPM"
else
    fail "expected exactly 1 attempt before giving up, got $CALLS"
fi
if grep -q "could not be cleared automatically" "$TMPDIR/stderr"; then
    pass "explains that automatic clearing failed, not a generic failure"
else
    fail "did not explain the failed auto-clear: $(cat "$TMPDIR/stderr")"
fi

echo "=== locked out, clear command reports success but the TPM is still locked on retry -- stops after one retry ==="
OUT=$(run_case FAKE_LOCKOUT_FAIL_COUNT=99 FAKE_LOCKOUT_CLEAR_OK=1 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello")
CODE=$?
case "$OUT" in
    "") pass "fails cleanly (empty output) when still locked after the one auto-clear retry" ;;
    *) fail "expected empty output, got: $OUT" ;;
esac
CALLS=$(cat "$TMPDIR/callcount")
if [ "$CALLS" -eq 2 ]; then
    pass "allows exactly one retry after clearing, then stops (does not loop the full attempt budget against a still-locked TPM)"
else
    fail "expected exactly 2 attempts (original + one post-clear retry), got $CALLS"
fi
if grep -q "still in dictionary-attack lockout after an automatic clear attempt" "$TMPDIR/stderr"; then
    pass "explains the TPM is still locked even after clearing"
else
    fail "did not explain the still-locked state: $(cat "$TMPDIR/stderr")"
fi

echo "=== a genuinely WRONG PIN escalates into a lockout mid-call -- must NOT be reported as a leftover/unrelated lockout ==="
cat > "$FAKEBIN/tpm2_nvread" <<'EOF'
#!/bin/sh
COUNT_FILE="$FAKE_CALL_COUNT_FILE"
N=0
[ -f "$COUNT_FILE" ] && N=$(cat "$COUNT_FILE")
N=$((N + 1))
echo "$N" > "$COUNT_FILE"
if [ "$N" -le "${FAKE_WRONGPIN_COUNT:-0}" ]; then
    echo "ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode (0x0000098e)" >&2
    echo "ERROR: Esys_NV_Read(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter incremented" >&2
else
    echo "ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode (0x00000921)" >&2
    echo "ERROR: Esys_NV_Read(0x921) - tpm:warn(2.0): authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode" >&2
fi
exit 1
EOF
chmod +x "$FAKEBIN/tpm2_nvread"
OUT=$(run_case FAKE_WRONGPIN_COUNT=2 FAKE_LOCKOUT_CLEAR_OK=1)
CODE=$?
case "$OUT" in
    "") pass "fails cleanly (empty output) for a wrong PIN that trips a lockout" ;;
    *) fail "expected empty output, got: $OUT" ;;
esac
CALLS=$(cat "$TMPDIR/callcount")
if [ "$CALLS" -eq 3 ]; then
    pass "stops within the normal 3-attempt budget (2 wrong-PIN failures, then the lockout they caused) instead of retrying"
else
    fail "expected exactly 3 attempts, got $CALLS"
fi
if [ "$(cat "$TMPDIR/lockout.log" 2>/dev/null | wc -l)" -eq 1 ]; then
    pass "still clears the lockout it caused (leaves the TPM usable), but only once"
else
    fail "expected exactly one clear-lockout call, got: $(cat "$TMPDIR/lockout.log" 2>/dev/null)"
fi
if grep -q "this PIN is almost certainly wrong" "$TMPDIR/stderr"; then
    pass "attributes the lockout to this PIN instead of calling it a leftover lockout"
else
    fail "did not attribute the lockout to the wrong PIN: $(cat "$TMPDIR/stderr")"
fi
if grep -q "has not yet failed" "$TMPDIR/stderr"; then
    fail "used the 'leftover lockout, not this PIN' wording even though this PIN caused it: $(cat "$TMPDIR/stderr")"
else
    pass "does not use the leftover-lockout wording for a lockout this PIN actually caused"
fi

echo "=== a lockout with no prior wrong-PIN evidence from THIS call is still reported as a leftover (not attributed to this PIN) ==="
cat > "$FAKEBIN/tpm2_nvread" <<'EOF'
#!/bin/sh
COUNT_FILE="$FAKE_CALL_COUNT_FILE"
N=0
[ -f "$COUNT_FILE" ] && N=$(cat "$COUNT_FILE")
N=$((N + 1))
echo "$N" > "$COUNT_FILE"
if [ "$N" -le "${FAKE_LOCKOUT_FAIL_COUNT:-0}" ]; then
    echo "ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode (0x00000921)" >&2
    echo "ERROR: Esys_NV_Read(0x921) - tpm:warn(2.0): authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode" >&2
    exit 1
fi
OFFSET=0
for ARG in "$@"; do
    case "$ARG" in --offset=*) OFFSET="${ARG#--offset=}" ;; esac
done
if [ "$OFFSET" = "0" ]; then
    printf '%b' "$FAKE_HDR_BYTES"
else
    printf '%s' "$FAKE_PAYLOAD"
fi
EOF
chmod +x "$FAKEBIN/tpm2_nvread"
run_case FAKE_LOCKOUT_FAIL_COUNT=1 FAKE_LOCKOUT_CLEAR_OK=1 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello" >/dev/null 2>"$TMPDIR/stderr"
if grep -q "this PIN is almost certainly wrong" "$TMPDIR/stderr"; then
    fail "attributed a first-attempt lockout (no prior wrong-PIN evidence) to this PIN: $(cat "$TMPDIR/stderr")"
else
    pass "does not blame this PIN for a lockout that was already there before the first attempt"
fi

echo "=== no lockout at all -- must never call tpm2_dictionarylockout ==="
run_case FAKE_LOCKOUT_FAIL_COUNT=0 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello" >/dev/null 2>"$TMPDIR/stderr"
if [ -s "$TMPDIR/lockout.log" ]; then
    fail "called tpm2_dictionarylockout even though nothing was locked"
else
    pass "does not touch lockout state on a clean read"
fi

echo "=== a session-exhaustion error (0x903) is not mistaken for a lockout ==="
cat > "$FAKEBIN/tpm2_nvread" <<'EOF'
#!/bin/sh
echo "ERROR:esys:src/tss2-esys/api/Esys_StartAuthSession.c:136:Esys_StartAuthSession() Esys Finish ErrorCode (0x00000903)" >&2
echo "ERROR: Esys_StartAuthSession(0x903) - tpm:warn(2.0): out of memory for session contexts" >&2
exit 1
EOF
chmod +x "$FAKEBIN/tpm2_nvread"
: > "$TMPDIR/lockout.log"
env PATH="$FAKEBIN:/bin:/usr/bin" sh -ec ". '$SNIPPET'; _tpm_read_secret 0x1502000 testpin" >/dev/null 2>"$TMPDIR/stderr"
if [ -s "$TMPDIR/lockout.log" ]; then
    fail "called tpm2_dictionarylockout for an unrelated session-exhaustion error"
else
    pass "does not call tpm2_dictionarylockout for a session-exhaustion (0x903) error"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
