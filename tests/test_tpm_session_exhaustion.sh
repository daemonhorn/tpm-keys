#!/bin/sh
# Regression test for a real incident found debugging a live account: a raw
# hardware TPM (no kernel/userspace resource manager) has only a handful of
# session slots, and back-to-back tpm2_nvread calls (this project's own
# extensive testing, or just several unlock attempts in a row) can exhaust
# them -- TPM_RC_SESSION_MEMORY (0x903), rendered by tpm2-tools as "out of
# memory for session contexts" followed by "Invalid handle or
# authorization". That looked exactly like a wrong PIN, and simply retrying
# the same failing call (the pre-existing retry loop) does nothing, since
# nothing frees the exhausted slots between attempts.
#
# Separately: the SAME incident showed a real live TPM's dictionary-attack
# lockout counter climb from 1 to 7 while debugging this, because when the
# SSH key fails to load (for ANY reason, including this exhaustion), the
# API-key unlock path in agent mode used to fall back to trying the raw
# Master PIN against an index that was never sealed with it -- a
# guaranteed-wrong authorization attempt that only burns the lockout
# counter for nothing. Covered separately below.
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

# FAKE_FAIL_COUNT calls fail with the real 0x903 error text before
# succeeding (reading a 6-byte header for FAKE_HDR_HEX, or the payload for
# FAKE_PAYLOAD, depending on -s/--offset). Counts real invocations via a
# call-count file so the test can assert exactly how many attempts happened
# and that a flush was actually run in between.
cat > "$FAKEBIN/tpm2_nvread" <<'EOF'
#!/bin/sh
COUNT_FILE="$FAKE_CALL_COUNT_FILE"
N=0
[ -f "$COUNT_FILE" ] && N=$(cat "$COUNT_FILE")
N=$((N + 1))
echo "$N" > "$COUNT_FILE"
if [ "$N" -le "${FAKE_FAIL_COUNT:-0}" ]; then
    echo "WARNING:esys:src/tss2-esys/api/Esys_StartAuthSession.c:391:Esys_StartAuthSession_Finish() Received TPM Error" >&2
    echo "ERROR:esys:src/tss2-esys/api/Esys_StartAuthSession.c:136:Esys_StartAuthSession() Esys Finish ErrorCode (0x00000903)" >&2
    echo "ERROR: Esys_StartAuthSession(0x903) - tpm:warn(2.0): out of memory for session contexts" >&2
    echo "ERROR: Invalid handle or authorization." >&2
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

cat > "$FAKEBIN/tpm2_flushcontext" <<EOF
#!/bin/sh
echo "flush \$1" >> "$TMPDIR/flush.log"
EOF
chmod +x "$FAKEBIN/tpm2_flushcontext"

run_case() {
    : > "$TMPDIR/callcount"
    : > "$TMPDIR/flush.log"
    # No `set -e` here: none of _tpm_read_secret's real callers (the
    # interactive-shell unlock_tpm hooks, .tpm_unlock_helper.sh) run under
    # it -- a non-zero return is an expected, handled outcome (wrong PIN,
    # index does not exist), not a script-ending error.
    env "$@" PATH="$FAKEBIN:/bin:/usr/bin" FAKE_CALL_COUNT_FILE="$TMPDIR/callcount" \
        TPM_HDR_SIZE=6 TPM_HDR_MAGIC1=165 TPM_HDR_MAGIC2=126 \
        sh -c ". '$SNIPPET'; RAW=\$(_tpm_read_secret 0x1502000 testpin); printf '%s' \"\$RAW\"" 2>"$TMPDIR/stderr"
}

echo "=== session exhaustion on the very first call, recovers via retry ==="
OUT=$(run_case FAKE_FAIL_COUNT=1 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello")
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE unexpectedly recovering from a single session-exhaustion failure"
else
    case "$OUT" in *"hello"*) pass "recovers the secret after one session-exhaustion failure" ;; *) fail "did not recover the secret: $OUT" ;; esac
fi
if grep -q "flush -t" "$TMPDIR/flush.log" && grep -q "flush -s" "$TMPDIR/flush.log" && grep -q "flush -l" "$TMPDIR/flush.log"; then
    pass "flushes transient/session/loaded contexts on detecting session exhaustion"
else
    fail "did not flush all three context types on detecting session exhaustion: $(cat "$TMPDIR/flush.log")"
fi
if grep -q "session slots" "$TMPDIR/stderr"; then
    pass "tells the user plainly what happened (not a silent retry)"
else
    fail "did not print a note about the session-exhaustion recovery: $(cat "$TMPDIR/stderr")"
fi

echo "=== no exhaustion at all -- must not flush unnecessarily ==="
run_case FAKE_FAIL_COUNT=0 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello" >/dev/null 2>"$TMPDIR/stderr"
if [ -s "$TMPDIR/flush.log" ]; then
    fail "flushed contexts even though nothing failed"
else
    pass "does not flush contexts on a clean read"
fi

echo "=== exhausted on every attempt -- fails cleanly, still only 3 tries ==="
OUT=$(run_case FAKE_FAIL_COUNT=99 FAKE_HDR_BYTES='\0245\01760005' FAKE_PAYLOAD="hello")
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE unexpectedly when every attempt hits session exhaustion"
else
    case "$OUT" in
        "") pass "still fails cleanly (empty output, no crash) when exhaustion never clears" ;;
        *) fail "expected empty output when every attempt fails, got: $OUT" ;;
    esac
fi
CALLS=$(cat "$TMPDIR/callcount")
if [ "$CALLS" -eq 3 ]; then
    pass "still caps header-peek attempts at 3, even under persistent exhaustion"
else
    fail "expected exactly 3 header-peek attempts, got $CALLS"
fi

echo "=== a genuinely wrong PIN (unrelated error) is not mistaken for session exhaustion ==="
cat > "$FAKEBIN/tpm2_nvread" <<'EOF'
#!/bin/sh
echo "ERROR: Esys_NV_Read(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter incremented" >&2
exit 1
EOF
chmod +x "$FAKEBIN/tpm2_nvread"
: > "$TMPDIR/flush.log"
env PATH="$FAKEBIN:/bin:/usr/bin" sh -ec ". '$SNIPPET'; _tpm_read_secret 0x1502000 wrongpin" >/dev/null 2>"$TMPDIR/stderr"
CODE=$?
if [ -s "$TMPDIR/flush.log" ]; then
    fail "flushed contexts for an unrelated auth failure -- should only trigger on session exhaustion"
else
    pass "does not flush contexts for a genuinely wrong PIN / unrelated TPM error"
fi

# Regression for a real report on dhorn@freebsd-test: typing a deliberately
# wrong PIN surfaced only ssh-add's own generic "error in libcrypto" (from
# being handed empty input) and a bare "Failed to load SSH key.", with
# nothing saying it was the PIN. _tpm_read_secret must now say so plainly
# on its own stderr, discriminating this specific TPM return code (0x98E)
# from any other reason a read might fail.
if grep -q "incorrect PIN" "$TMPDIR/stderr"; then
    pass "tells the user plainly that the PIN was rejected (not a silent/generic failure)"
else
    fail "did not explain that this was an incorrect PIN: $(cat "$TMPDIR/stderr")"
fi

echo "=== an unrecognized TPM failure (not session exhaustion, lockout, or a wrong PIN) still surfaces something, not silence ==="
cat > "$FAKEBIN/tpm2_nvread" <<'EOF'
#!/bin/sh
echo "ERROR: Esys_TR_FromTPMPublic(0x18B) - tpm:handle(1):the handle is not correct for the use" >&2
echo "ERROR: Unable to run tpm2_nvread" >&2
exit 1
EOF
chmod +x "$FAKEBIN/tpm2_nvread"
env PATH="$FAKEBIN:/bin:/usr/bin" sh -ec ". '$SNIPPET'; _tpm_read_secret 0x1502000 somepin" >/dev/null 2>"$TMPDIR/stderr"
if grep -q "incorrect PIN" "$TMPDIR/stderr"; then
    fail "misattributed an unrelated TPM error (bad/nonexistent index) to an incorrect PIN: $(cat "$TMPDIR/stderr")"
elif grep -q "Unable to run tpm2_nvread" "$TMPDIR/stderr"; then
    pass "surfaces the actual TPM error text instead of failing silently for an unrecognized error"
else
    fail "gave no usable diagnostic at all for an unrecognized TPM failure: $(cat "$TMPDIR/stderr")"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
