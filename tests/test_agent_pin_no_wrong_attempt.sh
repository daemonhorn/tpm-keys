#!/bin/sh
# Regression test for a real incident found debugging a live account
# (dhorn, PIN correct, but a completely separate live bug tripped over
# along the way): when API_AUTH_MODE=agent, the API key's TPM NV index is
# sealed with a PIN *derived* from an SSH-agent signature challenge, never
# with the raw Master PIN. If the SSH key fails to load for any reason
# (this session's own session-exhaustion incident, a genuinely wrong PIN,
# anything), _tpm_derive_api_pin has no agent identity to sign with, and
# used to silently fall back to trying the raw Master PIN against that
# index anyway -- a guaranteed-wrong TPM authorization attempt that only
# increments the TPM's dictionary-attack lockout counter for nothing.
# Watched this happen live: the counter climbed from 1 to 7 failed
# attempts purely from repeated unlock_tpm invocations during debugging.
# unlock_tpm now skips the API key entirely (with a clear message) rather
# than ever submit a PIN it already knows is wrong for that index.
# Exercises the real extracted unlock_tpm with its dependencies mocked so
# it never touches a real TPM or agent.
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

SNIPPET="$TMPDIR/unlock_tpm.sh"
extract_func "$REPO_ROOT/tpm_setup.sh" "unlock_tpm" > "$SNIPPET"
if [ ! -s "$SNIPPET" ]; then
    fail "could not extract unlock_tpm from tpm_setup.sh -- did it move/change shape?"
    printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
    exit 1
fi

# Mirrors what the real ssh-add prints (to stderr) when handed empty/bad
# input -- e.g. from a TPM read that failed for a wrong PIN. unlock_tpm's
# own read_secret already explains what actually went wrong (tested in
# test_tpm_session_exhaustion.sh); this raw, generic parse error should no
# longer reach the user alongside it.
cat > "$FAKEBIN/ssh-add" <<'EOF'
#!/bin/sh
echo 'Error loading key "(stdin)": error in libcrypto' >&2
exit 1
EOF
chmod +x "$FAKEBIN/ssh-add"

# Stubs for unlock_tpm's real dependencies, isolating this test to
# unlock_tpm's OWN logic (NEEDS_SSH/NEEDS_API are forced directly rather
# than exercising the real _tpm_needs_unlock, which is covered elsewhere).
MOCKS='
_tpm_needs_unlock() { NEEDS_SSH="${FAKE_NEEDS_SSH:-1}"; NEEDS_API="${FAKE_NEEDS_API:-1}"; }
_tpm_ensure_ssh_agent() { :; }
_tpm_derive_api_pin() {
    echo "derive_api_pin_called" >> "$FAKE_CALL_LOG"
    [ -n "${FAKE_AGENT_PIN:-}" ] && printf "%s" "$FAKE_AGENT_PIN"
    [ -n "${FAKE_AGENT_PIN:-}" ]
}
_tpm_read_secret() {
    # The extracted unlock_tpm text contains the literal characters
    # '"'"'"$API_NV_INDEX"'"'"' at this call site (the outer single-quote
    # context that made that interpolate to the real NV index number only
    # exists in the surrounding SHRC_SNIPPET-building code, which is not
    # part of the extracted, standalone function) -- so $1 here is
    # literally that unexpanded text, not a real NV index. It always
    # contains the identifier name as a substring regardless, so match on
    # that rather than trying to reconstruct the exact literal.
    echo "read_secret_called idx=$1" >> "$FAKE_CALL_LOG"
    case "$1" in
        *API_NV_INDEX*)
            echo "read_secret_called_for_API_INDEX pin=$2" >> "$FAKE_CALL_LOG"
            [ -n "${FAKE_API_SECRET:-}" ] && printf "%s" "$FAKE_API_SECRET"
            ;;
        *)
            printf "dummy-ssh-key-bytes"
            ;;
    esac
}
_tpm_load_secret() { echo "load_secret_called: $1" >> "$FAKE_CALL_LOG"; }
'

run_case() {
    : > "$TMPDIR/calllog"
    printf '%s\n' "1234" | env "$@" PATH="$FAKEBIN:/bin:/usr/bin" FAKE_CALL_LOG="$TMPDIR/calllog" \
        API_NV_INDEX="0xAPI" SSH_NV_INDEX="0xSSH" TPM_SSH_PUB_PATH="/nonexistent.pub" \
        sh -c "$MOCKS"'
'"$(cat "$SNIPPET")"'
unlock_tpm' 2>&1
}

echo "=== agent mode, derivation fails (no SSH identity available) -- must skip the API key, never attempt a wrong PIN ==="
OUT=$(run_case FAKE_NEEDS_SSH=1 FAKE_NEEDS_API=1 TPM_API_AUTH_MODE=agent)
if grep -q "read_secret_called_for_API_INDEX" "$TMPDIR/calllog"; then
    fail "attempted a TPM read against the API index despite having no way to derive its correct PIN -- this is exactly the bug that burned the DA lockout counter"
else
    pass "never attempts a TPM read against the agent-mode API index when derivation fails"
fi
case "$OUT" in
    *"error in libcrypto"*) fail "ssh-add's own generic parse-error noise leaked through instead of a clear explanation: $OUT" ;;
    *) pass "does not leak ssh-add's raw, generic parse error to the user" ;;
esac
case "$OUT" in
    *"skipping the API key"*) pass "prints a clear explanation instead of a generic failure" ;;
    *) fail "did not explain why the API key was skipped: $OUT" ;;
esac

echo "=== agent mode, derivation succeeds -- must use the DERIVED pin, not the raw Master PIN ==="
OUT=$(run_case FAKE_NEEDS_SSH=1 FAKE_NEEDS_API=1 TPM_API_AUTH_MODE=agent FAKE_AGENT_PIN=derivedpin123 FAKE_API_SECRET=secretvalue)
if grep -q "read_secret_called_for_API_INDEX pin=derivedpin123" "$TMPDIR/calllog"; then
    pass "reads the API index with the derived agent PIN when derivation succeeds"
else
    fail "did not use the derived PIN for the API index: $(cat "$TMPDIR/calllog")"
fi
if grep -q "load_secret_called: secretvalue" "$TMPDIR/calllog"; then
    pass "loads the API secret once correctly read"
else
    fail "did not load the API secret: $(cat "$TMPDIR/calllog")"
fi

echo "=== master-PIN mode (not agent mode) -- must still use the raw Master PIN as before ==="
OUT=$(run_case FAKE_NEEDS_SSH=1 FAKE_NEEDS_API=1 TPM_API_AUTH_MODE=master FAKE_API_SECRET=secretvalue2)
if grep -q "read_secret_called_for_API_INDEX pin=1234" "$TMPDIR/calllog"; then
    pass "master-PIN mode still uses the raw Master PIN (no regression)"
else
    fail "master-PIN mode did not use the raw Master PIN as expected: $(cat "$TMPDIR/calllog")"
fi
if grep -q "derive_api_pin_called" "$TMPDIR/calllog"; then
    fail "called the agent-derivation helper even in master-PIN mode"
else
    pass "does not call the agent-derivation helper in master-PIN mode"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
