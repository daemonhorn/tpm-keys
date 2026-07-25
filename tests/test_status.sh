#!/bin/sh
# Tests --status: a read-only summary (installed/not, locked/unlocked,
# user id, SSH key file state, environment secret count, ssh-agent +
# loaded public keys) that must never install/modify anything and must
# never abort under `set -e` regardless of what ssh-add/tpm2_nvreadpublic
# report (a real bug found during development: capturing a failing
# command's $? on a separate line trips `set -e` before the assignment
# ever runs). Runs the real extracted code with fake id/tpm2_nvreadpublic/
# ssh-add stubs so it never touches a real TPM or agent.
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

cat > "$FAKEBIN/id" <<'EOF'
#!/bin/sh
if [ "$1" = "-u" ]; then echo "${FAKE_UID:-9999}"; exit 0; fi
if [ "$1" = "-un" ]; then echo "faketestuser"; exit 0; fi
echo "faketestuser"
EOF
cat > "$FAKEBIN/tpm2_nvreadpublic" <<'EOF'
#!/bin/sh
[ "$FAKE_TPM_INSTALLED" = "1" ] && exit 0
exit 1
EOF
cat > "$FAKEBIN/tpm2_getcap" <<'EOF'
#!/bin/sh
# FAKE_TPM_ACCESSIBLE (default 1): simulates whether the TPM itself can be
# reached at all, independent of whether our own NV indices exist -- lets
# tests exercise "not accessible" separately from "accessible, nothing
# sealed yet".
[ "${FAKE_TPM_ACCESSIBLE:-1}" = "1" ] && exit 0
exit 1
EOF
cat > "$FAKEBIN/ssh-add" <<'EOF'
#!/bin/sh
# FAKE_SSH_ADD_EXIT: 0=identities present, 1=agent reachable but empty, 2=unreachable
case "$1" in
    -l)
        case "${FAKE_SSH_ADD_EXIT:-2}" in
            0) echo "256 SHA256:abcdef fake@test (${FAKE_KEY_TYPE:-ED25519})"; exit 0 ;;
            1) echo "The agent has no identities." >&2; exit 1 ;;
            *) echo "Could not open a connection to your authentication agent." >&2; exit 2 ;;
        esac
        ;;
    -L)
        case "${FAKE_SSH_ADD_EXIT:-2}" in
            0) echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfakepublickeymaterial fake@test" ;;
            1) echo "The agent has no identities." >&2; exit 1 ;;
            *) echo "Could not open a connection to your authentication agent." >&2; exit 2 ;;
        esac
        ;;
esac
EOF
chmod +x "$FAKEBIN/id" "$FAKEBIN/tpm2_nvreadpublic" "$FAKEBIN/tpm2_getcap" "$FAKEBIN/ssh-add"

SNIPPET="$TMPDIR/status_block.sh"
awk '/^if \[ "\$STATUS" -eq 1 \]; then/{found=1} found && /^# tpm2-tools.\x27 libtss2 backends/{exit} found{print}' "$REPO_ROOT/tpm_setup.sh" > "$SNIPPET"
if [ ! -s "$SNIPPET" ]; then
    fail "could not extract the --status block from tpm_setup.sh -- did it move/change shape?"
    printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
    exit 1
fi

# Runs the extracted block under `sh -e` (matching the real script's
# `set -e`) so any latent abort-under-set-e bug surfaces here the same
# way it would for real, with the given env vars and a fresh $HOME.
run_case() {
    HOME_DIR="$1"
    shift
    mkdir -p "$HOME_DIR"
    env "$@" PATH="$FAKEBIN:/bin:/usr/bin" HOME="$HOME_DIR" STATUS=1 USER=faketestuser \
        sh -ec ". '$SNIPPET'" 2>&1
}

echo "=== not installed, no SSH key, agent unreachable, untracked state ==="
OUT=$(run_case "$TMPDIR/home_a" FAKE_UID=1111 FAKE_TPM_INSTALLED=0 FAKE_SSH_ADD_EXIT=2)
CODE=$?
echo "$OUT"
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE (set -e abort?) for the not-installed case"
else
    OK=1
    case "$OUT" in *"not installed"*) ;; *) fail "did not report 'not installed'"; OK=0 ;; esac
    case "$OUT" in *"SSH key file"*"missing"*) ;; *) fail "did not report missing SSH key file"; OK=0 ;; esac
    case "$OUT" in *"ssh-agent: not reachable"*) ;; *) fail "did not report ssh-agent as not reachable"; OK=0 ;; esac
    [ "$OK" -eq 1 ] && pass "not-installed / no key / unreachable agent case reports correctly"
fi

echo "=== tpm2-tools not installed at all (only real PATH, no fake tpm2_nvreadpublic) ==="
OUT=$(env PATH="/bin:/usr/bin" HOME="$TMPDIR/home_b" STATUS=1 USER=faketestuser sh -ec ". '$SNIPPET'" 2>&1)
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE (set -e abort?) when tpm2-tools isn't installed"
else
    case "$OUT" in
        *"tpm2-tools not installed"*) pass "reports 'tpm2-tools not installed' cleanly, no crash" ;;
        *) fail "did not report tpm2-tools missing: $OUT" ;;
    esac
fi

echo "=== tpm2-tools installed but TPM device not accessible (must not be confused with 'not installed') ==="
OUT=$(run_case "$TMPDIR/home_c" FAKE_UID=6666 FAKE_TPM_ACCESSIBLE=0 FAKE_SSH_ADD_EXIT=2)
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE (set -e abort?) when the TPM device isn't accessible"
else
    case "$OUT" in
        *"TPM secrets: unknown (TPM not accessible"*) pass "reports 'TPM not accessible' distinctly from 'not installed'" ;;
        *) fail "did not distinguish inaccessible TPM from no-secrets-installed: $OUT" ;;
    esac
    case "$OUT" in
        *"TPM secrets: not installed"*) fail "wrongly reported 'not installed' when the TPM itself couldn't be reached" ;;
        *) pass "did not conflate an inaccessible TPM with 'not installed'" ;;
    esac
fi

echo "=== installed, agent has ED25519 key, named secrets fully loaded ==="
mkdir -p "$TMPDIR/home_d"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\nSECRET_NAMES="OPENAI_KEY AWS_SECRET_ACCESS_KEY"\n' > "$TMPDIR/home_d/.tpm_keys_state"
OUT=$(run_case "$TMPDIR/home_d" FAKE_UID=2222 FAKE_TPM_INSTALLED=1 FAKE_SSH_ADD_EXIT=0 OPENAI_KEY=sk-test AWS_SECRET_ACCESS_KEY=secretval)
CODE=$?
echo "$OUT"
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE (set -e abort?) for the fully-unlocked case"
else
    OK=1
    case "$OUT" in *"TPM secrets: installed"*) ;; *) fail "did not report installed"; OK=0 ;; esac
    case "$OUT" in *"SSH key: unlocked"*) ;; *) fail "did not report SSH key unlocked"; OK=0 ;; esac
    case "$OUT" in *"API secret(s): unlocked (2/2 loaded: OPENAI_KEY AWS_SECRET_ACCESS_KEY)"*) ;; *) fail "did not report both named secrets loaded"; OK=0 ;; esac
    case "$OUT" in *"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfakepublickeymaterial"*) ;; *) fail "did not print the loaded identity's public key material"; OK=0 ;; esac
    [ "$OK" -eq 1 ] && pass "fully-installed / unlocked / named-secrets case reports correctly, including pubkey material"
fi

echo "=== installed, named secrets partially loaded, agent reachable but empty ==="
mkdir -p "$TMPDIR/home_e"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\nSECRET_NAMES="OPENAI_KEY AWS_SECRET_ACCESS_KEY"\n' > "$TMPDIR/home_e/.tpm_keys_state"
OUT=$(run_case "$TMPDIR/home_e" FAKE_UID=3333 FAKE_TPM_INSTALLED=1 FAKE_SSH_ADD_EXIT=1 OPENAI_KEY=sk-test)
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE (set -e abort?) for the partially-unlocked case"
else
    case "$OUT" in
        *"API secret(s): partially unlocked (1/2 loaded: OPENAI_KEY)"*) pass "partially-loaded named secrets reported correctly" ;;
        *) fail "did not report partial load correctly: $OUT" ;;
    esac
    case "$OUT" in
        *"Loaded identities: none"*) pass "agent-reachable-but-empty reports 'none' instead of a stray message" ;;
        *) fail "did not report empty agent identities cleanly: $OUT" ;;
    esac
fi

echo "=== legacy single-key mode ==="
mkdir -p "$TMPDIR/home_f"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\nSECRET_NAMES=""\n' > "$TMPDIR/home_f/.tpm_keys_state"
OUT=$(run_case "$TMPDIR/home_f" FAKE_UID=4444 FAKE_TPM_INSTALLED=1 FAKE_SSH_ADD_EXIT=2 SECURE_API_KEY=sk-legacy)
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE (set -e abort?) for the legacy single-key case"
else
    case "$OUT" in
        *"API secret(s): unlocked (1/1 loaded: SECURE_API_KEY)"*) pass "legacy single-key mode reported correctly" ;;
        *) fail "did not report legacy secret correctly: $OUT" ;;
    esac
fi

echo "=== older install predating name tracking (no SECRET_NAMES in state file) ==="
mkdir -p "$TMPDIR/home_g"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\n' > "$TMPDIR/home_g/.tpm_keys_state"
OUT=$(run_case "$TMPDIR/home_g" FAKE_UID=5555 FAKE_TPM_INSTALLED=1 FAKE_SSH_ADD_EXIT=2)
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE (set -e abort?) for the untracked-old-install case"
else
    case "$OUT" in
        *"API secret(s): unknown (older install predates name tracking"*) pass "untracked old install reports honestly instead of guessing" ;;
        *) fail "did not handle untracked old install correctly: $OUT" ;;
    esac
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
