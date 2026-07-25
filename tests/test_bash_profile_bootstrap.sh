#!/bin/sh
# Regression test for a real bug found and fixed after initial release:
# bash invoked as a LOGIN shell (its own /etc/passwd entry, not just an
# interactive preference -- common on FreeBSD, whose skel(5) ships no
# bash-specific dotfiles) never reads ~/.bashrc at all. bash-as-login only
# checks ~/.bash_profile, then ~/.bash_login, then ~/.profile, stopping at
# the first that exists -- so the unlock_tpm hook installed in ~/.bashrc
# would silently never fire on a real login. Phase 5 now also ensures
# ~/.bash_profile sources ~/.bashrc, and the TPM block guards against
# running twice in the same shell (in case something else already sources
# it too). This checks both pieces by generating real Phase 5 output into
# a throwaway HOME and inspecting it -- no TPM required.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

TESTS_RUN=0
TESTS_FAILED=0
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
FH="$TMPDIR/fakehome"
mkdir -p "$FH"

PHASE5=$(awk '/^# --- 5\. Shell Integration ---/{found=1} found{print}' "$REPO_ROOT/tpm_setup.sh")
API_AUTH_MODE=master STRATEGY_CHOICE=1 SSH_AGENT_AUTOSTART=no \
    SSH_KEY_PATH="$FH/.ssh/id_ed25519" API_NV_INDEX=0x1502000 SSH_NV_INDEX=0x1502001 \
    HOME="$FH" sh -c "$PHASE5" >/dev/null 2>&1

if [ ! -f "$FH/.bash_profile" ]; then
    fail "Phase 5 did not create ~/.bash_profile"
else
    pass "~/.bash_profile was created"
fi

if grep -q '\. "\$HOME/\.bashrc"' "$FH/.bash_profile" 2>/dev/null; then
    pass "~/.bash_profile sources ~/.bashrc"
else
    fail "~/.bash_profile does not source ~/.bashrc"
fi

sh -n "$FH/.bash_profile" 2>/dev/null && pass "~/.bash_profile is valid sh syntax" || fail "~/.bash_profile has a syntax error"

if grep -q '_TPM_RC_LOADED' "$FH/.bashrc" 2>/dev/null; then
    pass "~/.bashrc has the double-source guard"
else
    fail "~/.bashrc is missing the double-source guard"
fi

# Re-running Phase 5 must replace the block idempotently, not duplicate it
# (matches the existing sed-based replace pattern for .bashrc/.shrc/.cshrc).
HOME="$FH" sh -c "$PHASE5" >/dev/null 2>&1
COUNT=$(grep -c '# --- TPM Secure Environment Setup (bash_profile bootstrap) ---' "$FH/.bash_profile")
if [ "$COUNT" -eq 1 ]; then
    pass "re-running Phase 5 does not duplicate the ~/.bash_profile block"
else
    fail "~/.bash_profile block appears $COUNT times after re-running (expected 1)"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
