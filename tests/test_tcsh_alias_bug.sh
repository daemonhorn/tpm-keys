#!/bin/sh
# Regression test for a real bug found this session: tcsh's single-line
# "if (expr) command" form does NOT go through alias substitution (alias
# expansion only happens for a command on its own input line), so
#   if ($?prompt) unlock_tpm
# fails with "unlock_tpm: Command not found." even though
#   alias unlock_tpm "source ~/.tpm_unlock.csh"
# was already defined -- this was the reported "tcsh Automatic mode gives
# an error running unlock_tpm" bug. The fix is the multi-line form:
#   if ($?prompt) then
#       unlock_tpm
#   endif
#
# This test has two parts:
#   1. A minimal, self-contained repro proving the underlying tcsh
#      behavior (so this documents *why* the fix is shaped the way it is,
#      independent of this repo's code).
#   2. A check against the actual generated .cshrc content (via a real
#      Phase 5 run in a throwaway HOME) confirming the Automatic-mode
#      trailer uses the multi-line form, not the single-line form.
# Requires tcsh; skips if not installed.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

TESTS_RUN=0
TESTS_FAILED=0
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

if ! command -v tcsh >/dev/null 2>&1; then
    printf "SKIP: tcsh not installed\n"
    exit 0
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# --- Part 1: minimal repro of the underlying tcsh behavior ---
cat > "$TMPDIR/repro.csh" <<'EOF'
alias my_alias "echo ALIAS_RAN"
set prompt = "x> "
if ($?prompt) my_alias
EOF
OUT=$(tcsh -f "$TMPDIR/repro.csh" 2>&1 </dev/null)
case "$OUT" in
    *"ALIAS_RAN"*)
        fail "expected tcsh's single-line if form to NOT expand aliases, but it did -- tcsh behavior may have changed; re-check whether the multi-line-if fix in tpm_setup.sh is still needed"
        ;;
    *)
        pass "confirmed: tcsh single-line 'if (expr) alias' does not expand the alias (this is why the fix uses if/then/endif)"
        ;;
esac

cat > "$TMPDIR/repro2.csh" <<'EOF'
alias my_alias "echo ALIAS_RAN"
set prompt = "x> "
if ($?prompt) then
    my_alias
endif
EOF
OUT2=$(tcsh -f "$TMPDIR/repro2.csh" 2>&1 </dev/null)
case "$OUT2" in
    *"ALIAS_RAN"*) pass "confirmed: tcsh multi-line if/then/endif form DOES expand the alias" ;;
    *) fail "multi-line if/then/endif form did not run the alias either: $OUT2" ;;
esac

# --- Part 2: the actual generated .cshrc uses the multi-line form ---
FH="$TMPDIR/fakehome"
mkdir -p "$FH"
PHASE5=$(awk '/^# --- 5\. Shell Integration ---/{found=1} found{print}' "$REPO_ROOT/tpm_setup.sh")
API_AUTH_MODE=master STRATEGY_CHOICE=1 SSH_AGENT_AUTOSTART=no \
    SSH_KEY_PATH="$FH/.ssh/id_ed25519" API_NV_INDEX=0x1502000 SSH_NV_INDEX=0x1502001 \
    HOME="$FH" sh -c "$PHASE5" >/dev/null 2>&1

if [ ! -f "$FH/.cshrc" ]; then
    fail "Phase 5 did not generate a .cshrc to check"
else
    if grep -qE '^if \(\$\?prompt\) unlock_tpm$' "$FH/.cshrc"; then
        fail "generated .cshrc still uses the broken single-line 'if (\$?prompt) unlock_tpm' form"
    else
        pass "generated .cshrc does not use the broken single-line form"
    fi
    if grep -qE '^if \(\$\?prompt\) then$' "$FH/.cshrc" && grep -q '    unlock_tpm' "$FH/.cshrc"; then
        pass "generated .cshrc uses the multi-line if/then/endif form for Automatic-mode unlock_tpm"
    else
        fail "generated .cshrc does not contain the expected multi-line if/then/endif unlock_tpm block"
    fi
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
