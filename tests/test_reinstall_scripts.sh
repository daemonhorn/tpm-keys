#!/bin/sh
# Tests the script-version tracking added to tpm_setup.sh: TPM_SETUP_VERSION
# is persisted into ~/.tpm_keys_state as SCRIPT_VERSION at the end of a
# successful run, --status reports it and hints at --reinstall-scripts when
# it's stale (or missing entirely, for an install that predates this
# feature), and --reinstall-scripts itself regenerates only the shell/profile
# integration (Phase 5) -- it must never touch sealed TPM secrets, and should
# need zero prompts when STRATEGY_CHOICE was already persisted by a prior
# run. Runs the real tpm_setup.sh end-to-end with fake id/tpm2_* stubs (or,
# for the reinstall-only cases, deliberately NO tpm2_nv* stubs at all, so a
# stray seeding call would fail loudly instead of silently succeeding).
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

# A fake, clearly-not-real UID (matches the convention in test_uninstall.sh)
# so the computed NV indices can never collide with anything real.
cat > "$FAKEBIN/id" <<'EOF'
#!/bin/sh
if [ "$1" = "-u" ]; then echo "9999"; exit 0; fi
echo "faketestuser"
EOF
chmod +x "$FAKEBIN/id"
NO_TPM_PATH="$FAKEBIN:/bin:/usr/bin"

# --status stubs: a TPM that's always reachable with both indices sealed.
cat > "$FAKEBIN/tpm2_nvreadpublic" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$FAKEBIN/tpm2_getcap" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$FAKEBIN/ssh-add" <<'EOF'
#!/bin/sh
exit 2
EOF
chmod +x "$FAKEBIN/tpm2_nvreadpublic" "$FAKEBIN/tpm2_getcap" "$FAKEBIN/ssh-add"
STATUS_PATH="$FAKEBIN:/bin:/usr/bin"

CURRENT_VERSION=$(awk -F'"' '/^TPM_SETUP_VERSION=/{print $2; exit}' "$REPO_ROOT/tpm_setup.sh")
if [ -z "$CURRENT_VERSION" ]; then
    fail "could not read TPM_SETUP_VERSION from tpm_setup.sh -- did it move/change shape?"
    printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
    exit 1
fi

# Seeds a fake install's shell-integration files by running the real Phase 5
# code directly (same technique as test_uninstall.sh's seed_fake_home), then
# writes a .tpm_keys_state by hand so each case can control its contents.
seed_fake_home() {
    FH="$1"
    rm -rf "$FH"; mkdir -p "$FH"
    PHASE5=$(awk '/^# --- 5\. Shell Integration ---/{found=1} found{print}' "$REPO_ROOT/tpm_setup.sh")
    API_AUTH_MODE=master STRATEGY_CHOICE=1 SSH_AGENT_AUTOSTART=no \
        SSH_KEY_PATH="$FH/.ssh/id_ed25519" API_NV_INDEX=0x1502000 SSH_NV_INDEX=0x1502001 \
        HOME="$FH" sh -c "$PHASE5" >/dev/null 2>&1
}

echo "=== --status: nothing installed at all -- no version hint printed ==="
FH="$TMPDIR/home_none"
mkdir -p "$FH"
OUT=$(env -i HOME="$FH" PATH="$STATUS_PATH:" USER=faketestuser sh "$REPO_ROOT/tpm_setup.sh" --status 2>&1)
case "$OUT" in
    *"Script version: $CURRENT_VERSION"*) pass "always reports the running script's version" ;;
    *) fail "did not report the running script's version: $OUT" ;;
esac
case "$OUT" in
    *"reinstall-scripts"*) fail "hinted at --reinstall-scripts with nothing installed: $OUT" ;;
    *) pass "does not hint at --reinstall-scripts when nothing is installed" ;;
esac

echo "=== --status: installed, state file predates version tracking ==="
FH="$TMPDIR/home_old"
mkdir -p "$FH"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\n' > "$FH/.tpm_keys_state"
OUT=$(env -i HOME="$FH" PATH="$STATUS_PATH" USER=faketestuser sh "$REPO_ROOT/tpm_setup.sh" --status 2>&1)
case "$OUT" in
    *"Installed shell integration: unknown version"*) pass "reports 'unknown version' for a pre-versioning install" ;;
    *) fail "did not report unknown-version state: $OUT" ;;
esac
case "$OUT" in
    *"--reinstall-scripts"*) pass "hints at --reinstall-scripts for a pre-versioning install" ;;
    *) fail "did not hint at --reinstall-scripts: $OUT" ;;
esac

echo "=== --status: installed, version matches -- no hint ==="
FH="$TMPDIR/home_match"
mkdir -p "$FH"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\nSTRATEGY_CHOICE=1\nSCRIPT_VERSION=%s\n' "$CURRENT_VERSION" > "$FH/.tpm_keys_state"
OUT=$(env -i HOME="$FH" PATH="$STATUS_PATH" USER=faketestuser sh "$REPO_ROOT/tpm_setup.sh" --status 2>&1)
case "$OUT" in
    *"Installed shell integration: v$CURRENT_VERSION (up to date)"*) pass "reports up to date when versions match" ;;
    *) fail "did not report up-to-date correctly: $OUT" ;;
esac
case "$OUT" in
    *"--reinstall-scripts"*) fail "hinted at --reinstall-scripts even though the version matches: $OUT" ;;
    *) pass "does not hint at --reinstall-scripts when the version matches" ;;
esac

echo "=== --status: installed, version stale -- hints at --reinstall-scripts ==="
FH="$TMPDIR/home_stale"
mkdir -p "$FH"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\nSTRATEGY_CHOICE=1\nSCRIPT_VERSION=0.0.1\n' > "$FH/.tpm_keys_state"
OUT=$(env -i HOME="$FH" PATH="$STATUS_PATH" USER=faketestuser sh "$REPO_ROOT/tpm_setup.sh" --status 2>&1)
case "$OUT" in
    *"Installed shell integration: v0.0.1 (this script is v$CURRENT_VERSION)"*) pass "reports the stale installed version alongside the current one" ;;
    *) fail "did not report the version mismatch correctly: $OUT" ;;
esac
case "$OUT" in
    *"run '$REPO_ROOT/tpm_setup.sh --reinstall-scripts'"*) pass "hints at the exact --reinstall-scripts command to run" ;;
    *) fail "did not hint at --reinstall-scripts: $OUT" ;;
esac

echo "=== --reinstall-scripts: no existing installation -- clean error, no crash ==="
FH="$TMPDIR/home_noinstall"
mkdir -p "$FH"
OUT=$(env -i HOME="$FH" PATH="$NO_TPM_PATH" USER=faketestuser sh "$REPO_ROOT/tpm_setup.sh" --reinstall-scripts 2>&1)
CODE=$?
if [ "$CODE" -eq 0 ]; then
    fail "exited 0 despite there being nothing to reinstall"
else
    case "$OUT" in
        *"No existing installation found"*) pass "errors clearly when there is nothing to reinstall" ;;
        *) fail "did not explain the missing-install error: $OUT" ;;
    esac
fi

echo "=== --reinstall-scripts: normal case, STRATEGY_CHOICE already persisted -- zero prompts, no TPM calls ==="
FH="$TMPDIR/home_reinstall"
seed_fake_home "$FH"
printf 'my own stuff\n' >> "$FH/.bashrc"
printf 'API_AUTH_MODE=agent\nSSH_AGENT_AUTOSTART=yes\nSTRATEGY_CHOICE=2\nSCRIPT_VERSION=0.0.1\nSECRET_NAMES="OPENAI_KEY"\n' > "$FH/.tpm_keys_state"
# No tpm2_nv* binaries at all on this PATH -- if --reinstall-scripts ever
# shelled out to one, this would fail with "command not found" instead of
# silently succeeding, so absence of such an error is itself the assertion.
OUT=$(printf '' | env -i HOME="$FH" PATH="$NO_TPM_PATH" USER=faketestuser sh "$REPO_ROOT/tpm_setup.sh" --reinstall-scripts 2>&1)
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "--reinstall-scripts exited $CODE with no stdin input available (means it tried to prompt): $OUT"
else
    pass "runs to completion with zero stdin input (no prompts) when state is fully persisted"
fi
case "$OUT" in
    *"command not found"*|*": not found"*) fail "shelled out to a missing tpm2_* command: $OUT" ;;
    *) pass "never invoked a TPM-seeding command" ;;
esac
case "$OUT" in
    *"Reinstall Complete"*) pass "prints the reinstall-specific completion message" ;;
    *) fail "did not print the reinstall completion message: $OUT" ;;
esac
case "$OUT" in
    *"Backup"*"offline drive"*) fail "printed the fresh-install SSH-key-backup reminder during a reinstall" ;;
    *) pass "does not print the fresh-install backup reminder during a reinstall" ;;
esac
if grep -q "SCRIPT_VERSION=$CURRENT_VERSION" "$FH/.tpm_keys_state" 2>/dev/null; then
    pass "persists the current script version into the state file"
else
    fail "did not update SCRIPT_VERSION in the state file: $(cat "$FH/.tpm_keys_state" 2>/dev/null)"
fi
if grep -q 'STRATEGY_CHOICE=2' "$FH/.tpm_keys_state" 2>/dev/null; then
    pass "keeps the already-persisted STRATEGY_CHOICE (Manual) unchanged"
else
    fail "lost or changed the persisted STRATEGY_CHOICE: $(cat "$FH/.tpm_keys_state" 2>/dev/null)"
fi
if grep -q 'SECRET_NAMES="OPENAI_KEY"' "$FH/.tpm_keys_state" 2>/dev/null; then
    pass "keeps the already-persisted SECRET_NAMES unchanged"
else
    fail "lost or changed the persisted SECRET_NAMES: $(cat "$FH/.tpm_keys_state" 2>/dev/null)"
fi
if grep -q 'TPM Secure Environment Setup' "$FH/.bashrc" 2>/dev/null; then
    pass "regenerated the sh/bash shell integration block"
else
    fail "shell integration block missing after --reinstall-scripts"
fi
if grep -q 'my own stuff' "$FH/.bashrc" 2>/dev/null; then
    pass "leaves the user's own .bashrc content untouched"
else
    fail "damaged the user's own .bashrc content"
fi

echo "=== --reinstall-scripts: legacy install with no persisted STRATEGY_CHOICE -- asks once, then persists it ==="
FH="$TMPDIR/home_legacy"
seed_fake_home "$FH"
printf 'API_AUTH_MODE=master\nSSH_AGENT_AUTOSTART=no\n' > "$FH/.tpm_keys_state"
OUT=$(printf '2\n' | env -i HOME="$FH" PATH="$NO_TPM_PATH" USER=faketestuser sh "$REPO_ROOT/tpm_setup.sh" --reinstall-scripts 2>&1)
CODE=$?
if [ "$CODE" -ne 0 ]; then
    fail "exited $CODE for the legacy no-STRATEGY_CHOICE case: $OUT"
else
    case "$OUT" in
        *"Unlock Strategy"*) pass "asks for the unlock strategy exactly once when it was never persisted" ;;
        *) fail "did not ask for the unlock strategy at all: $OUT" ;;
    esac
    if grep -q 'STRATEGY_CHOICE=2' "$FH/.tpm_keys_state" 2>/dev/null; then
        pass "persists the newly-answered STRATEGY_CHOICE for next time"
    else
        fail "did not persist the newly-answered STRATEGY_CHOICE: $(cat "$FH/.tpm_keys_state" 2>/dev/null)"
    fi
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
