#!/bin/sh
# Tests tpm_setup.sh --uninstall: removes the sealed TPM secrets (via
# tpm2_nvundefine) and the shell-integration blocks/files it installed,
# while leaving the user's own unrelated dotfile content untouched. Uses
# fake id/tpm2_nvundefine stubs on an isolated PATH so this never touches
# a real TPM index -- see the accidental real-index deletion this guarded
# against during development (a test that only overrode $HOME, not the
# invoking UID, ended up deleting the developer's own real sealed secrets).
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

# A fake, clearly-not-real UID, so the computed NV indices can never
# collide with anything real even if this test were somehow run wrong.
cat > "$FAKEBIN/id" <<'EOF'
#!/bin/sh
if [ "$1" = "-u" ]; then echo "9999"; exit 0; fi
echo "faketestuser"
EOF
cat > "$FAKEBIN/tpm2_nvundefine" <<EOF
#!/bin/sh
echo "\$*" >> "$TMPDIR/nvundefine.log"
exit "\${FAKE_NVUNDEFINE_EXIT:-0}"
EOF
chmod +x "$FAKEBIN/id" "$FAKEBIN/tpm2_nvundefine"
TESTPATH="$FAKEBIN:/bin:/usr/bin"

seed_fake_home() {
    FH="$1"
    rm -rf "$FH"; mkdir -p "$FH"
    PHASE5=$(awk '/^# --- 5\. Shell Integration ---/{found=1} found{print}' "$REPO_ROOT/tpm_setup.sh")
    API_AUTH_MODE=master STRATEGY_CHOICE=1 SSH_AGENT_AUTOSTART=yes \
        SSH_KEY_PATH="$FH/.ssh/id_ed25519" API_NV_INDEX=0x1502000 SSH_NV_INDEX=0x1502001 \
        HOME="$FH" sh -c "$PHASE5" >/dev/null 2>&1
    printf '\n# my own stuff\nalias ll="ls -la"\n' >> "$FH/.bashrc"
}

# --- Confirmed uninstall: removes everything, keeps the user's own content ---
FH="$TMPDIR/home_confirm"
seed_fake_home "$FH"
rm -f "$TMPDIR/nvundefine.log"
printf 'y\n' | env -i HOME="$FH" PATH="$TESTPATH" sh "$REPO_ROOT/tpm_setup.sh" --uninstall >/dev/null 2>&1

if grep -q '\-C o 0x1504E1E' "$TMPDIR/nvundefine.log" 2>/dev/null && grep -q '\-C o 0x1504E1F' "$TMPDIR/nvundefine.log" 2>/dev/null; then
    pass "tpm2_nvundefine called with the correct fake-UID-derived indices"
else
    fail "tpm2_nvundefine was not called with the expected indices: $(cat "$TMPDIR/nvundefine.log" 2>/dev/null)"
fi

if [ ! -f "$FH/.tpm_unlock.csh" ] && [ ! -f "$FH/.tpm_unlock_helper.sh" ]; then
    pass "generated helper files were removed"
else
    fail "generated helper files still present"
fi

if grep -q 'TPM Secure Environment Setup' "$FH/.bashrc" "$FH/.cshrc" "$FH/.bash_profile" 2>/dev/null; then
    fail "a TPM block is still present in a shell startup file"
else
    pass "TPM blocks removed from all shell startup files"
fi

if grep -q 'my own stuff' "$FH/.bashrc" 2>/dev/null && grep -q 'alias ll=' "$FH/.bashrc" 2>/dev/null; then
    pass "user's own .bashrc content survives uninstall"
else
    fail "user's own .bashrc content was damaged"
fi

# --- Cancelled uninstall: nothing touched ---
FH="$TMPDIR/home_cancel"
seed_fake_home "$FH"
rm -f "$TMPDIR/nvundefine.log"
BEFORE=$(wc -c < "$FH/.bashrc")
printf 'n\n' | env -i HOME="$FH" PATH="$TESTPATH" sh "$REPO_ROOT/tpm_setup.sh" --uninstall >/dev/null 2>&1
AFTER=$(wc -c < "$FH/.bashrc")

if [ ! -f "$TMPDIR/nvundefine.log" ]; then
    pass "answering 'n' does not call tpm2_nvundefine at all"
else
    fail "tpm2_nvundefine was called despite answering 'n': $(cat "$TMPDIR/nvundefine.log")"
fi
if [ "$BEFORE" = "$AFTER" ] && [ -f "$FH/.tpm_unlock.csh" ]; then
    pass "answering 'n' leaves shell integration untouched"
else
    fail "answering 'n' still modified shell integration files"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
