#!/bin/sh
# Regression test for a real logic flaw: Phase 3's "no key file at
# $SSH_KEY_PATH, generate one?" prompt didn't check whether ssh-agent
# already had an ED25519 identity loaded before offering to generate a
# brand-new one. An agent-loaded identity (a hardware security key, one
# loaded from a different path, an agent-forwarded identity, etc.) can't
# be reused here regardless -- ssh-agent never exports the private key
# material of an already-loaded identity, only signs with it -- but
# silently generating a second, unrelated key without saying so is a
# surprise waiting to happen. Both scripts now print a clear note in that
# case before asking. Exercises the real extracted code with fake
# ssh-add/ssh-keygen stubs so it doesn't touch a real agent or key.
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

cat > "$FAKEBIN/ssh-add" <<'EOF'
#!/bin/sh
if [ "$FAKE_AGENT_HAS_KEY" = "1" ]; then
    echo "256 SHA256:abcdef fake@test (ED25519)"
    exit 0
fi
echo "The agent has no identities." >&2
exit 1
EOF
cat > "$FAKEBIN/ssh-keygen" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-f" ]; then KEYPATH="$2"; fi
    shift
done
echo "fake-private-key-content" > "$KEYPATH"
exit 0
EOF
chmod +x "$FAKEBIN/ssh-add" "$FAKEBIN/ssh-keygen"

SNIPPET="$TMPDIR/phase3.sh"
awk '/^# --- 3\. SSH Key Generation ---/{found=1} found && /^SSH_KEY_SIZE=/{exit} found{print}' "$REPO_ROOT/tpm_setup.sh" > "$SNIPPET"
if [ ! -s "$SNIPPET" ]; then
    fail "could not extract the Phase 3 SSH key block from tpm_setup.sh -- did it move/change shape?"
else
    TESTHOME="$TMPDIR/home_a"
    mkdir -p "$TESTHOME"
    OUT=$(printf 'y\n' | env -i PATH="$FAKEBIN:/bin:/usr/bin" HOME="$TESTHOME" SSH_KEY_PATH="$TESTHOME/id_ed25519" FAKE_AGENT_HAS_KEY=1 sh -c ". $SNIPPET" 2>&1)
    case "$OUT" in
        *"already loaded in ssh-agent"*) pass "tpm_setup.sh: warns when agent has a key but no file exists" ;;
        *) fail "tpm_setup.sh: did not warn when agent has a key but no file exists: $OUT" ;;
    esac

    TESTHOME="$TMPDIR/home_b"
    mkdir -p "$TESTHOME"
    OUT=$(printf 'y\n' | env -i PATH="$FAKEBIN:/bin:/usr/bin" HOME="$TESTHOME" SSH_KEY_PATH="$TESTHOME/id_ed25519" FAKE_AGENT_HAS_KEY=0 sh -c ". $SNIPPET" 2>&1)
    case "$OUT" in
        *"already loaded in ssh-agent"*) fail "tpm_setup.sh: warned even though the agent has no key: $OUT" ;;
        *) pass "tpm_setup.sh: no warning when the agent has no key" ;;
    esac
fi

if command -v pwsh >/dev/null 2>&1; then
    PS1SNIPPET="$TMPDIR/phase3.ps1"
    awk '/^\$sshKeyPath = Join-Path \$sshDir "id_ed25519"/{found=1} found && /^\$sshKeyBytes = /{exit} found{print}' "$REPO_ROOT/tpm_setup.ps1" > "$PS1SNIPPET"
    if [ ! -s "$PS1SNIPPET" ]; then
        fail "could not extract the Phase 3 SSH key block from tpm_setup.ps1 -- did it move/change shape?"
    else
        cat > "$TMPDIR/run_ps1_case.ps1" <<PWEOF
\$ErrorActionPreference = 'Stop'
function Write-TpmLine { param([string]\$Text) Write-Host \$Text }
\$block = Get-Content "$PS1SNIPPET" -Raw
\$agentHasKey = [bool]::Parse(\$args[0])
if (\$agentHasKey) {
    function ssh-add { "256 SHA256:abcdef fake@test (ED25519)" }
} else {
    function ssh-add { \$global:LASTEXITCODE = 1 }
}
function ssh-keygen { param() \$global:LASTEXITCODE = 0 }
function Read-Host { param(\$Prompt) return "y" }
\$sshDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path \$sshDir | Out-Null
\$sb = [scriptblock]::Create(\$block)
& \$sb
Remove-Item -Recurse -Force \$sshDir -ErrorAction SilentlyContinue
PWEOF
        OUT=$(pwsh -NoProfile -File "$TMPDIR/run_ps1_case.ps1" true 2>&1)
        case "$OUT" in
            *"already loaded in ssh-agent"*) pass "tpm_setup.ps1: warns when agent has a key but no file exists" ;;
            *) fail "tpm_setup.ps1: did not warn when agent has a key but no file exists: $OUT" ;;
        esac

        OUT=$(pwsh -NoProfile -File "$TMPDIR/run_ps1_case.ps1" false 2>&1)
        case "$OUT" in
            *"already loaded in ssh-agent"*) fail "tpm_setup.ps1: warned even though the agent has no key: $OUT" ;;
            *) pass "tpm_setup.ps1: no warning when the agent has no key" ;;
        esac
    fi
else
    printf "SKIP: pwsh not installed, skipping tpm_setup.ps1 checks\n"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
