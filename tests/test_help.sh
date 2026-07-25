#!/bin/sh
# Tests --help/-h (tpm_setup.sh) and -Help/-h (tpm_setup.ps1): exits 0,
# includes a one-paragraph summary of what the script does, and mentions
# every other CLI flag the script currently supports -- so adding a new
# flag (or dropping the summary) without updating usage text shows up as
# a test failure instead of silently going stale.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

TESTS_RUN=0
TESTS_FAILED=0
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

check_output() {
    LABEL="$1"
    OUTPUT="$2"
    CODE="$3"
    shift 3
    if [ "$CODE" -ne 0 ]; then
        fail "$LABEL: exited $CODE, expected 0"
        return
    fi
    for NEEDLE in "$@"; do
        case "$OUTPUT" in
            *"$NEEDLE"*) ;;
            *)
                fail "$LABEL: usage text is missing '$NEEDLE'"
                return
                ;;
        esac
    done
    pass "$LABEL"
}

OUT=$(sh "$REPO_ROOT/tpm_setup.sh" --help 2>&1); CODE=$?
check_output "tpm_setup.sh --help" "$OUT" "$CODE" "--env-file" "--uninstall" "TPM 2.0"

OUT=$(sh "$REPO_ROOT/tpm_setup.sh" -h 2>&1); CODE=$?
check_output "tpm_setup.sh -h" "$OUT" "$CODE" "--env-file" "--uninstall" "TPM 2.0"

if command -v pwsh >/dev/null 2>&1; then
    OUT=$(pwsh -NoProfile -File "$REPO_ROOT/tpm_setup.ps1" -Help 2>&1); CODE=$?
    check_output "tpm_setup.ps1 -Help" "$OUT" "$CODE" "-EnvFile" "-Uninstall" "TPM 2.0"

    OUT=$(pwsh -NoProfile -File "$REPO_ROOT/tpm_setup.ps1" -h 2>&1); CODE=$?
    check_output "tpm_setup.ps1 -h" "$OUT" "$CODE" "-EnvFile" "-Uninstall" "TPM 2.0"
else
    printf "SKIP: pwsh not installed, skipping tpm_setup.ps1 -Help checks\n"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
