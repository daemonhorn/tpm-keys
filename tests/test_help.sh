#!/bin/sh
# Tests --help/-h (tpm_setup.sh) and -Help/-h (tpm_setup.ps1): exits 0,
# includes a one-paragraph summary of what the script does, and mentions
# every other CLI flag the script currently supports -- so adding a new
# flag (or dropping the summary) without updating usage text shows up as
# a test failure instead of silently going stale.
#
# Also tests that a genuine CLI syntax error (an unrecognized flag) prints
# that same usage text before exiting non-zero, rather than a bare error
# with no guidance -- on the PowerShell side this needs its own manual
# $args parsing (no formal param() block) specifically because a formal
# param() block's parameter binder rejects an unrecognized flag before a
# single line of the script runs, which would make showing our own usage
# text on a typo impossible.
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

check_error_output() {
    LABEL="$1"
    OUTPUT="$2"
    CODE="$3"
    shift 3
    if [ "$CODE" -eq 0 ]; then
        fail "$LABEL: exited 0, expected a non-zero syntax-error exit"
        return
    fi
    for NEEDLE in "$@"; do
        case "$OUTPUT" in
            *"$NEEDLE"*) ;;
            *)
                fail "$LABEL: error output is missing '$NEEDLE' -- syntax errors should show usage"
                return
                ;;
        esac
    done
    pass "$LABEL"
}

OUT=$(sh "$REPO_ROOT/tpm_setup.sh" --help 2>&1); CODE=$?
check_output "tpm_setup.sh --help" "$OUT" "$CODE" "--env-file" "--uninstall" "--status" "--reinstall-scripts" "TPM 2.0"

OUT=$(sh "$REPO_ROOT/tpm_setup.sh" -h 2>&1); CODE=$?
check_output "tpm_setup.sh -h" "$OUT" "$CODE" "--env-file" "--uninstall" "--status" "--reinstall-scripts" "TPM 2.0"

OUT=$(sh "$REPO_ROOT/tpm_setup.sh" --bogus-flag 2>&1); CODE=$?
check_error_output "tpm_setup.sh --bogus-flag (unknown flag)" "$OUT" "$CODE" "--env-file" "--uninstall" "Unknown argument"

OUT=$(sh "$REPO_ROOT/tpm_setup.sh" --env-file 2>&1); CODE=$?
check_error_output "tpm_setup.sh --env-file (missing value)" "$OUT" "$CODE" "--env-file" "--uninstall" "requires a path argument"

if command -v pwsh >/dev/null 2>&1; then
    OUT=$(pwsh -NoProfile -File "$REPO_ROOT/tpm_setup.ps1" -Help 2>&1); CODE=$?
    check_output "tpm_setup.ps1 -Help" "$OUT" "$CODE" "-EnvFile" "-Uninstall" "-Status" "-ReinstallScripts" "TPM 2.0"

    OUT=$(pwsh -NoProfile -File "$REPO_ROOT/tpm_setup.ps1" -h 2>&1); CODE=$?
    check_output "tpm_setup.ps1 -h" "$OUT" "$CODE" "-EnvFile" "-Uninstall" "-Status" "-ReinstallScripts" "TPM 2.0"

    OUT=$(pwsh -NoProfile -File "$REPO_ROOT/tpm_setup.ps1" -BogusFlag 2>&1); CODE=$?
    check_error_output "tpm_setup.ps1 -BogusFlag (unknown flag)" "$OUT" "$CODE" "-EnvFile" "-Uninstall" "Unknown argument"

    OUT=$(pwsh -NoProfile -File "$REPO_ROOT/tpm_setup.ps1" -EnvFile 2>&1); CODE=$?
    check_error_output "tpm_setup.ps1 -EnvFile (missing value)" "$OUT" "$CODE" "-EnvFile" "-Uninstall" "requires a path argument"
else
    printf "SKIP: pwsh not installed, skipping tpm_setup.ps1 -Help checks\n"
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
