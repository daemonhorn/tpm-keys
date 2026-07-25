#!/bin/sh
# Runs every test in this directory and prints a summary. Individual tests
# print SKIP and exit 0 when a prerequisite (tpm2-tools + TPM access, tcsh,
# pwsh) isn't available, so this is safe to run on a partial environment --
# it will just cover less.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

SUITES_RUN=0
SUITES_FAILED=0

run_suite() {
    LABEL="$1"
    shift
    SUITES_RUN=$((SUITES_RUN + 1))
    printf "\n=== %s ===\n" "$LABEL"
    if "$@"; then
        :
    else
        SUITES_FAILED=$((SUITES_FAILED + 1))
    fi
}

run_suite "sentinel header (sh)" sh "$SCRIPT_DIR/test_sentinel_header.sh"
run_suite "env file parser (sh)" sh "$SCRIPT_DIR/test_env_file_parser.sh"
run_suite "tcsh alias regression" sh "$SCRIPT_DIR/test_tcsh_alias_bug.sh"

if command -v pwsh >/dev/null 2>&1; then
    run_suite "sentinel header (PowerShell)" pwsh -NoProfile -File "$SCRIPT_DIR/test_sentinel_header.ps1"
    run_suite "env file parser (PowerShell)" pwsh -NoProfile -File "$SCRIPT_DIR/test_env_file_parser.ps1"
else
    printf "\n=== PowerShell tests ===\nSKIP: pwsh not installed\n"
fi

printf "\n%s/%s suites passed\n" "$((SUITES_RUN - SUITES_FAILED))" "$SUITES_RUN"
[ "$SUITES_FAILED" -eq 0 ]
