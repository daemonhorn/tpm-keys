#!/bin/sh
# Tests _tpm_parse_env_file (extracted verbatim from tpm_setup.sh) against
# a valid dotenv fixture and a handful of rejected-input cases. Pure logic,
# no TPM required.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/lib/extract.sh"

TESTS_RUN=0
TESTS_FAILED=0
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

eval "$(extract_func "$REPO_ROOT/tpm_setup.sh" _tpm_trim)"
eval "$(extract_func "$REPO_ROOT/tpm_setup.sh" _tpm_parse_env_file)"

EXPECTED='OPENAI_KEY="sk-abc123";AWS_SECRET_ACCESS_KEY="s3cr3t with spaces";SINGLE_QUOTED="hello world";TRAILING_SPACE="padded value"'
GOT=$(_tpm_parse_env_file "$SCRIPT_DIR/fixtures/sample.env" 2>/dev/null)
[ "$GOT" = "$EXPECTED" ] && pass "valid dotenv fixture parses correctly" || fail "valid dotenv fixture: got [$GOT]"

TMPDIR=$(mktemp -d)

printf 'BAD="has \\"quote\\" inside"\n' > "$TMPDIR/quote.env"
if _tpm_parse_env_file "$TMPDIR/quote.env" >/dev/null 2>&1; then
    fail "value with embedded double-quote should be rejected"
else
    pass "value with embedded double-quote is rejected"
fi

printf 'BAD=has;semicolon\n' > "$TMPDIR/semi.env"
if _tpm_parse_env_file "$TMPDIR/semi.env" >/dev/null 2>&1; then
    fail "value with embedded semicolon should be rejected"
else
    pass "value with embedded semicolon is rejected"
fi

printf '1BAD=value\n' > "$TMPDIR/badname.env"
if _tpm_parse_env_file "$TMPDIR/badname.env" >/dev/null 2>&1; then
    fail "invalid variable name should be rejected"
else
    pass "invalid variable name is rejected"
fi

printf 'notakeyvalueline\n' > "$TMPDIR/noeq.env"
if _tpm_parse_env_file "$TMPDIR/noeq.env" >/dev/null 2>&1; then
    fail "line without '=' should be rejected"
else
    pass "line without '=' is rejected"
fi

printf '# just a comment\n\n' > "$TMPDIR/empty.env"
if _tpm_parse_env_file "$TMPDIR/empty.env" >/dev/null 2>&1; then
    fail "file with no NAME=VALUE lines should be rejected"
else
    pass "file with no NAME=VALUE lines is rejected"
fi

rm -rf "$TMPDIR"

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
