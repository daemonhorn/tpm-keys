# Shared test helper: pulls a single top-level function definition out of
# tpm_setup.sh (or any file using the same style) by name, so tests exercise
# the actual shipped code instead of a reimplementation that could drift
# out of sync with it.
#
# Relies on this repo's convention that every top-level function is written
# as:
#   funcname() {
#       ...
#   }
# with the closing brace alone on a line at column 0. Nested if/case/while
# blocks are fine (they don't use literal '{'/'}'); this does NOT handle a
# function containing a nested function definition.
#
# Usage: extract_func <file> <funcname> -- prints the function source to stdout.
extract_func() {
    FILE="$1"
    NAME="$2"
    awk -v name="$NAME" '
        $0 ~ "^" name "\\(\\) \\{" { found=1 }
        found { print }
        found && /^}/ { exit }
    ' "$FILE"
}
