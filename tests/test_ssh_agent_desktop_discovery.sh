#!/bin/sh
# Regression test for a real bug found on a live Debian 13/GNOME desktop:
# a plain SSH login to a machine does NOT inherit the graphical session's
# environment (SSH_AUTH_SOCK, DISPLAY, ...) the way a new local terminal
# spawned from the desktop does, even though the desktop session's own
# ssh-agent (GNOME Keyring/gcr-ssh-agent/KDE Wallet, exported via
# `systemctl --user set-environment`) already has the SSH identity loaded
# from an earlier unlock_tpm run. _tpm_ensure_ssh_agent used to only check
# whether $SSH_AUTH_SOCK was already set, so any such session would spawn
# a brand-new, empty, throwaway ssh-agent instead of reusing the
# already-unsealed desktop one -- meaning the Master PIN got re-requested
# on every single such session forever, even though the secrets were
# already unsealed elsewhere. Now it tries `systemctl --user
# show-environment` first (confirmed live against a real GNOME Keyring
# agent: raw `ssh-add -`-loaded keys persist there across sessions, and
# `ssh-keygen -Y sign` against it works fine once SSH_AUTH_SOCK is set
# correctly) before falling back to spawning a private agent.
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/lib/extract.sh"

TESTS_RUN=0
TESTS_FAILED=0
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf "PASS: %s\n" "$1"; }
fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); printf "FAIL: %s\n" "$1"; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
FAKEBIN="$TMPDIR/fakebin"
mkdir -p "$FAKEBIN"

SNIPPET="$TMPDIR/ensure_agent.sh"
extract_func "$REPO_ROOT/tpm_setup.sh" "_tpm_ensure_ssh_agent" > "$SNIPPET"
if [ ! -s "$SNIPPET" ]; then
    fail "could not extract _tpm_ensure_ssh_agent from tpm_setup.sh -- did it move/change shape?"
    printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
    exit 1
fi

# FAKE_SYSTEMCTL_SOCK: path show-environment should report (empty = no
# systemd user session / not installed, matching FreeBSD or a headless box).
cat > "$FAKEBIN/systemctl" <<'EOF'
#!/bin/sh
if [ "$1" = "--user" ] && [ "$2" = "show-environment" ]; then
    [ -n "${FAKE_SYSTEMCTL_SOCK:-}" ] && printf 'SSH_AUTH_SOCK=%s\nOTHERVAR=x\n' "$FAKE_SYSTEMCTL_SOCK"
    exit 0
fi
exit 1
EOF
chmod +x "$FAKEBIN/systemctl"

# Records whether the real ssh-agent got invoked (i.e. a throwaway agent
# was spawned) instead of reusing a discovered/pre-set socket.
cat > "$FAKEBIN/ssh-agent" <<EOF
#!/bin/sh
echo "SPAWNED" >> "$TMPDIR/spawned.log"
echo "SSH_AUTH_SOCK=$TMPDIR/throwaway.sock; export SSH_AUTH_SOCK;"
echo "SSH_AGENT_PID=12345; export SSH_AGENT_PID;"
EOF
chmod +x "$FAKEBIN/ssh-agent"

run_case() {
    : > "$TMPDIR/spawned.log"
    # SSH_AUTH_SOCK="" first so this sandbox's own ambient agent socket
    # (inherited otherwise, since `env` only sets/overrides listed names
    # rather than clearing everything) never leaks into the "no
    # SSH_AUTH_SOCK at all" cases -- a later same-named override in "$@"
    # (the "already set" case) still wins, since env applies duplicate
    # assignments left to right.
    env SSH_AUTH_SOCK="" "$@" PATH="$FAKEBIN:/bin:/usr/bin" \
        sh -ec ". '$SNIPPET'; _tpm_ensure_ssh_agent; printf 'SOCK=%s\n' \"\$SSH_AUTH_SOCK\"" 2>&1
}

echo "=== no SSH_AUTH_SOCK, desktop session has a real discoverable socket ==="
# _tpm_ensure_ssh_agent's `-S` test needs a REAL unix socket, not just a
# path that exists (a plain file must be rejected -- see the next case) --
# bind one with python3 if available, else skip just this one assertion.
if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('$TMPDIR/real.sock')
" &
    LISTENER_PID=$!
    sleep 0.2
    OUT=$(run_case FAKE_SYSTEMCTL_SOCK="$TMPDIR/real.sock")
    kill "$LISTENER_PID" 2>/dev/null
    case "$OUT" in
        *"SOCK=$TMPDIR/real.sock"*) pass "adopts a real discovered desktop socket instead of spawning a new agent" ;;
        *) fail "did not adopt the discovered desktop socket: $OUT" ;;
    esac
    if grep -q SPAWNED "$TMPDIR/spawned.log"; then
        fail "spawned a throwaway agent even though a valid desktop socket was discoverable"
    else
        pass "does not spawn a throwaway agent when a valid desktop socket is discoverable"
    fi
else
    printf "SKIP: python3 not available, skipping real-socket adoption case\n"
fi

echo "=== no SSH_AUTH_SOCK, systemctl reports a path but it is not a real socket ==="
: > "$TMPDIR/notasocket"
OUT=$(run_case FAKE_SYSTEMCTL_SOCK="$TMPDIR/notasocket")
if grep -q SPAWNED "$TMPDIR/spawned.log"; then
    pass "falls back to spawning an agent when the discovered path is not a real socket"
else
    fail "did not fall back to spawning when the discovered path was not a real socket: $OUT"
fi

echo "=== no SSH_AUTH_SOCK, no desktop session at all (systemctl reports nothing) ==="
OUT=$(run_case)
if grep -q SPAWNED "$TMPDIR/spawned.log"; then
    pass "falls back to spawning an agent when nothing is discoverable (matches FreeBSD/headless)"
else
    fail "did not fall back to spawning when nothing was discoverable: $OUT"
fi

echo "=== SSH_AUTH_SOCK already set -- must never be overridden by discovery ==="
OUT=$(run_case FAKE_SYSTEMCTL_SOCK="$TMPDIR/notasocket" SSH_AUTH_SOCK="$TMPDIR/already-set.sock")
if grep -q SPAWNED "$TMPDIR/spawned.log"; then
    fail "spawned/replaced an agent even though SSH_AUTH_SOCK was already set: $OUT"
else
    case "$OUT" in
        *"SOCK=$TMPDIR/already-set.sock"*) pass "leaves an already-set SSH_AUTH_SOCK untouched" ;;
        *) fail "an already-set SSH_AUTH_SOCK was changed: $OUT" ;;
    esac
fi

printf "\n%s/%s tests passed\n" "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" -eq 0 ]
