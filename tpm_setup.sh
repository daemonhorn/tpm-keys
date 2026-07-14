#!/bin/sh
# Universal TPM 2.0 Secure Setup Script
# Features: Single Master PIN, Auto/Manual execution, Multi-User safe
# OS Support: Debian, RHEL (Rocky/Alma/CentOS), FreeBSD

set -e

# $USER isn't guaranteed to be set (containers, cron, some su contexts).
USER="${USER:-$(id -un)}"

# tpm2-tools' libtss2 backends log every TCTI probe attempt (device, swtpm,
# mssim, ...) straight to stderr, which buries our own error messages under
# a wall of "ERROR:tcti:..." noise. Silence it by default; an operator who
# wants the raw logs back can still set TSS2_LOG before running this script.
TSS2_LOG="${TSS2_LOG:-all+none}"
export TSS2_LOG

printf "%s\n" "=== Phase 1: OS Detection & Prerequisites ==="

OS_NAME=$(uname -s)
DISTRO="unknown"

if [ "$OS_NAME" = "Linux" ]; then
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ] || echo "$ID_LIKE" | grep -qi "debian"; then
            DISTRO="debian"
        elif [ "$ID" = "rocky" ] || [ "$ID" = "rhel" ] || [ "$ID" = "centos" ] || echo "$ID_LIKE" | grep -qi "rhel"; then
            DISTRO="rhel"
        fi
    fi
elif [ "$OS_NAME" = "FreeBSD" ]; then
    DISTRO="freebsd"
fi

# Configure OS-specific commands
case "$DISTRO" in
    "debian")
        printf "%s\n" "Detected Debian-based Linux."
        PKG_MGR="sudo apt-get update && sudo apt-get install -y tpm2-tools"
        TPM_DEV="/dev/tpmrm0"
        GROUP_NAME="tss"
        GROUP_CREATE="getent group tss >/dev/null 2>&1 || sudo groupadd --system tss"
        GROUP_CMD="sudo usermod -aG tss $USER"
        ;;
    "rhel")
        printf "%s\n" "Detected RHEL/Rocky-based Linux."
        if command -v dnf >/dev/null 2>&1; then
            PKG_MGR="sudo dnf install -y tpm2-tools"
        else
            PKG_MGR="sudo yum install -y tpm2-tools"
        fi
        TPM_DEV="/dev/tpmrm0"
        GROUP_NAME="tss"
        GROUP_CREATE="getent group tss >/dev/null 2>&1 || sudo groupadd --system tss"
        GROUP_CMD="sudo usermod -aG tss $USER"
        ;;
    "freebsd")
        printf "%s\n" "Detected FreeBSD."
        PKG_MGR="sudo pkg install -y tpm2-tools"
        TPM_DEV="/dev/tpm0"
        GROUP_NAME="_tss"
        GROUP_CREATE="pw groupshow _tss >/dev/null 2>&1 || sudo pw groupadd _tss"
        GROUP_CMD="sudo pw groupmod _tss -m $USER"
        ;;
    *)
        printf "[TPM] ERROR: Unsupported OS or Distribution (%s). Aborting.\n" "$OS_NAME"
        exit 1
        ;;
esac

# 1. Package Management
if ! command -v tpm2_nvread >/dev/null 2>&1; then
    printf "%s\n" "tpm2-tools not found. Installing..."
    if ! eval "$PKG_MGR"; then
        printf "[TPM] ERROR: Failed to install tpm2-tools. Check network/package manager output above and re-run.\n"
        exit 1
    fi
fi

# 2. Kernel Module & Driver Attachment Check
printf "%s\n" "Verifying TPM kernel driver attachment..."

if [ "$OS_NAME" = "Linux" ]; then
    if [ ! -c "$TPM_DEV" ] && [ ! -c "/dev/tpm0" ]; then
        printf "%s\n" "TPM node missing. Attempting to load common Linux TPM modules (tpm_tis, tpm_crb)..."
        sudo modprobe tpm_tis >/dev/null 2>&1 || true
        sudo modprobe tpm_crb >/dev/null 2>&1 || true
        sleep 1 # Give udev a moment to populate /dev
    fi
elif [ "$OS_NAME" = "FreeBSD" ]; then
    if [ ! -c "$TPM_DEV" ]; then
        printf "%s\n" "TPM node missing. Attempting to load FreeBSD tpm module..."
        sudo kldload tpm >/dev/null 2>&1 || true
    fi

    # Ensure persistence in rc.conf if running dynamically
    if kldstat -n tpm.ko >/dev/null 2>&1; then
        if ! sysrc -n kld_list 2>/dev/null | grep -qw "tpm"; then
            printf "%s\n" "Adding tpm to kld_list in /etc/rc.conf for persistence..."
            sudo sysrc kld_list+="tpm" >/dev/null 2>&1
        fi
    fi

    # Apply persistent devfs rules if missing
    if ! grep -q "^own.*tpm0" /etc/devfs.conf 2>/dev/null; then
        printf "%s\n" "Configuring persistent devfs permissions for /dev/tpm0 in /etc/devfs.conf..."
        sudo sh -c 'echo "" >> /etc/devfs.conf'
        sudo sh -c 'echo "# TPM 2.0 Group Access" >> /etc/devfs.conf'
        sudo sh -c 'echo "own tpm0 root:_tss" >> /etc/devfs.conf'
        sudo sh -c 'echo "perm tpm0 0660" >> /etc/devfs.conf'
        sudo service devfs restart >/dev/null 2>&1 || true
    fi
fi

# VERIFICATION: Did the driver actually attach to hardware?
if [ ! -c "$TPM_DEV" ] && [ ! -c "/dev/tpm0" ]; then
    printf "\n%s\n" "================================================================"
    printf "%s\n"   " WARNING: TPM DEVICE DRIVER FAILED TO ATTACH"
    printf "%s\n"   "================================================================"
    if [ "$OS_NAME" = "Linux" ]; then
        printf "%s\n" "The kernel modules were loaded, but no device node was created"
        printf "%s\n" "at $TPM_DEV or /dev/tpm0. This indicates the driver"
        printf "%s\n" "could not find or attach to a physical or firmware TPM."
        printf "%s\n" "Troubleshooting: Run 'dmesg | grep -i tpm'"
    elif [ "$OS_NAME" = "FreeBSD" ]; then
        printf "%s\n" "The 'tpm' module was loaded, but no device node was created"
        printf "%s\n" "at $TPM_DEV. This indicates the FreeBSD device driver"
        printf "%s\n" "could not find or attach to the TPM hardware."
        printf "%s\n" "Troubleshooting: Run 'dmesg | grep tpm' or 'devinfo -v | grep tpm'"
    fi
    printf "\n%s\n\n" "ACTION: Ensure TPM 2.0 (fTPM/Intel PTT) is enabled in your BIOS/UEFI."
    exit 1
fi

# Fallback for Linux if resource manager isn't present, but the base hardware node is
[ "$OS_NAME" = "Linux" ] && [ ! -c "$TPM_DEV" ] && TPM_DEV="/dev/tpm0"

# 3. Safe Group Creation & Assignment
#
# NOTE: "id -nG $USER" (with a username argument) reads group membership
# straight out of the passwd/group database, NOT the live process's actual
# supplementary groups. It would report the new group as active immediately
# after usermod runs, even in a shell that hasn't picked it up yet -- letting
# this check pass right before the TPM device open() fails with EACCES.
# "id -nG" with no argument reports this process's real, live group list,
# which is what actually determines whether we can open the TPM device.
eval "$GROUP_CREATE"
if ! id -nG | grep -qw "$GROUP_NAME"; then
    printf "Adding user %s to %s group...\n" "$USER" "$GROUP_NAME"
    eval "$GROUP_CMD"
    printf "\n%s\n" "================================================================"
    printf "%s\n"   "[TPM] ACTION REQUIRED: Group membership changed."
    printf "%s\n"   "================================================================"
    printf "%s\n" "Log out COMPLETELY and log back in, then re-run this script from a"
    printf "%s\n" "brand-new terminal. A partial logout (locking the screen, closing"
    printf "%s\n" "one window, or reusing an existing tmux/screen session that"
    printf "%s\n" "predates this change) will NOT pick up the new group -- you need a"
    printf "%s\n" "fresh login session."
    exit 0
fi

# --- SSH-agent-derived PIN helpers (optional API Key unlock optimization,
# see the "API Key Unlock Optimization" prompt in Phase 3 below) ---
_tpm_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | cut -d' ' -f1
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 -q
    fi
}

# Derives a stable PIN from a deterministic ed25519 signature: ssh-keygen -Y
# sign is deterministic per RFC 8032 (same key + message + namespace always
# produces the same signature bytes), whether signed directly from a private
# key file (setup time) or via an ssh-agent identity referenced by its public
# key (unlock time) -- verified empirically, both paths yield identical
# signature bytes. $1 is the key path (private key at setup, public key at
# unlock time so ssh-keygen can fall back to querying ssh-agent for it).
# Truncated to 32 hex chars (128 bits): a full sha256 digest is 64 bytes,
# which some TPMs reject as an auth value ("Invalid index authorization").
_tpm_derive_api_pin() {
    KEY_PATH="$1"
    [ -r "$KEY_PATH" ] || return 1
    SIGN_DIR=$(mktemp -d) || return 1
    printf '%s' "tpm-api-pin-v1:${USER}" > "$SIGN_DIR/challenge"
    DERIVED=""
    if ssh-keygen -Y sign -f "$KEY_PATH" -n tpm-api-pin "$SIGN_DIR/challenge" >/dev/null 2>&1; then
        DERIVED=$(_tpm_sha256 < "$SIGN_DIR/challenge.sig" 2>/dev/null | cut -c1-32)
    fi
    rm -rf "$SIGN_DIR"
    [ -n "$DERIVED" ] || return 1
    printf '%s' "$DERIVED"
}

# --- 2. Dynamic NV Index Allocation & User Choices ---
USER_UID=$(id -u)
API_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 )))
SSH_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 + 1 )))
API_NV_SIZE=1024
SSH_NV_SIZE=1024

# Remembers which PIN sealed the API Key NV index ("master" or "agent" -- see
# the "API Key Unlock Optimization" prompt below) across re-runs where the
# user keeps existing data (RESEED=0) and Phase 5 regenerates the shell
# integration without re-asking. Defaults to "master" for installs from
# before this feature existed.
STATE_FILE="$HOME/.tpm_keys_state"
API_AUTH_MODE="master"
[ -f "$STATE_FILE" ] && . "$STATE_FILE"

# Belt-and-suspenders check: even after the group-membership gate above, a
# device open() can still fail (odd devfs/udev rule, a group whose name
# matches but whose gid doesn't, running under su/sudo without a fresh
# login shell, etc). Catch that here, before asking for any secrets, with a
# clear diagnostic instead of letting a later tpm2 command fail and surface
# a confusing low-level error.
if [ ! -r "$TPM_DEV" ] || [ ! -w "$TPM_DEV" ]; then
    printf "\n%s\n" "================================================================"
    printf "%s\n"   " ERROR: Cannot access the TPM device ($TPM_DEV)"
    printf "%s\n"   "================================================================"
    if id -nG | grep -qw "$GROUP_NAME"; then
        printf "%s\n" "This shell IS in the '$GROUP_NAME' group, but still cannot"
        printf "%s\n" "read/write $TPM_DEV. Check the device's owner/permissions:"
        printf "%s\n" "  $(ls -l "$TPM_DEV" 2>/dev/null)"
        printf "%s\n" "and confirm its group matches '$GROUP_NAME'."
    else
        printf "%s\n" "This shell is NOT in the '$GROUP_NAME' group, even though an"
        printf "%s\n" "earlier run of this script should have added it. Log out"
        printf "%s\n" "COMPLETELY (all terminals/tmux/screen sessions, full desktop"
        printf "%s\n" "logout, not just a lock screen) and log back in, then re-run"
        printf "%s\n" "this script from a brand-new terminal."
    fi
    printf "[TPM] ERROR: Aborting.\n"
    exit 1
fi

# --- Idempotency check: has this user already seeded TPM data? ---
# Re-running this script (e.g. to pick up a shell-integration fix, or add
# support for another shell) must not force new secrets to be entered and
# the existing NV data destroyed -- that would break safe re-use.
API_EXISTS=0
SSH_EXISTS=0
tpm2_nvreadpublic "$API_NV_INDEX" >/dev/null 2>&1 && API_EXISTS=1
tpm2_nvreadpublic "$SSH_NV_INDEX" >/dev/null 2>&1 && SSH_EXISTS=1

RESEED=1
if [ "$API_EXISTS" -eq 1 ] && [ "$SSH_EXISTS" -eq 1 ]; then
    printf "\n%s\n" "=== Existing TPM Data Detected ==="
    printf "%s\n" "An API Key and SSH Key are already sealed in the TPM for this user"
    printf "%s\n" "(NV indices $API_NV_INDEX / $SSH_NV_INDEX)."
    printf "Re-seed and overwrite the existing data? (y/n) [default: n]: "
    read RESEED_CHOICE
    case "$RESEED_CHOICE" in
        [Yy]*) RESEED=1 ;;
        *) RESEED=0 ;;
    esac
fi

printf "\n%s\n" "--- Unlock Strategy ---"
printf "%s\n" "[1] Automatic : Prompt for PIN automatically when opening a new terminal."
printf "%s\n" "[2] Manual    : Print a hint in new terminals, wait for you to run 'unlock_tpm'."
printf "Choose (1 or 2) [default: 1]: "
read STRATEGY_CHOICE
[ "$STRATEGY_CHOICE" != "2" ] && STRATEGY_CHOICE="1"

SSH_KEY_PATH="$HOME/.ssh/id_ed25519"

if [ "$RESEED" -eq 0 ]; then
    printf "\n%s\n" "[TPM] Keeping existing TPM data; skipping secret entry and re-seeding."
else

printf "\n%s\n" "=== Phase 2: Configuration ==="

# --- Secret parsing helper, shared shape with the generated unlock scripts ---
# Recognizes NAME="VALUE" segments separated by ';'. If none are found the
# whole input is treated as a single legacy opaque API key.
_tpm_report_secret() {
    RAW="$1"
    FOUND_KV=0
    INVALID_SEGMENTS=0
    NAMES=""
    set -f
    OLD_IFS="$IFS"
    IFS=';'
    set -- $RAW
    IFS="$OLD_IFS"
    for PAIR in "$@"; do
        [ -z "$PAIR" ] && continue
        case "$PAIR" in
            *'="'*'"')
                NAME="${PAIR%%=*}"
                case "$NAME" in
                    '' | *[!A-Za-z0-9_]* | [0-9]*)
                        INVALID_SEGMENTS=$((INVALID_SEGMENTS + 1))
                        ;;
                    *)
                        FOUND_KV=1
                        NAMES="$NAMES $NAME"
                        ;;
                esac
                ;;
            *)
                # Only flag as a botched attempt when the part before the
                # first '=' actually looks like an identifier (e.g. a
                # missing-quotes typo); a legacy key with an incidental '='
                # (base64 padding, etc.) should not trigger the warning.
                case "$PAIR" in
                    *'='*)
                        CAND="${PAIR%%=*}"
                        case "$CAND" in
                            '' | *[!A-Za-z0-9_]* | [0-9]*) : ;;
                            *) INVALID_SEGMENTS=$((INVALID_SEGMENTS + 1)) ;;
                        esac
                        ;;
                esac
                ;;
        esac
    done
    set +f
}

API_ATTEMPTS=0
while :; do
    API_ATTEMPTS=$((API_ATTEMPTS + 1))
    printf "%s\n" "Enter the value(s) to store in the TPM. This can be either:"
    printf "%s\n" "  - a single API key/token, stored as \$SECURE_API_KEY, or"
    printf "%s\n" "  - one or more named values: NAME1=\"value1\";NAME2=\"value2\";..."
    printf "Enter value(s): "
    read API_KEY_INPUT

    if [ -z "$API_KEY_INPUT" ]; then
        printf "[TPM] ERROR: Value cannot be empty.\n\n"
    else
        INPUT_LEN=$(printf '%s' "$API_KEY_INPUT" | wc -c | tr -d ' ')
        if [ "$INPUT_LEN" -gt "$API_NV_SIZE" ]; then
            printf "[TPM] ERROR: Input is %s bytes, which exceeds the %s-byte limit. Please shorten it.\n\n" "$INPUT_LEN" "$API_NV_SIZE"
        else
            _tpm_report_secret "$API_KEY_INPUT"
            CONFIRM_OK=1
            if [ "$FOUND_KV" -eq 1 ]; then
                printf "[TPM] Detected named value(s):%s\n" "$NAMES"
                if [ "$INVALID_SEGMENTS" -gt 0 ]; then
                    printf "[TPM] Warning: %s segment(s) did not match NAME=\"VALUE\" and will be dropped at unlock time.\n" "$INVALID_SEGMENTS"
                    printf "Proceed anyway? (y/n): "
                    read CONFIRM
                    case "$CONFIRM" in [Yy]*) ;; *) CONFIRM_OK=0 ;; esac
                fi
            else
                if [ "$INVALID_SEGMENTS" -gt 0 ]; then
                    printf "%s\n" "[TPM] Warning: no valid NAME=\"VALUE\" pairs were recognized."
                    printf "%s\n" "This will be stored as a single opaque API key. If you intended"
                    printf "%s\n" "separate values, check the format (e.g. TOKEN=\"value\";TOKEN2=\"value2\")."
                    printf "Proceed anyway? (y/n): "
                    read CONFIRM
                    case "$CONFIRM" in [Yy]*) ;; *) CONFIRM_OK=0 ;; esac
                else
                    printf "%s\n" "[TPM] Storing as a single API key."
                fi
            fi
            [ "$CONFIRM_OK" -eq 1 ] && break
        fi
    fi

    if [ "$API_ATTEMPTS" -ge 3 ]; then
        printf "[TPM] ERROR: Too many invalid attempts. Aborting.\n"
        exit 1
    fi
    printf "\n"
done

PIN_ATTEMPTS=0
while :; do
    PIN_ATTEMPTS=$((PIN_ATTEMPTS + 1))
    printf "Create a Master PIN to protect your TPM keys: "
    trap 'stty echo' INT TERM
    stty -echo; read MASTER_PIN; stty echo; printf "\n"
    printf "Confirm Master PIN: "
    stty -echo; read MASTER_PIN_CONFIRM; stty echo; printf "\n\n"
    trap - INT TERM

    if [ -z "$MASTER_PIN" ]; then
        printf "[TPM] ERROR: PIN cannot be empty.\n\n"
    elif [ "$MASTER_PIN" != "$MASTER_PIN_CONFIRM" ]; then
        printf "[TPM] ERROR: PINs did not match.\n\n"
    else
        break
    fi
    if [ "$PIN_ATTEMPTS" -ge 3 ]; then
        printf "[TPM] ERROR: Too many failed attempts. Aborting.\n"
        exit 1
    fi
done

# --- 3. SSH Key Generation ---
printf "\n%s\n" "=== Phase 3: SSH Key Setup ==="
if [ ! -f "$SSH_KEY_PATH" ]; then
    printf "No Ed25519 key found at %s. Generate one now? (y/n): " "$SSH_KEY_PATH"
    read GEN_KEY
    case "$GEN_KEY" in
        [Yy]* )
            if ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N ""; then
                printf "%s\n" "[TPM] Key generated."
            else
                printf "[TPM] ERROR: ssh-keygen failed. Aborting.\n"
                exit 1
            fi
            ;;
        * ) printf "[TPM] ERROR: You must have an Ed25519 key to continue.\n"; exit 1;;
    esac
fi

SSH_KEY_SIZE=$(wc -c < "$SSH_KEY_PATH" | tr -d ' ')
if [ "$SSH_KEY_SIZE" -gt "$SSH_NV_SIZE" ]; then
    printf "[TPM] ERROR: %s is %s bytes, which exceeds the %s-byte NV limit. Aborting.\n" "$SSH_KEY_PATH" "$SSH_KEY_SIZE" "$SSH_NV_SIZE"
    exit 1
fi

printf "\n%s\n" "--- API Key Unlock Optimization ---"
printf "%s\n" "ssh-agent keeps your loaded SSH identity available across every new"
printf "%s\n" "gnome-terminal / gnome-shell tab in a session (they all inherit the"
printf "%s\n" "same SSH_AUTH_SOCK), but \$SECURE_API_KEY is just a shell variable,"
printf "%s\n" "so it does NOT carry over -- each new tab still prompts you for the"
printf "%s\n" "Master PIN just to reload the API key, even though the SSH identity"
printf "%s\n" "is already unlocked."
printf "%s\n" ""
printf "%s\n" "Enabling this seals the API Key under a PIN *derived* from your SSH"
printf "%s\n" "ed25519 key (a deterministic 'ssh-keygen -Y sign' challenge) instead"
printf "%s\n" "of the Master PIN. Once your SSH identity is loaded into ssh-agent in"
printf "%s\n" "any tab, every other tab can silently re-derive that same value and"
printf "%s\n" "load \$SECURE_API_KEY with NO PIN prompt."
printf "%s\n" ""
printf "%s\n" "Security note: this makes ssh-agent access equivalent to knowing the"
printf "%s\n" "API key's PIN -- anyone who can get your agent to sign on your behalf"
printf "%s\n" "(e.g. SSH agent forwarding to a hostile host) can derive it too."
printf "%s\n" "Requires OpenSSH >= 8.2 (ssh-keygen -Y sign)."
printf "Enable SSH-agent-derived PIN for the API Key? (y/n) [default: n]: "
read API_PIN_MODE_CHOICE
case "$API_PIN_MODE_CHOICE" in
    [Yy]*) API_AUTH_MODE="agent" ;;
    *) API_AUTH_MODE="master" ;;
esac

# --- 4. Seeding the TPM ---
printf "\n%s\n" "=== Phase 4: Seeding TPM NV RAM ==="

_tpm_confirm_overwrite() {
    IDX="$1"
    LABEL="$2"
    if tpm2_nvreadpublic "$IDX" >/dev/null 2>&1; then
        printf "[TPM] WARNING: An existing secret is already stored at %s (%s).\n" "$IDX" "$LABEL"
        printf "Overwriting it will PERMANENTLY DESTROY the existing data. Continue? (y/n): "
        read CONFIRM
        case "$CONFIRM" in
            [Yy]*) ;;
            *) printf "[TPM] Aborting to protect existing data.\n"; exit 1 ;;
        esac
    fi
}
_tpm_confirm_overwrite "$API_NV_INDEX" "API Key"
_tpm_confirm_overwrite "$SSH_NV_INDEX" "SSH Key"

tpm2_nvundefine -C o "$API_NV_INDEX" >/dev/null 2>&1 || true
tpm2_nvundefine -C o "$SSH_NV_INDEX" >/dev/null 2>&1 || true

API_NV_AUTH="$MASTER_PIN"
if [ "$API_AUTH_MODE" = "agent" ]; then
    printf "%s\n" "[TPM] Deriving API Key PIN from your SSH key (you may be asked for its passphrase)..."
    if DERIVED_API_PIN=$(_tpm_derive_api_pin "$SSH_KEY_PATH") && [ -n "$DERIVED_API_PIN" ]; then
        API_NV_AUTH="$DERIVED_API_PIN"
    else
        printf "[TPM] WARNING: Could not derive a PIN from the SSH key (requires OpenSSH >= 8.2's 'ssh-keygen -Y sign'). Falling back to the Master PIN for the API Key.\n"
        API_AUTH_MODE="master"
    fi
    unset DERIVED_API_PIN
fi
printf "API_AUTH_MODE=%s\n" "$API_AUTH_MODE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"

printf "Writing API Key to TPM (%s)...\n" "$API_NV_INDEX"
if ! tpm2_nvdefine -C o -s "$API_NV_SIZE" -a "authread|authwrite" -p "$API_NV_AUTH" "$API_NV_INDEX"; then
    printf "[TPM] ERROR: Failed to define the API Key NV index. Aborting.\n"
    exit 1
fi
if ! printf "%s" "$API_KEY_INPUT" | tpm2_nvwrite -C "$API_NV_INDEX" -P "$API_NV_AUTH" -i - "$API_NV_INDEX"; then
    printf "[TPM] ERROR: Failed to write the API Key to the TPM. Aborting.\n"
    exit 1
fi
unset API_NV_AUTH

printf "Writing SSH Key to TPM (%s)...\n" "$SSH_NV_INDEX"
if ! tpm2_nvdefine -C o -s "$SSH_NV_SIZE" -a "authread|authwrite" -p "$MASTER_PIN" "$SSH_NV_INDEX"; then
    printf "[TPM] ERROR: Failed to define the SSH Key NV index. Aborting.\n"
    exit 1
fi
if ! tpm2_nvwrite -C "$SSH_NV_INDEX" -P "$MASTER_PIN" -i "$SSH_KEY_PATH" "$SSH_NV_INDEX"; then
    printf "[TPM] ERROR: Failed to write the SSH Key to the TPM. Aborting.\n"
    exit 1
fi

# NOTE: tpm2-tools takes -p/-P auth values as plain command-line arguments,
# which are briefly visible to other local users via `ps`. This is a known
# limitation of the tpm2-tools CLI, not fixed here (the safer file-descriptor
# input forms are tpm2-tools-version-dependent and unverified on this system).

fi # RESEED

# --- 5. Shell Integration ---
printf "\n%s\n" "=== Phase 5: Integrating with Shells ==="

# 1. SH/BASH Payload
SHRC_SNIPPET='
# --- TPM Secure Environment Setup (sh/bash) ---
TPM_API_AUTH_MODE='"$API_AUTH_MODE"'
TPM_SSH_PUB_PATH="'"$SSH_KEY_PATH"'.pub"

# Only meaningful when TPM_API_AUTH_MODE=agent: derives the API Key'"'"'s TPM
# auth PIN from a deterministic ed25519 signature instead of the Master PIN.
# See _tpm_derive_api_pin in tpm_setup.sh for why this is safe/deterministic.
_tpm_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d" " -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | cut -d" " -f1
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 -q
    fi
}

_tpm_derive_api_pin() {
    # $1 is a fallback public-key path, only used if the agent itself has
    # nothing loaded -- the public key content normally comes straight from
    # the agent (ssh-add -L) so this works even if the on-disk .pub file was
    # deleted or never existed (only the private key half is required to be
    # present at Phase 4 seeding time; nothing guarantees the .pub sticks
    # around afterwards).
    FALLBACK_KEY="$1"
    SIGN_DIR=$(mktemp -d) || return 1
    SIGN_KEY=""
    AGENT_PUB=$(ssh-add -L 2>/dev/null | grep "^ssh-ed25519 " | head -n 1)
    if [ -n "$AGENT_PUB" ]; then
        printf "%s\n" "$AGENT_PUB" > "$SIGN_DIR/id.pub"
        SIGN_KEY="$SIGN_DIR/id.pub"
    elif [ -r "$FALLBACK_KEY" ]; then
        SIGN_KEY="$FALLBACK_KEY"
    fi
    if [ -z "$SIGN_KEY" ]; then
        rm -rf "$SIGN_DIR"
        return 1
    fi
    printf "%s" "tpm-api-pin-v1:${USER}" > "$SIGN_DIR/challenge"
    DERIVED=""
    if ssh-keygen -Y sign -f "$SIGN_KEY" -n tpm-api-pin "$SIGN_DIR/challenge" >/dev/null 2>&1; then
        DERIVED=$(_tpm_sha256 < "$SIGN_DIR/challenge.sig" 2>/dev/null | cut -c1-32)
    fi
    rm -rf "$SIGN_DIR"
    [ -n "$DERIVED" ] || return 1
    printf "%s" "$DERIVED"
}

_tpm_load_secret() {
    RAW="$1"
    FOUND_KV=0
    set -f
    OLD_IFS="$IFS"
    IFS=";"
    set -- $RAW
    IFS="$OLD_IFS"
    for PAIR in "$@"; do
        [ -z "$PAIR" ] && continue
        case "$PAIR" in
            *'"'"'="'"'"'*'"'"'"'"'"')
                NAME="${PAIR%%=*}"
                VALUE="${PAIR#*=\"}"
                VALUE="${VALUE%\"}"
                case "$NAME" in
                    '"'"''"'"' | *[!A-Za-z0-9_]* | [0-9]*)
                        printf "[TPM] Warning: skipping invalid variable name \"%s\"\n" "$NAME"
                        continue
                        ;;
                esac
                export "$NAME=$VALUE"
                printf "[TPM] Loaded env var: %s\n" "$NAME"
                FOUND_KV=1
                ;;
        esac
    done
    set +f
    if [ "$FOUND_KV" -eq 0 ]; then
        export SECURE_API_KEY="$RAW"
        [ -n "$SECURE_API_KEY" ] && printf "%s\n" "[TPM] API Key loaded."
    fi
}

# Read-only status check (no ssh-agent is started, no PIN is requested).
# Sets NEEDS_SSH / NEEDS_API. Shared by unlock_tpm and the shell-startup
# hint below, so the hint reflects the actual unlock state instead of
# printing unconditionally.
_tpm_needs_unlock() {
    NEEDS_SSH=0
    NEEDS_API=0
    if [ -z "$SSH_AUTH_SOCK" ]; then
        NEEDS_SSH=1
    elif ! ssh-add -l 2>/dev/null | grep -q "ED25519"; then
        NEEDS_SSH=1
    fi
    [ -z "$SECURE_API_KEY" ] && NEEDS_API=1
}

unlock_tpm() {
    _tpm_needs_unlock
    if [ "$NEEDS_SSH" -eq 1 ] || [ "$NEEDS_API" -eq 1 ]; then
        if [ -z "$SSH_AUTH_SOCK" ] || { [ -n "$SSH_AGENT_PID" ] && ! kill -0 "$SSH_AGENT_PID" 2>/dev/null; }; then
            eval "$(ssh-agent -s)" > /dev/null
        fi

        # Fast path: the SSH identity is already resident in the agent (e.g.
        # a second gnome-terminal tab in the same session) and only the API
        # key is missing -- derive its PIN from the agent instead of
        # re-prompting for the Master PIN.
        if [ "$NEEDS_SSH" -eq 0 ] && [ "$NEEDS_API" -eq 1 ] && [ "$TPM_API_AUTH_MODE" = "agent" ]; then
            if AGENT_PIN=$(_tpm_derive_api_pin "$TPM_SSH_PUB_PATH") && [ -n "$AGENT_PIN" ]; then
                RAW_SECRET=$(tpm2_nvread -C '"$API_NV_INDEX"' -P "$AGENT_PIN" '"$API_NV_INDEX"' 2>/dev/null | env LC_ALL=C tr -d '\''\0'\'')
                unset AGENT_PIN
                if [ -n "$RAW_SECRET" ]; then
                    _tpm_load_secret "$RAW_SECRET"
                    return 0
                fi
                printf "%s\n" "[TPM] Warning: SSH-agent-derived PIN did not unlock the API key; falling back to manual PIN entry."
            fi
        fi

        printf "\n[TPM] Secured keys missing from environment.\nEnter Master TPM PIN: "
        trap '"'"'stty echo'"'"' INT TERM
        stty -echo; read USER_PIN; stty echo; printf "\n"
        trap - INT TERM

        if [ "$NEEDS_SSH" -eq 1 ]; then
            tpm2_nvread -C '"$SSH_NV_INDEX"' -P "$USER_PIN" '"$SSH_NV_INDEX"' 2>/dev/null | ssh-add - || printf "%s\n" "[TPM] Error: Failed to load SSH key."
        fi
        if [ "$NEEDS_API" -eq 1 ]; then
            API_PIN="$USER_PIN"
            if [ "$TPM_API_AUTH_MODE" = "agent" ]; then
                AGENT_PIN=$(_tpm_derive_api_pin "$TPM_SSH_PUB_PATH")
                [ -n "$AGENT_PIN" ] && API_PIN="$AGENT_PIN"
                unset AGENT_PIN
            fi
            RAW_SECRET=$(tpm2_nvread -C '"$API_NV_INDEX"' -P "$API_PIN" '"$API_NV_INDEX"' 2>/dev/null | env LC_ALL=C tr -d '\''\0'\'')
            unset API_PIN
            if [ -n "$RAW_SECRET" ]; then
                _tpm_load_secret "$RAW_SECRET"
            else
                printf "%s\n" "[TPM] Error: Failed to load API secret."
            fi
        fi
    else
        printf "%s\n" "[TPM] All secure keys are already loaded."
    fi
}
'

if [ "$STRATEGY_CHOICE" = "2" ]; then
    SHRC_SNIPPET="$SHRC_SNIPPET"'
case "$-" in
    *i*)
        _tpm_needs_unlock
        if [ "$NEEDS_SSH" -eq 1 ] || [ "$NEEDS_API" -eq 1 ]; then
            printf "\n%s\n" "[TPM] Hint: Run '\''unlock_tpm'\'' to load your secure keys."
        fi
        ;;
esac'
else
    SHRC_SNIPPET="$SHRC_SNIPPET"'
case "$-" in *i*) unlock_tpm ;; esac'
fi

SHRC_SNIPPET="$SHRC_SNIPPET
# ----------------------------------------------"

# 2a. TCSH companion helper: a plain POSIX sh script (kept out of tcsh's own
# quoting/history-expansion rules entirely). Invoked as:
#   sh ~/.tpm_unlock_helper.sh ssh <NV_INDEX> <PIN>  -> raw SSH key bytes to stdout
#   sh ~/.tpm_unlock_helper.sh api <NV_INDEX> <PIN>  -> tcsh `setenv` lines to stdout
cat << 'EOF' > "$HOME/.tpm_unlock_helper.sh"
#!/bin/sh
MODE="$1"
IDX="$2"
PIN="$3"

case "$MODE" in
    ssh)
        tpm2_nvread -C "$IDX" -P "$PIN" "$IDX" 2>/dev/null
        ;;
    api)
        RAW=$(tpm2_nvread -C "$IDX" -P "$PIN" "$IDX" 2>/dev/null | env LC_ALL=C tr -d '\0')
        emit() {
            NAME="$1"
            VALUE="$2"
            ESCAPED=$(printf '%s' "$VALUE" | sed "s/'/'\\\\''/g; s/!/\\\\!/g")
            printf "setenv %s '%s'\n" "$NAME" "$ESCAPED"
        }
        FOUND_KV=0
        set -f
        OLD_IFS="$IFS"
        IFS=';'
        set -- $RAW
        IFS="$OLD_IFS"
        for PAIR in "$@"; do
            [ -z "$PAIR" ] && continue
            case "$PAIR" in
                *'="'*'"')
                    NAME="${PAIR%%=*}"
                    VALUE="${PAIR#*=\"}"
                    VALUE="${VALUE%\"}"
                    case "$NAME" in
                        '' | *[!A-Za-z0-9_]* | [0-9]*) continue ;;
                    esac
                    emit "$NAME" "$VALUE"
                    FOUND_KV=1
                    ;;
            esac
        done
        set +f
        [ "$FOUND_KV" -eq 0 ] && emit SECURE_API_KEY "$RAW"
        ;;
    agentpin)
        # Derives the API Key's TPM auth PIN from a deterministic ed25519
        # signature (ssh-keygen -Y sign) instead of the Master PIN -- used
        # only when the setup script's "SSH-agent-derived PIN" mode was
        # enabled. The public key content is read straight from the agent
        # (ssh-add -L) so this works even if the on-disk .pub file was
        # deleted or never existed; $2 is only a fallback path used if the
        # agent has nothing loaded.
        FALLBACK_KEY="$2"
        SIGN_DIR=$(mktemp -d) || exit 1
        SIGN_KEY=""
        AGENT_PUB=$(ssh-add -L 2>/dev/null | grep "^ssh-ed25519 " | head -n 1)
        if [ -n "$AGENT_PUB" ]; then
            printf '%s\n' "$AGENT_PUB" > "$SIGN_DIR/id.pub"
            SIGN_KEY="$SIGN_DIR/id.pub"
        elif [ -r "$FALLBACK_KEY" ]; then
            SIGN_KEY="$FALLBACK_KEY"
        fi
        if [ -z "$SIGN_KEY" ]; then
            rm -rf "$SIGN_DIR"
            exit 1
        fi
        printf '%s' "tpm-api-pin-v1:${USER}" > "$SIGN_DIR/challenge"
        DERIVED=""
        if ssh-keygen -Y sign -f "$SIGN_KEY" -n tpm-api-pin "$SIGN_DIR/challenge" >/dev/null 2>&1; then
            if command -v sha256sum >/dev/null 2>&1; then
                DERIVED=$(sha256sum < "$SIGN_DIR/challenge.sig" | cut -d' ' -f1 | cut -c1-32)
            elif command -v shasum >/dev/null 2>&1; then
                DERIVED=$(shasum -a 256 < "$SIGN_DIR/challenge.sig" | cut -d' ' -f1 | cut -c1-32)
            elif command -v sha256 >/dev/null 2>&1; then
                DERIVED=$(sha256 -q < "$SIGN_DIR/challenge.sig" | cut -c1-32)
            fi
        fi
        rm -rf "$SIGN_DIR"
        [ -n "$DERIVED" ] || exit 1
        printf '%s' "$DERIVED"
        ;;
esac
EOF

# 2b. TCSH Payload (Helper Script)
cat << 'EOF' > "$HOME/.tpm_unlock.csh"
# TPM Secure Environment Setup Helper (tcsh)
set needs_ssh = 0
set needs_api = 0
if (! $?SSH_AUTH_SOCK) then
    eval `ssh-agent -c` > /dev/null
endif
sh -c 'ssh-add -l 2>/dev/null' | grep -q "ED25519"
if ( $status != 0 ) set needs_ssh = 1
if (! $?SECURE_API_KEY) set needs_api = 1

if ( $needs_ssh == 1 || $needs_api == 1 ) then
    set _tpm_api_loaded = 0

    # Fast path: SSH identity already resident in the agent, only the API
    # key is missing -- derive its PIN from the agent silently, no prompt.
    if ( $needs_ssh == 0 && $needs_api == 1 && "AUTHMODE" == "agent" ) then
        set AGENT_PIN = `sh "$HOME/.tpm_unlock_helper.sh" agentpin "PUBPATH"`
        if ( "$AGENT_PIN" != "" ) then
            set TPM_ENV_FILE = `mktemp`
            sh "$HOME/.tpm_unlock_helper.sh" api API_IDX "$AGENT_PIN" > "$TPM_ENV_FILE"
            if ( -s "$TPM_ENV_FILE" ) then
                source "$TPM_ENV_FILE"
                echo "[TPM] Secrets loaded."
                set _tpm_api_loaded = 1
            endif
            rm -f "$TPM_ENV_FILE"
        endif
        unset AGENT_PIN
    endif

    if ( $_tpm_api_loaded == 0 ) then
        echo ""
        echo "[TPM] Secured keys missing from environment."
        echo -n "Enter Master TPM PIN: "
        stty -echo
        set USER_PIN = $<
        stty echo
        echo ""

        if ( $needs_ssh == 1 ) then
            sh "$HOME/.tpm_unlock_helper.sh" ssh SSH_IDX "$USER_PIN" | ssh-add -
            if ( $status != 0 ) echo "[TPM] Error: Failed to load SSH key."
        endif
        if ( $needs_api == 1 ) then
            set API_PIN = "$USER_PIN"
            if ( "AUTHMODE" == "agent" ) then
                set AGENT_PIN = `sh "$HOME/.tpm_unlock_helper.sh" agentpin "PUBPATH"`
                if ( "$AGENT_PIN" != "" ) set API_PIN = "$AGENT_PIN"
                unset AGENT_PIN
            endif
            set TPM_ENV_FILE = `mktemp`
            sh "$HOME/.tpm_unlock_helper.sh" api API_IDX "$API_PIN" > "$TPM_ENV_FILE"
            if ( -s "$TPM_ENV_FILE" ) then
                source "$TPM_ENV_FILE"
                echo "[TPM] Secrets loaded."
            else
                echo "[TPM] Error: Failed to load API secret."
            endif
            rm -f "$TPM_ENV_FILE"
            unset API_PIN
        endif
    endif
    unset _tpm_api_loaded
else
    echo "[TPM] All secure keys are already loaded."
endif
EOF
sed -i.bak "s/SSH_IDX/$SSH_NV_INDEX/g; s/API_IDX/$API_NV_INDEX/g; s/AUTHMODE/$API_AUTH_MODE/g; s#PUBPATH#$SSH_KEY_PATH.pub#g" "$HOME/.tpm_unlock.csh" && rm -f "$HOME/.tpm_unlock.csh.bak"

# 3. TCSH Injection Profile
CSHRC_SNIPPET='
# --- TPM Secure Environment Setup (tcsh) ---
alias unlock_tpm "source ~/.tpm_unlock.csh"
'

if [ "$STRATEGY_CHOICE" = "2" ]; then
    CSHRC_SNIPPET="$CSHRC_SNIPPET"'
if ($?prompt) then
    set _tpm_hint_needed = 0
    if ($?SSH_AUTH_SOCK) then
        sh -c '\''ssh-add -l 2>/dev/null'\'' | grep -q "ED25519"
        if ( $status != 0 ) set _tpm_hint_needed = 1
    else
        set _tpm_hint_needed = 1
    endif
    if (! $?SECURE_API_KEY) set _tpm_hint_needed = 1
    if ( $_tpm_hint_needed == 1 ) then
        echo ""
        echo "[TPM] Hint: Run '\''unlock_tpm'\'' to load your secure keys."
    endif
    unset _tpm_hint_needed
endif'
else
    CSHRC_SNIPPET="$CSHRC_SNIPPET"'
if ($?prompt) unlock_tpm'
fi

CSHRC_SNIPPET="$CSHRC_SNIPPET
# -------------------------------------------"

# 4. Apply to files
for SH_FILE in "$HOME/.shrc" "$HOME/.bashrc"; do
    if [ -f "$SH_FILE" ] || [ "$SH_FILE" = "$HOME/.bashrc" ]; then
        sed -i.bak '/# --- TPM Secure Environment Setup (sh\/bash) ---/,/# ----------------------------------------------/d' "$SH_FILE" 2>/dev/null || true
        rm -f "$SH_FILE.bak"
        printf "%s\n" "$SHRC_SNIPPET" >> "$SH_FILE"
        printf "Added sh/bash automation to %s\n" "$SH_FILE"
    fi
done

CSHRC_FILE="$HOME/.cshrc"
sed -i.bak '/# --- TPM Secure Environment Setup (tcsh) ---/,/# -------------------------------------------/d' "$CSHRC_FILE" 2>/dev/null || true
rm -f "$CSHRC_FILE.bak"
printf "%s\n" "$CSHRC_SNIPPET" >> "$CSHRC_FILE"
printf "Added tcsh automation to %s\n" "$CSHRC_FILE"

printf "\n%s\n" "=== Setup Complete! ==="
printf "IMPORTANT: Backup %s to an offline drive before deleting it from this system!\n" "$SSH_KEY_PATH"
