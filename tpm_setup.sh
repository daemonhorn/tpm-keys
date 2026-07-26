#!/bin/sh
# Universal TPM 2.0 Secure Setup Script
# Features: Single Master PIN, Auto/Manual execution, Multi-User safe
# OS Support: Debian, RHEL (Rocky/Alma/CentOS), FreeBSD

set -e

# Shared by both a clean -h/--help request and any CLI syntax error below,
# so a mistyped flag shows the same usage a deliberate --help would --
# printed before the error line so the error is the last thing on screen
# rather than scrolled out of view by the help text.
print_usage() {
    printf "%s\n" "Seals your SSH key and API key/token secrets inside this machine's TPM 2.0,"
    printf "%s\n" "protected by one Master PIN, and wires up automatic (or on-demand) unlocking"
    printf "%s\n" "in new shells for bash/sh and tcsh -- run with no arguments to seed a secret."
    printf "%s\n" "Reads/writes the same TPM NV RAM indices as tpm_setup.ps1, so a dual-booted"
    printf "%s\n" "machine can seal a secret in one OS and unlock it in the other."
    printf "\n"
    printf "Usage: %s [--env-file <path>] [--uninstall] [--status]\n\n" "$0"
    printf "%s\n" "  --env-file <path>  Read the API key/value(s) to seal from a dotenv-style"
    printf "%s\n" "                     file (NAME=VALUE per line) instead of the interactive"
    printf "%s\n" "                     Phase 2 prompt."
    printf "%s\n" "  --uninstall        Remove this user's sealed secrets from the TPM and the"
    printf "%s\n" "                     unlock_tpm hooks from shell startup files, then exit."
    printf "%s\n" "  --status           Print a summary of the current state (installed,"
    printf "%s\n" "                     locked/unlocked, ssh-agent) and exit -- makes no"
    printf "%s\n" "                     changes."
}

# --- CLI argument parsing ---
ENV_FILE=""
UNINSTALL=0
STATUS=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --env-file)
            if [ "$#" -lt 2 ]; then
                print_usage
                printf "\n[TPM] ERROR: --env-file requires a path argument.\n" >&2
                exit 1
            fi
            ENV_FILE="$2"
            shift 2
            ;;
        --env-file=*)
            ENV_FILE="${1#--env-file=}"
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --status)
            STATUS=1
            shift
            ;;
        -h | --help)
            print_usage
            exit 0
            ;;
        *)
            print_usage
            printf "\n[TPM] ERROR: Unknown argument: %s\n" "$1" >&2
            exit 1
            ;;
    esac
done

# $USER isn't guaranteed to be set (containers, cron, some su contexts).
USER="${USER:-$(id -un)}"

if [ "$UNINSTALL" -eq 1 ]; then
    USER_UID=$(id -u)
    API_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 )))
    SSH_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 + 1 )))

    printf "\n%s\n" "=== Uninstall ==="
    printf "%s\n" "This will, for user $USER:"
    printf "%s\n" "  - Permanently delete the sealed API Key and SSH Key from TPM NV RAM"
    printf "%s\n" "    (indices $API_NV_INDEX / $SSH_NV_INDEX)"
    printf "%s\n" "  - Remove the unlock_tpm hooks from ~/.bashrc, ~/.shrc, ~/.cshrc, and"
    printf "%s\n" "    ~/.bash_profile"
    printf "%s\n" "  - Remove ~/.tpm_unlock.csh, ~/.tpm_unlock_helper.sh, and ~/.tpm_keys_state"
    printf "%s\n" ""
    printf "%s\n" "This does NOT delete your SSH private key file on disk -- only the sealed"
    printf "%s\n" "copy in the TPM. This cannot be undone; make sure you have an offline"
    printf "%s\n" "backup of your SSH key if you haven't already."
    printf "Continue? (y/n) [default: n]: "
    read UNINSTALL_CONFIRM
    case "$UNINSTALL_CONFIRM" in
        [Yy]*) ;;
        *)
            printf "[TPM] Aborting uninstall.\n"
            exit 0
            ;;
    esac

    if command -v tpm2_nvundefine >/dev/null 2>&1; then
        if tpm2_nvundefine -C o "$API_NV_INDEX" >/dev/null 2>&1; then
            printf "[TPM] Removed API Key NV index (%s).\n" "$API_NV_INDEX"
        else
            printf "[TPM] Note: could not remove API Key NV index (%s) -- it may already be gone, or the TPM device isn't accessible.\n" "$API_NV_INDEX"
        fi
        if tpm2_nvundefine -C o "$SSH_NV_INDEX" >/dev/null 2>&1; then
            printf "[TPM] Removed SSH Key NV index (%s).\n" "$SSH_NV_INDEX"
        else
            printf "[TPM] Note: could not remove SSH Key NV index (%s) -- it may already be gone, or the TPM device isn't accessible.\n" "$SSH_NV_INDEX"
        fi
    else
        printf "[TPM] tpm2-tools not found; skipping TPM NV cleanup (nothing to remove locally).\n"
    fi

    for RC_FILE in "$HOME/.shrc" "$HOME/.bashrc"; do
        if [ -f "$RC_FILE" ]; then
            sed -i.bak '/# --- TPM Secure Environment Setup (sh\/bash) ---/,/# ----------------------------------------------/d' "$RC_FILE" 2>/dev/null || true
            rm -f "$RC_FILE.bak"
        fi
    done
    if [ -f "$HOME/.bash_profile" ]; then
        sed -i.bak '/# --- TPM Secure Environment Setup (bash_profile bootstrap) ---/,/# ----------------------------------------------/d' "$HOME/.bash_profile" 2>/dev/null || true
        rm -f "$HOME/.bash_profile.bak"
    fi
    if [ -f "$HOME/.cshrc" ]; then
        sed -i.bak '/# --- TPM Secure Environment Setup (tcsh) ---/,/# -------------------------------------------/d' "$HOME/.cshrc" 2>/dev/null || true
        rm -f "$HOME/.cshrc.bak"
    fi
    rm -f "$HOME/.tpm_unlock.csh" "$HOME/.tpm_unlock_helper.sh" "$HOME/.tpm_keys_state"
    printf "[TPM] Removed unlock_tpm hooks from shell startup files.\n"

    printf "\n%s\n" "=== Uninstall Complete ==="
    printf "%s\n" "Log out and back in (or start a fresh shell) for the change to take effect."
    exit 0
fi

if [ "$STATUS" -eq 1 ]; then
    USER_UID=$(id -u)
    API_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 )))
    SSH_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 + 1 )))
    SSH_KEY_PATH="$HOME/.ssh/id_ed25519"
    STATE_FILE="$HOME/.tpm_keys_state"
    # Distinguishes "never persisted" (older install, predates name
    # tracking) from "persisted as empty" (legacy single-key mode was
    # chosen) -- both look like an empty string otherwise.
    SECRET_NAMES="__UNTRACKED__"
    [ -f "$STATE_FILE" ] && . "$STATE_FILE"

    printf "%s\n" "=== TPM Status ==="
    printf "User: %s (uid %s)\n" "$USER" "$USER_UID"

    # --- Installed? A plain NV_ReadPublic needs no PIN, so this is safe
    # and side-effect-free; deliberately does NOT try to install
    # tpm2-tools or fix group/device access the way normal setup would.
    API_INSTALLED=0
    SSH_INSTALLED=0
    TPM_ACCESSIBLE=0
    if command -v tpm2_nvreadpublic >/dev/null 2>&1; then
        # Probe TPM reachability independently of whether OUR indices exist:
        # tpm2_getcap needs no PIN and succeeds against any reachable TPM,
        # so its result tells apart "can't talk to the TPM at all" (no
        # device, permissions, tpm2-abrmd not running, ...) from "TPM is
        # fine, nothing sealed here yet" -- these used to be reported with
        # the same ambiguous message.
        if tpm2_getcap properties-fixed >/dev/null 2>&1; then
            TPM_ACCESSIBLE=1
            tpm2_nvreadpublic "$API_NV_INDEX" >/dev/null 2>&1 && API_INSTALLED=1
            tpm2_nvreadpublic "$SSH_NV_INDEX" >/dev/null 2>&1 && SSH_INSTALLED=1
        fi
    fi

    if ! command -v tpm2_nvreadpublic >/dev/null 2>&1; then
        printf "TPM secrets: unknown (tpm2-tools not installed)\n"
    elif [ "$TPM_ACCESSIBLE" -eq 0 ]; then
        printf "TPM secrets: unknown (TPM not accessible -- check device permissions/group membership)\n"
    elif [ "$API_INSTALLED" -eq 1 ] && [ "$SSH_INSTALLED" -eq 1 ]; then
        printf "TPM secrets: installed (API %s, SSH %s)\n" "$API_NV_INDEX" "$SSH_NV_INDEX"
    elif [ "$API_INSTALLED" -eq 0 ] && [ "$SSH_INSTALLED" -eq 0 ]; then
        printf "TPM secrets: not installed\n"
    else
        printf "TPM secrets: partially installed (API %s, SSH %s)\n" \
            "$( [ "$API_INSTALLED" -eq 1 ] && printf present || printf missing )" \
            "$( [ "$SSH_INSTALLED" -eq 1 ] && printf present || printf missing )"
    fi

    if [ -f "$SSH_KEY_PATH" ]; then
        printf "SSH key file (%s): present\n" "$SSH_KEY_PATH"
    else
        printf "SSH key file (%s): missing\n" "$SSH_KEY_PATH"
    fi

    AGENT_HAS_ED25519=0
    if [ -n "$SSH_AUTH_SOCK" ] && ssh-add -l >/dev/null 2>&1; then
        if ssh-add -l 2>/dev/null | grep -q "ED25519"; then
            AGENT_HAS_ED25519=1
        fi
    fi
    if [ "$AGENT_HAS_ED25519" -eq 1 ]; then
        printf "SSH key: unlocked (ED25519 identity loaded in ssh-agent)\n"
    else
        printf "SSH key: locked (no ED25519 identity loaded in ssh-agent)\n"
    fi

    # --- Environment secret(s): count depends on whether Phase 4 recorded
    # NAME="value" secret names (SECRET_NAMES) or this used the legacy
    # single opaque $SECURE_API_KEY -- see the three-way distinction above.
    if [ "$SECRET_NAMES" = "__UNTRACKED__" ]; then
        if [ -n "$SECURE_API_KEY" ]; then
            printf "API secret(s): unlocked (legacy \$SECURE_API_KEY loaded)\n"
        else
            printf "API secret(s): unknown (older install predates name tracking; re-seed to enable this)\n"
        fi
    elif [ -z "$SECRET_NAMES" ]; then
        if [ -n "$SECURE_API_KEY" ]; then
            printf "API secret(s): unlocked (1/1 loaded: SECURE_API_KEY)\n"
        else
            printf "API secret(s): locked (0/1 loaded)\n"
        fi
    else
        LOADED_COUNT=0
        TOTAL_COUNT=0
        LOADED_LIST=""
        OLD_IFS="$IFS"
        IFS=" "
        for SECRET_NAME in $SECRET_NAMES; do
            TOTAL_COUNT=$((TOTAL_COUNT + 1))
            eval "SECRET_VAL=\"\${$SECRET_NAME:-}\""
            if [ -n "$SECRET_VAL" ]; then
                LOADED_COUNT=$((LOADED_COUNT + 1))
                LOADED_LIST="$LOADED_LIST $SECRET_NAME"
            fi
        done
        IFS="$OLD_IFS"
        if [ "$LOADED_COUNT" -eq 0 ]; then
            printf "API secret(s): locked (0/%s loaded)\n" "$TOTAL_COUNT"
        elif [ "$LOADED_COUNT" -eq "$TOTAL_COUNT" ]; then
            printf "API secret(s): unlocked (%s/%s loaded:%s)\n" "$LOADED_COUNT" "$TOTAL_COUNT" "$LOADED_LIST"
        else
            printf "API secret(s): partially unlocked (%s/%s loaded:%s)\n" "$LOADED_COUNT" "$TOTAL_COUNT" "$LOADED_LIST"
        fi
    fi

    if [ -z "$SSH_AUTH_SOCK" ]; then
        printf "ssh-agent: not running\n"
    else
        # ssh-add -l exit codes: 0 = identities listed, 1 = agent reachable
        # but empty, 2 = couldn't connect (stale/dead socket) -- only 2
        # means the agent itself isn't actually reachable. Captured via
        # if/else (not a bare command + trailing $?) since this runs under
        # `set -e`, which would otherwise abort the whole script the
        # moment ssh-add exits non-zero.
        if ssh-add -l >/dev/null 2>&1; then
            SSH_ADD_STATUS=0
        else
            SSH_ADD_STATUS=$?
        fi
        if [ "$SSH_ADD_STATUS" -eq 2 ]; then
            printf "ssh-agent: not reachable (\$SSH_AUTH_SOCK is set but stale)\n"
        else
            printf "ssh-agent: running (%s)\n" "$SSH_AUTH_SOCK"
            # Only ask for public keys when $SSH_ADD_STATUS (from -l above)
            # already confirmed identities exist -- ssh-add -L's own exit
            # code and stdout are indistinguishable between "no identities"
            # and "identities present" without this (both print a message
            # to stdout and exit non-zero for the empty case), and calling
            # it unconditionally would be another set -e hazard besides.
            if [ "$SSH_ADD_STATUS" -eq 0 ]; then
                AGENT_PUBKEYS=$(ssh-add -L 2>/dev/null || true)
            else
                AGENT_PUBKEYS=""
            fi
            if [ -n "$AGENT_PUBKEYS" ]; then
                printf "Loaded identities:\n"
                printf "%s\n" "$AGENT_PUBKEYS" | while IFS= read -r PUBLINE; do
                    printf "  %s\n" "$PUBLINE"
                done
            else
                printf "Loaded identities: none\n"
            fi
        fi
    fi

    exit 0
fi

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
        # FreeBSD's base system doesn't include sudo (unlike most Linux
        # distros' default images) -- and everything below this point,
        # starting with the tpm2-tools install a few lines down, assumes
        # it's already there. Bootstrap it now rather than let the first
        # "sudo: not found" a dozen lines from now be the only clue.
        if ! command -v sudo >/dev/null 2>&1; then
            printf "%s\n" "[TPM] 'sudo' not found; this script needs it for privileged operations"
            printf "%s\n" "(package installs, kernel module loading, group management, devfs rules)."
            if [ "$(id -u)" -eq 0 ]; then
                printf "%s\n" "Installing sudo (running as root)..."
                SUDO_INSTALL_OK=1
                pkg install -y sudo || SUDO_INSTALL_OK=0
            else
                printf "%s\n" "Installing it via 'su' to root -- you may be prompted for the root password."
                SUDO_INSTALL_OK=1
                su root -c 'pkg install -y sudo' || SUDO_INSTALL_OK=0
            fi
            if [ "$SUDO_INSTALL_OK" -eq 1 ] && command -v sudo >/dev/null 2>&1; then
                printf "%s\n" "[TPM] sudo installed successfully."
            else
                printf "\n%s\n" "================================================================"
                printf "%s\n"   " ERROR: 'sudo' is required but could not be installed"
                printf "%s\n"   "================================================================"
                printf "%s\n" "This script relies on 'sudo' for privileged operations and could"
                printf "%s\n" "not install it automatically (wrong/unknown root password, or this"
                printf "%s\n" "account isn't in the 'wheel' group su(1) requires to become root)."
                printf "%s\n" ""
                printf "%s\n" "To proceed, have an administrator (or yourself, with the root"
                printf "%s\n" "password) run:"
                printf "%s\n" "    su root -c 'pkg install -y sudo'"
                printf "%s\n" "then make sure your user is permitted to use it (see visudo or"
                printf "%s\n" "/usr/local/etc/sudoers, typically uncommenting the '%wheel' line"
                printf "%s\n" "and adding your user to that group), and re-run this script."
                exit 1
            fi
        fi
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

# Derives a stable PIN from an ed25519 signature over a fixed challenge.
# ssh-keygen -Y sign is deterministic per RFC 8032 for a *given signer*
# (same key + message + namespace always produces the same signature bytes
# from that signer again) -- but different ssh-agent implementations are NOT
# guaranteed to agree with each other or with direct-file signing on the
# same key+message: verified empirically that GNOME Keyring's ssh-agent
# produces a genuinely different (though internally consistent) signature
# than signing straight from the private key file. So this always prefers
# whatever identity is already loaded in a running agent (ssh-add -L) and
# only falls back to the raw key file if no agent has it loaded -- this
# function is shared verbatim with the generated unlock scripts, so as long
# as *some* agent already holds the identity at seeding time, setup and
# every later unlock go through the same signer and agree. $1 is a fallback
# private/public key path used only when no agent has the identity loaded.
# Truncated to 32 hex chars (128 bits): a full sha256 digest is 64 bytes,
# which some TPMs reject as an auth value ("Invalid index authorization").
_tpm_derive_api_pin() {
    FALLBACK_KEY="$1"
    SIGN_DIR=$(mktemp -d) || return 1
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
        return 1
    fi
    printf '%s' "tpm-api-pin-v1:${USER}" > "$SIGN_DIR/challenge"
    DERIVED=""
    if ssh-keygen -Y sign -f "$SIGN_KEY" -n tpm-api-pin "$SIGN_DIR/challenge" >/dev/null 2>&1; then
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

# --- On-TPM wire format: a 6-byte header (2-byte magic + 4-digit zero-
# padded ASCII decimal length) is prepended to every write, so a read can
# pull back exactly the real payload instead of the TPM's erase-fill
# garbage padding out the rest of the fixed-size NV region (0x00 on some
# TPMs, 0xFF on others -- verified on FreeBSD, where it previously
# corrupted $SECURE_API_KEY and the raw SSH key bytes with trailing junk).
# Secrets sealed before this existed have no header; the read side falls
# back to a full-region read with trailing 0x00/0xFF stripped for those, so
# already-sealed data keeps working. This constant pair is shared verbatim
# (as literal numbers) with the generated unlock scripts -- see
# _tpm_read_secret below.
#
# The length is ASCII decimal, not a raw binary big-endian value, because
# real-world testing on FreeBSD's native /bin/sh found that `printf '%b'`
# truncates its whole output at the first embedded NUL byte it emits --
# and a binary length's high byte is 0x00 for every payload under 256
# bytes, i.e. virtually always, silently dropping the rest of the header
# (and misaligning the payload behind it) on that shell. bash's printf
# doesn't have this problem, which is why it went undetected until tested
# on a real target shell. ASCII digits are never NUL, sidestepping the
# issue entirely, at the cost of 2 extra header bytes.
TPM_HDR_MAGIC1=165  # 0xA5
TPM_HDR_MAGIC2=126  # 0x7E
TPM_HDR_SIZE=6
API_PAYLOAD_MAX=$((API_NV_SIZE - TPM_HDR_SIZE))
SSH_PAYLOAD_MAX=$((SSH_NV_SIZE - TPM_HDR_SIZE))

# Emits the 6 raw header bytes (2-byte magic, via printf's POSIX-guaranteed
# \0NNN octal-escape handling for %b, plus a 4-digit zero-padded ASCII
# decimal length via a plain, universally-portable printf conversion -- see
# the wire-format comment above for why the length isn't raw binary).
_tpm_emit_header() {
    LEN="$1"
    printf '%b' '\0245\0176'
    printf '%04d' "$LEN"
}

# Reads a secret from NV index $1 (auth $2) and writes the exact payload
# bytes to stdout: if the header's magic matches, reads exactly the
# recorded length at offset $TPM_HDR_SIZE (exact, no trimming needed);
# otherwise falls back to a full-region read with trailing 0x00/0xFF
# stripped, for secrets sealed before this header format existed. Safe for
# both text (API key, captured via `$()`) and binary (SSH key, streamed
# straight to `ssh-add -`) payloads -- the header itself is decoded via
# `od`, which never holds raw bytes in a shell variable, so it can't be
# truncated by an embedded NUL the way capturing raw bytes in `$()` would.
_tpm_read_secret() {
    IDX="$1"
    PIN="$2"
    # A raw hardware TPM with no kernel/userspace resource manager has only
    # a handful of session slots -- back-to-back tpm2_nvread calls (e.g.
    # this session's own extensive testing, or just several unlock
    # attempts in a row) can exhaust them (TPM_RC_SESSION_MEMORY, 0x903).
    # That surfaces as "Invalid handle or authorization", indistinguishable
    # from a wrong PIN by exit status alone, but retrying the exact same
    # call does nothing -- the slots stay full until something is flushed.
    # Captured to a temp file (not swallowed by 2>/dev/null) so it can be
    # inspected for this specific, well-known error text; if found, flush
    # every session/transient object and say plainly what happened instead
    # of leaving the PIN looking wrong.
    NVERR=$(mktemp) || return 1
    ATTEMPT=0
    LOCKOUT_HANDLED=0
    while [ "$ATTEMPT" -lt 3 ]; do
        ATTEMPT=$((ATTEMPT + 1))
        HDR=$(tpm2_nvread -C "$IDX" -P "$PIN" -s "$TPM_HDR_SIZE" --offset=0 "$IDX" 2>"$NVERR" | od -An -tu1)
        if grep -qE "0x903|session context" "$NVERR" 2>/dev/null; then
            printf "%s\n" "[TPM] Note: the TPM ran out of session slots (a resource limit on the chip itself, not a wrong PIN) -- flushing stale sessions and retrying." >&2
            tpm2_flushcontext -t >/dev/null 2>&1
            tpm2_flushcontext -s >/dev/null 2>&1
            tpm2_flushcontext -l >/dev/null 2>&1
        elif grep -qE "0x921|lockout mode" "$NVERR" 2>/dev/null; then
            if [ "$LOCKOUT_HANDLED" = "0" ]; then
                LOCKOUT_HANDLED=1
                if tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1; then
                    printf "%s\n" "[TPM] Note: the TPM was in dictionary-attack lockout from prior failed attempts (not a wrong PIN) -- cleared automatically, retrying." >&2
                else
                    printf "%s\n" "[TPM] Error: the TPM is in dictionary-attack lockout and could not be cleared automatically (a lockout password may be set on this TPM) -- clear it manually with: tpm2_dictionarylockout --clear-lockout -- or wait for the lockout recovery interval, then retry." >&2
                    break
                fi
            else
                printf "%s\n" "[TPM] Error: the TPM is still in dictionary-attack lockout after an automatic clear attempt -- wait for the lockout recovery interval and retry." >&2
                break
            fi
        fi
        OLD_IFS="$IFS"
        IFS=" $(printf '\t')"
        set -- $HDR
        IFS="$OLD_IFS"
        [ "$#" -ge 6 ] && break
    done
    if [ "$#" -lt 6 ]; then
        # Every NV index this script defines is at least TPM_HDR_SIZE bytes,
        # so a successful read always returns at least this many bytes -- a
        # short/empty result here (even after retrying) means the read
        # itself failed (wrong PIN, a transient TPM/TCTI I/O error -- seen
        # in practice under back-to-back tpm2_nvread calls, or the index
        # doesn't exist), not "no header, this must be legacy data". Report
        # a clean failure instead of falling through to the legacy
        # full-region read below: that path would misread the still-present
        # header bytes as leading payload garbage if this was just a
        # transient hiccup rather than genuinely headerless legacy data.
        rm -f "$NVERR"
        return 1
    fi
    IS_HEADER=0
    if [ "$1" = "$TPM_HDR_MAGIC1" ] && [ "$2" = "$TPM_HDR_MAGIC2" ]; then
        IS_HEADER=1
        for D in "$3" "$4" "$5" "$6"; do
            case "$D" in
                4[89] | 5[0-7]) ;;
                *) IS_HEADER=0 ;;
            esac
        done
    fi
    [ "$IS_HEADER" -eq 1 ] && HDR_LEN=$(( ($3 - 48) * 1000 + ($4 - 48) * 100 + ($5 - 48) * 10 + ($6 - 48) ))
    # Retry the payload read itself too, not just the header peek above --
    # the same transient I/O error can strike here. Written to a temp file
    # rather than a shell variable so binary payloads (the SSH key) survive
    # exactly, including any embedded NUL bytes a `$()` capture would
    # truncate; an empty result (rather than a specific expected length,
    # which the API-key case doesn't have on hand here) is what's retried
    # on, which is safe since every secret this script seeds is non-empty.
    TMPFILE=$(mktemp) || { rm -f "$NVERR"; return 1; }
    ATTEMPT=0
    LOCKOUT_HANDLED=0
    while [ "$ATTEMPT" -lt 3 ]; do
        ATTEMPT=$((ATTEMPT + 1))
        if [ "$IS_HEADER" -eq 1 ]; then
            tpm2_nvread -C "$IDX" -P "$PIN" -s "$HDR_LEN" --offset="$TPM_HDR_SIZE" "$IDX" 2>"$NVERR" > "$TMPFILE"
        else
            tpm2_nvread -C "$IDX" -P "$PIN" "$IDX" 2>"$NVERR" | env LC_ALL=C tr -d '\0\377' > "$TMPFILE"
        fi
        if grep -qE "0x903|session context" "$NVERR" 2>/dev/null; then
            printf "%s\n" "[TPM] Note: the TPM ran out of session slots (a resource limit on the chip itself, not a wrong PIN) -- flushing stale sessions and retrying." >&2
            tpm2_flushcontext -t >/dev/null 2>&1
            tpm2_flushcontext -s >/dev/null 2>&1
            tpm2_flushcontext -l >/dev/null 2>&1
        elif grep -qE "0x921|lockout mode" "$NVERR" 2>/dev/null; then
            if [ "$LOCKOUT_HANDLED" = "0" ]; then
                LOCKOUT_HANDLED=1
                if tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1; then
                    printf "%s\n" "[TPM] Note: the TPM was in dictionary-attack lockout from prior failed attempts (not a wrong PIN) -- cleared automatically, retrying." >&2
                else
                    printf "%s\n" "[TPM] Error: the TPM is in dictionary-attack lockout and could not be cleared automatically (a lockout password may be set on this TPM) -- clear it manually with: tpm2_dictionarylockout --clear-lockout -- or wait for the lockout recovery interval, then retry." >&2
                    break
                fi
            else
                printf "%s\n" "[TPM] Error: the TPM is still in dictionary-attack lockout after an automatic clear attempt -- wait for the lockout recovery interval and retry." >&2
                break
            fi
        fi
        [ -s "$TMPFILE" ] && break
    done
    cat "$TMPFILE"
    rm -f "$TMPFILE" "$NVERR"
}

# Remembers which PIN sealed the API Key NV index ("master" or "agent" -- see
# the "API Key Unlock Optimization" prompt below) across re-runs where the
# user keeps existing data (RESEED=0) and Phase 5 regenerates the shell
# integration without re-asking. Defaults to "master" for installs from
# before this feature existed.
STATE_FILE="$HOME/.tpm_keys_state"
API_AUTH_MODE="master"
SSH_AGENT_AUTOSTART="no"
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

# Reads NAME=VALUE lines from a dotenv-style file (blank lines and lines
# whose first non-whitespace character is '#' are skipped) and re-encodes
# them into this script's internal NAME="VALUE";NAME2="VALUE2" form.
# Whitespace around NAME/VALUE is trimmed; VALUE may optionally be wrapped
# in matching single or double quotes in the source file (stripped here).
# Values containing a literal '"' or ';' are rejected since the internal
# format has no escaping for those. Exits the script on any parse error
# rather than prompting -- there's no interactive user to ask when the
# input came from a file.
_tpm_trim() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

_tpm_parse_env_file() {
    FILE="$1"
    RESULT=""
    LINE_NO=0
    while IFS= read -r LINE || [ -n "$LINE" ]; do
        LINE_NO=$((LINE_NO + 1))
        TRIMMED=$(_tpm_trim "$LINE")
        [ -z "$TRIMMED" ] && continue
        case "$TRIMMED" in
            '#'*) continue ;;
        esac
        case "$TRIMMED" in
            *=*)
                NAME=$(_tpm_trim "${TRIMMED%%=*}")
                VALUE=$(_tpm_trim "${TRIMMED#*=}")
                ;;
            *)
                printf "[TPM] ERROR: %s:%s is not a NAME=VALUE line: %s\n" "$FILE" "$LINE_NO" "$TRIMMED" >&2
                return 1
                ;;
        esac
        case "$NAME" in
            '' | *[!A-Za-z0-9_]* | [0-9]*)
                printf "[TPM] ERROR: %s:%s has an invalid variable name \"%s\"\n" "$FILE" "$LINE_NO" "$NAME" >&2
                return 1
                ;;
        esac
        case "$VALUE" in
            \"*\") VALUE="${VALUE#\"}"; VALUE="${VALUE%\"}" ;;
            \'*\') VALUE="${VALUE#\'}"; VALUE="${VALUE%\'}" ;;
        esac
        case "$VALUE" in
            *'"'*)
                printf "[TPM] ERROR: %s:%s value for %s contains a literal \" character, which this script's NAME=\"VALUE\" format cannot represent.\n" "$FILE" "$LINE_NO" "$NAME" >&2
                return 1
                ;;
            *';'*)
                printf "[TPM] ERROR: %s:%s value for %s contains a literal ; character, which this script's NAME=\"VALUE\" format cannot represent.\n" "$FILE" "$LINE_NO" "$NAME" >&2
                return 1
                ;;
        esac
        [ -n "$RESULT" ] && RESULT="$RESULT;"
        RESULT="$RESULT$NAME=\"$VALUE\""
    done < "$FILE"
    if [ -z "$RESULT" ]; then
        printf "[TPM] ERROR: %s contains no NAME=VALUE lines.\n" "$FILE" >&2
        return 1
    fi
    printf '%s' "$RESULT"
}

if [ -n "$ENV_FILE" ]; then
    if [ ! -r "$ENV_FILE" ]; then
        printf "[TPM] ERROR: Cannot read env file '%s'. Aborting.\n" "$ENV_FILE"
        exit 1
    fi
    if ! API_KEY_INPUT=$(_tpm_parse_env_file "$ENV_FILE"); then
        exit 1
    fi
    INPUT_LEN=$(printf '%s' "$API_KEY_INPUT" | wc -c | tr -d ' ')
    if [ "$INPUT_LEN" -gt "$API_PAYLOAD_MAX" ]; then
        printf "[TPM] ERROR: %s contains %s bytes, which exceeds the %s-byte limit (%s bytes reserved for the on-TPM header). Aborting.\n" "$ENV_FILE" "$INPUT_LEN" "$API_PAYLOAD_MAX" "$TPM_HDR_SIZE"
        exit 1
    fi
    _tpm_report_secret "$API_KEY_INPUT"
    printf "[TPM] Loaded value(s) from %s:%s\n" "$ENV_FILE" "$NAMES"
else

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
        if [ "$INPUT_LEN" -gt "$API_PAYLOAD_MAX" ]; then
            printf "[TPM] ERROR: Input is %s bytes, which exceeds the %s-byte limit (%s bytes reserved for the on-TPM header). Please shorten it.\n\n" "$INPUT_LEN" "$API_PAYLOAD_MAX" "$TPM_HDR_SIZE"
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

fi # ENV_FILE

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
    # An identity already loaded in ssh-agent (a hardware security key, one
    # loaded from a different path, an agent-forwarded identity, etc.) does
    # NOT mean there's a key file to seal here: agents intentionally never
    # let you export the private key material of an already-loaded
    # identity, only sign with it. Flag this before offering to generate a
    # new one, so it's a deliberate choice (a separate, TPM-dedicated key)
    # rather than a surprise once they notice they now have two identities.
    if ssh-add -l 2>/dev/null | grep -q "ED25519"; then
        printf "\n%s\n" "[TPM] Note: an ED25519 identity is already loaded in ssh-agent, but no key"
        printf "%s\n" "file exists at $SSH_KEY_PATH. This script seals the actual private key"
        printf "%s\n" "FILE in the TPM -- ssh-agent can't export the key material of an"
        printf "%s\n" "already-loaded identity, so that one can't be reused here even though"
        printf "%s\n" "it's active. Continuing will generate a NEW key dedicated to this setup."
        printf "\n"
    fi
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
if [ "$SSH_KEY_SIZE" -gt "$SSH_PAYLOAD_MAX" ]; then
    printf "[TPM] ERROR: %s is %s bytes, which exceeds the %s-byte NV limit (%s bytes reserved for the on-TPM header). Aborting.\n" "$SSH_KEY_PATH" "$SSH_KEY_SIZE" "$SSH_PAYLOAD_MAX" "$TPM_HDR_SIZE"
    exit 1
fi

printf "\n%s\n" "--- ssh-agent Autostart ---"
printf "%s\n" "Independent of unlocking your TPM secrets, a new shell can also make sure"
printf "%s\n" "an ssh-agent is running for general ssh-add/agent-forwarding use -- handy"
printf "%s\n" "if you use Manual unlock mode and don't always run 'unlock_tpm'. This is"
printf "%s\n" "a no-op if a desktop keychain agent (GNOME Keyring, KDE Wallet, etc.)"
printf "%s\n" "already owns \$SSH_AUTH_SOCK by the time the shell starts."
printf "Automatically start ssh-agent in every new shell if none is already running? (y/n) [default: y]: "
read SSH_AGENT_AUTOSTART_CHOICE
case "$SSH_AGENT_AUTOSTART_CHOICE" in
    [Nn]*) SSH_AGENT_AUTOSTART="no" ;;
    *) SSH_AGENT_AUTOSTART="yes" ;;
esac

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
printf "Enable SSH-agent-derived PIN for the API Key? (y/n) [default: y]: "
read API_PIN_MODE_CHOICE
case "$API_PIN_MODE_CHOICE" in
    [Nn]*) API_AUTH_MODE="master" ;;
    *) API_AUTH_MODE="agent" ;;
esac

# Different ssh-agent implementations can compute genuinely different
# signatures for the same key+message (verified: GNOME Keyring's agent
# disagrees with direct key-file signing) -- so make sure whatever agent is
# actually available now is the one used to derive the seed PIN, since
# that's what future unlocks will also go through.
if [ "$API_AUTH_MODE" = "agent" ]; then
    if [ -n "$SSH_AUTH_SOCK" ] && ! ssh-add -l 2>/dev/null | grep -q "ED25519"; then
        printf "%s\n" "[TPM] Loading your SSH identity into the running agent first, so the"
        printf "%s\n" "PIN is derived the same way future unlocks will compute it..."
        ssh-add "$SSH_KEY_PATH" || printf "[TPM] WARNING: ssh-add failed; this seed will sign directly from the key file instead.\n"
    elif [ -z "$SSH_AUTH_SOCK" ]; then
        printf "\n%s\n" "[TPM] WARNING: no ssh-agent is currently running, so this PIN would be"
        printf "%s\n" "derived by signing directly from the private key file. Different agent"
        printf "%s\n" "implementations (e.g. GNOME Keyring, common on GNOME desktops) can"
        printf "%s\n" "compute a DIFFERENT signature for the same key, which would make future"
        printf "%s\n" "unlocks fail with no obvious cause. For reliable results, start your"
        printf "%s\n" "normal login ssh-agent, run 'ssh-add $SSH_KEY_PATH', then re-run this"
        printf "%s\n" "script."
        printf "Continue anyway, signing directly from the key file? (y/n) [default: n]: "
        read API_PIN_NOAGENT_CONFIRM
        case "$API_PIN_NOAGENT_CONFIRM" in
            [Yy]*) ;;
            *) printf "[TPM] Falling back to the Master PIN for the API Key.\n"; API_AUTH_MODE="master" ;;
        esac
    fi
fi

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
    printf "%s\n" "[TPM] Deriving API Key PIN from your SSH identity (you may be asked for its passphrase if no agent has it loaded)..."
    if DERIVED_API_PIN=$(_tpm_derive_api_pin "$SSH_KEY_PATH") && [ -n "$DERIVED_API_PIN" ]; then
        API_NV_AUTH="$DERIVED_API_PIN"
    else
        printf "[TPM] WARNING: Could not derive a PIN from the SSH key (requires OpenSSH >= 8.2's 'ssh-keygen -Y sign'). Falling back to the Master PIN for the API Key.\n"
        API_AUTH_MODE="master"
    fi
    unset DERIVED_API_PIN
fi
TRIMMED_NAMES=$(_tpm_trim "$NAMES")
printf 'API_AUTH_MODE=%s\nSSH_AGENT_AUTOSTART=%s\nSECRET_NAMES="%s"\n' "$API_AUTH_MODE" "$SSH_AGENT_AUTOSTART" "$TRIMMED_NAMES" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"

printf "Writing API Key to TPM (%s)...\n" "$API_NV_INDEX"
if ! tpm2_nvdefine -C o -s "$API_NV_SIZE" -a "authread|authwrite" -p "$API_NV_AUTH" "$API_NV_INDEX"; then
    printf "[TPM] ERROR: Failed to define the API Key NV index. Aborting.\n"
    exit 1
fi
if ! { _tpm_emit_header "$INPUT_LEN"; printf "%s" "$API_KEY_INPUT"; } | tpm2_nvwrite -C "$API_NV_INDEX" -P "$API_NV_AUTH" -i - "$API_NV_INDEX"; then
    printf "[TPM] ERROR: Failed to write the API Key to the TPM. Aborting.\n"
    exit 1
fi
unset API_NV_AUTH

printf "Writing SSH Key to TPM (%s)...\n" "$SSH_NV_INDEX"
if ! tpm2_nvdefine -C o -s "$SSH_NV_SIZE" -a "authread|authwrite" -p "$MASTER_PIN" "$SSH_NV_INDEX"; then
    printf "[TPM] ERROR: Failed to define the SSH Key NV index. Aborting.\n"
    exit 1
fi
if ! { _tpm_emit_header "$SSH_KEY_SIZE"; cat "$SSH_KEY_PATH"; } | tpm2_nvwrite -C "$SSH_NV_INDEX" -P "$MASTER_PIN" -i - "$SSH_NV_INDEX"; then
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
# Guards against running twice in the same shell -- e.g. the
# ~/.bash_profile bootstrap below sourcing ~/.bashrc, on top of a shell
# that reaches this file some other way too. Re-running unlock_tpm'"'"'s
# trailer a second time is harmless on its own (it just re-checks and
# reports "already loaded"), but this avoids the redundant work/output.
if [ -n "$_TPM_RC_LOADED" ]; then
    return 0 2>/dev/null || exit 0
fi
_TPM_RC_LOADED=1
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

# Reads a secret from NV index $1 (auth $2), writing the exact payload
# bytes to stdout. See _tpm_read_secret in tpm_setup.sh for the full
# rationale -- this is the same function, embedded verbatim here so the
# generated unlock code has no dependency back on the setup script.
_tpm_read_secret() {
    IDX="$1"
    PIN="$2"
    # A raw hardware TPM (no resource manager) has only a handful of
    # session slots -- back-to-back reads can exhaust them (0x903), which
    # looks like a wrong PIN ("Invalid handle or authorization") but is
    # not; flushing frees them up, so retrying does nothing without it.
    NVERR=$(mktemp) || return 1
    ATTEMPT=0
    LOCKOUT_HANDLED=0
    while [ "$ATTEMPT" -lt 3 ]; do
        ATTEMPT=$((ATTEMPT + 1))
        HDR=$(tpm2_nvread -C "$IDX" -P "$PIN" -s 6 --offset=0 "$IDX" 2>"$NVERR" | od -An -tu1)
        if grep -qE "0x903|session context" "$NVERR" 2>/dev/null; then
            printf "%s\n" "[TPM] Note: the TPM ran out of session slots (a resource limit on the chip itself, not a wrong PIN) -- flushing stale sessions and retrying." >&2
            tpm2_flushcontext -t >/dev/null 2>&1
            tpm2_flushcontext -s >/dev/null 2>&1
            tpm2_flushcontext -l >/dev/null 2>&1
        elif grep -qE "0x921|lockout mode" "$NVERR" 2>/dev/null; then
            if [ "$LOCKOUT_HANDLED" = "0" ]; then
                LOCKOUT_HANDLED=1
                if tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1; then
                    printf "%s\n" "[TPM] Note: the TPM was in dictionary-attack lockout from prior failed attempts (not a wrong PIN) -- cleared automatically, retrying." >&2
                else
                    printf "%s\n" "[TPM] Error: the TPM is in dictionary-attack lockout and could not be cleared automatically (a lockout password may be set on this TPM) -- clear it manually with: tpm2_dictionarylockout --clear-lockout -- or wait for the lockout recovery interval, then retry." >&2
                    break
                fi
            else
                printf "%s\n" "[TPM] Error: the TPM is still in dictionary-attack lockout after an automatic clear attempt -- wait for the lockout recovery interval and retry." >&2
                break
            fi
        fi
        OLD_IFS="$IFS"
        IFS=" $(printf '"'"'\t'"'"')"
        set -- $HDR
        IFS="$OLD_IFS"
        [ "$#" -ge 6 ] && break
    done
    if [ "$#" -lt 6 ]; then
        rm -f "$NVERR"
        return 1
    fi
    IS_HEADER=0
    if [ "$1" = "165" ] && [ "$2" = "126" ]; then
        IS_HEADER=1
        for D in "$3" "$4" "$5" "$6"; do
            case "$D" in
                4[89] | 5[0-7]) ;;
                *) IS_HEADER=0 ;;
            esac
        done
    fi
    [ "$IS_HEADER" -eq 1 ] && HDR_LEN=$(( ($3 - 48) * 1000 + ($4 - 48) * 100 + ($5 - 48) * 10 + ($6 - 48) ))
    TMPFILE=$(mktemp) || { rm -f "$NVERR"; return 1; }
    ATTEMPT=0
    LOCKOUT_HANDLED=0
    while [ "$ATTEMPT" -lt 3 ]; do
        ATTEMPT=$((ATTEMPT + 1))
        if [ "$IS_HEADER" -eq 1 ]; then
            tpm2_nvread -C "$IDX" -P "$PIN" -s "$HDR_LEN" --offset=6 "$IDX" 2>"$NVERR" > "$TMPFILE"
        else
            tpm2_nvread -C "$IDX" -P "$PIN" "$IDX" 2>"$NVERR" | env LC_ALL=C tr -d '"'"'\0\377'"'"' > "$TMPFILE"
        fi
        if grep -qE "0x903|session context" "$NVERR" 2>/dev/null; then
            printf "%s\n" "[TPM] Note: the TPM ran out of session slots (a resource limit on the chip itself, not a wrong PIN) -- flushing stale sessions and retrying." >&2
            tpm2_flushcontext -t >/dev/null 2>&1
            tpm2_flushcontext -s >/dev/null 2>&1
            tpm2_flushcontext -l >/dev/null 2>&1
        elif grep -qE "0x921|lockout mode" "$NVERR" 2>/dev/null; then
            if [ "$LOCKOUT_HANDLED" = "0" ]; then
                LOCKOUT_HANDLED=1
                if tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1; then
                    printf "%s\n" "[TPM] Note: the TPM was in dictionary-attack lockout from prior failed attempts (not a wrong PIN) -- cleared automatically, retrying." >&2
                else
                    printf "%s\n" "[TPM] Error: the TPM is in dictionary-attack lockout and could not be cleared automatically (a lockout password may be set on this TPM) -- clear it manually with: tpm2_dictionarylockout --clear-lockout -- or wait for the lockout recovery interval, then retry." >&2
                    break
                fi
            else
                printf "%s\n" "[TPM] Error: the TPM is still in dictionary-attack lockout after an automatic clear attempt -- wait for the lockout recovery interval and retry." >&2
                break
            fi
        fi
        [ -s "$TMPFILE" ] && break
    done
    cat "$TMPFILE"
    rm -f "$TMPFILE" "$NVERR"
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

# Starts ssh-agent only if none is actually reachable: a no-op when
# $SSH_AUTH_SOCK already points at a live agent (whether ours from an
# earlier shell, or a desktop keychain agent like GNOME Keyring/KDE Wallet
# that owns it before any terminal even launches), and only replaces it
# when $SSH_AGENT_PID names a process of ours that has since died. Shared
# by unlock_tpm and the standalone shell-startup autostart hook below, so
# both agree on what counts as "already running".
_tpm_ensure_ssh_agent() {
    if [ -z "$SSH_AUTH_SOCK" ]; then
        # A shell that has not inherited ANY agent socket at all -- notably
        # a plain SSH login to this machine, which does NOT get the
        # environment of the desktop session (SSH_AUTH_SOCK, DISPLAY, ...)
        # the way a new local terminal spawned from the desktop does. If
        # the desktop session already unsealed the SSH key into its own
        # systemd-user-managed agent (GNOME Keyring, gcr-ssh-agent, KDE
        # Wallet), reuse that instead of spawning a private, throwaway
        # agent that nothing else will ever see -- otherwise every such
        # session re-prompts for the Master PIN forever even though the
        # key is already unsealed elsewhere. The "|| _TPM_ENV_OUT=" fallback
        # keeps this safe under set -e if systemctl is not installed
        # (FreeBSD, no desktop session, ...) or there is no user session
        # to query.
        _TPM_ENV_OUT=$(systemctl --user show-environment 2>/dev/null) || _TPM_ENV_OUT=""
        _TPM_DESKTOP_SOCK=$(printf '%s\n' "$_TPM_ENV_OUT" | sed -n 's/^SSH_AUTH_SOCK=//p')
        if [ -n "$_TPM_DESKTOP_SOCK" ] && [ -S "$_TPM_DESKTOP_SOCK" ]; then
            SSH_AUTH_SOCK="$_TPM_DESKTOP_SOCK"
            export SSH_AUTH_SOCK
        fi
        unset _TPM_ENV_OUT _TPM_DESKTOP_SOCK
    fi
    if [ -z "$SSH_AUTH_SOCK" ] || { [ -n "$SSH_AGENT_PID" ] && ! kill -0 "$SSH_AGENT_PID" 2>/dev/null; }; then
        eval "$(ssh-agent -s)" > /dev/null
    fi
}

unlock_tpm() {
    _tpm_needs_unlock
    if [ "$NEEDS_SSH" -eq 1 ] || [ "$NEEDS_API" -eq 1 ]; then
        _tpm_ensure_ssh_agent

        # Fast path: the SSH identity is already resident in the agent (e.g.
        # a second gnome-terminal tab in the same session) and only the API
        # key is missing -- derive its PIN from the agent instead of
        # re-prompting for the Master PIN.
        if [ "$NEEDS_SSH" -eq 0 ] && [ "$NEEDS_API" -eq 1 ] && [ "$TPM_API_AUTH_MODE" = "agent" ]; then
            if AGENT_PIN=$(_tpm_derive_api_pin "$TPM_SSH_PUB_PATH") && [ -n "$AGENT_PIN" ]; then
                RAW_SECRET=$(_tpm_read_secret '"$API_NV_INDEX"' "$AGENT_PIN")
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
            _tpm_read_secret '"$SSH_NV_INDEX"' "$USER_PIN" | ssh-add - || printf "%s\n" "[TPM] Error: Failed to load SSH key."
        fi
        if [ "$NEEDS_API" -eq 1 ]; then
            SKIP_API=0
            if [ "$TPM_API_AUTH_MODE" = "agent" ]; then
                API_PIN=$(_tpm_derive_api_pin "$TPM_SSH_PUB_PATH")
                if [ -z "$API_PIN" ]; then
                    # NEVER fall back to the raw Master PIN here: this
                    # index was sealed with an agent-derived PIN, not the
                    # Master PIN, so that would be a guaranteed-wrong TPM
                    # authorization attempt -- one that only burns a
                    # dictionary-attack lockout counter for nothing (seen
                    # directly: it climbed from 1 to 7 failed attempts
                    # this way while debugging this exact scenario).
                    SKIP_API=1
                    printf "%s\n" "[TPM] Error: No SSH identity available to derive the agent-based PIN for the API key -- skipping the API key rather than risk a wrong TPM authorization attempt against it."
                fi
            else
                API_PIN="$USER_PIN"
            fi
            if [ "$SKIP_API" -eq 0 ]; then
                RAW_SECRET=$(_tpm_read_secret '"$API_NV_INDEX"' "$API_PIN")
                if [ -n "$RAW_SECRET" ]; then
                    _tpm_load_secret "$RAW_SECRET"
                else
                    printf "%s\n" "[TPM] Error: Failed to load API secret."
                fi
            fi
            unset API_PIN
        fi
    else
        printf "%s\n" "[TPM] All secure keys are already loaded."
    fi
}
'

if [ "$SSH_AGENT_AUTOSTART" = "yes" ]; then
    SHRC_SNIPPET="$SHRC_SNIPPET"'
case "$-" in *i*) _tpm_ensure_ssh_agent ;; esac'
fi

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

# Reads a secret from NV index $1 (auth $2), writing the exact payload
# bytes to stdout -- see _tpm_read_secret in tpm_setup.sh for the full
# rationale (magic-header detection with a legacy-data fallback).
_tpm_read_secret() {
    IDX="$1"
    PIN="$2"
    # A raw hardware TPM (no resource manager) has only a handful of
    # session slots -- back-to-back reads can exhaust them (0x903), which
    # looks like a wrong PIN ("Invalid handle or authorization") but is
    # not; flushing frees them up, so retrying does nothing without it.
    NVERR=$(mktemp) || return 1
    ATTEMPT=0
    LOCKOUT_HANDLED=0
    while [ "$ATTEMPT" -lt 3 ]; do
        ATTEMPT=$((ATTEMPT + 1))
        HDR=$(tpm2_nvread -C "$IDX" -P "$PIN" -s 6 --offset=0 "$IDX" 2>"$NVERR" | od -An -tu1)
        if grep -qE "0x903|session context" "$NVERR" 2>/dev/null; then
            printf "%s\n" "[TPM] Note: the TPM ran out of session slots (a resource limit on the chip itself, not a wrong PIN) -- flushing stale sessions and retrying." >&2
            tpm2_flushcontext -t >/dev/null 2>&1
            tpm2_flushcontext -s >/dev/null 2>&1
            tpm2_flushcontext -l >/dev/null 2>&1
        elif grep -qE "0x921|lockout mode" "$NVERR" 2>/dev/null; then
            if [ "$LOCKOUT_HANDLED" = "0" ]; then
                LOCKOUT_HANDLED=1
                if tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1; then
                    printf "%s\n" "[TPM] Note: the TPM was in dictionary-attack lockout from prior failed attempts (not a wrong PIN) -- cleared automatically, retrying." >&2
                else
                    printf "%s\n" "[TPM] Error: the TPM is in dictionary-attack lockout and could not be cleared automatically (a lockout password may be set on this TPM) -- clear it manually with: tpm2_dictionarylockout --clear-lockout -- or wait for the lockout recovery interval, then retry." >&2
                    break
                fi
            else
                printf "%s\n" "[TPM] Error: the TPM is still in dictionary-attack lockout after an automatic clear attempt -- wait for the lockout recovery interval and retry." >&2
                break
            fi
        fi
        OLD_IFS="$IFS"
        IFS=" $(printf '\t')"
        set -- $HDR
        IFS="$OLD_IFS"
        [ "$#" -ge 6 ] && break
    done
    if [ "$#" -lt 6 ]; then
        rm -f "$NVERR"
        return 1
    fi
    IS_HEADER=0
    if [ "$1" = "165" ] && [ "$2" = "126" ]; then
        IS_HEADER=1
        for D in "$3" "$4" "$5" "$6"; do
            case "$D" in
                4[89] | 5[0-7]) ;;
                *) IS_HEADER=0 ;;
            esac
        done
    fi
    [ "$IS_HEADER" -eq 1 ] && HDR_LEN=$(( ($3 - 48) * 1000 + ($4 - 48) * 100 + ($5 - 48) * 10 + ($6 - 48) ))
    TMPFILE=$(mktemp) || { rm -f "$NVERR"; return 1; }
    ATTEMPT=0
    LOCKOUT_HANDLED=0
    while [ "$ATTEMPT" -lt 3 ]; do
        ATTEMPT=$((ATTEMPT + 1))
        if [ "$IS_HEADER" -eq 1 ]; then
            tpm2_nvread -C "$IDX" -P "$PIN" -s "$HDR_LEN" --offset=6 "$IDX" 2>"$NVERR" > "$TMPFILE"
        else
            tpm2_nvread -C "$IDX" -P "$PIN" "$IDX" 2>"$NVERR" | env LC_ALL=C tr -d '\0\377' > "$TMPFILE"
        fi
        if grep -qE "0x903|session context" "$NVERR" 2>/dev/null; then
            printf "%s\n" "[TPM] Note: the TPM ran out of session slots (a resource limit on the chip itself, not a wrong PIN) -- flushing stale sessions and retrying." >&2
            tpm2_flushcontext -t >/dev/null 2>&1
            tpm2_flushcontext -s >/dev/null 2>&1
            tpm2_flushcontext -l >/dev/null 2>&1
        elif grep -qE "0x921|lockout mode" "$NVERR" 2>/dev/null; then
            if [ "$LOCKOUT_HANDLED" = "0" ]; then
                LOCKOUT_HANDLED=1
                if tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1; then
                    printf "%s\n" "[TPM] Note: the TPM was in dictionary-attack lockout from prior failed attempts (not a wrong PIN) -- cleared automatically, retrying." >&2
                else
                    printf "%s\n" "[TPM] Error: the TPM is in dictionary-attack lockout and could not be cleared automatically (a lockout password may be set on this TPM) -- clear it manually with: tpm2_dictionarylockout --clear-lockout -- or wait for the lockout recovery interval, then retry." >&2
                    break
                fi
            else
                printf "%s\n" "[TPM] Error: the TPM is still in dictionary-attack lockout after an automatic clear attempt -- wait for the lockout recovery interval and retry." >&2
                break
            fi
        fi
        [ -s "$TMPFILE" ] && break
    done
    cat "$TMPFILE"
    rm -f "$TMPFILE" "$NVERR"
}

case "$MODE" in
    ssh)
        _tpm_read_secret "$IDX" "$PIN"
        ;;
    api)
        RAW=$(_tpm_read_secret "$IDX" "$PIN")
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
        # Only emit the legacy single-key form when RAW is non-empty --
        # otherwise a failed/empty read (bad PIN, index doesn't exist) would
        # still produce a `setenv SECURE_API_KEY ''` line, making the output
        # file non-empty and tricking .tpm_unlock.csh's `-s` check into
        # reporting success for a secret that was never actually loaded.
        [ "$FOUND_KV" -eq 0 ] && [ -n "$RAW" ] && emit SECURE_API_KEY "$RAW"
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
# Starts ssh-agent only if none is actually reachable: a no-op when
# $SSH_AUTH_SOCK already points at a live agent (ours or a desktop keychain
# agent that owns it before tcsh even starts), and only replaces it when
# $SSH_AGENT_PID names a process of ours that has since died. tcsh's own
# `kill` builtin is shelled out to via `sh` for consistent -0 semantics --
# through an exported env var, NOT `sh -c '...' -- "$var"`: tcsh silently
# drops extra positional args after a quoted -c script, so $1 in the child
# sh script is always empty (confirmed directly: even a live PID reports
# "not alive" through that pattern).
set _tpm_start_agent = 0
if (! $?SSH_AUTH_SOCK) then
    # A fresh tcsh that has not inherited ANY agent socket at all --
    # notably a plain SSH login to this machine, which does NOT get the
    # environment of the desktop session (SSH_AUTH_SOCK, DISPLAY, ...) the
    # way a new local terminal spawned from the desktop does. If the
    # desktop session already unsealed the SSH key into its own
    # systemd-user-managed agent (GNOME Keyring, gcr-ssh-agent, KDE
    # Wallet), reuse that instead of spawning a private, throwaway agent
    # that nothing else will ever see.
    set _tpm_desktop_sock = `sh -c 'systemctl --user show-environment 2>/dev/null | sed -n "s/^SSH_AUTH_SOCK=//p"'`
    if ("$_tpm_desktop_sock" != "") then
        setenv _TPM_CANDIDATE_SOCK "$_tpm_desktop_sock"
        sh -c 'test -S "$_TPM_CANDIDATE_SOCK"'
        if ( $status == 0 ) then
            setenv SSH_AUTH_SOCK "$_tpm_desktop_sock"
        else
            set _tpm_start_agent = 1
        endif
        unsetenv _TPM_CANDIDATE_SOCK
    else
        set _tpm_start_agent = 1
    endif
    unset _tpm_desktop_sock
else if ($?SSH_AGENT_PID) then
    setenv _TPM_CANDIDATE_PID "$SSH_AGENT_PID"
    sh -c 'kill -0 "$_TPM_CANDIDATE_PID" 2>/dev/null'
    if ( $status != 0 ) set _tpm_start_agent = 1
    unsetenv _TPM_CANDIDATE_PID
endif
if ( $_tpm_start_agent == 1 ) eval `ssh-agent -c` > /dev/null
unset _tpm_start_agent
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
            set _tpm_skip_api = 0
            if ( "AUTHMODE" == "agent" ) then
                set API_PIN = `sh "$HOME/.tpm_unlock_helper.sh" agentpin "PUBPATH"`
                if ( "$API_PIN" == "" ) then
                    # NEVER fall back to the raw Master PIN here: this
                    # index was sealed with an agent-derived PIN, not the
                    # Master PIN, so that would be a guaranteed-wrong TPM
                    # authorization attempt -- one that only burns a
                    # dictionary-attack lockout counter for nothing.
                    set _tpm_skip_api = 1
                    echo "[TPM] Error: No SSH identity available to derive the API key's agent-based PIN -- skipping the API key rather than risk a wrong TPM authorization attempt against it."
                endif
            else
                set API_PIN = "$USER_PIN"
            endif
            if ( $_tpm_skip_api == 0 ) then
                set TPM_ENV_FILE = `mktemp`
                sh "$HOME/.tpm_unlock_helper.sh" api API_IDX "$API_PIN" > "$TPM_ENV_FILE"
                if ( -s "$TPM_ENV_FILE" ) then
                    source "$TPM_ENV_FILE"
                    echo "[TPM] Secrets loaded."
                else
                    echo "[TPM] Error: Failed to load API secret."
                endif
                rm -f "$TPM_ENV_FILE"
            endif
            unset API_PIN
            unset _tpm_skip_api
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

if [ "$SSH_AGENT_AUTOSTART" = "yes" ]; then
    CSHRC_SNIPPET="$CSHRC_SNIPPET"'
if ($?prompt) then
    set _tpm_start_agent = 0
    if (! $?SSH_AUTH_SOCK) then
        set _tpm_desktop_sock = `sh -c '\''systemctl --user show-environment 2>/dev/null | sed -n "s/^SSH_AUTH_SOCK=//p"'\''`
        if ("$_tpm_desktop_sock" != "") then
            setenv _TPM_CANDIDATE_SOCK "$_tpm_desktop_sock"
            sh -c '\''test -S "$_TPM_CANDIDATE_SOCK"'\''
            if ( $status == 0 ) then
                setenv SSH_AUTH_SOCK "$_tpm_desktop_sock"
            else
                set _tpm_start_agent = 1
            endif
            unsetenv _TPM_CANDIDATE_SOCK
        else
            set _tpm_start_agent = 1
        endif
        unset _tpm_desktop_sock
    else if ($?SSH_AGENT_PID) then
        setenv _TPM_CANDIDATE_PID "$SSH_AGENT_PID"
        sh -c '\''kill -0 "$_TPM_CANDIDATE_PID" 2>/dev/null'\''
        if ( $status != 0 ) set _tpm_start_agent = 1
        unsetenv _TPM_CANDIDATE_PID
    endif
    if ( $_tpm_start_agent == 1 ) eval `ssh-agent -c` > /dev/null
    unset _tpm_start_agent
endif'
fi

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
    # NOT "if ($?prompt) unlock_tpm" -- tcsh's single-line "if (expr) command"
    # form does not go through alias substitution (confirmed: it runs a
    # *different* code path than a command typed on its own line, which is
    # where alias expansion actually happens), so it fails with
    # "unlock_tpm: Command not found." even though the alias is defined.
    # Only the multi-line if/then/endif form expands aliases correctly.
    CSHRC_SNIPPET="$CSHRC_SNIPPET"'
if ($?prompt) then
    unlock_tpm
endif'
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

# bash invoked as a LOGIN shell (its own /etc/passwd entry -- common when
# bash is the account's login shell, e.g. FreeBSD, whose skel(5) doesn't
# ship any bash-specific dotfiles at all) never reads ~/.bashrc: it only
# checks ~/.bash_profile, then ~/.bash_login, then ~/.profile, stopping at
# the first one that exists, same as ~/.shrc/~/.bashrc above -- so a bare
# login session would silently never see the unlock_tpm hook. Ensure
# ~/.bash_profile sources ~/.bashrc; harmless if some other file already
# does, since the block above guards against running twice.
BASH_PROFILE_SNIPPET='
# --- TPM Secure Environment Setup (bash_profile bootstrap) ---
if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
# ----------------------------------------------'
sed -i.bak '/# --- TPM Secure Environment Setup (bash_profile bootstrap) ---/,/# ----------------------------------------------/d' "$HOME/.bash_profile" 2>/dev/null || true
rm -f "$HOME/.bash_profile.bak"
printf "%s\n" "$BASH_PROFILE_SNIPPET" >> "$HOME/.bash_profile"
printf "Added bash_profile bootstrap (sources .bashrc for bash login shells) to %s\n" "$HOME/.bash_profile"

CSHRC_FILE="$HOME/.cshrc"
sed -i.bak '/# --- TPM Secure Environment Setup (tcsh) ---/,/# -------------------------------------------/d' "$CSHRC_FILE" 2>/dev/null || true
rm -f "$CSHRC_FILE.bak"
printf "%s\n" "$CSHRC_SNIPPET" >> "$CSHRC_FILE"
printf "Added tcsh automation to %s\n" "$CSHRC_FILE"

printf "\n%s\n" "=== Setup Complete! ==="
printf "IMPORTANT: Backup %s to an offline drive before deleting it from this system!\n" "$SSH_KEY_PATH"
