#!/bin/sh
# Universal TPM 2.0 Secure Setup Script
# Features: Single Master PIN, Auto/Manual execution, Multi-User safe
# OS Support: Debian, RHEL (Rocky/Alma/CentOS), FreeBSD

set -e

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
        printf "ERROR: Unsupported OS or Distribution. (%s)\n" "$OS_NAME"
        exit 1
        ;;
esac

# 1. Package Management
if ! command -v tpm2_nvread >/dev/null 2>&1; then
    printf "%s\n" "tpm2-tools not found. Installing..."
    eval "$PKG_MGR"
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
eval "$GROUP_CREATE"
if ! id -nG "$USER" | grep -qw "$GROUP_NAME"; then
    printf "Adding user %s to %s group...\n" "$USER" "$GROUP_NAME"
    eval "$GROUP_CMD"
    printf "\n%s\n" "ERROR: Group permissions changed. You MUST completely log out and log back in."
    exit 1
fi

# --- 2. Dynamic NV Index Allocation & User Choices ---
USER_UID=$(id -u)
API_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 )))
SSH_NV_INDEX=$(printf "0x%X" $(( 22020096 + USER_UID * 2 + 1 )))

printf "\n%s\n" "=== Phase 2: Configuration ==="
printf "Enter the API Key to store in the TPM: "
read API_KEY_INPUT

printf "Create a Master PIN to protect your TPM keys: "
stty -echo; read MASTER_PIN; stty echo; printf "\n\n"

printf "%s\n" "--- Unlock Strategy ---"
printf "%s\n" "[1] Automatic : Prompt for PIN automatically when opening a new terminal."
printf "%s\n" "[2] Manual    : Print a hint in new terminals, wait for you to run 'unlock_tpm'."
printf "Choose (1 or 2) [default: 1]: "
read STRATEGY_CHOICE
[ "$STRATEGY_CHOICE" != "2" ] && STRATEGY_CHOICE="1"

# --- 3. SSH Key Generation ---
printf "\n%s\n" "=== Phase 3: SSH Key Setup ==="
SSH_KEY_PATH="$HOME/.ssh/id_ed25519"
if [ ! -f "$SSH_KEY_PATH" ]; then
    printf "No Ed25519 key found at %s. Generate one now? (y/n): " "$SSH_KEY_PATH"
    read GEN_KEY
    case "$GEN_KEY" in
        [Yy]* ) ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N ""; printf "%s\n" "Key generated.";;
        * ) printf "%s\n" "ERROR: You must have an Ed25519 key to continue."; exit 1;;
    esac
fi

# --- 4. Seeding the TPM ---
printf "\n%s\n" "=== Phase 4: Seeding TPM NV RAM ==="
tpm2_nvundefine -C o "$API_NV_INDEX" >/dev/null 2>&1 || true
tpm2_nvundefine -C o "$SSH_NV_INDEX" >/dev/null 2>&1 || true

printf "Writing API Key to TPM (%s)...\n" "$API_NV_INDEX"
tpm2_nvdefine -C o -s 128 -a "authread|authwrite" -p "$MASTER_PIN" "$API_NV_INDEX"
printf "%s" "$API_KEY_INPUT" | tpm2_nvwrite -C "$API_NV_INDEX" -P "$MASTER_PIN" -i - "$API_NV_INDEX"

printf "Writing SSH Key to TPM (%s)...\n" "$SSH_NV_INDEX"
tpm2_nvdefine -C o -s 1024 -a "authread|authwrite" -p "$MASTER_PIN" "$SSH_NV_INDEX"
tpm2_nvwrite -C "$SSH_NV_INDEX" -P "$MASTER_PIN" -i "$SSH_KEY_PATH" "$SSH_NV_INDEX"

# --- 5. Shell Integration ---
printf "\n%s\n" "=== Phase 5: Integrating with Shells ==="

# 1. SH/BASH Payload
SHRC_SNIPPET='
# --- TPM Secure Environment Setup (sh/bash) ---
unlock_tpm() {
    NEEDS_SSH=0
    NEEDS_API=0
    if [ -z "$SSH_AUTH_SOCK" ] || ! kill -0 "$SSH_AGENT_PID" >/dev/null 2>&1; then
        eval "$(ssh-agent -s)" > /dev/null
    fi
    if ! ssh-add -l | grep -q "ED25519"; then NEEDS_SSH=1; fi
    if [ -z "$SECURE_API_KEY" ]; then NEEDS_API=1; fi

    if [ "$NEEDS_SSH" -eq 1 ] || [ "$NEEDS_API" -eq 1 ]; then
        printf "\n[TPM] Secured keys missing from environment.\nEnter Master TPM PIN: "
        stty -echo; read USER_PIN; stty echo; printf "\n"

        if [ "$NEEDS_SSH" -eq 1 ]; then
            tpm2_nvread -C '"$SSH_NV_INDEX"' -P "$USER_PIN" '"$SSH_NV_INDEX"' 2>/dev/null | ssh-add - || printf "[TPM] Error: Failed to load SSH key.\n"
        fi
        if [ "$NEEDS_API" -eq 1 ]; then
            export SECURE_API_KEY=$(tpm2_nvread -C '"$API_NV_INDEX"' -P "$USER_PIN" '"$API_NV_INDEX"' 2>/dev/null | env LC_ALL=C tr -d '\''\0'\'')
            [ -n "$SECURE_API_KEY" ] && printf "[TPM] API Key loaded.\n"
        fi
    else
        printf "%s\n" "[TPM] All secure keys are already loaded."
    fi
}
'

if [ "$STRATEGY_CHOICE" = "2" ]; then
    SHRC_SNIPPET="$SHRC_SNIPPET"'
case "$-" in *i*) printf "\n%s\n" "[TPM] Hint: Run '\''unlock_tpm'\'' to load your secure keys." ;; esac'
else
    SHRC_SNIPPET="$SHRC_SNIPPET"'
case "$-" in *i*) unlock_tpm ;; esac'
fi

SHRC_SNIPPET="$SHRC_SNIPPET
# ----------------------------------------------"

# 2. TCSH Payload (Helper Script)
cat << 'EOF' > "$HOME/.tpm_unlock.csh"
# TPM Secure Environment Setup Helper (tcsh)
set needs_ssh = 0
set needs_api = 0
if (! $?SSH_AUTH_SOCK) then
    eval `ssh-agent -c` > /dev/null
endif
ssh-add -l | grep -q "ED25519"
if ( $status != 0 ) set needs_ssh = 1
if (! $?SECURE_API_KEY) set needs_api = 1

if ( $needs_ssh == 1 || $needs_api == 1 ) then
    echo "\n[TPM] Secured keys missing from environment."
    echo -n "Enter Master TPM PIN: "
    stty -echo
    set USER_PIN = $<
    stty echo
    echo ""
    if ( $needs_ssh == 1 ) then
        sh -c "tpm2_nvread -C SSH_IDX -P '$USER_PIN' SSH_IDX 2>/dev/null" | ssh-add -
    endif
    if ( $needs_api == 1 ) then
        setenv SECURE_API_KEY `sh -c "tpm2_nvread -C API_IDX -P '$USER_PIN' API_IDX 2>/dev/null | env LC_ALL=C tr -d '\0'"`
        if ( "$SECURE_API_KEY" != "" ) echo "[TPM] API Key loaded."
    endif
else
    echo "[TPM] All secure keys are already loaded."
endif
EOF
sed -i.bak "s/SSH_IDX/$SSH_NV_INDEX/g; s/API_IDX/$API_NV_INDEX/g" "$HOME/.tpm_unlock.csh" && rm -f "$HOME/.tpm_unlock.csh.bak"

# 3. TCSH Injection Profile
CSHRC_SNIPPET='
# --- TPM Secure Environment Setup (tcsh) ---
alias unlock_tpm "source ~/.tpm_unlock.csh"
'

if [ "$STRATEGY_CHOICE" = "2" ]; then
    CSHRC_SNIPPET="$CSHRC_SNIPPET"'
if ($?prompt) echo "\n[TPM] Hint: Run '\''unlock_tpm'\'' to load your secure keys."'
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
        printf "%s\n" "$SHRC_SNIPPET" >> "$SH_FILE"
        printf "Added sh/bash automation to %s\n" "$SH_FILE"
    fi
done

CSHRC_FILE="$HOME/.cshrc"
sed -i.bak '/# --- TPM Secure Environment Setup (tcsh) ---/,/# -------------------------------------------/d' "$CSHRC_FILE" 2>/dev/null || true
printf "%s\n" "$CSHRC_SNIPPET" >> "$CSHRC_FILE"
printf "Added tcsh automation to %s\n" "$CSHRC_FILE"

printf "\n%s\n" "=== Setup Complete! ==="
printf "IMPORTANT: Backup %s to an offline drive before deleting it from this system!\n" "$SSH_KEY_PATH"
