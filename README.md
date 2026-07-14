# tpm-keys-portable

A single POSIX `sh` script (`tpm_setup.sh`) that seals your SSH key and API
key/token secrets inside your machine's TPM 2.0, protected by one Master PIN,
and wires up automatic (or on-demand) unlocking in new shells — for both
**sh/bash** and **tcsh**. A companion PowerShell script (`tpm_setup.ps1`)
does the same thing on Windows 11, reading and writing the *same* TPM NV RAM
indices on the *same* physical chip, so a dual-booted machine can seal a
secret in one OS and unlock it in the other.

Instead of your SSH private key and API keys sitting in plaintext on disk,
they live encrypted in TPM NV RAM. A new terminal either prompts you for the
PIN automatically, or waits for you to run `unlock_tpm`, then loads the SSH
key into `ssh-agent` and the API key(s) into your environment.

## Supported platforms

- Debian / Ubuntu (and derivatives)
- RHEL / Rocky / AlmaLinux / CentOS
- FreeBSD
- Windows 11 (PowerShell 7+) — see [Windows 11 / PowerShell 7](#windows-11--powershell-7) below

## Prerequisites

### All platforms

- A TPM 2.0 chip (discrete, firmware/fTPM, or Intel PTT), **enabled in
  BIOS/UEFI**.
- `sudo` access (the script installs packages, loads kernel modules, and
  manages group membership on your behalf).
- An interactive terminal (the script prompts for input and disables echo
  while you type the PIN).

### Linux (Debian/Ubuntu, RHEL/Rocky/Alma/CentOS)

- Package manager access (`apt-get`, `dnf`, or `yum`) to install
  `tpm2-tools` if it isn't already present.
- A TPM device node the kernel can expose as `/dev/tpmrm0` (resource
  manager) or `/dev/tpm0`. The script will attempt to `modprobe tpm_tis` /
  `modprobe tpm_crb` if no device node is found.
- Membership in the `tss` group (created automatically) so tpm2-tools can
  talk to the TPM without root.

### FreeBSD

- `pkg` access to install `tpm2-tools`.
- The `tpm` kernel module (the script will `kldload tpm` and persist it via
  `kld_list` in `/etc/rc.conf` if needed).
- Membership in the `_tss` group (created automatically), plus a
  `/dev/tpm0` devfs rule (`own tpm0 root:_tss`, `perm tpm0 0660`) that the
  script adds to `/etc/devfs.conf` for you.

## Installation

```sh
git clone git@github.com:daemonhorn/tpm-keys.git
cd tpm-keys
chmod +x tpm_setup.sh
./tpm_setup.sh
```

The script is interactive and safe to re-run — running it again on a
machine with a group change pending, or with keys already sealed, is
handled gracefully (see [Re-running the script](#re-running-the-script)).

## What the script does

1. **Phase 1 — OS detection & prerequisites**: detects your distro,
   installs `tpm2-tools` if missing, loads the TPM kernel module if the
   device node is absent, and adds you to the `tss`/`_tss` group.
   - If your group membership just changed, the script exits and asks you
     to **log out and back in**, then re-run it — group membership doesn't
     take effect in your current session.
2. **Phase 2 — configuration**: prompts for the secret(s) to store and a
   Master PIN (entered twice, hidden, and validated non-empty).
3. **Phase 3 — SSH key setup**: uses `~/.ssh/id_ed25519`, offering to
   generate one with `ssh-keygen` if it doesn't exist. Also asks whether to
   enable the [API Key Unlock Optimization](#api-key-unlock-optimization-ssh-agent-derived-pin)
   (SSH-agent-derived PIN), on by default (can be turned off).
4. **Phase 4 — seeding the TPM**: writes both secrets into TPM NV RAM,
   authenticated by your Master PIN (the API Key instead by the derived PIN,
   if that optimization is enabled). If a secret is already stored at that
   NV index, you're asked to confirm before it's overwritten.
5. **Phase 5 — shell integration**: installs an `unlock_tpm` function/alias
   into `~/.bashrc`, `~/.shrc`, and `~/.cshrc` (re-running the script
   replaces the old block cleanly rather than duplicating it).

## Usage examples

### Single API key

```
Enter the value(s) to store in the TPM. This can be either:
  - a single API key/token, stored as $SECURE_API_KEY, or
  - one or more named values: NAME1="value1";NAME2="value2";...
Enter value(s): sk-my-plain-api-token
[TPM] Storing as a single API key.
```

After unlocking, this is available as `$SECURE_API_KEY`.

### Multiple named secrets

You can store several named values in one go using `NAME="value"` pairs
separated by `;`:

```
Enter value(s): OPENAI_KEY="sk-abc123";AWS_SECRET_ACCESS_KEY="xyz789"
[TPM] Detected named value(s): OPENAI_KEY AWS_SECRET_ACCESS_KEY
```

After unlocking, `$OPENAI_KEY` and `$AWS_SECRET_ACCESS_KEY` are both set in
your shell. Quotes around each value are required — that's what tells the
parser you mean multiple named values rather than a single opaque key (so a
plain key that happens to contain `=`, like base64 padding, is never
misread).

### Unlock strategies

- **[1] Automatic** (default): every new interactive shell prompts for the
  Master PIN immediately if secrets aren't already loaded.
- **[2] Manual**: new shells print a one-line hint; you run `unlock_tpm`
  yourself whenever you need the keys.

### API Key Unlock Optimization (SSH-agent-derived PIN)

`ssh-agent` keeps your loaded SSH identity available across every new
gnome-terminal / gnome-shell tab in a session — they all inherit the same
`SSH_AUTH_SOCK` — but `$SECURE_API_KEY` is just a shell variable, so it does
**not** carry over. Without this feature, every new tab still prompts for
the Master PIN just to reload the API key, even though the SSH identity is
already unlocked.

Phase 3 (after SSH key setup, only when seeding/re-seeding) offers to seal
the API Key under a PIN *derived* from your SSH ed25519 key instead — a
SHA-256 digest (truncated to 32 hex chars) of a fixed, deterministic
`ssh-keygen -Y sign` challenge signed with that key. ed25519 signing is
deterministic (RFC 8032) *for a given signer* — the same agent (or the same
direct key-file signing) always reproduces the same signature for the same
key/message/namespace — but different `ssh-agent` implementations are
**not** guaranteed to agree with each other: verified on real hardware that
GNOME Keyring's `ssh-agent` (the default, persistent agent on most GNOME
desktops) computes a different signature than signing directly from the key
file for the identical key and message. To avoid that mismatch, Phase 4
always derives (and seals) the PIN using whatever agent already has the
identity loaded at seeding time — proactively loading it into the running
agent first if it isn't there yet — so setup and every later unlock go
through the same signer. It only falls back to direct key-file signing (and
warns you) if no agent is running at all when you seed.

The practical effect: once your SSH identity is loaded into `ssh-agent` in
any tab, every other tab can silently re-derive that same PIN and load
`$SECURE_API_KEY` with **no PIN prompt at all**. The very first tab in a
session (where the SSH identity isn't in the agent yet) still needs one
Master PIN entry — which loads the SSH key *and* the API key together, same
as today.

This is **on by default** (`y` on a bare Enter) and asked for by y/n prompt
during seeding; answer `n` to keep the API Key under the Master PIN instead.
It's remembered across re-runs that keep existing data (in
`~/.tpm_keys_state`), so re-running the script doesn't force you to
reconsider it.

**Security note**: enabling this makes `ssh-agent` access equivalent to
knowing the API key's PIN. Anyone who can get your agent to sign on your
behalf (e.g. via SSH agent forwarding to a compromised host) can derive the
same PIN and read the sealed API key. Requires OpenSSH ≥ 8.2 (`ssh-keygen -Y
sign`); the script falls back to the Master PIN with a warning if signing
fails.

### Unlocking (after setup)

```
$ unlock_tpm
[TPM] Secured keys missing from environment.
Enter Master TPM PIN:
Identity added: (stdin) (you@host)
[TPM] Loaded env var: OPENAI_KEY
[TPM] Loaded env var: AWS_SECRET_ACCESS_KEY
```

If everything is already loaded (SSH identity present, secrets already in
the environment), `unlock_tpm` just reports:

```
[TPM] All secure keys are already loaded.
```

This works identically whether your login shell is **bash/sh** or **tcsh**.

## Re-running the script

Running `tpm_setup.sh` again is safe:

- If it detects your group membership changed on a prior run, it will exit
  and remind you to log out/in first.
- If a secret already exists at your TPM NV index (API key or SSH key), it
  asks for explicit confirmation before overwriting it — nothing is
  destroyed silently.
- The `unlock_tpm` blocks added to `~/.bashrc`/`~/.shrc`/`~/.cshrc` are
  replaced in place, not duplicated.
- Whether the API Key is sealed under the Master PIN or an SSH-agent-derived
  PIN is remembered in `~/.tpm_keys_state`, so re-running without
  re-seeding (keeping existing data) regenerates the shell integration
  scripts with the correct unlock method instead of re-asking.

## Security notes

- The Master PIN is required to read or write either TPM NV index — without
  it, the sealed SSH key and API secrets are inaccessible.
- `tpm2-tools` passes the PIN as a command-line argument to `tpm2_nvread`/
  `tpm2_nvwrite`, which is briefly visible to other local users via `ps`.
  This is a known limitation of the `tpm2-tools` CLI itself, not something
  this script works around.
- **Back up your SSH private key** (`~/.ssh/id_ed25519`) to an offline
  drive before deleting it from disk. Sealing it in the TPM ties it to this
  specific machine's TPM — losing the machine or the TPM means losing the
  key unless you kept an offline backup.

## Windows 11 / PowerShell 7

`tpm_setup.ps1` is a PowerShell port for dual-boot machines: it targets the
same TPM 2.0 chip as `tpm_setup.sh`, so a secret sealed on Linux/FreeBSD can
be unlocked on Windows and vice versa.

### Why it's implemented differently

There's no official `tpm2-tools` build for Windows, so this doesn't shell
out to it. Instead it talks to the TPM directly over Windows' own **TBS**
(TPM Base Services, `tbs.dll`) using hand-built TPM2 command buffers — the
same protocol `tpm2-tools` speaks, just implemented natively in PowerShell.
One side effect: since it never shells out for TPM operations, the PIN never
appears in another process's command-line arguments (unlike the `ps`-visible
caveat above for `tpm2-tools` on Linux/FreeBSD).

Reading or writing a sealed secret only needs the NV index's own PIN, so
`unlock_tpm` and day-to-day use never require admin rights. **First-time
setup does**, though: defining or removing an NV index (Phase 4) uses the
TPM *owner hierarchy*, and independent of that hierarchy's own auth value,
Windows TBS enforces its own allow-list of TPM 2.0 command ordinals that's
different for standard-user vs. administrator processes — `NV_DefineSpace`/
`NV_UndefineSpace` are excluded from the standard-user list and are blocked
by Windows itself (`TPM_E_COMMAND_BLOCKED`) before ever reaching the TPM.
Run `tpm_setup.ps1` itself from an elevated PowerShell; nothing after that
first run needs elevation. If Windows' built-in `sudo` is enabled (Windows
11 24H2+, `Settings > System > For developers > Enable sudo`), the script
detects a non-elevated run in Phase 1 and self-relaunches through it
automatically — you get a single UAC prompt and never have to close the
window and reopen an admin one yourself. This happens *before* Phase 2 asks
for anything, so you only enter your secrets/PIN once, inside the elevated
relaunch.

### Prerequisites

- Windows 11 with PowerShell 7+ (`pwsh`), a TPM 2.0 device enabled in UEFI,
  and the OpenSSH Client feature (`ssh-keygen`, `ssh-add`, and the
  `ssh-agent` service — usually preinstalled; if not,
  `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0` from an
  elevated PowerShell).
- **Admin rights for the first run.** Phase 4 (seeding the TPM) calls
  `NV_DefineSpace`/`NV_UndefineSpace`, which Windows TBS blocks for
  non-admin processes regardless of the TPM's own owner-hierarchy auth
  value (see [Why it's implemented differently](#why-its-implemented-differently)).
  The script checks for this in Phase 1, before any prompts, and handles it
  one of two ways:
  - If Windows' built-in `sudo` is available, it self-relaunches through
    `sudo pwsh -File tpm_setup.ps1` automatically (see above) — just
    approve the UAC prompt. **`sudo` mode matters**: if `sudo` is
    configured with input disabled (`Settings > System > For developers >
    Enable sudo`, "input disabled" option), the elevated relaunch can't
    reach this script's interactive prompts (API key, PIN, etc.) — use
    "New window" or "Inline" mode instead. Check your current mode with
    `sudo config`.
  - Otherwise, it exits with instructions to re-run from an elevated
    ("Run as administrator") PowerShell 7 window yourself.

  Either way, elevation is only needed for this initial run — `unlock_tpm`
  and everyday use never require it.
- **Execution policy**: `tpm_setup.ps1` is unsigned, so your effective
  `Get-ExecutionPolicy` can't be `AllSigned` or `Restricted`, or PowerShell
  will refuse to run it at all. `RemoteSigned` (the common default) is
  fine. If needed: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
  This also determines whether your PowerShell profile (and therefore the
  automatic `unlock_tpm` hook) loads on new sessions at all — the script
  checks this in Phase 1 and warns if your policy would block it.

### Cross-OS key sharing

TPM NV indices are computed from a numeric UID (`22020096 + UID*2` and
`+1`), matching `tpm_setup.sh`'s own formula. Windows has no `id -u`
equivalent, so Phase 2 asks for the UID `tpm_setup.sh` used on the
Linux/FreeBSD side of the dual boot (run `id -u` there). Leave it blank to
use a Windows-only index instead (won't be shared with the other OS).

### Usage

```powershell
pwsh -File tpm_setup.ps1
```

It walks through the same five phases as `tpm_setup.sh` (prerequisites,
configuration, SSH key setup, seeding the TPM, shell integration), and
installs an `unlock_tpm` PowerShell function the same way — appended to
your `$PROFILE`, idempotently replaced on re-run. If your profile ends in
an Authenticode signature block (common under `AllSigned` policies), the
hook is inserted *before* that block, since PowerShell refuses to parse
anything after `# SIG # End signature block`; doing so invalidates the
existing signature, so re-sign the profile afterwards if your policy
requires it.

The loaded SSH key is written briefly to a per-user-ACL'd temp file for
`ssh-add` (Windows OpenSSH's `ssh-add` doesn't support reading a key from
stdin the way `tpm2_nvread ... | ssh-add -` does on Linux/FreeBSD) and
deleted immediately after.
