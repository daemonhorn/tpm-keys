# tpm-keys-portable

A single POSIX `sh` script (`tpm_setup.sh`) that seals your SSH key and API
key/token secrets inside your machine's TPM 2.0, protected by one Master PIN,
and wires up automatic (or on-demand) unlocking in new shells — for both
**sh/bash** and **tcsh**.

Instead of your SSH private key and API keys sitting in plaintext on disk,
they live encrypted in TPM NV RAM. A new terminal either prompts you for the
PIN automatically, or waits for you to run `unlock_tpm`, then loads the SSH
key into `ssh-agent` and the API key(s) into your environment.

## Supported platforms

- Debian / Ubuntu (and derivatives)
- RHEL / Rocky / AlmaLinux / CentOS
- FreeBSD

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
   generate one with `ssh-keygen` if it doesn't exist.
4. **Phase 4 — seeding the TPM**: writes both secrets into TPM NV RAM,
   authenticated by your Master PIN. If a secret is already stored at that
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
