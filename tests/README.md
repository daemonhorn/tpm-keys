# Tests

Run everything:

```sh
./tests/run_all.sh
```

Or run a single suite directly, e.g. `sh tests/test_sentinel_header.sh` or
`pwsh -File tests/test_sentinel_header.ps1`.

## What's here

- `test_sentinel_header.sh` / `.ps1` -- round-trips the on-TPM sentinel
  header format (`_tpm_emit_header`/`_tpm_read_secret` in `tpm_setup.sh`,
  `Write-Tpm2Nv`/`Read-Tpm2Nv` in `tpm_setup.ps1`) covering fresh writes
  under both `0x00` and `0xFF` TPM erase-fill, the legacy (headerless)
  fallback under both fill values, and an exact binary byte round-trip.
  The `.sh` version needs a real writable TPM 2.0 device + tpm2-tools and
  skips cleanly without one; the `.ps1` version stubs the TBS transport
  with an in-memory fake NV store (no real TPM needed) since there's no
  TBS access outside Windows.
- `test_env_file_parser.sh` / `.ps1` -- tests the `--env-file`/`-EnvFile`
  dotenv parser (`_tpm_parse_env_file` / `Get-TpmEnvFileSecret`) against
  `fixtures/sample.env` and a set of inputs that must be rejected (embedded
  `"` or `;` in a value, an invalid variable name, a line with no `=`, a
  file with no valid lines).
- `test_tcsh_alias_bug.sh` -- regression test for a real bug found and
  fixed this session: tcsh's single-line `if (expr) command` form does not
  expand aliases, so `if ($?prompt) unlock_tpm` silently failed with
  `unlock_tpm: Command not found.` in Automatic unlock mode even though the
  alias was defined. Proves the underlying tcsh behavior directly, then
  checks that the actual generated `.cshrc` uses the multi-line
  `if/then/endif` form instead.
- `test_bash_profile_bootstrap.sh` -- regression test for a real bug found
  and fixed after initial release: bash invoked as a *login* shell (its own
  `/etc/passwd` entry, not just an interactive preference -- notably on
  FreeBSD, whose `skel(5)` ships no bash-specific dotfiles) never reads
  `~/.bashrc` at all; it only checks `~/.bash_profile`, `~/.bash_login`,
  then `~/.profile`. Confirms Phase 5 creates/updates `~/.bash_profile` to
  source `~/.bashrc`, that the block is idempotent across re-runs, and that
  `~/.bashrc` has a guard against running twice in the same shell.
- `test_freebsd_sudo_bootstrap.sh` -- tests the FreeBSD `sudo`-bootstrap
  logic (FreeBSD's base system doesn't ship `sudo`, and everything from the
  `tpm2-tools` install onward assumes it's already there): covers running
  as root vs. needing `su`, and install success vs. failure, with fake
  `id`/`pkg`/`su` stubs so it doesn't touch the real system.
- `test_uninstall.sh` / `.ps1` -- tests `--uninstall`/`-Uninstall`'s removal
  of sealed TPM secrets and shell/profile integration. The `.sh` version
  runs the real script end-to-end with fake
  `id`/`tpm2_nvundefine` stubs on an isolated `PATH` (a fake, obviously-not-
  real UID drives the computed NV index, so this can never touch a real
  one), covering both confirmed and cancelled uninstalls, and that the
  user's own unrelated dotfile content survives. The `.ps1` version tests
  the parts that are pure text/logic (NV index formula, the `$PROFILE`
  block-removal regex, that the elevation self-relaunch forwards `-Uninstall`
  to the elevated child) since the full flow needs Windows-only
  `WindowsPrincipal`/TBS access not available outside Windows.
- `test_help.sh` -- runs `tpm_setup.sh --help`/`-h` and (if `pwsh` is
  available) `tpm_setup.ps1 -Help`/`-h`, checking each exits 0 and mentions
  every other CLI flag the script currently supports, so adding a new flag
  without updating its usage text shows up as a test failure.
- `test_ssh_agent_key_check.sh` -- regression test for a real logic flaw:
  Phase 3's "no key file, generate one?" prompt didn't check whether
  ssh-agent already had an ED25519 identity loaded (e.g. a hardware
  security key, or one loaded from a different path) before offering to
  generate a brand-new one -- which can't ever reuse that identity anyway
  (agents never export the private key material of an already-loaded
  identity), so silently generating a second, unrelated key was a surprise
  waiting to happen. Confirms both scripts now print a clear note in that
  case, and don't when the agent has nothing loaded, using fake
  `ssh-add`/`ssh-keygen` stubs against the real extracted code.
- `test_status.sh` / `.ps1` -- tests `--status`/`-Status`, the read-only
  summary of installed/locked/unlocked state, effective UID, `~/.ssh/id_ed25519`
  presence, environment secret count, and ssh-agent/loaded-identity state
  (including public key material). Covers not-installed, fully-installed
  and unlocked, partially loaded named secrets with an agent reachable but
  empty, legacy single-key mode, and an older install that predates name
  tracking. The `.sh` version runs the real extracted block under `sh -e`
  (matching the real script's `set -e`) with fake `id`/`tpm2_nvreadpublic`/
  `ssh-add` stubs on an isolated `PATH`, specifically to catch the class of
  bug where capturing a failing command's exit code aborts the whole
  script under `set -e` before the assignment runs. The `.ps1` version runs
  the real extracted block in a background job (`Start-Job`/`Receive-Job`)
  with `Connect-Tpm2`/`Get-Tpm2NvPublic`/`ssh-add`/`Get-Service` mocked as
  literal text embedded in the same scriptblock -- the block ends with
  `exit 0`, which running it directly in-process would take the whole test
  runner down with it (confirmed by reproducing that exact failure during
  development), and a job isolates `exit` to its own child process.
- `lib/extract.sh` -- pulls a single named function's source out of
  `tpm_setup.sh` so these tests exercise the real shipped code rather than
  a reimplementation that could drift out of sync with it.
- `fixtures/sample.env` -- shared dotenv fixture used by both env-file
  parser tests.

## Notes for future changes

- tpm2-tools talking to a raw `/dev/tpm0` with no kernel/userspace resource
  manager has been observed (in this project's development sandbox) to hit
  transient TCTI I/O errors under back-to-back commands. `_tpm_read_secret`
  retries both its header-peek read and its payload read for this reason;
  `test_sentinel_header.sh` also retries its own setup/write calls so an
  unrelated environment hiccup doesn't fail the suite. If you see a
  genuinely new failure mode here (not a bare transient I/O error retried
  away), treat it as a real bug, not flakiness.
- Real FreeBSD-hardware validation isn't something these tests can do from
  a non-FreeBSD CI host -- the `0xFF` erase-fill scenarios are exercised by
  explicitly constructing that byte pattern rather than relying on a
  specific TPM's actual erase behavior, so they're meaningful regardless of
  what the host TPM naturally does.
