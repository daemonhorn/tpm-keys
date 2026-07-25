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
