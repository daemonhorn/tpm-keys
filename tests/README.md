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
  without updating its usage text shows up as a test failure. Also runs
  each script with an unknown flag and with `--env-file`/`-EnvFile` given
  no value, checking each exits non-zero and *also* prints that same usage
  text -- a CLI syntax error should point at the fix, not just say "no".
  On the PowerShell side this is why `tpm_setup.ps1` parses `$args` by hand
  instead of using a formal `param()` block: PowerShell's own parameter
  binder rejects an unrecognized or malformed flag before a single line of
  the script runs, which would make showing custom usage text on a typo
  impossible.
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
- `test_ssh_agent_desktop_discovery.sh` -- regression test for a real bug
  found debugging a live Debian 13/GNOME desktop: a plain SSH login does
  not inherit the graphical session's `SSH_AUTH_SOCK` the way a new local
  terminal spawned from the desktop does, even though the desktop
  session's own agent (GNOME Keyring/gcr-ssh-agent/KDE Wallet) already has
  the SSH identity loaded from an earlier `unlock_tpm` run -- so every
  such SSH session re-prompted for the Master PIN forever instead of
  reusing what was already unsealed. `_tpm_ensure_ssh_agent` now tries
  `systemctl --user show-environment` first when `$SSH_AUTH_SOCK` is
  completely unset, confirmed live against a real GNOME Keyring agent
  (raw `ssh-add -`-loaded keys persist there across sessions, and
  `ssh-keygen -Y sign` works once `SSH_AUTH_SOCK` points at it correctly)
  before falling back to spawning a private agent. Covers: adopting a
  real discovered socket, rejecting a discovered path that is not a real
  socket, falling back cleanly when nothing is discoverable (FreeBSD/
  headless), and never touching an already-set `SSH_AUTH_SOCK`. tcsh has
  the identical fix in the generated `.tpm_unlock.csh`/`.cshrc` (verified
  directly against real tcsh) -- along the way this also found and fixed
  a real, independent bug in the *existing* tcsh `kill -0` liveness check:
  `sh -c 'kill -0 "$1"' -- "$PID"` silently drops the positional argument
  under tcsh (confirmed directly, even with a genuinely live PID), always
  reporting the agent as dead; both now pass the value through an
  exported env var instead.
- `test_tpm_session_exhaustion.sh` -- regression test for a real incident:
  a raw hardware TPM (no resource manager) has only a handful of session
  slots, and back-to-back `tpm2_nvread` calls (this project's own
  extensive testing, or just several unlock attempts in a row) can
  exhaust them (`TPM_RC_SESSION_MEMORY`, `0x903`), which surfaces as
  "Invalid handle or authorization" -- indistinguishable from a wrong PIN
  by exit status alone, and simply retrying the identical call (the
  pre-existing retry loop) does nothing since nothing frees the exhausted
  slots between attempts. `_tpm_read_secret` now detects this specific
  error text, flushes all transient/session/loaded contexts, and tells
  the user plainly what happened before retrying. Covers: recovering
  after one exhaustion failure, not flushing unnecessarily on a clean
  read, failing cleanly (not via a `set -e` abort) when exhaustion never
  clears, and not mistaking a genuinely wrong PIN's unrelated error text
  for session exhaustion. Uses a fake `tpm2_nvread`/`tpm2_flushcontext` on
  an isolated `PATH` so it never touches a real TPM.
- `test_agent_pin_no_wrong_attempt.sh` -- regression test for a real,
  separate bug tripped over debugging the incident above: when
  `API_AUTH_MODE=agent`, the API key's NV index is sealed with a PIN
  *derived* from an SSH-agent signature, never the raw Master PIN. If the
  SSH key fails to load for any reason, `_tpm_derive_api_pin` has no
  agent identity to sign with, and `unlock_tpm` used to silently fall
  back to trying the raw Master PIN against that index anyway -- a
  guaranteed-wrong TPM authorization attempt that only increments the
  dictionary-attack lockout counter for nothing (watched this happen
  live: the counter climbed from 1 to 7 failed attempts purely from
  repeated `unlock_tpm` invocations while debugging). `unlock_tpm` now
  skips the API key entirely, with a clear message, rather than ever
  submit a PIN it already knows is wrong. Covers: skipping and explaining
  when derivation fails, using the derived PIN (not the Master PIN) when
  it succeeds, and confirming Master-PIN mode is unaffected (no
  regression). Exercises the real extracted `unlock_tpm` with its
  dependencies (`_tpm_needs_unlock`, `_tpm_derive_api_pin`,
  `_tpm_read_secret`, `_tpm_load_secret`, `ssh-add`) mocked, so it never
  touches a real TPM or agent.
- `test_status.sh` / `.ps1` -- tests `--status`/`-Status`, the read-only
  summary of installed/locked/unlocked state, effective UID, `~/.ssh/id_ed25519`
  presence, environment secret count, and ssh-agent/loaded-identity state
  (including public key material). Covers not-installed, fully-installed
  and unlocked, partially loaded named secrets with an agent reachable but
  empty, legacy single-key mode, an older install that predates name
  tracking, and -- since "no secrets sealed" and "couldn't even check" are
  different problems that used to be reported identically -- a case where
  the TPM itself can't be reached/queried, which must be reported as
  unknown rather than misread as "not installed". The `.sh` version runs
  the real extracted block under `sh -e` (matching the real script's
  `set -e`) with fake `id`/`tpm2_nvreadpublic`/`tpm2_getcap`/`ssh-add`
  stubs on an isolated `PATH`, specifically to catch the class of bug
  where capturing a failing command's exit code aborts the whole script
  under `set -e` before the assignment runs. The `.ps1` version runs the
  real extracted block in a background job (`Start-Job`/`Receive-Job`)
  with `Connect-Tpm2`/`Get-Tpm2NvPublic`/`Get-TpmUid`/`ssh-add`/
  `Get-Service` mocked as literal text embedded in the same scriptblock --
  the block ends with `exit 0`, which running it directly in-process would
  take the whole test runner down with it (confirmed by reproducing that
  exact failure during development), and a job isolates `exit` to its own
  child process.
- `test_reinstall_scripts.sh` -- tests script-version tracking and
  `--reinstall-scripts`: `TPM_SETUP_VERSION` is persisted into
  `~/.tpm_keys_state` as `SCRIPT_VERSION` at the end of every successful run,
  and `--status` reports it, staying silent when nothing is installed,
  reporting "up to date" when it matches, and hinting at the exact
  `--reinstall-scripts` command to run when it's stale or missing entirely
  (an install that predates this feature). `--reinstall-scripts` itself
  re-runs only Phase 5 (shell/profile integration) -- errors cleanly with no
  existing install, needs zero prompts when `STRATEGY_CHOICE` was already
  persisted by a prior run (asking once and then persisting it for an older
  install that predates that field), regenerates the shell integration
  blocks without disturbing the user's own dotfile content, and prints a
  distinct "Reinstall Complete" message instead of the fresh-install
  SSH-key-backup reminder. Runs the real `tpm_setup.sh` end-to-end; the
  reinstall cases deliberately have no `tpm2_nv*` stub on `PATH` at all, so a
  stray TPM-seeding call would fail loudly ("command not found") instead of
  silently succeeding -- proving the flag never touches sealed secrets.
- `test_reinstall_scripts.ps1` -- the PowerShell-side counterpart:
  `Invoke-TpmPhase5` (the extracted Phase 5 body shared by normal setup and
  `-ReinstallScripts`) regenerates the `$PROFILE` integration block, and
  running it twice in a row -- simulating a later `-ReinstallScripts` call --
  must never duplicate that block or disturb the user's own `$PROFILE`
  content. Also confirms `ApiAuthMode`/`StrategyChoice`/`ScriptVersion` are
  persisted to `tpm_keys_state.txt` (the PowerShell equivalent of
  `~/.tpm_keys_state`) after Phase 5 runs. Extracts the real function
  definitions (`Get-TpmKeysStateFile`, `Read-TpmKeysState`,
  `Write-TpmKeysState`, `Invoke-TpmPhase5`) using PowerShell's own AST parser
  rather than a text/regex match, since `Invoke-TpmPhase5`'s body contains an
  embedded here-string with its own `function unlock_tpm { ... }` TEXT
  (written to a generated file, never executed here) whose closing brace
  would fool a naive "brace alone on its own line" extractor into truncating
  the real function early.
- `test_uid_breadcrumb.ps1` -- tests `Get-TpmUid` (PowerShell-only), the
  helper shared by `-Status`, `-Uninstall`, and the main setup flow's
  cross-OS UID prompt: once a UID is determined it's recorded in
  `$HOME\.tpm_keys\uid.txt` so later invocations for the same Windows user
  reuse it without re-prompting. Covers the first-ever call (prompts,
  persists the result), a second call (reuses the breadcrumb, does not
  re-prompt), and a call after the breadcrumb directory is removed (as
  `-Uninstall` leaves it) correctly asking again rather than reusing a
  stale value.
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
