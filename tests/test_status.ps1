<#
Tests tpm_setup.ps1's -Status block against the real extracted code, with
Connect-Tpm2/Get-Tpm2NvPublic/Disconnect-Tpm2/ssh-add/Get-Service stubbed
out (no real TBS/agent needed) and Read-Host returning a fixed UID so the
WindowsIdentity-based fallback (unavailable outside Windows) is never
exercised. Also confirms -Status never installs/modifies anything and
mirrors the tests/test_status.sh scenarios for parity between the two
scripts.
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptText = Get-Content (Join-Path $repoRoot 'tpm_setup.ps1') -Raw

if ($scriptText -notmatch '(?s)(if \(\$Status\) \{.*?\n\}\n\n# Windows TBS enforces)') {
    Write-Host "FAIL: could not extract the -Status block from tpm_setup.ps1 -- did it move/change shape?"
    exit 1
}
$block = $Matches[1] -replace '\n# Windows TBS enforces$', ''

$script:TestsRun = 0
$script:TestsFailed = 0
function Test-Pass { param([string]$Name) $script:TestsRun++; Write-Host "PASS: $Name" }
function Test-Fail { param([string]$Name) $script:TestsRun++; $script:TestsFailed++; Write-Host "FAIL: $Name" }

# Mock function definitions as a source-text TEMPLATE (single-quoted
# here-string, so $ is never interpolated) rather than real functions
# defined in Invoke-StatusBlock's own scope: a [scriptblock]::Create()'d
# block invoked via `&` resolves command NAMES dynamically, and that
# lookup proved unreliable across repeated Create() calls in testing
# (Write-TpmLine/ssh-add intermittently came back "not recognized" even
# though the exact same nested-function setup worked in isolation).
# Embedding the mocks as literal text in the SAME scriptblock as the real
# block sidesteps command-name resolution entirely -- everything is one
# parse unit. __TOKEN__ placeholders carry the few values that vary
# per test case; they're plain string substitutions, not regex, so no
# escaping concerns there.
$MockTemplate = @'
function Write-TpmLine { param([string]$Text) Write-Host $Text }
function Read-Host { param($Prompt) return "__FAKEUID__" }
function Get-TpmUid { return __FAKEUID__ }
function Connect-Tpm2 {
    if (__CONNECTTHROWS__) { throw "simulated TBS session failure" }
    return [IntPtr]::Zero
}
function Disconnect-Tpm2 { param($Context) }
function Get-Tpm2NvPublic {
    param($Context, [uint32]$NvIndex)
    # Even index = API (per 22020096 + uid*2), odd = SSH -- matches how
    # the real block computes $ApiNvIndex/$SshNvIndex from $uid.
    if ($NvIndex % 2 -eq 0) { return @{ Exists = __APIINSTALLED__ } }
    return @{ Exists = __SSHINSTALLED__ }
}
function ssh-add {
    # No param() block: PowerShell parameter binding is case-insensitive,
    # so a declared switch/string param can't tell -l from -L apart (both
    # bind to the same name). $args preserves the exact text as typed.
    $Flag = $args[0]
    # Local -Continue override: a real ssh-add writes to native stderr on
    # failure, which 2>$null at the call site suppresses cleanly. Write-Error
    # under the ambient $ErrorActionPreference = 'Stop' (inherited from the
    # real script) would instead raise a terminating exception that no
    # redirection operator can suppress -- and [Console]::Error.WriteLine
    # writes to the real OS stderr fd, bypassing PowerShell's own stream
    # plumbing (and *>&1) entirely instead of landing in the error stream.
    # Scoping the override to just this function keeps it from leaking out.
    $ErrorActionPreference = 'Continue'
    switch (__SSHADDEXIT__) {
        0 {
            if ($Flag -ceq '-L') { "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfakepublickeymaterial fake@test" }
            else { "256 SHA256:abcdef fake@test (ED25519)" }
        }
        1 { Write-Error "The agent has no identities."; $global:LASTEXITCODE = 1 }
        default { Write-Error "Could not open a connection to your authentication agent."; $global:LASTEXITCODE = 2 }
    }
}
function Get-Service {
    param($Name)
    if (-not (__AGENTRUNNING__)) { return $null }
    return [pscustomobject]@{ Status = 'Running' }
}
$Status = $true
'@

function Invoke-StatusBlock {
    param(
        [string]$FakeHome,
        [string]$FakeUid = "1234",
        [bool]$ApiInstalled = $false,
        [bool]$SshInstalled = $false,
        [int]$SshAddExit = 2,
        [bool]$AgentServiceRunning = $false,
        [bool]$ConnectThrows = $false
    )
    $mockScript = $MockTemplate.
        Replace('__FAKEUID__', $FakeUid).
        Replace('__APIINSTALLED__', $(if ($ApiInstalled) { '$true' } else { '$false' })).
        Replace('__SSHINSTALLED__', $(if ($SshInstalled) { '$true' } else { '$false' })).
        Replace('__SSHADDEXIT__', "$SshAddExit").
        Replace('__AGENTRUNNING__', $(if ($AgentServiceRunning) { '$true' } else { '$false' })).
        Replace('__CONNECTTHROWS__', $(if ($ConnectThrows) { '$true' } else { '$false' }))

    # The real block ends with `exit 0`. Invoking it directly (`& $sb`) in
    # this process really does terminate the WHOLE test run the instant it
    # hits that exit -- confirmed by reproducing it in isolation: even a
    # Write-Host BEFORE the exit never made it out, because Out-String (and
    # any other output collection) only flushes on normal pipeline
    # completion, which the abrupt process teardown preempts. Running the
    # scriptblock in a job isolates `exit` to that job's own child process,
    # so it can't take the test runner down with it, and Receive-Job still
    # returns everything the job streamed before exiting.
    #
    # $HOME (PowerShell's automatic variable, distinct from $env:HOME) is
    # set once per runspace at startup from the process environment, so it
    # can't be poked from here after the fact -- set $env:HOME instead
    # before starting the job so the child process's own $HOME picks it up.
    $prevHomeEnv = $env:HOME
    $env:HOME = $FakeHome
    try {
        $sb = [scriptblock]::Create($mockScript + "`n" + $block)
        $job = Start-Job -ScriptBlock $sb
        $job | Wait-Job | Out-Null
        $result = Receive-Job -Job $job *>&1 | Out-String
        Remove-Job -Job $job -Force
        $result
    } finally {
        $env:HOME = $prevHomeEnv
    }
}

$TMPDIR = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TMPDIR | Out-Null
try {
    # --- Case 1: not installed, no SSH key file, agent unreachable ---
    $home1 = Join-Path $TMPDIR "home1"
    New-Item -ItemType Directory -Path $home1 | Out-Null
    $out = Invoke-StatusBlock -FakeHome $home1 -ApiInstalled $false -SshInstalled $false -SshAddExit 2 -AgentServiceRunning $false
    if ($out -match 'not installed' -and $out -match 'SSH key file .*: missing' -and $out -match 'ssh-agent: not (installed|running)') {
        Test-Pass "not-installed / no key file / agent unavailable case reports correctly"
    } else {
        Test-Fail "not-installed case did not report as expected"
    }

    # --- Case 2: installed, SSH key file present, agent running with ED25519 key, named secrets fully loaded ---
    $home2 = Join-Path $TMPDIR "home2"
    New-Item -ItemType Directory -Path (Join-Path $home2 ".ssh") -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $home2 ".ssh\id_ed25519") | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $home2 ".tpm_keys") -Force | Out-Null
    Set-Content -Path (Join-Path $home2 ".tpm_keys\secret_names.txt") -Value "OPENAI_KEY AWS_SECRET_ACCESS_KEY" -NoNewline
    $env:OPENAI_KEY = "sk-test"
    $env:AWS_SECRET_ACCESS_KEY = "secretval"
    try {
        $out = Invoke-StatusBlock -FakeHome $home2 -ApiInstalled $true -SshInstalled $true -SshAddExit 0 -AgentServiceRunning $true
        $ok = $true
        if ($out -notmatch 'TPM secrets: installed') { Test-Fail "did not report installed"; $ok = $false }
        if ($out -notmatch 'SSH key file .*: present') { Test-Fail "did not report SSH key file present"; $ok = $false }
        if ($out -notmatch 'SSH key: unlocked') { Test-Fail "did not report SSH key unlocked"; $ok = $false }
        if ($out -notmatch [regex]::Escape('API secret(s): unlocked (2/2 loaded: OPENAI_KEY AWS_SECRET_ACCESS_KEY)')) { Test-Fail "did not report both named secrets loaded"; $ok = $false }
        if ($out -notmatch 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfakepublickeymaterial') { Test-Fail "did not print the loaded identity's public key material"; $ok = $false }
        if ($ok) { Test-Pass "fully-installed / unlocked / named-secrets case reports correctly, including pubkey material" }
    } finally {
        Remove-Item Env:\OPENAI_KEY, Env:\AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue
    }

    # --- Case 3: partially loaded named secrets, agent reachable but empty ---
    $home3 = Join-Path $TMPDIR "home3"
    New-Item -ItemType Directory -Path (Join-Path $home3 ".tpm_keys") -Force | Out-Null
    Set-Content -Path (Join-Path $home3 ".tpm_keys\secret_names.txt") -Value "OPENAI_KEY AWS_SECRET_ACCESS_KEY" -NoNewline
    $env:OPENAI_KEY = "sk-test"
    try {
        $out = Invoke-StatusBlock -FakeHome $home3 -ApiInstalled $true -SshInstalled $true -SshAddExit 1 -AgentServiceRunning $true
        if ($out -match [regex]::Escape('API secret(s): partially unlocked (1/2 loaded: OPENAI_KEY)')) {
            Test-Pass "partially-loaded named secrets reported correctly"
        } else {
            Test-Fail "did not report partial load correctly: $out"
        }
        if ($out -match 'Loaded identities: none') {
            Test-Pass "agent-reachable-but-empty reports 'none' instead of a stray message"
        } else {
            Test-Fail "did not report empty agent identities cleanly: $out"
        }
    } finally {
        Remove-Item Env:\OPENAI_KEY -ErrorAction SilentlyContinue
    }

    # --- Case 4: legacy single-key mode (empty secret_names.txt) ---
    $home4 = Join-Path $TMPDIR "home4"
    New-Item -ItemType Directory -Path (Join-Path $home4 ".tpm_keys") -Force | Out-Null
    Set-Content -Path (Join-Path $home4 ".tpm_keys\secret_names.txt") -Value "" -NoNewline
    $env:SECURE_API_KEY = "sk-legacy"
    try {
        $out = Invoke-StatusBlock -FakeHome $home4 -ApiInstalled $true -SshInstalled $true -SshAddExit 2 -AgentServiceRunning $false
        if ($out -match [regex]::Escape('API secret(s): unlocked (1/1 loaded: SECURE_API_KEY)')) {
            Test-Pass "legacy single-key mode reported correctly"
        } else {
            Test-Fail "did not report legacy secret correctly: $out"
        }
    } finally {
        Remove-Item Env:\SECURE_API_KEY -ErrorAction SilentlyContinue
    }

    # --- Case 5: older install predating name tracking (no secret_names.txt) ---
    $home5 = Join-Path $TMPDIR "home5"
    New-Item -ItemType Directory -Path $home5 | Out-Null
    $out = Invoke-StatusBlock -FakeHome $home5 -ApiInstalled $true -SshInstalled $true -SshAddExit 2 -AgentServiceRunning $false
    if ($out -match 'API secret\(s\): unknown \(older install predates name tracking') {
        Test-Pass "untracked old install reports honestly instead of guessing"
    } else {
        Test-Fail "did not handle untracked old install correctly: $out"
    }

    # --- Case 6: TPM query fails (e.g. a transient TBS hiccup) -- must not
    # be misreported as "not installed" (no secrets sealed yet). ---
    $home6 = Join-Path $TMPDIR "home6"
    New-Item -ItemType Directory -Path $home6 | Out-Null
    $out = Invoke-StatusBlock -FakeHome $home6 -ConnectThrows $true
    if ($out -match [regex]::Escape('TPM secrets: unknown (could not query the TPM')) {
        Test-Pass "TPM query failure reported distinctly from 'not installed'"
    } else {
        Test-Fail "did not distinguish a TPM query failure from 'not installed': $out"
    }
    if ($out -match 'TPM secrets: not installed') {
        Test-Fail "wrongly reported 'not installed' when the TPM query itself failed"
    } else {
        Test-Pass "did not conflate a TPM query failure with 'not installed'"
    }
} finally {
    Remove-Item -Recurse -Force $TMPDIR -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
