<#
Tests the generated `unlock_tpm` function's "is the SSH key already loaded"
detection: found on real hardware (dell-7550) that it matched on key TYPE
only ("any ED25519 identity in the agent"), not on the SPECIFIC key this
install manages -- so a stale, unrelated ED25519 identity already loaded in
ssh-agent (e.g. left over from before the managed key was regenerated) was
mistaken for "already loaded," and the actual TPM-sealed key never got
loaded at all. Runs the real generated function (via Invoke-TpmPhase5,
extracted the same way tests/test_reinstall_scripts.ps1 does), with
Connect-Tpm2/Read-Tpm2Nv/Set-TpmSecretFromRaw/Get-Service/ssh-add mocked.
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptText = Get-Content (Join-Path $repoRoot 'tpm_setup.ps1') -Raw

$script:TestsRun = 0
$script:TestsFailed = 0
function Test-Pass { param([string]$Name) $script:TestsRun++; Write-Host "PASS: $Name" }
function Test-Fail { param([string]$Name) $script:TestsRun++; $script:TestsFailed++; Write-Host "FAIL: $Name" }

function Get-TpmFunctionSource {
    param([string]$Text, [string]$Name)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $funcAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name }, $true)
    if ($null -eq $funcAst) { return $null }
    return $funcAst.Extent.Text
}

function Write-TpmLine { param([string]$Text) Write-Host $Text }

$funcNames = @('Get-TpmKeysStateFile', 'Read-TpmKeysState', 'Write-TpmKeysState', 'Invoke-TpmPhase5')
$sources = @()
$missing = @()
foreach ($name in $funcNames) {
    $src = Get-TpmFunctionSource -Text $scriptText -Name $name
    if ($null -eq $src) { $missing += $name } else { $sources += $src }
}
if ($missing.Count -gt 0) {
    Test-Fail "could not extract from tpm_setup.ps1 (did it move/change shape?): $($missing -join ', ')"
    Write-Host ""
    Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
    exit 1
}
Invoke-Expression ($sources -join "`n")

$TMPDIR = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TMPDIR | Out-Null
try {
    $fakeHome = Join-Path $TMPDIR "home"
    New-Item -ItemType Directory -Path $fakeHome | Out-Null
    $prevHomeEnv = $env:HOME
    $env:HOME = $fakeHome

    $fakeProfile = Join-Path $TMPDIR "profile.ps1"
    Set-Content -Path $fakeProfile -Value "# user's own profile stuff`n"

    $PROFILE = $fakeProfile
    Set-Variable -Name HOME -Value $fakeHome -Scope Global -Force
    $TpmSetupVersion = '9.9.9'
    $TpmHelperDir = Join-Path $fakeHome ".tpm_keys"
    if (-not (Test-Path $TpmHelperDir)) { New-Item -ItemType Directory -Path $TpmHelperDir | Out-Null }
    $TpmHelperFile = Join-Path $TpmHelperDir "Tpm2Raw.ps1"
    $Tpm2RawSource = "# fake raw TPM2 client placeholder`n"
    $apiAuthMode = 'master'
    $strategyChoice = '2'  # manual: generated unlock_tpm.ps1 won't auto-invoke itself when loaded
    $ApiNvIndex = [uint32]0x1502000
    $SshNvIndex = [uint32]0x1502001
    $sshDir = Join-Path $fakeHome ".ssh"
    New-Item -ItemType Directory -Path $sshDir | Out-Null
    $sshKeyPath = Join-Path $sshDir "id_ed25519"
    Set-Content -Path $sshKeyPath -Value "fake-private-key-material`n"
    $managedPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOasy7e3rMdyzwMR1QOAnxrkbXEyyvSEbUa81eEY8yi0 managed-key"
    Set-Content -Path "$sshKeyPath.pub" -Value $managedPub

    Invoke-TpmPhase5

    $unlockScriptPath = Join-Path $TpmHelperDir "unlock_tpm.ps1"
    if (-not (Test-Path $unlockScriptPath)) {
        Test-Fail "Invoke-TpmPhase5 did not generate $unlockScriptPath"
        Write-Host ""
        Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
        exit 1
    }
    $unlockScriptText = Get-Content -Path $unlockScriptPath -Raw
    $unlockFuncSrc = Get-TpmFunctionSource -Text $unlockScriptText -Name 'unlock_tpm'
    if ($null -eq $unlockFuncSrc) {
        Test-Fail "could not extract the generated unlock_tpm function -- did its shape change?"
        Write-Host ""
        Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
        exit 1
    }

    # --- Mocks for everything unlock_tpm depends on ---
    function Get-Service { param([string]$Name) return [pscustomobject]@{ Status = 'Running' } }
    function Connect-Tpm2 { return [IntPtr]::Zero }
    function Disconnect-Tpm2 { param($Context) }
    function Set-TpmSecretFromRaw { param([string]$Raw) $script:ApiLoadedCount++ }
    function Read-Tpm2Nv {
        param($Context, [uint32]$NvIndex, [string]$Pin)
        return [System.Text.Encoding]::UTF8.GetBytes("fake-secret-value")
    }
    function icacls { }
    function Read-Host { param($Prompt) return (ConvertTo-SecureString -String 'fakepin' -AsPlainText -Force) }

    $script:SshAddCalls = New-Object System.Collections.ArrayList
    $script:MockLoadedPubs = ''
    function ssh-add {
        [void]$script:SshAddCalls.Add(($args -join ' '))
        if ($args -contains '-L') { $global:LASTEXITCODE = 0; return $script:MockLoadedPubs }
        if ($args -contains '-l') { $global:LASTEXITCODE = 0; return $(if ($script:MockLoadedPubs) { 'some-fingerprint ED25519' } else { '' }) }
        $global:LASTEXITCODE = 0
        return ''
    }

    Invoke-Expression $unlockFuncSrc

    # --- Scenario A: a STALE, unrelated ED25519 identity is already loaded
    # (different pubkey content than the managed key) -- must still attempt
    # to load the managed key, not conclude "already loaded". ---
    $script:SshAddCalls.Clear()
    $script:ApiLoadedCount = 0
    $script:MockLoadedPubs = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentUnrelatedStaleKeyContent0000 other-key"
    Remove-Item Env:\SECURE_API_KEY -ErrorAction SilentlyContinue

    unlock_tpm

    $attemptedLoad = $script:SshAddCalls | Where-Object { $_ -notmatch '^-[lL]$' }
    if ($attemptedLoad.Count -gt 0) {
        Test-Pass "attempts to load the managed key even though a different, stale ED25519 identity is already in the agent"
    } else {
        Test-Fail "concluded the managed SSH key was already loaded just because SOME ED25519 identity was present (stale/unrelated key mistaken for the managed one); ssh-add calls: $($script:SshAddCalls -join ' | ')"
    }

    # --- Scenario B: the managed key's own pubkey IS already loaded, and
    # the API key is already in the environment -- must recognize both as
    # loaded and do no redundant work (no PIN prompt, no extra ssh-add). ---
    $script:SshAddCalls.Clear()
    $script:ApiLoadedCount = 0
    $script:MockLoadedPubs = $managedPub
    $env:SECURE_API_KEY = 'already-loaded-placeholder'

    $out = unlock_tpm 6>&1 | Out-String

    $attemptedLoad2 = $script:SshAddCalls | Where-Object { $_ -notmatch '^-[lL]$' }
    if ($attemptedLoad2.Count -eq 0 -and $script:ApiLoadedCount -eq 0) {
        Test-Pass "recognizes the managed key is already loaded and does no redundant work"
    } else {
        Test-Fail "did redundant work even though the managed key and API secret were both already loaded: ssh-add calls: $($script:SshAddCalls -join ' | '), API reloads: $script:ApiLoadedCount"
    }

    Remove-Item Env:\SECURE_API_KEY -ErrorAction SilentlyContinue
    $env:HOME = $prevHomeEnv
} finally {
    Remove-Item -Recurse -Force $TMPDIR -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
