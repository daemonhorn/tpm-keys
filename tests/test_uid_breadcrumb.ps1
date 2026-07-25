<#
Tests Get-TpmUid (extracted from tpm_setup.ps1), the shared helper behind
-Status, -Uninstall, and the main setup flow's UID prompt. Once a UID is
determined (typed or derived from the Windows session's own SID), it must
be remembered in a $HOME\.tpm_keys\uid.txt breadcrumb so later invocations
for the same Windows user reuse it without re-prompting -- and forgotten
again once that directory is gone (as -Uninstall leaves it after cleanup),
so a fresh UID is asked for next time. Pure logic, no TPM required.
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptText = Get-Content (Join-Path $repoRoot 'tpm_setup.ps1') -Raw
if ($scriptText -notmatch '(?s)function Get-TpmUid \{.*?\n\}\n') {
    throw "could not extract Get-TpmUid from tpm_setup.ps1 -- did it move/change shape?"
}
function Write-TpmLine { param([string]$Text) Write-Host $Text }
Invoke-Expression $Matches[0]

$script:TestsRun = 0
$script:TestsFailed = 0
function Test-Pass { param([string]$Name) $script:TestsRun++; Write-Host "PASS: $Name" }
function Test-Fail { param([string]$Name) $script:TestsRun++; $script:TestsFailed++; Write-Host "FAIL: $Name" }

$script:ReadHostCalls = 0
$script:ReadHostReturn = "4242"
function Read-Host { param($Prompt) $script:ReadHostCalls++; return $script:ReadHostReturn }

$TMPDIR = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TMPDIR | Out-Null
$prevHome = $HOME
Set-Variable -Name HOME -Value $TMPDIR -Scope Global -Force
try {
    $breadcrumbFile = Join-Path (Join-Path $TMPDIR ".tpm_keys") "uid.txt"

    # --- First call: no breadcrumb yet -- must prompt, and persist the result ---
    $script:ReadHostCalls = 0
    $script:ReadHostReturn = "4242"
    $uid1 = Get-TpmUid
    if ($uid1 -eq 4242) { Test-Pass "first call returns the typed UID" } else { Test-Fail "first call returned $uid1, expected 4242" }
    if ($script:ReadHostCalls -eq 1) { Test-Pass "first call prompts once (no breadcrumb yet)" } else { Test-Fail "first call made $($script:ReadHostCalls) Read-Host calls, expected 1" }
    if (Test-Path $breadcrumbFile) {
        Test-Pass "first call writes the UID breadcrumb file"
        $saved = (Get-Content -Path $breadcrumbFile -Raw).Trim()
        if ($saved -eq '4242') { Test-Pass "breadcrumb file contains the determined UID" } else { Test-Fail "breadcrumb file contains '$saved', expected '4242'" }
    } else {
        Test-Fail "first call did not write a breadcrumb file at $breadcrumbFile"
    }

    # --- Second call: breadcrumb exists -- must reuse it, no re-prompt ---
    $script:ReadHostCalls = 0
    $script:ReadHostReturn = "9999"  # if this gets used, the breadcrumb was ignored
    $uid2 = Get-TpmUid
    if ($uid2 -eq 4242) { Test-Pass "second call reuses the recorded UID" } else { Test-Fail "second call returned $uid2, expected the recorded 4242" }
    if ($script:ReadHostCalls -eq 0) { Test-Pass "second call does not re-prompt" } else { Test-Fail "second call made $($script:ReadHostCalls) Read-Host calls, expected 0" }

    # --- After the breadcrumb directory is removed (as -Uninstall leaves
    # it), a fresh UID must be asked for again rather than reusing a stale
    # value from an account that no longer has secrets sealed. ---
    Remove-Item -Recurse -Force (Join-Path $TMPDIR ".tpm_keys")
    $script:ReadHostCalls = 0
    $script:ReadHostReturn = "5555"
    $uid3 = Get-TpmUid
    if ($uid3 -eq 5555) { Test-Pass "call after breadcrumb removal returns the newly typed UID" } else { Test-Fail "call after removal returned $uid3, expected 5555" }
    if ($script:ReadHostCalls -eq 1) { Test-Pass "call after breadcrumb removal re-prompts" } else { Test-Fail "call after removal made $($script:ReadHostCalls) Read-Host calls, expected 1" }
} finally {
    Set-Variable -Name HOME -Value $prevHome -Scope Global -Force
    Remove-Item -Recurse -Force $TMPDIR -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
