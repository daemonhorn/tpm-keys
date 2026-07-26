<#
Tests the PowerShell side of script-version tracking and -ReinstallScripts:
Invoke-TpmPhase5 (the extracted Phase 5 body, shared by the normal setup
flow and -ReinstallScripts) regenerates the $PROFILE integration block
idempotently -- re-running it must never duplicate the block or disturb the
user's own $PROFILE content -- and persists ApiAuthMode/StrategyChoice/
ScriptVersion via Write-TpmKeysState/Read-TpmKeysState so a later
-ReinstallScripts run can pick them back up without re-prompting. Runs the
real extracted functions from tpm_setup.ps1 (not a reimplementation) against
a fake $HOME/$PROFILE, with $Tpm2RawSource replaced by a short placeholder
string since only its persistence to disk (not its actual TPM behavior)
matters here.
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptText = Get-Content (Join-Path $repoRoot 'tpm_setup.ps1') -Raw

$script:TestsRun = 0
$script:TestsFailed = 0
function Test-Pass { param([string]$Name) $script:TestsRun++; Write-Host "PASS: $Name" }
function Test-Fail { param([string]$Name) $script:TestsRun++; $script:TestsFailed++; Write-Host "FAIL: $Name" }

# Invoke-TpmPhase5's body contains an embedded here-string with its own
# `function unlock_tpm { ... }` TEXT (written out verbatim to a generated
# file, never itself executed here) -- a plain "closing brace alone on its
# own line" regex (the technique tests/lib/extract.sh uses on the sh side)
# matches that embedded text's closing brace first and truncates the real
# function. Using PowerShell's own parser (AST) instead finds the true
# function boundaries regardless of what's inside any nested string/here-string.
function Get-TpmFunctionSource {
    param([string]$Text, [string]$Name)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $funcAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name }, $true)
    if ($null -eq $funcAst) { return $null }
    return $funcAst.Extent.Text
}

# Write-TpmLine is a trivial one-liner (`function Write-TpmLine { param(...) Write-Host $Text }`)
# -- defined directly rather than extracted, since nothing here tests its
# own behavior.
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
# Evaluate the extracted, real function definitions into this scope.
Invoke-Expression ($sources -join "`n")

$TMPDIR = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TMPDIR | Out-Null
try {
    $fakeHome = Join-Path $TMPDIR "home"
    New-Item -ItemType Directory -Path $fakeHome | Out-Null
    $prevHomeEnv = $env:HOME
    $env:HOME = $fakeHome

    $fakeProfile = Join-Path $TMPDIR "profile.ps1"
    Set-Content -Path $fakeProfile -Value "# user's own profile stuff`nSet-Alias ll Get-ChildItem`n"

    # Shadow the automatic $PROFILE/$HOME variables for the extracted
    # Invoke-TpmPhase5 to read -- it only reads these, never reassigns them.
    # $HOME is read-only (not just an ordinary variable), so Set-Variable
    # -Force is needed to override it in this process.
    $PROFILE = $fakeProfile
    Set-Variable -Name HOME -Value $fakeHome -Scope Global -Force
    $TpmSetupVersion = '9.9.9'
    $TpmHelperDir = Join-Path $fakeHome ".tpm_keys"
    if (-not (Test-Path $TpmHelperDir)) { New-Item -ItemType Directory -Path $TpmHelperDir | Out-Null }
    $TpmHelperFile = Join-Path $TpmHelperDir "Tpm2Raw.ps1"
    $Tpm2RawSource = "# fake raw TPM2 client placeholder`n"
    $apiAuthMode = 'agent'
    $strategyChoice = '2'
    $ApiNvIndex = [uint32]0x1502000
    $SshNvIndex = [uint32]0x1502001
    $sshKeyPath = Join-Path (Join-Path $fakeHome ".ssh") "id_ed25519"

    Invoke-TpmPhase5

    $profileContent1 = Get-Content -Path $fakeProfile -Raw
    if (([regex]::Matches($profileContent1, 'TPM Secure Environment Setup \(PowerShell\)')).Count -eq 1) {
        Test-Pass "first run adds exactly one PowerShell integration block to `$PROFILE"
    } else {
        Test-Fail "first run did not add exactly one integration block: $profileContent1"
    }
    if ($profileContent1 -match "user's own profile stuff" -and $profileContent1 -match 'Set-Alias ll') {
        Test-Pass "first run leaves the user's own `$PROFILE content untouched"
    } else {
        Test-Fail "first run damaged the user's own `$PROFILE content"
    }

    $state1 = Read-TpmKeysState
    if ($state1.ScriptVersion -eq '9.9.9' -and $state1.ApiAuthMode -eq 'agent' -and $state1.StrategyChoice -eq '2') {
        Test-Pass "persists ApiAuthMode/StrategyChoice/ScriptVersion after Phase 5 runs"
    } else {
        Test-Fail "did not persist state correctly: ApiAuthMode=$($state1.ApiAuthMode) StrategyChoice=$($state1.StrategyChoice) ScriptVersion=$($state1.ScriptVersion)"
    }

    # --- Re-run Invoke-TpmPhase5 again (simulating a later -ReinstallScripts
    # call against the same $PROFILE) -- must not duplicate the block. ---
    Invoke-TpmPhase5

    $profileContent2 = Get-Content -Path $fakeProfile -Raw
    $blockCount2 = ([regex]::Matches($profileContent2, 'TPM Secure Environment Setup \(PowerShell\)')).Count
    if ($blockCount2 -eq 1) {
        Test-Pass "re-running Phase 5 (as -ReinstallScripts would) does not duplicate the `$PROFILE block"
    } else {
        Test-Fail "re-running Phase 5 left $blockCount2 integration blocks in `$PROFILE instead of 1 -- duplicated on re-run"
    }
    if ($profileContent2 -match "user's own profile stuff" -and $profileContent2 -match 'Set-Alias ll') {
        Test-Pass "re-running Phase 5 still leaves the user's own `$PROFILE content untouched"
    } else {
        Test-Fail "re-running Phase 5 damaged the user's own `$PROFILE content"
    }

    # --- Edge case found on real hardware (dell-7550): a $PROFILE that
    # already contains a TPM block whose closing marker has a DIFFERENT
    # dash count than what this script version currently writes (observed
    # in the wild from a much older script version whose block predates
    # this repo's version tracking) must still be recognized and replaced
    # on the next Phase 5 run, not left in place with a fresh block
    # appended alongside it -- a literal-length-sensitive regex silently
    # fails to match and duplicates instead of replacing.
    $oldDashes = '-' * 45  # deliberately NOT the 46 this script currently writes
    $legacyProfile = Join-Path $TMPDIR "legacy_dashes_profile.ps1"
    $legacyProfileContent = @"
# user's own profile stuff
Set-Alias ll Get-ChildItem

# --- TPM Secure Environment Setup (PowerShell) ---
Get-Content 'C:\old\path\unlock_tpm.ps1' -Raw | Invoke-Expression
# $oldDashes
# SIG # Begin signature block
# fake-signature-data-not-real
# SIG # End signature block
"@
    Set-Content -Path $legacyProfile -Value $legacyProfileContent
    $PROFILE = $legacyProfile
    Invoke-TpmPhase5

    $legacyContent = Get-Content -Path $legacyProfile -Raw
    $legacyBlockCount = ([regex]::Matches($legacyContent, 'TPM Secure Environment Setup \(PowerShell\)')).Count
    if ($legacyBlockCount -eq 1) {
        Test-Pass "replaces an old-format block (different closing-marker dash count) instead of duplicating it"
    } else {
        Test-Fail "left $legacyBlockCount integration blocks after regenerating over an old-format block (dash-count mismatch) -- duplicated instead of replaced"
    }
    if ($legacyContent -match "user's own profile stuff" -and $legacyContent -match 'Set-Alias ll') {
        Test-Pass "regenerating over an old-format block still leaves the user's own `$PROFILE content untouched"
    } else {
        Test-Fail "regenerating over an old-format block damaged the user's own `$PROFILE content"
    }

    $env:HOME = $prevHomeEnv
} finally {
    Remove-Item -Recurse -Force $TMPDIR -ErrorAction SilentlyContinue
}


# --- The `if ($ReinstallScripts) { ... }` block itself: covers the legacy
# fallback (no tpm_keys_state.txt yet, since that file is brand new in this
# change -- every PS1 install made before this ships starts out this way)
# and the genuine "nothing to reinstall" error. Runs in a job (the block
# ends in `exit`, which would take this whole test process down if invoked
# directly -- same reasoning as tests/test_status.ps1), with Connect-Tpm2/
# Get-Tpm2NvPublic/Get-TpmUid/Read-Host mocked as literal text alongside the
# real extracted helpers, all one parse unit.
if ($scriptText -notmatch '(?s)(if \(\$ReinstallScripts\) \{.*?\n\}\n\n# Windows TBS enforces)') {
    Test-Fail "could not extract the -ReinstallScripts block from tpm_setup.ps1 -- did it move/change shape?"
} else {
    $reinstallBlock = $Matches[1] -replace '\n# Windows TBS enforces$', ''
    $realHelperSrc = ($sources -join "`n")

    $mockTemplate = @'
function Write-TpmLine { param([string]$Text) Write-Host $Text }
function Get-TpmUid { return 4242 }
function Read-Host { param($Prompt) return "__STRATEGYANSWER__" }
function Connect-Tpm2 { return [IntPtr]::Zero }
function Disconnect-Tpm2 { param($Context) }
function Get-Tpm2NvPublic {
    param($Context, [uint32]$NvIndex)
    if ($NvIndex % 2 -eq 0) { return @{ Exists = __APIINSTALLED__ } }
    return @{ Exists = __SSHINSTALLED__ }
}
'@

    function Invoke-ReinstallBlock {
        param([string]$FakeHome, [bool]$ApiInstalled, [bool]$SshInstalled, [string]$StrategyAnswer = "2")
        $mockScript = $mockTemplate.
            Replace('__APIINSTALLED__', $(if ($ApiInstalled) { '$true' } else { '$false' })).
            Replace('__SSHINSTALLED__', $(if ($SshInstalled) { '$true' } else { '$false' })).
            Replace('__STRATEGYANSWER__', $StrategyAnswer)
        $fullScript = "`$TpmSetupVersion = '9.9.9'`n`$PROFILE = Join-Path '$FakeHome' 'profile.ps1'`n" + $mockScript + "`n" + $realHelperSrc + "`n`$ReinstallScripts = `$true`n" + $reinstallBlock
        $prevHomeEnv = $env:HOME
        $env:HOME = $FakeHome
        try {
            $sb = [scriptblock]::Create($fullScript)
            $job = Start-Job -ScriptBlock $sb
            $job | Wait-Job | Out-Null
            $result = Receive-Job -Job $job *>&1 | Out-String
            Remove-Job -Job $job -Force
            $result
        } finally {
            $env:HOME = $prevHomeEnv
        }
    }

    $homeNoState = Join-Path $TMPDIR "reinstall_no_state"
    New-Item -ItemType Directory -Path $homeNoState | Out-Null
    $outNoInstall = Invoke-ReinstallBlock -FakeHome $homeNoState -ApiInstalled $false -SshInstalled $false
    if ($outNoInstall -match 'No existing installation found') {
        Test-Pass "-ReinstallScripts errors cleanly when there is truly nothing installed and no state file"
    } else {
        Test-Fail "did not error cleanly with nothing installed: $outNoInstall"
    }

    # The genuine legacy scenario this feature must support: an install from
    # before tpm_keys_state.txt existed -- secrets ARE sealed (confirmed via
    # the real TPM indices), but there is no state file to read
    # ApiAuthMode/StrategyChoice back from.
    $homeLegacy = Join-Path $TMPDIR "reinstall_legacy"
    New-Item -ItemType Directory -Path $homeLegacy | Out-Null
    $outLegacy = Invoke-ReinstallBlock -FakeHome $homeLegacy -ApiInstalled $true -SshInstalled $true -StrategyAnswer "2"
    if ($outLegacy -match 'No existing installation found') {
        Test-Fail "refused to reinstall a legacy install that has sealed secrets but no state file yet: $outLegacy"
    } else {
        Test-Pass "-ReinstallScripts proceeds for a legacy install with sealed secrets but no state file"
    }
    if ($outLegacy -match 'Unlock Strategy') {
        Test-Pass "asks for the unlock strategy once for a legacy install with no persisted choice"
    } else {
        Test-Fail "did not ask for the unlock strategy for a legacy install: $outLegacy"
    }
    if ($outLegacy -match 'Reinstall Complete') {
        Test-Pass "completes successfully for a legacy install once secrets are confirmed sealed"
    } else {
        Test-Fail "did not complete successfully for a legacy install: $outLegacy"
    }
    $legacyState = Get-Content -Path (Join-Path (Join-Path $homeLegacy ".tpm_keys") "tpm_keys_state.txt") -ErrorAction SilentlyContinue
    if ($legacyState -match 'ScriptVersion=9\.9\.9' -and $legacyState -match 'StrategyChoice=2') {
        Test-Pass "persists state going forward once a legacy install completes -ReinstallScripts"
    } else {
        Test-Fail "did not persist state after a legacy install's -ReinstallScripts run: $legacyState"
    }
}

Write-Host ""
Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
