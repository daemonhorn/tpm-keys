<#
Tests the mechanical pieces of tpm_setup.ps1's -Uninstall block: the NV
index formula matches what Phase 2 uses at seed time, and the $PROFILE
block-removal regex correctly strips the TPM block while leaving the
user's own profile content untouched (including being idempotent on
already-clean content). The full -Uninstall flow can't run end-to-end
here since it requires WindowsPrincipal/WindowsIdentity (elevation check)
and real TBS access, neither available outside Windows -- this exercises
the parts that are pure text/logic and so are actually testable, by
extracting them from the real file rather than reimplementing them.
#>

$ErrorActionPreference = 'Stop'
$scriptText = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'tpm_setup.ps1') -Raw

$script:TestsRun = 0
$script:TestsFailed = 0
function Test-Pass { param([string]$Name) $script:TestsRun++; Write-Host "PASS: $Name" }
function Test-Fail { param([string]$Name) $script:TestsRun++; $script:TestsFailed++; Write-Host "FAIL: $Name" }

if ($scriptText -match '(?s)if \(\$Uninstall\) \{(.*?)\n\}\n\n# 2\. ssh-agent service') {
    $uninstallBlock = $Matches[1]
    if ($uninstallBlock -match '\$ApiNvIndex = \[uint32\]\(22020096 \+ \$uid \* 2\)' -and
        $uninstallBlock -match '\$SshNvIndex = \[uint32\]\(22020096 \+ \$uid \* 2 \+ 1\)') {
        Test-Pass "Uninstall block's NV index formula matches the seed-time formula"
    } else {
        Test-Fail "Uninstall block's NV index formula does not match Phase 2's"
    }
    if ($uninstallBlock -match 'Remove-Tpm2NvIndex -Context \$ctx -NvIndex \$ApiNvIndex' -and
        $uninstallBlock -match 'Remove-Tpm2NvIndex -Context \$ctx -NvIndex \$SshNvIndex') {
        Test-Pass "Uninstall block removes both the API and SSH NV indices"
    } else {
        Test-Fail "Uninstall block is missing a Remove-Tpm2NvIndex call"
    }
} else {
    Test-Fail "could not extract the Uninstall block from tpm_setup.ps1 -- did it move/change shape?"
}

if ($scriptText -match "(?m)^\`$blockPattern = '(.+)'$") {
    $blockPattern = $Matches[1]
    $fakeProfile = @"
# user's own stuff
Set-Alias ll Get-ChildItem

# --- TPM Secure Environment Setup (PowerShell) ---
function unlock_tpm { Write-Host "unlock" }
# ----------------------------------------------

# more user stuff
`$env:FOO = "bar"
"@
    $stripped = [regex]::Replace($fakeProfile, $blockPattern, '')
    if ($stripped -notmatch 'TPM Secure Environment Setup') {
        Test-Pass "TPM block removed from `$PROFILE-like content"
    } else {
        Test-Fail "TPM block was not removed from `$PROFILE-like content"
    }
    if ($stripped -match "user's own stuff" -and $stripped -match 'more user stuff' -and $stripped -match 'Set-Alias ll') {
        Test-Pass "user's own `$PROFILE content survives"
    } else {
        Test-Fail "user's own `$PROFILE content was damaged"
    }
    $strippedTwice = [regex]::Replace($stripped, $blockPattern, '')
    if ($strippedTwice -eq $stripped) {
        Test-Pass "re-applying the strip is idempotent"
    } else {
        Test-Fail "re-applying the strip changed already-clean content"
    }
} else {
    Test-Fail "could not extract blockPattern regex from tpm_setup.ps1"
}

# The elevation self-relaunch must forward -Uninstall (and any other bound
# parameter) to the elevated child, or it would silently run a plain
# interactive setup instead of uninstalling.
if ($scriptText -match 'foreach \(\$paramName in \$PSBoundParameters\.Keys\)' -and
    $scriptText -match '@forwardArgs') {
    Test-Pass "elevation relaunch forwards bound parameters (e.g. -Uninstall) to the elevated child"
} else {
    Test-Fail "elevation relaunch does not forward parameters -- -Uninstall would be silently dropped on relaunch"
}

Write-Host ""
Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
