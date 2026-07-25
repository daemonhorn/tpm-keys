<#
Tests Get-TpmEnvFileSecret (extracted from tpm_setup.ps1) against the
shared dotenv fixture and a handful of rejected-input cases. Pure logic,
no TPM required.
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptText = Get-Content (Join-Path $repoRoot 'tpm_setup.ps1') -Raw
if ($scriptText -notmatch '(?s)function Get-TpmEnvFileSecret \{.*?\n\}\n') {
    throw "could not extract Get-TpmEnvFileSecret from tpm_setup.ps1"
}
function Write-TpmLine { param([string]$Text) Write-Host $Text }
Invoke-Expression $Matches[0]

$script:TestsRun = 0
$script:TestsFailed = 0
function Test-Pass { param([string]$Name) $script:TestsRun++; Write-Host "PASS: $Name" }
function Test-Fail { param([string]$Name) $script:TestsRun++; $script:TestsFailed++; Write-Host "FAIL: $Name" }

# Get-TpmEnvFileSecret calls `exit` on error (there's no interactive user to
# prompt when reading from a file), so run each rejected-input case in a
# child pwsh process and check its exit code rather than trying to catch it
# in-process.
function Test-RejectsInChildProcess {
    param([string]$Name, [string]$Content)
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $Content -NoNewline
    $fnFile = New-TemporaryFile
    Set-Content -Path $fnFile -Value "function Write-TpmLine { param(`$Text) }`n$($Matches0Global)" -NoNewline
    $result = & pwsh -NoProfile -Command "`$ErrorActionPreference='Stop'; . '$fnFile'; Get-TpmEnvFileSecret -Path '$tmp' | Out-Null" 2>$null
    $code = $LASTEXITCODE
    Remove-Item $tmp, $fnFile -ErrorAction SilentlyContinue
    if ($code -ne 0) { Test-Pass $Name } else { Test-Fail "$Name (child process exited 0)" }
}
$Matches0Global = $Matches[0]

$repoRoot = Split-Path -Parent $PSScriptRoot
$expected = 'OPENAI_KEY="sk-abc123";AWS_SECRET_ACCESS_KEY="s3cr3t with spaces";SINGLE_QUOTED="hello world";TRAILING_SPACE="padded value"'
$got = Get-TpmEnvFileSecret -Path (Join-Path $repoRoot 'tests/fixtures/sample.env')
if ($got -eq $expected) { Test-Pass "valid dotenv fixture parses correctly" } else { Test-Fail "valid dotenv fixture: got [$got]" }

Test-RejectsInChildProcess -Name "value with embedded double-quote is rejected" -Content 'BAD="has \"quote\" inside"'
Test-RejectsInChildProcess -Name "value with embedded semicolon is rejected" -Content 'BAD=has;semicolon'
Test-RejectsInChildProcess -Name "invalid variable name is rejected" -Content '1BAD=value'
Test-RejectsInChildProcess -Name "line without '=' is rejected" -Content 'notakeyvalueline'
Test-RejectsInChildProcess -Name "file with no NAME=VALUE lines is rejected" -Content "# just a comment`n"

Write-Host ""
Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
