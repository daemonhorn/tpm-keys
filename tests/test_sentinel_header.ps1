<#
Tests the real Write-Tpm2Nv/Read-Tpm2Nv functions (extracted from
tpm_setup.ps1's embedded $Tpm2RawSource) against an in-memory fake NV store,
since there's no TBS/TPM device access from a non-Windows PowerShell host.
Get-Tpm2NvPublic / Get-Tpm2NvBufferMax / Read-Tpm2NvRange are stubbed to
back onto a hashtable instead of real TPM2 commands; Write-Tpm2Nv and
Read-Tpm2Nv themselves are the actual, unmodified shipped code.

Covers the same scenarios as tests/test_sentinel_header.sh:
  - fresh header-formatted write/read with 0x00 erase-fill
  - fresh header-formatted write/read with 0xFF erase-fill (the FreeBSD bug)
  - legacy (headerless) data with 0xFF and 0x00 erase-fill tails
  - binary payload round-trips byte-for-byte
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptText = Get-Content (Join-Path $repoRoot 'tpm_setup.ps1') -Raw
if ($scriptText -notmatch "(?s)`\$Tpm2RawSource = @'\r?\n(.*?)\r?\n'@") {
    throw "could not extract `$Tpm2RawSource from tpm_setup.ps1"
}
Invoke-Expression $Matches[1]

$script:FakeNv = @{}
function Get-Tpm2NvPublic {
    param($Context, [uint32]$NvIndex)
    if (-not $script:FakeNv.ContainsKey($NvIndex)) { return @{ Exists = $false; DataSize = 0 } }
    return @{ Exists = $true; DataSize = $script:FakeNv[$NvIndex].Size }
}
function Get-Tpm2NvBufferMax { param($Context) return 512 }
function Read-Tpm2NvRange {
    param($Context, [uint32]$NvIndex, $PinBytes, [int]$Start, [int]$Length, [int]$ChunkMax)
    $entry = $script:FakeNv[$NvIndex]
    [byte[]]$buf = New-Object byte[] $entry.Size
    [Array]::Copy($entry.Data, 0, $buf, 0, $entry.Data.Length)
    for ($i = $entry.Data.Length; $i -lt $entry.Size; $i++) { $buf[$i] = $entry.FillByte }
    ,$buf[$Start..($Start + $Length - 1)]
}
function Write-Tpm2NvFake {
    # Runs the REAL Write-Tpm2Nv against a fake NV store by intercepting
    # Invoke-Tpm2RawCommand for the duration of the call, parsing the actual
    # NV_Write command bytes it builds (per Build-Tpm2Command's layout) so
    # the header-prepend logic under test is exercised unmodified.
    param([uint32]$NvIndex, [int]$Size, [byte]$FillByte, [byte[]]$Data, [string]$Pin)
    $script:FakeNv[$NvIndex] = @{ Size = $Size; FillByte = $FillByte; Data = [byte[]]@() }
    $captured = [System.Collections.Generic.List[byte]]::new()
    function Invoke-Tpm2RawCommand {
        param($Context, [byte[]]$Command)
        # Reuse the file's own ConvertFrom-BE32/BE16 (which correctly cast
        # each byte to [int] before shifting) rather than hand-rolling the
        # same bit math here -- an earlier version of this test did that
        # inline and silently truncated (byte-typed -shl 8 overflows an
        # 8-bit value and wraps to 0 in PowerShell), corrupting the test
        # itself rather than the code under test.
        $authAreaAt = 18
        $authAreaLen = ConvertFrom-BE32 $Command $authAreaAt
        $paramsAt = $authAreaAt + 4 + $authAreaLen
        $chunkLen = ConvertFrom-BE16 $Command $paramsAt
        $chunkStart = $paramsAt + 2
        [byte[]]$chunk = $Command[$chunkStart..($chunkStart + $chunkLen - 1)]
        $captured.AddRange($chunk)
        [byte[]]$resp = @(0x80,0x02, 0,0,0,10, 0,0,0,0)
        return @{ ResponseCode = 0; Bytes = $resp }
    }
    Write-Tpm2Nv -Context ([IntPtr]::Zero) -NvIndex $NvIndex -Data $Data -Pin $Pin
    $script:FakeNv[$NvIndex].Data = $captured.ToArray()
}

$script:TestsRun = 0
$script:TestsFailed = 0
function Test-Pass { param([string]$Name) $script:TestsRun++; Write-Host "PASS: $Name" }
function Test-Fail { param([string]$Name) $script:TestsRun++; $script:TestsFailed++; Write-Host "FAIL: $Name" }

$payload = [System.Text.Encoding]::UTF8.GetBytes("hello-world-secret-123")

Write-Tpm2NvFake -NvIndex 100 -Size 64 -FillByte 0x00 -Data $payload -Pin "pin1"
$got = [System.Text.Encoding]::UTF8.GetString((Read-Tpm2Nv -Context ([IntPtr]::Zero) -NvIndex 100 -Pin "pin1"))
if ($got -eq "hello-world-secret-123") { Test-Pass "fresh header round-trip, 0x00 erase-fill" } else { Test-Fail "fresh header round-trip, 0x00 erase-fill: got [$got]" }

Write-Tpm2NvFake -NvIndex 101 -Size 64 -FillByte 0xFF -Data $payload -Pin "pin1"
$got2 = [System.Text.Encoding]::UTF8.GetString((Read-Tpm2Nv -Context ([IntPtr]::Zero) -NvIndex 101 -Pin "pin1"))
if ($got2 -eq "hello-world-secret-123") { Test-Pass "fresh header round-trip, 0xFF erase-fill (the FreeBSD bug)" } else { Test-Fail "fresh header round-trip, 0xFF erase-fill: got [$got2]" }

$legacyPayload = [System.Text.Encoding]::UTF8.GetBytes("legacy-freebsd-secret")
$script:FakeNv[[uint32]102] = @{ Size = 64; FillByte = 0xFF; Data = $legacyPayload }
$got3 = [System.Text.Encoding]::UTF8.GetString((Read-Tpm2Nv -Context ([IntPtr]::Zero) -NvIndex 102 -Pin "pin1"))
if ($got3 -eq "legacy-freebsd-secret") { Test-Pass "legacy fallback, 0xFF-filled tail" } else { Test-Fail "legacy fallback, 0xFF-filled tail: got [$got3]" }

$script:FakeNv[[uint32]103] = @{ Size = 64; FillByte = 0x00; Data = $legacyPayload }
$got4 = [System.Text.Encoding]::UTF8.GetString((Read-Tpm2Nv -Context ([IntPtr]::Zero) -NvIndex 103 -Pin "pin1"))
if ($got4 -eq "legacy-freebsd-secret") { Test-Pass "legacy fallback, 0x00-filled tail" } else { Test-Fail "legacy fallback, 0x00-filled tail: got [$got4]" }

$binPayload = [byte[]](0..249 | ForEach-Object { $_ % 256 })
Write-Tpm2NvFake -NvIndex 104 -Size 300 -FillByte 0xFF -Data $binPayload -Pin "pin1"
$got5 = Read-Tpm2Nv -Context ([IntPtr]::Zero) -NvIndex 104 -Pin "pin1"
$identical = ($got5.Length -eq $binPayload.Length) -and (-not (Compare-Object $got5 $binPayload))
if ($identical) { Test-Pass "binary payload exact byte round-trip (len=$($got5.Length))" } else { Test-Fail "binary payload exact byte round-trip: len got=$($got5.Length) want=$($binPayload.Length)" }

Write-Host ""
Write-Host "$($script:TestsRun - $script:TestsFailed)/$($script:TestsRun) tests passed"
if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
