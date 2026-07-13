#Requires -Version 7.0
<#
Universal TPM 2.0 Secure Setup Script - Windows 11 / PowerShell 7 companion
to tpm_setup.sh. Reads/writes the SAME TPM NV RAM indices on the SAME
physical TPM as the Linux/FreeBSD script, so a dual-booted machine can seal
a secret in one OS and unlock it in the other.

Talks to the TPM directly over Windows TBS (tbs.dll) using hand-built TPM2
command buffers -- there is no official tpm2-tools build for Windows, so
this avoids depending on one. No admin rights are required for NV
read/write (they authorize with the index's own PIN, and Windows TBS allows
those ordinals for standard-user processes). Defining/removing an index
(Phase 4, one-time setup) DOES require admin rights: independent of the
TPM's own owner-hierarchy auth value, Windows TBS enforces its own
allow-list of TPM 2.0 command ordinals that differs for standard-user vs.
administrator processes, and NV_DefineSpace/NV_UndefineSpace are excluded
from the standard-user list. Run this script itself elevated; day-to-day
use afterwards (unlock_tpm) does not need elevation.
#>

$ErrorActionPreference = 'Stop'

function Write-TpmLine { param([string]$Text) Write-Host $Text }

Write-TpmLine "=== Phase 1: Prerequisites ==="

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-TpmLine "[TPM] ERROR: PowerShell 7+ is required (found $($PSVersionTable.PSVersion)). Install from https://aka.ms/powershell and re-run under pwsh."
    exit 1
}

# ---------------------------------------------------------------------------
# Raw TPM2 client, embedded so this stays a single-file distribution (like
# tpm_setup.sh). Loaded via Invoke-Expression rather than Import-Module /
# dot-sourcing a file, because those go through PowerShell's script-file
# execution-policy gate -- under the common "AllSigned" CurrentUser policy,
# an unsigned helper file would refuse to load even though the user
# explicitly ran this script. Evaluating source text via -Command/iex is
# not subject to that gate.
# ---------------------------------------------------------------------------
$Tpm2RawSource = @'
Add-Type -Namespace Tpm2Raw -Name Tbs -MemberDefinition @"
[DllImport("tbs.dll")]
public static extern uint Tbsi_Context_Create(byte[] pContextParams, out IntPtr phContext);

[DllImport("tbs.dll")]
public static extern uint Tbsip_Submit_Command(IntPtr hContext, uint locality, uint priority, byte[] pabCommand, uint cbCommand, byte[] pabResult, ref uint pcbResult);

[DllImport("tbs.dll")]
public static extern uint Tbsip_Context_Close(IntPtr hContext);
"@

$script:TPM_ST_NO_SESSIONS   = 0x8001
$script:TPM_ST_SESSIONS      = 0x8002
$script:TPM_RS_PW            = 0x40000009
$script:TPM_RH_OWNER         = 0x40000001
$script:TPM_ALG_SHA256       = 0x000B
$script:TPM_CAP_TPM_PROPERTIES = 0x00000006
$script:TPM_PT_NV_BUFFER_MAX   = 0x0000012C
$script:TPMA_NV_AUTHWRITE    = 0x00000004
$script:TPMA_NV_AUTHREAD     = 0x00040000

$script:TPM_CC_NV_UndefineSpace = 0x00000122
$script:TPM_CC_NV_DefineSpace   = 0x0000012A
$script:TPM_CC_NV_Write         = 0x00000137
$script:TPM_CC_NV_Read          = 0x0000014E
$script:TPM_CC_NV_ReadPublic    = 0x00000169
$script:TPM_CC_GetCapability    = 0x0000017A

$script:TPM_RC_N_MASK    = 0xF00
$script:TPM_RC_HANDLE    = 0x08B
$script:TPM_RC_AUTH_FAIL = 0x08E
$script:TPM_RC_BAD_AUTH  = 0x0A2
$script:TPM_RC_LOCKOUT   = 0x921
$script:TPM_RC_NV_LOCKED = 0x148
# Not the TPM's own RC -- Windows TBS synthesizes this (as HRESULT 0x80280400,
# TPM_E_COMMAND_BLOCKED) when it refuses to submit a command at all, before it
# ever reaches the TPM. TPM 2.0 command dispatch on Windows uses a per-command
# allow-list that differs between elevated and standard-user processes; owner-
# hierarchy commands like NV_DefineSpace/NV_UndefineSpace are excluded from the
# standard-user list regardless of the TPM's own owner-auth value.
$script:TPM_RC_COMMAND_BLOCKED = 0x400

class Tpm2Exception : System.Exception {
    [uint32]$RawCode
    Tpm2Exception([string]$msg, [uint32]$rawCode) : base($msg) { $this.RawCode = $rawCode }
}

function ConvertTo-BE16 {
    param([Parameter(Mandatory)][int]$Value)
    [byte[]]$r = @( (($Value -shr 8) -band 0xFF), ($Value -band 0xFF) )
    ,$r
}
function ConvertTo-BE32 {
    param([Parameter(Mandatory)][long]$Value)
    [byte[]]$r = @( (($Value -shr 24) -band 0xFF), (($Value -shr 16) -band 0xFF), (($Value -shr 8) -band 0xFF), ($Value -band 0xFF) )
    ,$r
}
function ConvertFrom-BE16 {
    param([byte[]]$Bytes,[int]$Offset=0)
    # Cast to [int] BEFORE shifting -- shifting a [byte] left by 8 overflows
    # the 8-bit type and silently truncates to 0 for any value >= 256.
    [int]((([int]$Bytes[$Offset]) -shl 8) -bor [int]$Bytes[$Offset+1])
}
function ConvertFrom-BE32 { param([byte[]]$Bytes,[int]$Offset=0)
    [uint32]((([uint32]$Bytes[$Offset]) -shl 24) -bor (([uint32]$Bytes[$Offset+1]) -shl 16) -bor (([uint32]$Bytes[$Offset+2]) -shl 8) -bor [uint32]$Bytes[$Offset+3])
}
function New-Tpm2B {
    param([byte[]]$Data)
    if (-not $Data) { $Data = [byte[]]@() }
    [byte[]]$r = (ConvertTo-BE16 $Data.Length) + $Data
    ,$r
}

function New-Tpm2PwapSession {
    param([byte[]]$Password)
    if (-not $Password) { $Password = [byte[]]@() }
    [byte[]]$r = @()
    $r += (ConvertTo-BE32 $script:TPM_RS_PW)  # sessionHandle
    $r += (ConvertTo-BE16 0)                  # nonce (empty)
    $r += [byte]0x00                          # sessionAttributes
    $r += (New-Tpm2B $Password)                # hmac == plaintext password for PWAP
    ,$r
}

function Get-Tpm2RcDescription {
    param([uint32]$Rc)
    $low = $Rc -band 0xFFF
    if ($low -eq 0) { return "TPM_RC_SUCCESS" }
    if ($low -band 0x80) {
        $base = $low -band (-bnot $script:TPM_RC_N_MASK) -band 0xFFF
        switch ($base) {
            $script:TPM_RC_HANDLE    { return "TPM_RC_HANDLE (index not found)" }
            $script:TPM_RC_AUTH_FAIL { return "TPM_RC_AUTH_FAIL (incorrect PIN)" }
            $script:TPM_RC_BAD_AUTH  { return "TPM_RC_BAD_AUTH (incorrect PIN)" }
            default { return ("TPM format-1 error 0x{0:X}" -f $low) }
        }
    }
    switch ($low) {
        $script:TPM_RC_LOCKOUT          { return "TPM_RC_LOCKOUT (TPM dictionary-attack lockout is active)" }
        $script:TPM_RC_NV_LOCKED        { return "TPM_RC_NV_LOCKED" }
        $script:TPM_RC_COMMAND_BLOCKED  { return "TPM_E_COMMAND_BLOCKED (Windows TBS refused to submit this command for a non-admin process)" }
        default { return ("TPM error 0x{0:X}" -f $low) }
    }
}

function Connect-Tpm2 {
    # TBS_CONTEXT_PARAMS2: version=2 (TBS_CONTEXT_VERSION_TWO), params.includeTpm20=1 (bit2).
    # Version-1 params default to locating a TPM 1.2 device and fail with
    # TBS_E_TPM_NOT_FOUND on TPM-2.0-only hardware.
    $ctxParams = [BitConverter]::GetBytes([uint32]2) + [BitConverter]::GetBytes([uint32]0x4)
    $hContext = [IntPtr]::Zero
    $rc = [Tpm2Raw.Tbs]::Tbsi_Context_Create($ctxParams, [ref]$hContext)
    if ($rc -ne 0) { throw "Tbsi_Context_Create failed: 0x$($rc.ToString('X8')) (is the TPM present/enabled in UEFI?)" }
    return $hContext
}

function Disconnect-Tpm2 {
    param([IntPtr]$Context)
    if ($Context -ne [IntPtr]::Zero) { [void][Tpm2Raw.Tbs]::Tbsip_Context_Close($Context) }
}

function Invoke-Tpm2RawCommand {
    param(
        [Parameter(Mandatory)][IntPtr]$Context,
        [Parameter(Mandatory)][byte[]]$Command
    )
    $resultBuf = New-Object byte[] 4096
    [uint32]$resultLen = $resultBuf.Length
    $rc = [Tpm2Raw.Tbs]::Tbsip_Submit_Command($Context, 0, 200, $Command, [uint32]$Command.Length, $resultBuf, [ref]$resultLen)
    if ($rc -ne 0) { throw "Tbsip_Submit_Command failed: 0x$($rc.ToString('X8'))" }
    [byte[]]$response = $resultBuf[0..($resultLen - 1)]
    if ($response.Length -lt 10) { throw "TPM response too short ($($response.Length) bytes)" }
    $responseCode = ConvertFrom-BE32 $response 6
    return @{ ResponseCode = $responseCode; Bytes = $response }
}

function Assert-Tpm2Success {
    param($Result, [string]$Operation)
    if ($Result.ResponseCode -ne 0) {
        $desc = Get-Tpm2RcDescription -Rc $Result.ResponseCode
        throw [Tpm2Exception]::new("$Operation failed: $desc [0x$($Result.ResponseCode.ToString('X8'))]", $Result.ResponseCode)
    }
}

function Build-Tpm2Command {
    param(
        [Parameter(Mandatory)][int]$Tag,
        [Parameter(Mandatory)][long]$CommandCode,
        [byte[]]$Handles = @(),
        $AuthArea = $null,
        [byte[]]$Params = @()
    )
    [byte[]]$body = @()
    $body += $Handles
    if ($null -ne $AuthArea) {
        $body += (ConvertTo-BE32 ([byte[]]$AuthArea).Length)
        $body += $AuthArea
    }
    $body += $Params
    $totalSize = 10 + $body.Length
    [byte[]]$cmd = @()
    $cmd += (ConvertTo-BE16 $Tag)
    $cmd += (ConvertTo-BE32 $totalSize)
    $cmd += (ConvertTo-BE32 $CommandCode)
    $cmd += $body
    ,$cmd
}

function Get-Tpm2NvBufferMax {
    param([Parameter(Mandatory)][IntPtr]$Context)
    [byte[]]$params = (ConvertTo-BE32 $script:TPM_CAP_TPM_PROPERTIES) + (ConvertTo-BE32 $script:TPM_PT_NV_BUFFER_MAX) + (ConvertTo-BE32 1)
    $cmd = Build-Tpm2Command -Tag $script:TPM_ST_NO_SESSIONS -CommandCode $script:TPM_CC_GetCapability -Params $params
    $res = Invoke-Tpm2RawCommand -Context $Context -Command $cmd
    Assert-Tpm2Success -Result $res -Operation "GetCapability(NV_BUFFER_MAX)"
    $b = $res.Bytes
    $off = 10 + 1 + 4 + 4  # moreData(1) + capability selector(4) + TPML count(4)
    if ($b.Length -lt ($off + 8)) { return 512 }  # conservative fallback
    $value = ConvertFrom-BE32 $b ($off + 4)
    if ($value -lt 16 -or $value -gt 8192) { return 512 }
    return [int]$value
}

function Get-Tpm2NvPublic {
    param([Parameter(Mandatory)][IntPtr]$Context, [Parameter(Mandatory)][uint32]$NvIndex)
    [byte[]]$handles = (ConvertTo-BE32 $NvIndex)
    $cmd = Build-Tpm2Command -Tag $script:TPM_ST_NO_SESSIONS -CommandCode $script:TPM_CC_NV_ReadPublic -Handles $handles
    $res = Invoke-Tpm2RawCommand -Context $Context -Command $cmd
    if ($res.ResponseCode -ne 0) { return @{ Exists = $false; DataSize = 0 } }
    $b = $res.Bytes
    $policySize = ConvertFrom-BE16 $b (10 + 2 + 4 + 2 + 4)
    $dataSizeOffset = 10 + 2 + 4 + 2 + 4 + 2 + $policySize
    $dataSize = ConvertFrom-BE16 $b $dataSizeOffset
    return @{ Exists = $true; DataSize = $dataSize }
}

function New-Tpm2NvIndex {
    param(
        [Parameter(Mandatory)][IntPtr]$Context,
        [Parameter(Mandatory)][uint32]$NvIndex,
        [Parameter(Mandatory)][int]$Size,
        [Parameter(Mandatory)][string]$Pin
    )
    $pinBytes = [System.Text.Encoding]::UTF8.GetBytes($Pin)
    $authArea = New-Tpm2PwapSession -Password @()  # empty owner auth (Windows default)
    [byte[]]$nvPublic = @()
    $nvPublic += (ConvertTo-BE32 $NvIndex)
    $nvPublic += (ConvertTo-BE16 $script:TPM_ALG_SHA256)
    $nvPublic += (ConvertTo-BE32 ($script:TPMA_NV_AUTHREAD -bor $script:TPMA_NV_AUTHWRITE))
    $nvPublic += (New-Tpm2B @())          # authPolicy (empty)
    $nvPublic += (ConvertTo-BE16 $Size)   # dataSize
    [byte[]]$params = (New-Tpm2B $pinBytes) + (New-Tpm2B $nvPublic)
    [byte[]]$handles = (ConvertTo-BE32 $script:TPM_RH_OWNER)
    $cmd = Build-Tpm2Command -Tag $script:TPM_ST_SESSIONS -CommandCode $script:TPM_CC_NV_DefineSpace `
        -Handles $handles -AuthArea $authArea -Params $params
    $res = Invoke-Tpm2RawCommand -Context $Context -Command $cmd
    Assert-Tpm2Success -Result $res -Operation "NV_DefineSpace(0x$($NvIndex.ToString('X')))"
}

function Remove-Tpm2NvIndex {
    param([Parameter(Mandatory)][IntPtr]$Context, [Parameter(Mandatory)][uint32]$NvIndex)
    $authArea = New-Tpm2PwapSession -Password @()
    [byte[]]$handles = (ConvertTo-BE32 $script:TPM_RH_OWNER) + (ConvertTo-BE32 $NvIndex)
    $cmd = Build-Tpm2Command -Tag $script:TPM_ST_SESSIONS -CommandCode $script:TPM_CC_NV_UndefineSpace -Handles $handles -AuthArea $authArea
    $res = Invoke-Tpm2RawCommand -Context $Context -Command $cmd
    Assert-Tpm2Success -Result $res -Operation "NV_UndefineSpace(0x$($NvIndex.ToString('X')))"
}

function Write-Tpm2Nv {
    param(
        [Parameter(Mandatory)][IntPtr]$Context,
        [Parameter(Mandatory)][uint32]$NvIndex,
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][string]$Pin
    )
    $pinBytes = [System.Text.Encoding]::UTF8.GetBytes($Pin)
    $chunkMax = Get-Tpm2NvBufferMax -Context $Context
    [byte[]]$handles = (ConvertTo-BE32 $NvIndex) + (ConvertTo-BE32 $NvIndex)
    $offset = 0
    while ($offset -lt $Data.Length) {
        $len = [Math]::Min($chunkMax, $Data.Length - $offset)
        [byte[]]$chunk = $Data[$offset..($offset + $len - 1)]
        $authArea = New-Tpm2PwapSession -Password $pinBytes
        [byte[]]$params = (New-Tpm2B $chunk) + (ConvertTo-BE16 $offset)
        $cmd = Build-Tpm2Command -Tag $script:TPM_ST_SESSIONS -CommandCode $script:TPM_CC_NV_Write -Handles $handles -AuthArea $authArea -Params $params
        $res = Invoke-Tpm2RawCommand -Context $Context -Command $cmd
        Assert-Tpm2Success -Result $res -Operation "NV_Write(0x$($NvIndex.ToString('X')), offset=$offset)"
        $offset += $len
    }
}

function Read-Tpm2Nv {
    param(
        [Parameter(Mandatory)][IntPtr]$Context,
        [Parameter(Mandatory)][uint32]$NvIndex,
        [Parameter(Mandatory)][string]$Pin
    )
    $pub = Get-Tpm2NvPublic -Context $Context -NvIndex $NvIndex
    if (-not $pub.Exists) { throw [Tpm2Exception]::new("NV index 0x$($NvIndex.ToString('X')) does not exist", $script:TPM_RC_HANDLE) }
    $pinBytes = [System.Text.Encoding]::UTF8.GetBytes($Pin)
    $chunkMax = Get-Tpm2NvBufferMax -Context $Context
    [byte[]]$handles = (ConvertTo-BE32 $NvIndex) + (ConvertTo-BE32 $NvIndex)
    [byte[]]$out = @()
    $offset = 0
    $total = $pub.DataSize
    while ($offset -lt $total) {
        $len = [Math]::Min($chunkMax, $total - $offset)
        $authArea = New-Tpm2PwapSession -Password $pinBytes
        [byte[]]$params = (ConvertTo-BE16 $len) + (ConvertTo-BE16 $offset)
        $cmd = Build-Tpm2Command -Tag $script:TPM_ST_SESSIONS -CommandCode $script:TPM_CC_NV_Read -Handles $handles -AuthArea $authArea -Params $params
        $res = Invoke-Tpm2RawCommand -Context $Context -Command $cmd
        Assert-Tpm2Success -Result $res -Operation "NV_Read(0x$($NvIndex.ToString('X')), offset=$offset)"
        $b = $res.Bytes
        $dataLen = ConvertFrom-BE16 $b 14
        if ($dataLen -gt 0) { $out += $b[16..(16 + $dataLen - 1)] }
        $offset += $len
    }
    ,$out
}
'@

Invoke-Expression $Tpm2RawSource

function Test-Tpm2OwnerAuthHint {
    param($Exception)
    if ($Exception -isnot [Tpm2Exception]) { return }
    $low = $Exception.RawCode -band 0xFFF
    if (($low -band (-bnot 0xF00)) -in @(0x08E, 0x0A2)) {
        Write-TpmLine "[TPM] Hint: this TPM's owner hierarchy has a non-empty auth value (common on managed/enterprise devices)."
        Write-TpmLine "      Defining or removing NV indices needs owner auth; reading an already-sealed secret does not, since that only needs the index's own PIN."
    } elseif ($low -eq $script:TPM_RC_COMMAND_BLOCKED) {
        Write-TpmLine "[TPM] Hint: Windows blocked this command before it reached the TPM (TPM_E_COMMAND_BLOCKED), NOT a TPM owner-auth failure."
        Write-TpmLine "      Windows TBS enforces a separate allow-list of TPM 2.0 commands for standard-user vs. administrator processes;"
        Write-TpmLine "      NV_DefineSpace/NV_UndefineSpace (used only here, in Phase 4) are excluded from the standard-user list."
        Write-TpmLine "      Re-run this script from an elevated ('Run as administrator') PowerShell 7 window."
        Write-TpmLine "      Reading/writing an already-defined index (unlock_tpm, Phase 4's own writes after this point) does not need elevation."
    }
}

# 1. TPM presence
# Get-Tpm (Win32_Tpm under the hood) needs an elevated process for a non-admin
# caller -- but it doesn't throw or write to the error stream when it lacks
# that, it just returns the plain string "Administrator privilege is required
# to execute this command." in place of a TPM info object. A naive
# `$tpmInfo.TpmPresent` check on that string silently evaluates to $null
# (falsy), so this used to hard-fail every unelevated run with a misleading
# "enable TPM in UEFI" message. Since this script is explicitly designed to
# NOT require admin rights for NV read/write, only use Get-Tpm for the
# informational banner when it actually returns a real info object, and let
# the TBS probe below -- which works fine unelevated -- be the actual
# presence/readiness gate.
$tpmInfo = $null
try { $tpmInfo = Get-Tpm } catch { $tpmInfo = $null }
if ($tpmInfo -and ($tpmInfo.PSObject.Properties.Name -contains 'TpmPresent') -and ($null -ne $tpmInfo.TpmPresent)) {
    if (-not $tpmInfo.TpmPresent -or -not $tpmInfo.TpmReady) {
        Write-TpmLine "[TPM] ERROR: No ready TPM 2.0 device found (TpmPresent=$($tpmInfo.TpmPresent), TpmReady=$($tpmInfo.TpmReady))."
        Write-TpmLine "Ensure TPM 2.0 (fTPM/Intel PTT/discrete) is enabled in UEFI."
        exit 1
    }
    Write-TpmLine "TPM detected: $($tpmInfo.ManufacturerIdTxt), owned=$($tpmInfo.TpmOwned)."
} else {
    Write-TpmLine "[TPM] Note: Get-Tpm did not return TPM details (commonly needs an elevated PowerShell); continuing without it."
}

try {
    $probeCtx = Connect-Tpm2
    Disconnect-Tpm2 -Context $probeCtx
    Write-TpmLine "TPM detected via TBS (no admin rights required)."
} catch {
    Write-TpmLine "[TPM] ERROR: Could not open a TBS session: $_"
    Write-TpmLine "Ensure TPM 2.0 (fTPM/Intel PTT/discrete) is enabled in UEFI."
    exit 1
}

# Windows TBS enforces its own allow-list of TPM 2.0 command ordinals, separate
# from the TPM's owner-hierarchy auth, and that list differs for standard-user
# vs. administrator processes. NV_DefineSpace/NV_UndefineSpace (Phase 4, this
# script's whole purpose) are excluded from the standard-user list and fail
# with TPM_E_COMMAND_BLOCKED (0x80280400) for a non-admin caller -- so check
# elevation now rather than walking the user through API key / PIN / SSH key
# entry only to hit a wall in Phase 4.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Windows 11's built-in `sudo` (Settings > System > For developers > Enable
    # sudo) can self-elevate us without the user having to close this window
    # and manually open an admin one. This check runs before Phase 2 asks for
    # any secrets, so relaunching here means the user only enters values once,
    # inside the elevated child -- not a re-prompt after a failed attempt.
    $sudoCmd = Get-Command sudo.exe -ErrorAction SilentlyContinue
    if ($sudoCmd) {
        Write-TpmLine "[TPM] Not elevated -- relaunching via 'sudo' for Phase 4 (NV_DefineSpace/NV_UndefineSpace need admin; see README)."
        Write-TpmLine "      If a UAC prompt appears, approve it. If 'sudo' is configured with input disabled, this"
        Write-TpmLine "      script's prompts (API key, PIN, etc.) won't be reachable -- switch to 'Enable sudo' with"
        Write-TpmLine "      'New window' or 'Inline' in Settings > System > For developers instead."
        $pwshPath = (Get-Process -Id $PID).Path
        # -ExecutionPolicy Bypass is scoped to just this one relaunched process
        # (not a persistent policy change): the elevated child is a fresh pwsh
        # instance that does NOT inherit whatever execution-policy context this
        # shell is running under, so without it, an unsigned script here would
        # fail to load under a CurrentUser/LocalMachine policy of AllSigned or
        # Restricted even though the current, non-elevated invocation succeeded.
        & $sudoCmd.Source $pwshPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
    Write-TpmLine "[TPM] ERROR: This script must be run from an elevated ('Run as administrator') PowerShell 7 window."
    Write-TpmLine "      Windows TBS blocks TPM2_NV_DefineSpace/TPM2_NV_UndefineSpace (Phase 4, used to create the NV"
    Write-TpmLine "      indices) for non-admin processes -- this is a Windows-driver-level command allow-list,"
    Write-TpmLine "      separate from the TPM's own owner-hierarchy auth. Day-to-day use afterwards (unlock_tpm's"
    Write-TpmLine "      NV_Read) does NOT need elevation."
    Write-TpmLine "      Tip: enable Windows' built-in 'sudo' (Settings > System > For developers > Enable sudo) so"
    Write-TpmLine "      this script can self-elevate automatically next time."
    exit 1
}

# 2. ssh-agent service
$sshAgentSvc = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
if (-not $sshAgentSvc) {
    Write-TpmLine "[TPM] ERROR: The OpenSSH Authentication Agent service (ssh-agent) is not installed."
    Write-TpmLine "Install it with (elevated PowerShell): Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
    exit 1
}
if ($sshAgentSvc.Status -ne 'Running') {
    Write-TpmLine "[TPM] The ssh-agent service is not running (status: $($sshAgentSvc.Status))."
    Write-TpmLine "Start it from an elevated PowerShell with:"
    Write-TpmLine "  Set-Service -Name ssh-agent -StartupType Automatic; Start-Service ssh-agent"
    Write-TpmLine "Re-run this script once it's running."
    exit 1
}

# 3. ssh-keygen / ssh-add present
foreach ($cmd in @('ssh-keygen', 'ssh-add')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-TpmLine "[TPM] ERROR: '$cmd' was not found on PATH. Install the OpenSSH Client Windows feature."
        exit 1
    }
}

# 4. Execution policy -- only matters for automatic profile loading (Phase 5);
# doesn't block this run (you're already executing this script), but the
# generated PROFILE hook is itself a .ps1 file subject to the same gate, so
# warn now rather than let "Automatic" unlock silently never fire.
$effectivePolicy = Get-ExecutionPolicy
if ($effectivePolicy -in @('AllSigned', 'Restricted')) {
    Write-TpmLine "[TPM] WARNING: Current effective execution policy is '$effectivePolicy'."
    Write-TpmLine "      Under this policy PowerShell will refuse to auto-load your profile (`$PROFILE), so the unlock_tpm"
    Write-TpmLine "      hook installed in Phase 5 will not run automatically in new shells (manual 'unlock_tpm' calls still work)."
    Write-TpmLine "      To fix, run in an elevated or normal PowerShell 7 window: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned"
}

$TpmHelperDir = Join-Path $HOME ".tpm_keys"
if (-not (Test-Path $TpmHelperDir)) { New-Item -ItemType Directory -Path $TpmHelperDir | Out-Null }
$TpmHelperFile = Join-Path $TpmHelperDir "Tpm2Raw.ps1"

# --- Secret parsing helper, shared shape with the generated unlock hook ---
function Get-TpmSecretReport {
    param([string]$Raw)
    $pairPattern = '^(?<name>[A-Za-z_][A-Za-z0-9_]*)="(?<value>.*)"$'
    $segments = $Raw -split ';'
    $names = @()
    $invalid = 0
    $foundKv = $false
    foreach ($seg in $segments) {
        if ([string]::IsNullOrEmpty($seg)) { continue }
        if ($seg -match $pairPattern) {
            $foundKv = $true
            $names += $Matches['name']
        } elseif ($seg -match '^([^=]+)=') {
            $cand = $Matches[1]
            if ($cand -match '^[A-Za-z_][A-Za-z0-9_]*$') { $invalid++ }
        }
    }
    return @{ FoundKv = $foundKv; Names = $names; Invalid = $invalid }
}

Write-TpmLine "`n=== Phase 2: Configuration ==="

$ApiNvSize = 1024
$SshNvSize = 1024

$apiKeyInput = $null
for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-TpmLine "Enter the value(s) to store in the TPM. This can be either:"
    Write-TpmLine "  - a single API key/token, stored as `$env:SECURE_API_KEY, or"
    Write-TpmLine "  - one or more named values: NAME1=`"value1`";NAME2=`"value2`";..."
    $candidate = Read-Host "Enter value(s)"

    if ([string]::IsNullOrEmpty($candidate)) {
        Write-TpmLine "[TPM] ERROR: Value cannot be empty.`n"
        continue
    }
    $byteLen = [System.Text.Encoding]::UTF8.GetByteCount($candidate)
    if ($byteLen -gt $ApiNvSize) {
        Write-TpmLine "[TPM] ERROR: Input is $byteLen bytes, which exceeds the $ApiNvSize-byte limit. Please shorten it.`n"
        continue
    }

    $report = Get-TpmSecretReport -Raw $candidate
    $confirmOk = $true
    if ($report.FoundKv) {
        Write-TpmLine "[TPM] Detected named value(s): $($report.Names -join ' ')"
        if ($report.Invalid -gt 0) {
            Write-TpmLine "[TPM] Warning: $($report.Invalid) segment(s) did not match NAME=`"VALUE`" and will be dropped at unlock time."
            $confirmOk = (Read-Host "Proceed anyway? (y/n)") -match '^[Yy]'
        }
    } else {
        if ($report.Invalid -gt 0) {
            Write-TpmLine "[TPM] Warning: no valid NAME=`"VALUE`" pairs were recognized."
            Write-TpmLine "This will be stored as a single opaque API key. If you intended separate values, check the format."
            $confirmOk = (Read-Host "Proceed anyway? (y/n)") -match '^[Yy]'
        } else {
            Write-TpmLine "[TPM] Storing as a single API key."
        }
    }
    if ($confirmOk) { $apiKeyInput = $candidate; break }
    Write-TpmLine ""
}
if ($null -eq $apiKeyInput) {
    Write-TpmLine "[TPM] ERROR: Too many invalid attempts. Aborting."
    exit 1
}

$masterPin = $null
for ($attempt = 1; $attempt -le 3; $attempt++) {
    $s1 = Read-Host "Create a Master PIN to protect your TPM keys" -AsSecureString
    $s2 = Read-Host "Confirm Master PIN" -AsSecureString
    $p1 = [System.Net.NetworkCredential]::new('', $s1).Password
    $p2 = [System.Net.NetworkCredential]::new('', $s2).Password
    if ([string]::IsNullOrEmpty($p1)) {
        Write-TpmLine "[TPM] ERROR: PIN cannot be empty.`n"
    } elseif ($p1 -ne $p2) {
        Write-TpmLine "[TPM] ERROR: PINs did not match.`n"
    } else {
        $masterPin = $p1
        break
    }
}
if ($null -eq $masterPin) {
    Write-TpmLine "[TPM] ERROR: Too many failed attempts. Aborting."
    exit 1
}

Write-TpmLine "--- Unlock Strategy ---"
Write-TpmLine "[1] Automatic : Prompt for PIN automatically when opening a new PowerShell session."
Write-TpmLine "[2] Manual    : Print a hint in new sessions, wait for you to run 'unlock_tpm'."
$strategyChoice = Read-Host "Choose (1 or 2) [default: 1]"
if ($strategyChoice -ne '2') { $strategyChoice = '1' }

# --- Cross-OS NV index matching ---
Write-TpmLine "`nTo read/write the SAME TPM NV indices as tpm_setup.sh on Linux/FreeBSD, this"
Write-TpmLine "needs the numeric UID that script used (run 'id -u' there to check)."
$uidInput = Read-Host "Enter that UID (or press Enter to use this Windows session's own scheme)"
if ([string]::IsNullOrEmpty($uidInput)) {
    # No cross-OS sharing requested: derive a UID-like value from the Windows
    # SID's RID so repeated runs by the same user stay stable.
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $rid = [int]($sid.Split('-')[-1]) % 1000000
    $uid = $rid
    Write-TpmLine "Using a Windows-derived index (RID-based UID $uid) -- this will NOT match a Linux/FreeBSD-sealed secret."
} else {
    $uid = [int]$uidInput
}
$ApiNvIndex = [uint32](22020096 + $uid * 2)
$SshNvIndex = [uint32](22020096 + $uid * 2 + 1)
Write-TpmLine ("API NV index: 0x{0:X}, SSH NV index: 0x{1:X}" -f $ApiNvIndex, $SshNvIndex)

Write-TpmLine "`n=== Phase 3: SSH Key Setup ==="
$sshDir = Join-Path $HOME ".ssh"
$sshKeyPath = Join-Path $sshDir "id_ed25519"
if (-not (Test-Path $sshKeyPath)) {
    $gen = Read-Host "No Ed25519 key found at $sshKeyPath. Generate one now? (y/n)"
    if ($gen -match '^[Yy]') {
        if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
        & ssh-keygen -t ed25519 -f $sshKeyPath -N '""'
        if ($LASTEXITCODE -ne 0) { Write-TpmLine "[TPM] ERROR: ssh-keygen failed. Aborting."; exit 1 }
        Write-TpmLine "[TPM] Key generated."
    } else {
        Write-TpmLine "[TPM] ERROR: You must have an Ed25519 key to continue."
        exit 1
    }
}
$sshKeyBytes = [System.IO.File]::ReadAllBytes($sshKeyPath)
if ($sshKeyBytes.Length -gt $SshNvSize) {
    Write-TpmLine "[TPM] ERROR: $sshKeyPath is $($sshKeyBytes.Length) bytes, which exceeds the $SshNvSize-byte NV limit. Aborting."
    exit 1
}

Write-TpmLine "`n=== Phase 4: Seeding TPM NV RAM ==="
$ctx = Connect-Tpm2
try {
    foreach ($pair in @(@{ Idx = $ApiNvIndex; Label = "API Key" }, @{ Idx = $SshNvIndex; Label = "SSH Key" })) {
        $pub = Get-Tpm2NvPublic -Context $ctx -NvIndex $pair.Idx
        if ($pub.Exists) {
            Write-TpmLine "[TPM] WARNING: An existing secret is already stored at 0x$($pair.Idx.ToString('X')) ($($pair.Label))."
            $confirm = Read-Host "Overwriting it will PERMANENTLY DESTROY the existing data. Continue? (y/n)"
            if ($confirm -notmatch '^[Yy]') { Write-TpmLine "[TPM] Aborting to protect existing data."; exit 1 }
        }
    }

    try {
        try { Remove-Tpm2NvIndex -Context $ctx -NvIndex $ApiNvIndex } catch { }
        try { Remove-Tpm2NvIndex -Context $ctx -NvIndex $SshNvIndex } catch { }

        Write-TpmLine "Writing API Key to TPM (0x$($ApiNvIndex.ToString('X')))..."
        New-Tpm2NvIndex -Context $ctx -NvIndex $ApiNvIndex -Size $ApiNvSize -Pin $masterPin
        Write-Tpm2Nv -Context $ctx -NvIndex $ApiNvIndex -Data ([System.Text.Encoding]::UTF8.GetBytes($apiKeyInput)) -Pin $masterPin

        Write-TpmLine "Writing SSH Key to TPM (0x$($SshNvIndex.ToString('X')))..."
        New-Tpm2NvIndex -Context $ctx -NvIndex $SshNvIndex -Size $SshNvSize -Pin $masterPin
        Write-Tpm2Nv -Context $ctx -NvIndex $SshNvIndex -Data $sshKeyBytes -Pin $masterPin
    } catch {
        Test-Tpm2OwnerAuthHint -Exception $_.Exception
        Write-TpmLine "[TPM] ERROR: Failed to seed the TPM: $_"
        exit 1
    }
} finally {
    Disconnect-Tpm2 -Context $ctx
}

# Unlike tpm2-tools on Linux/FreeBSD (which passes -p/-P PIN as a command-line
# argument, briefly visible to other local users via ps/procfs), this raw
# implementation never shells out for TPM operations -- the PIN stays inside
# this process and is never exposed as another process's argv.

Write-TpmLine "`n=== Phase 5: Integrating with PowerShell ==="

$unlockFunctionBody = @"
function unlock_tpm {
    `$needsSsh = `$false
    `$needsApi = `$false

    `$sshAgentSvc = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
    if (-not `$sshAgentSvc -or `$sshAgentSvc.Status -ne 'Running') {
        Write-Host "[TPM] Error: ssh-agent service is not running. Start it with: Start-Service ssh-agent"
        return
    }
    `$identities = & ssh-add -l 2>`$null
    if (-not ((`$identities -join "`n") -match 'ED25519')) { `$needsSsh = `$true }
    if (-not `$env:SECURE_API_KEY) { `$needsApi = `$true }

    if (-not `$needsSsh -and -not `$needsApi) {
        Write-Host "[TPM] All secure keys are already loaded."
        return
    }

    if (-not (Get-Command Connect-Tpm2 -ErrorAction SilentlyContinue)) {
        Get-Content '$TpmHelperFile' -Raw | Invoke-Expression
    }

    Write-Host ""
    Write-Host "[TPM] Secured keys missing from environment."
    `$secure = Read-Host "Enter Master TPM PIN" -AsSecureString
    `$pin = [System.Net.NetworkCredential]::new('', `$secure).Password

    `$ctx = Connect-Tpm2
    try {
        if (`$needsSsh) {
            try {
                `$keyBytes = Read-Tpm2Nv -Context `$ctx -NvIndex $SshNvIndex -Pin `$pin
                `$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tpm_ssh_" + [guid]::NewGuid().ToString("N"))
                [System.IO.File]::WriteAllBytes(`$tmp, `$keyBytes)
                icacls `$tmp /inheritance:r /grant:r "`$([Environment]::UserName):(R,W)" | Out-Null
                & ssh-add `$tmp 2>&1 | Out-Null
                if (`$LASTEXITCODE -ne 0) { Write-Host "[TPM] Error: Failed to load SSH key." }
                Remove-Item -Force `$tmp -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[TPM] Error: Failed to load SSH key: `$_"
            }
        }
        if (`$needsApi) {
            try {
                `$rawBytes = Read-Tpm2Nv -Context `$ctx -NvIndex $ApiNvIndex -Pin `$pin
                `$raw = [System.Text.Encoding]::UTF8.GetString(`$rawBytes).TrimEnd([char]0)
                `$foundKv = `$false
                foreach (`$seg in (`$raw -split ';')) {
                    if ([string]::IsNullOrEmpty(`$seg)) { continue }
                    if (`$seg -match '^(?<name>[A-Za-z_][A-Za-z0-9_]*)="(?<value>.*)"$') {
                        [Environment]::SetEnvironmentVariable(`$Matches['name'], `$Matches['value'], 'Process')
                        Write-Host "[TPM] Loaded env var: `$(`$Matches['name'])"
                        `$foundKv = `$true
                    }
                }
                if (-not `$foundKv) {
                    `$env:SECURE_API_KEY = `$raw
                    if (`$raw) { Write-Host "[TPM] API Key loaded." }
                }
            } catch {
                Write-Host "[TPM] Error: Failed to load API secret: `$_"
            }
        }
    } finally {
        Disconnect-Tpm2 -Context `$ctx
        `$pin = `$null
    }
}
"@

if ($strategyChoice -eq '2') {
    $autoCall = 'if ($Host.UI.RawUI -and [Environment]::UserInteractive) { Write-Host "`n[TPM] Hint: Run ''unlock_tpm'' to load your secure keys." }'
} else {
    $autoCall = 'if ($Host.UI.RawUI -and [Environment]::UserInteractive) { unlock_tpm }'
}

# Everything TPM-related lives in its own dedicated file under
# .tpm_keys\, loaded from $PROFILE via a single, minimal line -- keeping
# the footprint in the user's own profile as small as possible, since
# $PROFILE is a file we don't fully control the layout of (see below).
$UnlockScriptFile = Join-Path $TpmHelperDir "unlock_tpm.ps1"
Set-Content -Path $UnlockScriptFile -Value @"
$unlockFunctionBody
$autoCall
"@

# Persist the raw TPM2 client for unlock_tpm to load in future sessions.
Set-Content -Path $TpmHelperFile -Value $Tpm2RawSource -NoNewline

if (-not (Test-Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force | Out-Null
}
$existing = Get-Content -Path $PROFILE -Raw -ErrorAction SilentlyContinue
if (-not $existing) { $existing = "" }
$blockPattern = '(?s)\r?\n?# --- TPM Secure Environment Setup \(PowerShell\) ---.*?# ----------------------------------------------\r?\n?'
$existing = [regex]::Replace($existing, $blockPattern, "")

$profileBlock = @"

# --- TPM Secure Environment Setup (PowerShell) ---
Get-Content '$UnlockScriptFile' -Raw | Invoke-Expression
# ----------------------------------------------
"@

# PowerShell hard-refuses to parse ANY code appearing after a
# "# SIG # End signature block" marker (Authenticode-signed profiles, e.g.
# under an AllSigned policy, commonly end with one) -- so our block must go
# BEFORE that marker, not appended at end-of-file, or the whole profile
# becomes unparseable.
$sigBlockPattern = '(?s)# SIG # Begin signature block.*# SIG # End signature block\r?\n?'
$sigMatch = [regex]::Match($existing, $sigBlockPattern)
if ($sigMatch.Success) {
    $newContent = $existing.Substring(0, $sigMatch.Index) + $profileBlock + "`n" + $existing.Substring($sigMatch.Index)
    Write-TpmLine "[TPM] NOTE: $PROFILE has an Authenticode signature block. Inserting before it to keep the file parseable, but this edit invalidates that signature."
    if ($existing -match 'function\s+user-sign-psscript') {
        Write-TpmLine "      If your execution policy requires a valid signature (e.g. AllSigned), re-sign it afterwards, e.g.: user-sign-psscript `$PROFILE"
    } else {
        Write-TpmLine "      If your execution policy requires a valid signature (e.g. AllSigned), re-sign it afterwards with Set-AuthenticodeSignature, or switch to RemoteSigned."
    }
} else {
    $newContent = $existing + $profileBlock
}
Set-Content -Path $PROFILE -Value $newContent
Write-TpmLine "Added PowerShell automation to $PROFILE"

Write-TpmLine "`n=== Setup Complete! ==="
Write-TpmLine "IMPORTANT: Backup $sshKeyPath to an offline drive before deleting it from this system!"
Write-TpmLine "Restart PowerShell (or run '. `$PROFILE') to pick up the 'unlock_tpm' command."
