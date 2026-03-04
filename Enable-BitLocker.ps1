#requires -version 5.1
<#
.SYNOPSIS
    Enables BitLocker on the OS drive and saves the Recovery Key to C:\tools\

.DESCRIPTION
    - Uses TPM for OS drive protection (TPM must be present and ready).
    - Creates a Recovery Password protector.
    - Writes the 48-digit Recovery Key to a timestamped file in C:\tools\.
    - If BitLocker is already enabled, exports the existing Recovery Key to file.
    - Designed for Windows 10/11 with Windows PowerShell 5.1.

.PARAMETER MountPoint
    The drive letter to encrypt. Defaults to the system drive (e.g. C:).

.PARAMETER KeyDir
    Directory where the Recovery Key file will be saved. Defaults to C:\tools.

.NOTES
    Must be run as Administrator.
#>

[CmdletBinding()]
param(
    [Parameter()][string]$MountPoint = "$($env:SystemDrive)",
    [Parameter()][string]$KeyDir     = 'C:\tools'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Assert-Admin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run in an elevated PowerShell session (Run as Administrator)."
    }
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-KeyToFile {
    param(
        [string]$RecoveryPassword,
        [string]$Drive
    )
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $driveTag  = $Drive.TrimEnd(':\').Replace(':', '')
    $file      = Join-Path $KeyDir ('{0}-{1}-BitLockerKey-{2}.txt' -f $env:COMPUTERNAME, $driveTag, $timestamp)

    $utcNow = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')

    @"
Computer:     $($env:COMPUTERNAME)
Drive:        $Drive
Date (UTC):   $utcNow
--------------
RECOVERY KEY: $RecoveryPassword
"@ | Out-File -FilePath $file -Encoding UTF8 -Force

    Write-Host ("`u2714 Recovery Key saved to: {0}" -f $file) -ForegroundColor Green
}

function Get-RecoveryPassword {
    param([string]$Drive)

    # First try to get the key directly from the volume object
    $vol = Get-BitLockerVolume -MountPoint $Drive
    $rk  = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
    if ($rk -and $rk.RecoveryPassword) {
        return $rk.RecoveryPassword
    }

    # Fallback: parse manage-bde output (48-digit format xxxxxx-xxxxxx-...)
    try {
        $bdeOutput   = manage-bde -protectors -get $Drive 2>$null
        $matchResult = $bdeOutput | Select-String -Pattern 'Password:\s*([0-9]{6}(?:-[0-9]{6}){7})' -AllMatches
        if ($matchResult -and $matchResult.Matches.Count -gt 0) {
            return $matchResult.Matches[0].Groups[1].Value
        }
    } catch { }

    return $null
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    Assert-Admin
    Ensure-Directory -Path $KeyDir

    $MountPoint = $MountPoint.TrimEnd('\')
    $vol        = Get-BitLockerVolume -MountPoint $MountPoint

    # --- Already encrypted: export the existing key and exit ---
    if ($vol.ProtectionStatus -eq 'On') {
        Write-Host "BitLocker is already enabled on $MountPoint." -ForegroundColor Yellow

        $existingKey = Get-RecoveryPassword -Drive $MountPoint
        if ($existingKey) {
            Write-KeyToFile -RecoveryPassword $existingKey -Drive $MountPoint
        } else {
            Write-Warning "A Recovery Password protector was not found on $MountPoint. No key file written."
        }
        exit 0
    }

    # --- Not encrypted: validate TPM then enable BitLocker ---
    Write-Host "BitLocker is OFF on $MountPoint. Preparing to enable..." -ForegroundColor Cyan

    $tpm = $null
    try { $tpm = Get-Tpm } catch { }
    if (-not $tpm -or -not $tpm.TpmPresent -or -not $tpm.TpmReady) {
        throw "TPM is not present or not ready. Ensure TPM is enabled in firmware, then re-run this script."
    }

    # 1) Add a Recovery Password protector so we can capture the key before encryption starts
    $rp              = Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector
    $recoveryPassword = $rp.RecoveryPassword

    # Allow a moment for the protector to be committed, then re-query if needed
    if (-not $recoveryPassword) {
        Start-Sleep -Seconds 2
        $recoveryPassword = Get-RecoveryPassword -Drive $MountPoint
    }
    if (-not $recoveryPassword) {
        throw "Could not retrieve the Recovery Password after creating it. Aborting to avoid data loss."
    }

    # 2) Enable BitLocker with TPM protector; XTS-AES 256; used-space-only for speed
    Enable-BitLocker -MountPoint $MountPoint `
                     -EncryptionMethod XtsAes256 `
                     -UsedSpaceOnly `
                     -TpmProtector

    Write-Host "BitLocker enablement initiated on $MountPoint. Encryption will continue in the background." -ForegroundColor Green

    # 3) Save the Recovery Key to the output directory
    Write-KeyToFile -RecoveryPassword $recoveryPassword -Drive $MountPoint

} catch {
    Write-Error ("ERROR: {0}" -f $_.Exception.Message)
    exit 1
}
