<#
.SYNOPSIS
    Forcibly removes leftover VMware Tools registry entries, files, and
    services on Windows Server 2008-2019, for use when the normal
    uninstaller is missing or fails - e.g. ahead of a VMware -> Hyper-V move.

.PARAMETER Force
    Skip the interactive y/n prompt. Use for unattended/remote runs
    (PowerShell remoting, Jenkins, SCCM, etc.) across many hosts.

.NOTES
    Tested on Server 2019/2016. Best-effort on 2012 R2/2008 R2.
    Run elevated.

    Does NOT remove kernel driver binaries under C:\Windows\System32\drivers
    (vmxnet3.sys, pvscsi.sys, vmci.sys, etc.) or their Driver Store packages.
    These are harmless once the matching PCI hardware IDs are gone post-
    migration, but run `driverquery /v | findstr /i vmware` afterward if you
    want full hygiene.
#>
param(
    [switch]$Force
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    return
}

# Pulls out EVERY "VMware Tools" Installer Products entry - there can be more
# than one orphaned entry after repeated upgrades/reinstalls - plus the MSI
# ProductCode embedded in each one's ProductIcon value.
function Get-VMwareToolsInstallerIDs {
    $found = @()
    Get-ChildItem Registry::HKEY_CLASSES_ROOT\Installer\Products -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($_.GetValue('ProductName') -eq 'VMware Tools') {
                $icon = $_.GetValue('ProductIcon')
                $msiId = $null
                if ($icon) {
                    $m = [Regex]::Match($icon, '(?<=\{)(.*?)(?=\})')
                    if ($m.Success) { $msiId = $m.Value }
                }
                $found += [PSCustomObject]@{ reg_id = $_.PSChildName; msi_id = $msiId }
            }
        } catch {
            Write-Warning "Skipped unreadable installer entry $($_.PSChildName): $_"
        }
    }
    return $found
}

$vmware_tools_entries = Get-VMwareToolsInstallerIDs

$reg_targets = @(
    "Registry::HKEY_CLASSES_ROOT\Installer\Features\",
    "Registry::HKEY_CLASSES_ROOT\Installer\Products\",
    "HKLM:\SOFTWARE\Classes\Installer\Features\",
    "HKLM:\SOFTWARE\Classes\Installer\Products\"
)

$VMware_Tools_Directory       = "C:\Program Files\VMware"
$VMware_Common_Directory      = "C:\Program Files\Common Files\VMware"
$VMware_ProgramData_Directory = "C:\ProgramData\VMware"

$targets = @()

foreach ($entry in $vmware_tools_entries) {
    foreach ($base in $reg_targets) {
        $targets += $base + $entry.reg_id
    }
    if ($entry.msi_id) {
        $targets += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$($entry.msi_id)}"
    }

    # UserData product registration can sit under ANY user SID, not just
    # SYSTEM (S-1-5-18) - e.g. when Tools was installed interactively under
    # an admin account. Walk every SID instead of hardcoding one.
    $userDataRoot = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData"
    if (Test-Path $userDataRoot) {
        Get-ChildItem $userDataRoot -ErrorAction SilentlyContinue | ForEach-Object {
            $targets += (Join-Path $_.PSPath "Products\$($entry.reg_id)")
        }
    }
}

# Shotgun entries for pre-2016 (NT < 10.0) that aren't reliably auto-detected.
if ([Environment]::OSVersion.Version.Major -lt 10) {
    $targets += "Registry::HKEY_CLASSES_ROOT\CLSID\{D86ADE52-C4D9-4B98-AA0D-9B0C7F1EBBC8}"
    $targets += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9709436B-5A41-4946-8BE7-2AA433CAF108}"
    $targets += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FE2F6A2C-196E-4210-9C04-2B1BC21F07EF}"
}

if (Test-Path "HKLM:\SOFTWARE\VMware, Inc.")  { $targets += "HKLM:\SOFTWARE\VMware, Inc." }
if (Test-Path $VMware_Tools_Directory)        { $targets += $VMware_Tools_Directory }
if (Test-Path $VMware_Common_Directory)       { $targets += $VMware_Common_Directory }
if (Test-Path $VMware_ProgramData_Directory)  { $targets += $VMware_ProgramData_Directory }

# Filter to what's actually present and de-dupe, so the list you confirm
# against matches what will really be touched.
$targets = $targets | Where-Object { Test-Path $_ } | Select-Object -Unique

# Match on Name as well as DisplayName - some Tools components (e.g. GISvc,
# the Guest Info service) don't have a DisplayName starting with "VMware".
$services = @(
    Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'VMware*' -or $_.Name -like 'vm*' -or $_.Name -eq 'GISvc' }
)

Write-Host "The following registry keys, filesystem folders, and services will be deleted:"
if (-not $targets -and -not $services) {
    Write-Host "Nothing to do!"
} else {
    $targets
    $services | Select-Object Name, DisplayName, Status

    $proceed = $Force.IsPresent
    if (-not $proceed) {
        $proceed = (Read-Host "Continue (y/n)") -eq 'y'
    }

    if ($proceed) {
        $services | Stop-Service -Force -Confirm:$false -ErrorAction SilentlyContinue

        if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
            $services | Remove-Service -Confirm:$false -ErrorAction SilentlyContinue
        } else {
            foreach ($s in $services) { sc.exe DELETE $($s.Name) | Out-Null }
        }

        foreach ($item in $targets) {
            try {
                Remove-Item -Path $item -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning "Failed to remove $item : $_"
            }
        }

        Write-Host "Done. Reboot to complete removal."
    } else {
        Write-Host "Cancelled - no changes made."
    }
}
