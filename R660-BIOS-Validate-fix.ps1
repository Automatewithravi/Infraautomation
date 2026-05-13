# Dell R660 - BIOS & iDRAC Validation + Interactive Remediation (Redfish)
# Checks: System Profile | Memory | Processor | Boot | PXE | SR-IOV | iDRAC IPv4/IPv6
# On any FAIL the script prompts Y/N to apply the correct value.
# BIOS fixes are staged and require a manual reboot to take effect.
# iDRAC fixes (IPv4/IPv6) apply immediately — no reboot required.
# All BIOS attribute names verified against PowerEdge R660 / BIOS 2.10.1
# iDRAC attribute keys verified against live iDRAC 9 v7.30.10.50
# Example : - .\R660-BIOS-Validate.ps1 -iDRACIP 10.x.x.x -iDRACPassword xxx -DumpAttributes

param (
    [Parameter(Mandatory)][string]$iDRACIP,
    [string]$iDRACUser      = "rootadmin",
    [Parameter(Mandatory)][string]$iDRACPassword,
    [switch]$DumpAttributes   # Print all iDRAC attribute keys/values for diagnostics then exit
)

# ─────────────────────────────────────────────────────────────────────────────
# SSL / TLS SETUP
# ─────────────────────────────────────────────────────────────────────────────
if (-not ([System.Management.Automation.PSTypeName]'TrustAll').Type) {
    Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAll : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
                WebRequest req, int problem) { return true; }
        }
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
[System.Net.ServicePointManager]::SecurityProtocol  = [Net.SecurityProtocolType]::Tls12

# ─────────────────────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────────────────────
$encodedCreds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${iDRACUser}:${iDRACPassword}"))
$headers = @{ "Authorization" = "Basic $encodedCreds"; "Accept" = "application/json" }

$patchHeaders = $headers.Clone()
$patchHeaders["Content-Type"] = "application/json"

function Invoke-RF { param([string]$Uri)
    Invoke-RestMethod -Uri $Uri -Headers $headers -Method GET -ContentType "application/json"
}

# ─────────────────────────────────────────────────────────────────────────────
# FETCH ALL DATA
# ─────────────────────────────────────────────────────────────────────────────
$base = "https://$iDRACIP/redfish/v1"

Write-Host ""
Write-Host "  Connecting to iDRAC and fetching data..." -ForegroundColor DarkCyan

$biosResp    = Invoke-RF "$base/Systems/System.Embedded.1/Bios"
$attrs       = $biosResp.Attributes

$sysResp     = Invoke-RF "$base/Systems/System.Embedded.1"
$serviceTag  = $sysResp.SKU
$bootOrder   = $sysResp.Boot.BootOrder

$bootOptResp = Invoke-RF "$base/Systems/System.Embedded.1/BootOptions?`$expand=*(`$levels=1)"

$idracAttrs  = (Invoke-RF "$base/Managers/iDRAC.Embedded.1/Attributes").Attributes

# ─────────────────────────────────────────────────────────────────────────────
# OPTIONAL : DUMP ALL iDRAC ATTRIBUTES  (-DumpAttributes switch)
# ─────────────────────────────────────────────────────────────────────────────
if ($DumpAttributes) {
    Write-Host ""
    Write-Host "=================================================" -ForegroundColor Magenta
    Write-Host "   iDRAC ATTRIBUTE DUMP (diagnostic mode)"        -ForegroundColor Magenta
    Write-Host "=================================================" -ForegroundColor Magenta
    $idracAttrs.PSObject.Properties | Sort-Object Name | ForEach-Object {
        Write-Host ("  {0,-60} : {1}" -f $_.Name, $_.Value)
    }
    Write-Host "=================================================" -ForegroundColor Magenta
    Write-Host ""
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# iDRAC ATTRIBUTE KEYS  (verified from live DumpAttributes output)
# Writable config keys — CurrentIPv4/CurrentIPv6 are read-only, do not PATCH
# ─────────────────────────────────────────────────────────────────────────────
$ipv4EnableKey = "IPv4.1.Enable"
$ipv6EnableKey = "IPv6.1.Enable"

# ─────────────────────────────────────────────────────────────────────────────
# BUILD BOOT OPTION MAP  (ID -> DisplayName)
# ─────────────────────────────────────────────────────────────────────────────
$bootMap = @{}
foreach ($member in $bootOptResp.Members) {
    $id = $member.'@odata.id'.Split('/')[-1]
    $bootMap[$id] = if ($member.DisplayName) { $member.DisplayName } else { $member.Name }
}

# ─────────────────────────────────────────────────────────────────────────────
# COUNTERS
# ─────────────────────────────────────────────────────────────────────────────
$totalPass     = 0
$totalFail     = 0
$totalFixed    = 0
$totalSkipped  = 0
$pendingReboot = $false   # set to $true when any BIOS fix is staged

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Pass($label, $current, $display) {
    Write-Host "  [PASS]    $label" -ForegroundColor Green
    Write-Host "            Current  : $current"
    Write-Host "            Expected : $display"
    Write-Host ""
    $script:totalPass++
}

function Write-Fail($label, $current, $display) {
    Write-Host "  [FAIL]    $label" -ForegroundColor Red
    Write-Host "            Current  : $current"
    Write-Host "            Expected : $display"
    $script:totalFail++
}

function Write-Fixed($label) {
    Write-Host "  [FIXED]   $label — change staged successfully" -ForegroundColor DarkGreen
    Write-Host ""
    $script:totalFixed++
}

function Write-Skipped($label) {
    Write-Host "  [SKIPPED] $label — no change made" -ForegroundColor DarkGray
    Write-Host ""
    $script:totalSkipped++
}

function Write-ApplyError($msg) {
    Write-Host "  [ERROR]   PATCH failed: $msg" -ForegroundColor Red
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# CORE CHECK FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Check a BIOS attribute. On FAIL, prompt Y/N to stage the fix via Bios/Settings.
# Staged changes only apply after a manual reboot — server is never rebooted automatically.
function Check-And-Fix-Attr($label, $key, $expected, $display) {
    $current = $attrs.$key
    if ($current -eq $expected) {
        Write-Pass $label $current $display
        return
    }

    Write-Fail $label $current $display
    Write-Host ""
    $ans = Read-Host "            Apply fix? Set to '$display' (staged — requires manual reboot) [Y/N]"
    Write-Host ""

    if ($ans -match '^[Yy]') {
        try {
            $body = @{ Attributes = @{ $key = $expected } } | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Uri "$base/Systems/System.Embedded.1/Bios/Settings" `
                -Headers $patchHeaders -Method PATCH -Body $body | Out-Null
            Write-Fixed $label
            $script:pendingReboot = $true
        } catch {
            Write-ApplyError $_.Exception.Message
        }
    } else {
        Write-Skipped $label
    }
}

# Check an iDRAC attribute. On FAIL, prompt Y/N to apply immediately (no reboot needed).
function Check-And-Fix-iDRAC($label, $key, $expected, $display) {
    $current = $idracAttrs.$key
    if ($current -eq $expected) {
        Write-Pass $label $current $display
        return
    }

    Write-Fail $label $current $display
    Write-Host ""
    $ans = Read-Host "            Apply fix? Set to '$display' (applies immediately, no reboot) [Y/N]"
    Write-Host ""

    if ($ans -match '^[Yy]') {
        try {
            $body = @{ Attributes = @{ $key = $expected } } | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Uri "$base/Managers/iDRAC.Embedded.1/Attributes" `
                -Headers $patchHeaders -Method PATCH -Body $body | Out-Null
            Write-Fixed $label
        } catch {
            Write-ApplyError $_.Exception.Message
        }
    } else {
        Write-Skipped $label
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# HEADER BANNER
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "   BIOS & iDRAC Validation - Dell PowerEdge R660" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "   iDRAC       : $iDRACIP"
Write-Host "   Service Tag : $serviceTag"
Write-Host "   Time        : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 : SYSTEM PROFILE
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "--- System Profile Settings ---" -ForegroundColor Yellow
Check-And-Fix-Attr "System Profile"   "SysProfile"      "PerfOptimized" "Performance"
Check-And-Fix-Attr "Workload Profile" "WorkloadProfile" "NotConfigured" "Not Configured"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 : MEMORY
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "--- Memory Settings ---" -ForegroundColor Yellow
Check-And-Fix-Attr "Node Interleaving"    "NodeInterleave" "Disabled"     "Disabled"
Check-And-Fix-Attr "Memory Paging Policy" "PagingPolicy"   "PagingClosed" "Closed Paging"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 : PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "--- Processor Settings ---" -ForegroundColor Yellow
Check-And-Fix-Attr "Logical Processor"             "LogicalProc"             "Enabled"     "Enabled"
Check-And-Fix-Attr "CPU Interconnect Speed"        "CpuInterconnectBusSpeed" "MaxDataRate" "Maximum Data Rate"
Check-And-Fix-Attr "Virtualization Technology"     "ProcVirtualization"      "Enabled"     "Enabled"
Check-And-Fix-Attr "Adjacent Cache Line Prefetch"  "ProcAdjCacheLine"        "Enabled"     "Enabled"
Check-And-Fix-Attr "Hardware Prefetcher"           "ProcHwPrefetcher"        "Enabled"     "Enabled"
Check-And-Fix-Attr "DCU Streamer Prefetcher"       "DcuStreamerPrefetcher"   "Enabled"     "Enabled"
Check-And-Fix-Attr "DCU IP Prefetcher"             "DcuIpPrefetcher"         "Enabled"     "Enabled"
Check-And-Fix-Attr "SST-Performance Profile"       "ProcPwrPerf"             "MaxPerf"     "Operating Point 1 (All Cores)"
Check-And-Fix-Attr "Number of Cores Per Processor" "ProcCores"               "All"         "All"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 : BOOT SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "--- Boot Settings ---" -ForegroundColor Yellow

Check-And-Fix-Attr "Boot Mode" "BootMode" "Uefi" "UEFI"

# Boot Order — resolve IDs to display names, validate BOSS is first.
# Boot order resequencing via Redfish requires reordering the full BootOrder
# array on the System resource. If this fails, correct manually in:
#   iDRAC UI > Configuration > BIOS Settings > Boot Settings > UEFI Boot Sequence
Write-Host "  [CHECK]   Boot Order" -ForegroundColor White

if ($bootOrder -and $bootOrder.Count -gt 0) {

    $orderedNames = $bootOrder | ForEach-Object {
        $id = $_.Split('/')[-1]
        if ($bootMap.ContainsKey($id)) { $bootMap[$id] } else { $id }
    }

    Write-Host "            Current Boot Order:"
    for ($i = 0; $i -lt $orderedNames.Count; $i++) {
        Write-Host "              $($i + 1). $($orderedNames[$i])"
    }
    Write-Host ""

    if ($orderedNames[0] -match "BOSS") {
        Write-Host "  [PASS]    Boot Order — BOSS is first" -ForegroundColor Green
        Write-Host "            Expected : BOSS → CD/DVD → C:\ → NIC (if available)"
        Write-Host ""
        $totalPass++
    } else {
        Write-Host "  [FAIL]    Boot Order — BOSS is NOT first" -ForegroundColor Red
        Write-Host "            Expected : BOSS → CD/DVD → C:\ → NIC (if available)"
        Write-Host "            Current  : $($orderedNames[0]) is first"
        Write-Host ""
        $totalFail++
        Write-Host "  [INFO]    Fix manually in iDRAC UI:" -ForegroundColor Yellow
        Write-Host "            Configuration > BIOS Settings > Boot Settings > UEFI Boot Sequence"
        Write-Host ""
        $totalSkipped++
    }

} else {
    Write-Host "  [FAIL]    Boot order data not available via Redfish" -ForegroundColor Red
    Write-Host "            Fix manually in iDRAC UI:"
    Write-Host "            Configuration > BIOS Settings > Boot Settings > UEFI Boot Sequence"
    Write-Host ""
    $totalFail++
    $totalSkipped++
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 : NETWORK SETTINGS — PXE DEVICES
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "--- Network Settings (PXE) ---" -ForegroundColor Yellow
1..4 | ForEach-Object {
    Check-And-Fix-Attr "PXE Device $_ (PxeDev${_}EnDis)" "PxeDev${_}EnDis" "Disabled" "Disabled"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 : INTEGRATED DEVICES — SR-IOV
# Always expected Disabled. Prompt to fix if Enabled.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "--- Integrated Devices ---" -ForegroundColor Yellow
Check-And-Fix-Attr "SR-IOV Global Enable" "SriovGlobalEnable" "Disabled" "Disabled"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 : iDRAC NETWORK SETTINGS
# iDRAC attribute fixes apply immediately — no server reboot required.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "--- iDRAC Network Settings ---" -ForegroundColor Yellow
Check-And-Fix-iDRAC "IPv4 Enabled"  $ipv4EnableKey "Enabled"  "Enabled"
Check-And-Fix-iDRAC "IPv6 Disabled" $ipv6EnableKey "Disabled" "Disabled"

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
$totalChecks = $totalPass + $totalFail
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  TOTAL CHECKS : $totalChecks"
Write-Host "  PASS         : $totalPass"    -ForegroundColor Green
Write-Host "  FAIL         : $totalFail"    -ForegroundColor $(if ($totalFail -gt 0) { "Red" } else { "Green" })
Write-Host "  FIXED        : $totalFixed"   -ForegroundColor DarkGreen
Write-Host "  SKIPPED      : $totalSkipped" -ForegroundColor DarkGray
Write-Host "=================================================" -ForegroundColor Cyan

if ($totalFail -eq 0) {
    Write-Host ""
    Write-Host "  All checks passed. No issues found." -ForegroundColor Green
} else {
    $remaining = $totalFail - $totalFixed - $totalSkipped
    Write-Host ""
    if ($totalFixed -gt 0)    { Write-Host "  $totalFixed fix(es) applied successfully." -ForegroundColor DarkGreen }
    if ($totalSkipped -gt 0)  { Write-Host "  $totalSkipped item(s) skipped — no change made." -ForegroundColor DarkGray }
    if ($remaining -gt 0)     { Write-Host "  $remaining item(s) still require attention." -ForegroundColor Red }
}

# ─────────────────────────────────────────────────────────────────────────────
# REBOOT REMINDER
# Only displayed when at least one BIOS fix was staged.
# Server is never rebooted automatically by this script.
# ─────────────────────────────────────────────────────────────────────────────
if ($pendingReboot) {
    Write-Host ""
    Write-Host "=================================================" -ForegroundColor Magenta
    Write-Host "   !! MANUAL REBOOT REQUIRED !!"                  -ForegroundColor Magenta
    Write-Host "   One or more BIOS settings have been staged."   -ForegroundColor Magenta
    Write-Host "   They will NOT take effect until the server"    -ForegroundColor Magenta
    Write-Host "   is rebooted manually."                         -ForegroundColor Magenta
    Write-Host "=================================================" -ForegroundColor Magenta
}

Write-Host ""
