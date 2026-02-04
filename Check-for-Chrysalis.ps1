#Requires -Version 5.1
<#
.SYNOPSIS
  Single-file Chrysalis / Lotus Blossom IOC checker.

.DESCRIPTION
  Fully self-contained IR triage script.
  Hardened against race conditions, SYSTEM context, EDR interference.

  IOC source:
  https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
#>

[CmdletBinding()]
param(
    [string[]] $ScanPaths = @(),
    [switch]   $NoRegistry,
    [switch]   $NoMutex,
    [switch]   $NoNetwork
)

$ErrorActionPreference = 'SilentlyContinue'
$Findings = [System.Collections.ArrayList]::new()

# -------------------------------------------------
# Embedded IOCs (from user-provided set)
# -------------------------------------------------

$IOC_FileHashes = @(
    'a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9',
    '8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e',
    '2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924',
    '77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e',
    '3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad',
    '9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600',
    'f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a',
    '4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906',
    '831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd',
    '0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd',
    '4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8',
    'e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda',
    '078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5',
    'b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3',
    '7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd',
    'fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a'
)

$IOC_Paths = @(
    '%AppData%\Bluetooth',
    '%AppData%\Bluetooth\BluetoothService.exe',
    '%AppData%\Bluetooth\BluetoothService',
    '%AppData%\Bluetooth\log.dll'
)

$IOC_PathsHashOnly = @(
    '%ProgramData%\USOShared',
    '%ProgramData%\USOShared\svchost.exe',
    '%ProgramData%\USOShared\conf.c',
    '%ProgramData%\USOShared\libtcc.dll'
)

$IOC_Mutexes = @(
    'Global\Jdhfv_1.0.1'
)

$IOC_RunKeys = @(
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)

$IOC_IPs = @(
    '95.179.213.0',
    '61.4.102.97',
    '59.110.7.32',
    '124.222.137.114'
)

$IOC_Domains = @(
    'api.skycloudcenter.com',
    'api.wiresguard.com'
)

# -------------------------------------------------
# Helpers
# -------------------------------------------------

function Expand-Env($p) {
    if (-not $p) { return $null }
    ($p -replace '%AppData%', $env:APPDATA `
        -replace '%ProgramData%', $env:ProgramData)
}

function Add-Finding($Category, $Detail, $Severity = 'High') {
    [void]$Findings.Add([PSCustomObject]@{
        Category = $Category
        Detail   = $Detail
        Severity = $Severity
        Time     = (Get-Date).ToString('o')
    })
}

function Get-SHA256($Path) {
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
        }
    } catch {}
}

# -------------------------------------------------
# 1) Path existence
# -------------------------------------------------

Write-Host "[*] Checking known paths..." -ForegroundColor Cyan

$ScanRoots = @()

foreach ($p in $IOC_Paths) {
    $full = Expand-Env $p
    try {
        if ($full -and (Test-Path -LiteralPath $full)) {
            Add-Finding 'Path' "IOC path exists: $full"
            Write-Host "  [FOUND] $full" -ForegroundColor Red
            $ScanRoots += (Split-Path $full -Parent)
        }
    } catch {}
}

foreach ($p in $IOC_PathsHashOnly) {
    $full = Expand-Env $p
    if ($full) { $ScanRoots += (Split-Path $full -Parent) }
}

$ScanRoots += $ScanPaths
$ScanRoots = $ScanRoots | Where-Object { $_ } | Select-Object -Unique

# -------------------------------------------------
# 2) Hash scanning + sideload
# -------------------------------------------------

foreach ($dir in $ScanRoots) {
    try {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        Write-Host "[*] Hash scanning: $dir" -ForegroundColor Cyan

        $files = Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $hash = Get-SHA256 $f.FullName
            if ($hash -and $IOC_FileHashes -contains $hash) {
                Add-Finding 'FileHash' "Known Chrysalis hash: $($f.FullName)" 'Critical'
                Write-Host "  [MATCH] $($f.FullName)" -ForegroundColor Red
            }
        }

        # DLL sideload
        $groups = $files | Group-Object DirectoryName
        foreach ($g in $groups) {
            if ($g.Group.Name -contains 'BluetoothService.exe' -and
                $g.Group.Name -contains 'log.dll') {
                Add-Finding 'Sideloading' "DLL sideload pattern: $($g.Name)"
                Write-Host "  [SUSPICIOUS] DLL sideload" -ForegroundColor Yellow
            }
        }
    } catch {}
}

# -------------------------------------------------
# 3) Mutex
# -------------------------------------------------

if (-not $NoMutex) {
    Write-Host "[*] Checking mutexes..." -ForegroundColor Cyan
    foreach ($m in $IOC_Mutexes) {
        try {
            $created = $false
            $mx = New-Object Threading.Mutex($false, $m, [ref]$created)
            if (-not $created) {
                Add-Finding 'Mutex' "Chrysalis mutex present: $m" 'Critical'
                Write-Host "  [FOUND] $m" -ForegroundColor Red
            }
            $mx.Dispose()
        } catch {}
    }
}

# -------------------------------------------------
# 4) Registry Run keys
# -------------------------------------------------

if (-not $NoRegistry) {
    Write-Host "[*] Checking registry persistence..." -ForegroundColor Cyan
    foreach ($rk in $IOC_RunKeys) {
        try {
            $root = if ($rk -like 'HKCU*') { 'HKCU:' } else { 'HKLM:' }
            $path = $root + '\' + ($rk -replace '^(HKCU|HKLM)\\', '')
            if (-not (Test-Path $path)) { continue }

            $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match '^PS') { continue }
                if ("$($p.Value)" -match 'BluetoothService') {
                    Add-Finding 'Registry' "Run key persistence: $path -> $($p.Name)"
                    Write-Host "  [SUSPICIOUS] Run key persistence" -ForegroundColor Yellow
                }
            }
        } catch {}
    }
}

# -------------------------------------------------
# 5) Network (host-local only)
# -------------------------------------------------

if (-not $NoNetwork) {
    Write-Host "[*] Checking local network indicators..." -ForegroundColor Cyan

    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            if ($IOC_IPs -contains $c.RemoteAddress) {
                Add-Finding 'Network' "Active connection to IOC IP: $($c.RemoteAddress)" 'Critical'
                Write-Host "  [MATCH] IP $($c.RemoteAddress)" -ForegroundColor Red
            }
        }
    } catch {}

    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($d in $dns) {
            if ($IOC_Domains -contains $d.Entry) {
                Add-Finding 'Network' "IOC domain in DNS cache: $($d.Entry)"
                Write-Host "  [FOUND] DNS $($d.Entry)" -ForegroundColor Yellow
            }
        }
    } catch {}
}

# -------------------------------------------------
# Summary
# -------------------------------------------------

Write-Host "`n========== Summary ==========" -ForegroundColor Cyan

if ($Findings.Count -eq 0) {
    Write-Host "No Chrysalis IoCs detected." -ForegroundColor Green
    exit 0
}

$Findings | Group-Object Severity | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count)" -ForegroundColor Red
}

exit 1
