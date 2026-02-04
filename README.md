# Chrysalis / Lotus Blossom IOC Checker

Single-file PowerShell incident response script for detecting **Chrysalis** backdoor artifacts associated with the **Lotus Blossom (Billbug)** threat actor.

This script is **self-contained**, **SYSTEM-safe**, and hardened for **live response / EDR execution**.  
All indicators are embedded directly in the script there is no external JSON or config files required, it's an all-in-one script!

---

## Overview

The script checks for known **Indicators of Compromise (IOCs)** documented by Rapid7 and subsequent community research, including:

- Malicious file hashes
- Known install paths
- DLL sideloading patterns
- Registry Run key persistence
- Named mutex (live implant indicator)
- Optional host-local network indicators

Source analysis:  
https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/

---

## What This Script Detects

### File-Based IOCs
- SHA-256 hashes associated with:
  - `BluetoothService.exe`
  - Encrypted shellcode blobs
  - Malicious DLLs (e.g. `log.dll`)
  - Supporting tooling dropped in `USOShared`

### Path-Based Indicators
- `%AppData%\Bluetooth\`
- `%AppData%\Bluetooth\BluetoothService.exe`
- `%ProgramData%\USOShared\*`

### DLL Sideloading
Detects the presence of:
- `BluetoothService.exe`
- `log.dll`

in the **same directory**, which is a core Chrysalis execution technique.

### Persistence
- Registry Run keys:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`

### Live Implant Indicator
- Mutex:
  - `Global\Jdhfv_1.0.1`

Presence strongly suggests the backdoor is currently running.

### Network (Host-Local Only)
- Active TCP connections to known IOC IPs
- IOC domains observed in the local DNS cache

> ⚠️ Network checks are **best-effort only** and do not replace proxy or firewall log analysis.

---

## Requirements

- Windows
- PowerShell **5.1 or newer**
- Administrator or SYSTEM context recommended

---

## How to Run

### 1. Open PowerShell

**As Administrator (recommended):**
- Right-click Start
- Select **Windows PowerShell (Admin)** or **Terminal (Admin)**

**As SYSTEM (EDR / PsExec):**
```cmd
psexec -s powershell.exe
```

### 2. (Optional) Allow Script Execution (Session Only)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 3. Run the Script
```powershell
.\Check-ChrysalisIoC.ps1
```

### 4. Optional: Scan Additional Directories
```powershell
.\Check-ChrysalisIoC.ps1 -ScanPaths "C:\Users","C:\ProgramData"
```

### 5. Optional: Disable Specific Checks

Disable registry checks:
```powershell
.\Check-ChrysalisIoC.ps1 -NoRegistry
```

Disable mutex checks:
```powershell
.\Check-ChrysalisIoC.ps1 -NoMutex
```

Disable network checks:
```powershell
.\Check-ChrysalisIoC.ps1 -NoNetwork
```
Output & Exit Codes
```Console Output

[FOUND] → IOC path or artifact present

[MATCH] → Confirmed hash or network IOC

[SUSPICIOUS] → High-confidence behavioral indicator

Exit Codes
Exit Code	Meaning
0	No IOCs detected
1	One or more IOCs detected
```
---

### This makes the script suitable for:

- EDR automation
- Fleet sweeps
- SOAR pipelines

---

### How to Interpret Results

Any Critical finding = assume compromise

Preserve disk and memory before remediation

Pivot immediately to:

- Proxy logs
- Firewall logs
- EDR telemetry

This script is a triage and confirmation tool, not a remediation utility.

---

## Design Goals

- Single-file deployment
- No external dependencies
- SYSTEM / live-response safe
- TOCTOU-safe filesystem access
- Defensive error handling
- IR-grade signal quality

## Disclaimer

This tool is provided for defensive security and incident response purposes only.
Detection coverage is limited to known public indicators and host-local visibility.

---

## Author Notes

If this script flags a system:

- Treat it as **potentially compromised**
- Perform full incident response
- Do **not** rely on this script alone for eradication
