# Windows - Suspicious PowerShell Detection - Splunk PoC

## Overview
This repository is a minimal proof-of-concept (PoC) demonstrating detection of suspicious PowerShell activity using Splunk. The project contains the detection SPL queries, Splunk-forwarder and Sysmon configs used for log collection, a small safe payload used to trigger events, exported sample logs and screenshots proving the detections, and instructions for reproducing and manually validating the results (no automated alerts or triage included).

**Goal:** build and validate a PowerShell activity detection pipeline in Splunk using native Windows event logs and Sysmon telemetry.

---

## Repository layout
```
windows-splunk-suspicious-powershell/
├─ configs/
│ ├─ inputs.conf
│ └─ outputs.conf
│
├─ data/
│ └─ payload.ps1
│
├─ queries/
│ ├─ sysmon_process_create.spl
│ ├─ powershell_process_creation.spl
│ └─ suspicious_scriptblock.spl
│
├─ logs/
│ ├─ sysmon_event1_powershell.json
│ ├─ security_4688_powershell.json
│ └─ powershell_4104_scriptblock.json
│
├─ screenshots/
│ ├─ eventviewer_powershell_4104_scriptblock.png
│ ├─ eventviewer_security_4688_powershell.png
│ ├─ eventviewer_sysmon_event1_powershell.png
│ ├─ splunk_powershell_4104_scriptblock.png
│ ├─ splunk_security_4688_powershell.png
│ ├─ splunk_sysmon_event1_powershell.png
│ ├─ ss_estab_9997.png
│ ├─ ss_listen_9997.png
│ ├─ test_payload_execution_windows.png
│ ├─ uf_active_forwards.png
│ └─ vbox_port_forwarding.png
│
├─ README.md
└─ REPRO.md
   ```
---

## Detection queries (queries/*.spl)
Use these Splunk searches in `queries/`:

### `sysmon_process_create.spl`
Detect Sysmon process create events for PowerShell.
### `powershell_process_creation.spl`
Detect Windows Security process creation for PowerShell (4688).
### `suspicious_scriptblock.spl`
Detect suspicious PowerShell scriptblocks / commands (4104).

**Notes:**
- Filters NOT like "%\\windows\\system32%" and NOT like "%splunk%" are included to reduce benign noise in a lab/demo environment.

## Configs (configs/*.conf)
Files provided in configs/ are minimal examples for the UF. Use them as a starting point and adapt to your environment. Сonfiguration files should be located in `*/SplunkUniversalForwarder/etc/system/local/`

## Trigger events (data/payload.ps1)
A small safe payload used to trigger events. This payload is local and harmless. The data/payload.ps1 file must be placed in some folder on the machine that will host it. To run a simple HTTP server on a host (Linux/Ubuntu or Windows with Python) in the folder with the file, run:
```
python3 -m http.server 8001
```
To check server availability, run:
```
curl http://127.0.0.1:8001/payload.ps1
```
If the VM in VirtualBox has NAT, make sure that Port Forwarding is configured (host 8001 → guest 8001) or that the VM sees the host by IP.
To run the payload on Windows:
```
powershell -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:8001/payload.ps1')"
```
One line loads the script into memory and executes it (IEX = Invoke-Expression).

## logs/ - file descriptions
These are exported JSON results and used as evidence of ingestion and detection.
### logs/sysmon_event1_powershell.json
JSON export of the Sysmon EventID=1 (Process Create) for the executed PowerShell process.
### logs/security_4688_powershell.json
JSON export of the Windows Security EventID=4688 (New Process Created) for the PowerShell process.
### logs/powershell_4104_scriptblock.json
JSON export of the PowerShell Operational EventID=4104 containing ScriptBlockText or executed command content.

## screenshots/ - image descriptions
### screenshots/eventviewer_powershell_4104_scriptblock.png
Windows Event Viewer showing PowerShell 4104 ScriptBlock event.
### screenshots/eventviewer_security_4688_powershell.png
Windows Event Viewer showing Security 4688 process creation.
### screenshots/eventviewer_sysmon_event1_powershell.png
Windows Event Viewer showing Sysmon EventID=1 process creation.
### screenshots/splunk_powershell_4104_scriptblock.png
Splunk Search results for 4104 showing ScriptBlockText.
### screenshots/splunk_security_4688_powershell.png
Splunk Search results for 4688 events.
### screenshots/splunk_sysmon_event1_powershell.png
Splunk Search results for Sysmon EventID=1.
### screenshots/ss_estab_9997.png
ss/netstat output demonstrating connection to port 9997 (indexer listening).
### screenshots/ss_listen_9997.png
indexer listening on port 9997.
### screenshots/test_payload_execution_windows.png
screenshot of PowerShell execution of the test payload.
### screenshots/uf_active_forwards.png
splunk list forward-server output on the UF showing active forward-server.
### screenshots/vbox_port_forwarding.png
VirtualBox NAT port forwarding settings used in the lab.
