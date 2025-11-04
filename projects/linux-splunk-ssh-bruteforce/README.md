# Linux - SSH Brute-force Detection - Splunk PoC

## Overview
This repository is a minimal proof-of-concept (PoC) demonstrating detection of SSH brute-force attempts using Splunk. The project contains the detection SPL query, a saved Splunk alert configuration, a small simulator to generate failed-login events for testing, sample logs and screenshots proving the alert fired.

**Goal:** show how to detect repeated "Failed password" events from a single source IP and trigger a Splunk alert.

---

## Repository layout
```
linux-splunk-ssh-bruteforce/
├── README.md
├── REPRO.md
├── LICENSE
│
├── configs/
│ └── savedsearches.conf
│
├── queries/
│ └── search_spl.txt
│
├── data/
│ └── simulate_bruteforce.sh
│
├── logs/
│ ├── raw_auth_tail.log
│ ├── sample_auth.log
│ ├── splunk_search_results.json
│ ├── splunkd_tail.log
│ └── triggered_alerts.txt
│
└── screenshots/
│ ├── alert_triggered.png
│ ├── btool_output.png
│ ├── permissions_and_owner.png
│ ├── savedsearches_conf.png
│ ├── simulator_run.png
│ ├── splunk_events_list.png
│ ├── splunk_stats_results.png
│ ├── tail_authlog.png
│ └── triggered_alerts_page.png
```
---

## Detection queries (queries/failed_ssh.spl)
Use this search in Splunk (or save it as `queries/failed_ssh.spl`):

```
index=linux_auth sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) port (?<port>\d+)"
| stats count as failed_count earliest(_time) as first_seen latest(_time) as last_seen by src_ip
| where failed_count >= 5
```
**Notes:**
- Replace index and sourcetype if your ingestion uses different names.
- Tune failed_count threshold to your environment: 5 is an example for lab/demo.

## Saved alert (configs/savedsearches.conf)
A PoC savedsearch that you can import into Splunk:
```
﻿[Failed SSH brute-force (PoC)]
search = index=linux_auth sourcetype=linux_secure "Failed password" 
| rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+) port (?<port>\d+)" 
| stats count as failed_count earliest(_time) as first_seen latest(_time) as last_seen by src_ip 
| where failed_count >= 5
dispatch.earliest_time = -30m
dispatch.latest_time = now
enableSched = 1
cron_schedule = */5 * * * *
counttype = number of results
relation = greater than
quantity = 0
actions = logevent, addtotriggeredalerts
action.logevent = 1
action.logevent.param.index = main
action.logevent.param.host = soc-alert
action.logevent.param.source = ssh_bruteforce alert
action.logevent.param.event = Failed SSH brute-force from .src_ip$ count=.failed_count$
action.addtotriggeredalerts = 1
alert.track = 1
alert.expires = 24h
alert.digest_mode = 0
alert.suppress = 1
alert.suppress.fields = src_ip
alert.suppress.period = 10m
disabled = 0
```

## Simulate bruteforce script (data/simulate_bruteforce.sh)
Simple simulator script that emits multiple Failed password SSH lines to syslog (via logger) to simulate a brute-force sequence from a single source IP.
```
#!/bin/bash
# Usage: sudo bash simulate_bruteforce.sh <attempts> [ip]
ATTEMPTS=${1:-20}
IP=${2:-127.0.0.1}
USER="invaliduser"

for (( i=1; i<=ATTEMPTS; i++ )); do
  MSG="sshd[$$]: Failed password for invalid user ${USER} from ${IP} port $((1024 + RANDOM % 40000)) ssh2"
  logger -p authpriv.notice -t sshd "$MSG"
  sleep 0.2
done

echo "Simulated $ATTEMPTS failed SSH attempts from $IP"
```

## logs/ - file descriptions
### logs/raw_auth_tail.log
Raw tail output of /var/log/auth.log captured during the script run.
### logs/sample_auth.log
Trimmed sample of auth.log entries used for local testing.
### logs/splunk_search_results.json
JSON export of Splunk search results.
### logs/splunkd_tail.log
Extract (tail) of splunkd.log captured while the saved search ran.
### logs/triggered_alerts.txt
Plain text export of the triggered alerts listing.

## screenshots/ - image descriptions
### screenshots/alert_triggered.png
Splunk UI screenshot showing an opened alert result
### screenshots/btool_output.png
Terminal output of sudo /opt/splunk/bin/splunk btool savedsearches list --debug (or btool ... --debug). Proves which configuration file Splunk actually loaded for the saved search
### screenshots/permissions_and_owner.png
Terminal output showing file permissions and ownership for savedsearches.conf. Demonstrates Splunk/user permissions and that Splunk has access to the log file.
### screenshots/savedsearches_conf.png
Cat /opt/splunk/etc/apps/search/local/savedsearches.conf output (the exact savedsearch stanza for the PoC).
### screenshots/simulator_run.png
Terminal output of the simulator script run; e.g., Simulated 20 failed SSH attempts from 192.0.2.123.
### screenshots/splunk_events_list.png
Splunk Search - Events view with Failed password events listed from /var/log/auth.log, showing per-event content and source.
### screenshots/splunk_stats_results.png
Splunk Search - Statistics view showing aggregated row(s) with src_ip, failed_count, first_seen, last_seen. For example, 192.0.2.123 with failed_count = 20.
### screenshots/tail_authlog.png
Terminal tail of /var/log/auth.log displaying the series of Failed password messages created by the simulator.
### screenshots/triggered_alerts_page.png
Splunk UI - Triggered Alerts page listing the alert Failed SSH brute-force (PoC) with time and severity.
