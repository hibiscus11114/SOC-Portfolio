# Linux SSH Brute-force Detection - Splunk PoC

## Overview
This repository is a minimal proof-of-concept (PoC) demonstrating detection of SSH brute-force attempts using Splunk. The project contains the detection SPL query, a saved Splunk alert configuration, a small simulator to generate failed-login events for testing, sample logs and screenshots proving the alert fired.

**Goal:** show how to detect repeated "Failed password" events from a single source IP and trigger a Splunk alert.

---

## Repository layout
linux-splunk-ssh-bruteforce/
├─ README.md
├─ REPRO.md
├─ LICENSE
├─ configs/
│ └─ savedsearches.conf
├─ queries/
│ └─ search_spl.txt
├─ data/
│ └─ simulate_bruteforce.sh
├─ logs/
│ ├─ raw_auth_tail.log
│ ├─ sample_auth.log
│ ├─ splunk_search_results.json
│ ├─ splunkd_tail.log
│ └─ triggered_alerts.txt
└─ screenshots/
├─ alert_triggered.png
├─ btool_output.png
├─ permissions_and_owner.png
├─ savedsearches_conf.png
├─ simulator_run.png
├─ splunk_events_list.png
├─ splunk_stats_results.png
├─ tail_authlog.png
└─ triggered_alerts_page.png

---

## Detection SPL (queries/search_spl.txt)
Use this search in Splunk (or save it as `queries/search_spl.txt`):

```spl
index=linux_auth sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) port (?<port>\d+)"
| stats count as failed_count earliest(_time) as first_seen latest(_time) as last_seen by src_ip
| where failed_count >= 5
```
Notes
- Replace index and sourcetype if your ingestion uses different names.
- Tune failed_count threshold to your environment: 5 is an example for lab/demo.
