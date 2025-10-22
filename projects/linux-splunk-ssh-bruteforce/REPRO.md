## How to reproduce

1. Ensure Splunk is ingesting `/var/log/auth.log` into `index=linux_auth` as `sourcetype=linux_secure`.

2. Copy `configs/savedsearches.conf` into Splunk app local directory (or create alert via Splunk UI).
```
sudo cp configs/savedsearches.conf /opt/splunk/etc/apps/search/local/savedsearches.conf
sudo /opt/splunk/bin/splunk restart
```
3. Make script executable:
```
chmod +x scripts/simulate_bruteforce.sh
```
4. Run the script:
```
sudo bash scripts/simulate_bruteforce.sh 20 192.0.2.123
```
5. In Splunk Search run `queries/failed_ssh.spl` - you should see `failed_count` grouped by `src_ip`.

6. Open Triggered Alerts in Splunk UI - the PoC alert should be visible.
