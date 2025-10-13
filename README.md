# Hi - I'm Yurii Kholmohorov
Cybersecurity Trainee focused on defensive security, log analysis, SIEM and incident triage. Building hands-on projects to prepare for SOC L1 roles.

---

## Goal
Open to remote/hybrid entry-level cybersecurity positions (SOC L1, internships, apprenticeships).

---

## What’s inside
Each project under `projects/` contains:
- `README.md` - short reproduction steps  
- `configs/` - config files (sysmon, filebeat, logstash, etc.)  
- `queries/` - detection queries (SPL, KQL, Kibana DSL)  
- `data/` - anonymized sample logs  
- `reports/` - 1-page triage/incident reports  
- `screenshots/` - dashboards / alerts

---

## Featured projects
- **linux-splunk-ssh-bruteforce** - Failed SSH detection (Splunk).  
- **elk-filebeat-pipeline** - Filebeat → Logstash → Kibana pipeline.  
- **sysmon-triage** - Windows + Sysmon triage.

---

## Quick reproduce (high-level)
1. Deploy environment (Docker/VM or local Splunk/ELK).  
2. Load `projects/<name>/configs` and `data`.  
3. Run search from `projects/<name>/queries`, review `reports/` and `screenshots/`.

---

## 📬 Contact
- LinkedIn: https://www.linkedin.com/in/yurii-kholmohorov-09725628a
- Email: hibiscus11114@gmail.com

---

## License
MIT License - see `LICENSE` file.
