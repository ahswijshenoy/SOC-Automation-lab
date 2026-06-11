# 🛡️ SOC Automation Lab - End-to-End Threat Detection & Response

## 📋 Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Workflow 1 - Mimikatz Detection & Alert Pipeline](#workflow-1---mimikatz-detection--alert-pipeline)
- [Workflow 2 - Brute Force Detection & IP Blocking](#workflow-2---brute-force-detection--ip-blocking)
- [AWS Infrastructure](#aws-infrastructure)
- [Component Deep Dive](#component-deep-dive)
- [Custom Detection Rules](#custom-detection-rules)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Difficulties & How I Solved Them](#difficulties--how-i-solved-them)
- [Current Drawbacks & Limitations](#current-drawbacks--limitations)
- [Future Plans](#future-plans)
- [Screenshots](#screenshots)
- [Configuration Files](#configuration-files)
- [Tools & Technologies](#tools--technologies)
- [What I Learned](#what-i-learned)
- [Author](#author)

---

## Overview

A fully automated Security Operations Centre (SOC) lab built on AWS from scratch. This project implements two complete security automation workflows that detect threats, enrich indicators of compromise, create cases, notify analysts, and execute active response - all without manual intervention.

**Why I built this:** As a cybersecurity master's graduate, I wanted to go beyond theoretical knowledge and build something that mirrors what real SOC teams operate daily. Every component was deployed, configured, broken, debugged, and rebuilt by hand - no pre-built templates, no Docker shortcuts.

**What makes this different from tutorial projects:**
- Multiple EC2 instances communicating across a real AWS VPC - not a single-machine Docker setup
- Two distinct automation workflows handling different threat types
- Real troubleshooting of production issues (Cassandra memory crashes, Elasticsearch JVM failures, API authentication chains, active response formatting)
- Custom detection rules written from scratch, not copied from default rulesets

---

## Architecture

```
                        ┌─────────────────────────────┐
                        │     Windows 10 VM           │
                        │  ┌─────────────────────┐    │
                        │  │  Sysmon (Event Logs)│    │
                        │  │  Wazuh Agent (001)  │    │ 
                        │  └─────────────────────┘    │
                        └────────────┬────────────────┘
                                     │ TCP 1514
                                     ▼
┌────────────────────────────────────────────────────────────────┐
│                        AWS VPC                                 │
│                                                                │
│  ┌───────────────────┐    ┌──────────────────┐                 │
│  │  Wazuh Manager    │    │  Cassandra +     │                 │
│  │  172.31.12.1      │    │  Elasticsearch   │                 │
│  │                   │    │  172.31.2.3      │                 │
│  │  • Wazuh 4.7.5    │    │                  │                 │
│  │  • Indexer        │    │  • Cassandra 4.x │                 │
│  │  • Dashboard      │    │  • ES 7.x        │                 │
│  │  • Custom Rules   │    └────────┬─────────┘                 │
│  │  • Active Response│             │ 9042/9200                 │
│  └──┬──────────┬─────┘             │                           │
│     │          │              ┌────▼─────────────┐             │
│     │ Webhook  │              │  TheHive 5.7     │             │
│     │          │              │  172.31.15.110   │             │
│     │          │              │  Case Management │             │
│  ┌──▼──────────▼──┐           └──────────────────┘             │
│  │  Ubuntu Agent  │                                            │
│  │  172.31.24.142 │                                            │
│  │  Agent (002)   │                                            │
│  │  AR Target     │                                            │
│  └────────────────┘                                            │
└────────────────────────────────────────────────────────────────┘
          │                           │
          ▼                           ▼
┌──────────────────┐        ┌──────────────────┐
│  Shuffle SOAR    │        │  VirusTotal API  │
│  (Cloud)         │        │  v3              │
│  • Workflow 1    │        │  • Hash Lookup   │
│  • Workflow 2    │        │  • IP Reputation │
└──────────────────┘        └──────────────────┘
```


## Workflow 1 - Mimikatz Detection & Alert Pipeline

**Purpose:** Detect credential dumping tools on Windows endpoints and automatically create enriched security cases.

**Trigger:** Wazuh custom rule 100003 fires when Mimikatz is executed (Sysmon Event ID 1)

### How it works step by step:

```
Windows VM                    Wazuh Manager                 Shuffle SOAR
    │                              │                              │
    │  1. User runs Mimikatz       │                              │
    │  2. Sysmon logs Event ID 1   │                              │
    │  3. Agent forwards event --> │                              │
    │                              │   4. Custom rule 100003      │
    │                              │      fires (Level 15)        │
    │                              │   5. Webhook sends alert --> │
    │                              │                              │  6. Regex extracts SHA256
    │                              │                              │  7. VirusTotal hash lookup
    │                              │                              │  8. TheHive case created
    │                              │                              │  9. Email sent to analyst
```

### Shuffle Workflow Nodes:

| Node | Tool | Action | Purpose |
|------|------|--------|---------|
| Wazuh-alerts | Webhook | Receive alert | Entry point — receives JSON alert from Wazuh |
| SHA256-HASH | Shuffle Tools | Regex capture group | Extracts SHA256 hash from `eventdata.hashes` field |
| Virustotal v3 | VirusTotal | Get a hash report | Checks file hash reputation against VT database |
| Email 1 | Email | Send email | Notifies SOC analyst with alert details |
| TheHive1 | TheHive | Post create alert | Creates case with severity, MITRE tags, and context |

### Wazuh Integration Config:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_[REDACTED]</hook_url>
  <rule_id>100003</rule_id>
  <alert_format>json</alert_format>
</integration>
```

### SHA256 Hash Extraction:
- **Input:** `$exec.all_fields.data.win.eventdata.hashes`
- **Regex:** `SHA256=([0-9A-Fa-f]{64})`
- **Output:** Pure SHA256 hash string passed to VirusTotal

### TheHive Alert Fields:
```json
{
  "title": "Mimikatz Execution Detected - Process Created",
  "description": "Full alert context from Wazuh",
  "severity": 3,
  "tlp": 2,
  "pap": 2,
  "source": "Wazuh",
  "sourceRef": "$exec.all_fields.id",
  "status": "New",
  "tags": ["T1003"],
  "type": "intern"
}
```

## Workflow 2 - Brute Force Detection & IP Blocking

**Purpose:** Detect SSH brute force attacks and give the SOC analyst a one-click option to block the attacker's IP.

**Trigger:** Wazuh rule 5712 fires after multiple failed SSH login attempts from the same source IP

### How it works step by step:

```
Attacker                  Ubuntu VM (Agent 002)         Wazuh Manager
    │                              │                         │
    │  1. Failed SSH attempts -->  │                         │
    │                              │  2. auth.log entries    │
    │                              │  3. Agent forwards -->  │
    │                              │                         │  4. Rule 5712 fires
    │                              │                         │     (Level 10)
    │                              │                         │
                                                             │
    Shuffle SOAR                                             │
    │  5. Webhook receives alert <─────────────────────────  │
    │  6. GET API — authenticate with Wazuh API              │
    │  7. VirusTotal — check attacker IP reputation          │
    │  8. User Input — email analyst "Block this IP?"        │
    │  9. Analyst clicks APPROVE                             │
    │  10. Wazuh Active Response — firewall-drop on agent    │
    │                              │                         │
    │                              │  <── iptables DROP rule │
    │                              │       added for srcip   │
```

### Shuffle Workflow Nodes:

| Node | Tool | Action | Purpose |
|------|------|--------|---------|
| Wazuh-Alerts | Webhook | Receive alert | Entry point — brute force alert from Wazuh |
| Get API | HTTP | Curl | Authenticates with Wazuh API, retrieves JWT token |
| Virustotal v3 | VirusTotal | Get IP address report | Checks attacker IP reputation |
| User Input | Shuffle | Email approval | Sends email with approve/decline buttons |
| Wazuh 1 | Wazuh | Run command | Executes firewall-drop via Wazuh API |

### Active Response Body:
```json
{
  "command": "firewall-drop180",
  "arguments": [],
  "alert": {
    "data": {
      "srcip": "$exec.all_fields.data.srcip"
    }
  }
}
```

### Brute Force Simulation:
```bash
# From Wazuh Manager to Ubuntu Agent
for i in $(seq 1 10); do
  sshpass -p 'wrongpass' ssh -o StrictHostKeyChecking=no fakeuser@172.31.24.142 2>/dev/null
done
```

### Verification:
```bash
# On Ubuntu Agent — check if IP was blocked
sudo iptables -L INPUT -n
# Output: DROP all -- 172.31.12.1 0.0.0.0/0

# After 180 seconds, auto-unblock occurs
# Wazuh logs: "Host Unblocked by firewall-drop Active Response"
```

## AWS Infrastructure

### EC2 Instances

| Instance | Role | Private IP | OS | Key Services |
|----------|------|-----------|-----|-------------|
| ip-172-31-12-1 | Wazuh Manager | 172.31.12.1 | Ubuntu 24.04 | Wazuh Manager 4.7.5, Wazuh Indexer, Wazuh Dashboard, Filebeat |
| ip-172-31-2-3 | Database Server | 172.31.2.3 | Ubuntu 24.04 | Apache Cassandra 4.x, Elasticsearch 7.x |
| ip-172-31-15-110 | Case Management | 172.31.15.110 | Ubuntu 24.04 | TheHive 5.7 |
| ip-172-31-24-142 | Test Agent | 172.31.24.142 | Ubuntu 24.04 | Wazuh Agent (002), Active Response target |
| SOC-LAb-Windows | Windows Endpoint | 10.0.2.15 (NAT) | Windows 10 | Sysmon, Wazuh Agent (001) |

### Networking

- All EC2 instances communicate via AWS VPC private IPs
- Elastic IP assigned to Wazuh Manager - prevents agent disconnection when instances restart
- Security groups configured for inter-instance communication on required ports
- Windows VM connects via NAT through VirtualBox to Wazuh Manager's public IP

### Key Ports

| Port | Protocol | Service |
|------|----------|---------|
| 1514 | TCP | Wazuh agent communication |
| 1515 | TCP | Wazuh agent enrollment |
| 9042 | TCP | Cassandra CQL |
| 9200 | TCP | Elasticsearch REST API |
| 9000 | TCP | TheHive web interface |
| 55000 | TCP | Wazuh API |
| 443 | TCP | Wazuh Dashboard (HTTPS) |

---

## Component Deep Dive

### Wazuh 4.7.5 - SIEM & IDS

Installed using the all-in-one deployment script with the `-i` flag required for Ubuntu 24.04:
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a -i
```

Key configurations in `/var/ossec/etc/ossec.conf`:
- Archive logging enabled (`logall` and `logall_json` set to yes) for full event retention
- Two Shuffle webhook integrations - one per workflow
- Active response configured with `firewall-drop` command and 180-second timeout
- Sysmon event channel collection from Windows agent

### Sysmon — Endpoint Telemetry

Installed on Windows 10 VM to capture detailed process-level events:
- **Event ID 1** - Process Creation (captures image path, hashes, command line, parent process)
- **Event ID 10** - Process Access (captures source/target process, granted access rights)

Windows agent `ossec.conf` includes:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### TheHive 5.7 - Case Management

Self-hosted on a dedicated EC2 instance, connected to:
- **Cassandra** on 172.31.2.3:9042 — stores case data
- **Elasticsearch** on 172.31.2.3:9200 — provides search indexing

Configuration at `/etc/thehive/application.conf` points to the database server's private IP.

### Shuffle - SOAR

Cloud-hosted at shuffler.io. Two separate workflows with independent webhook URLs. Each workflow receives alerts only for its specific rule ID, keeping the logic clean and separated.

---

## Custom Detection Rules

Located at `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,syslog,sshd,">

  <!-- Mimikatz Process Access Detection (Sysmon Event ID 10) -->
  <rule id="100002" level="15">
    <if_group>sysmon_event10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected - Process Access</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

  <!-- Mimikatz Process Creation Detection (Sysmon Event ID 1) -->
  <rule id="100003" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Execution Detected - Process Created</description>
    <group>windows,sysmon,credential_access,</group>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

</group>
```

### Why two rules?

- **Rule 100003 (Event ID 1)** catches when Mimikatz is executed directly - this event includes file hashes, which are essential for the VirusTotal enrichment workflow
- **Rule 100002 (Event ID 10)** catches when another process accesses Mimikatz - useful for detecting process injection techniques but does not include file hashes

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Detection Method | Wazuh Rule |
|-------------|------|--------|-----------------|------------|
| T1003 | OS Credential Dumping | Credential Access | Mimikatz execution via Sysmon Event ID 1 | 100003 |
| T1003 | OS Credential Dumping | Credential Access | Process access to Mimikatz via Sysmon Event ID 10 | 100002 |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation | Process access monitoring via Sysmon Event ID 10 | 92910 (built-in) |
| T1110 | Brute Force | Credential Access | Multiple failed SSH logins from same source | 5712 (built-in) |
| T1110.001 | Password Guessing | Credential Access | Invalid user SSH login attempts | 5710 (built-in) |

---

## Difficulties & How I Solved Them

### 1. Cassandra Refuses to Start via systemctl
**Problem:** After installing Cassandra on the database server, `systemctl start cassandra` would fail silently with no useful error messages.

**Root cause:** The EC2 instance had only 15GB of disk space. Cassandra's commit logs and data directory consumed all available space.

**Solution:** Expanded the EBS volume from 15GB to 40GB, added 4GB swap space, and configured Cassandra to start via crontab using `@reboot sudo -u cassandra cassandra -R` since the systemd unit was unreliable.

### 2. Elasticsearch JVM Crashes on Startup
**Problem:** Elasticsearch would crash immediately after starting with JVM garbage collection errors.

**Root cause:** Three separate issues - the `/var/log/elasticsearch/` directory didn't exist, deprecated GC logging options in `jvm.options` were causing errors on the installed JVM version, and no heap size was configured (defaulting to an unsustainable amount on a small instance).

**Solution:** Created the missing log directory, commented out all `8:-XX:+PrintGC*` lines in `jvm.options`, and created `/etc/elasticsearch/jvm.options.d/heap.options` with `-Xms2g` and `-Xmx2g`.

### 3. Windows Agent Keeps Disconnecting
**Problem:** The Windows 10 VM Wazuh agent would show as "Disconnected" every time the Wazuh EC2 instance was stopped and restarted.

**Root cause:** EC2 instances get a new public IP every time they're stopped and started. The Windows agent had the old public IP configured.

**Solution:** Assigned an Elastic IP to the Wazuh Manager instance, giving it a permanent public IP. Updated the Windows agent `ossec.conf` with the Elastic IP. Never had this problem again.

### 4. Wazuh Manager Won't Start - "Invalid element 'rule_id'"
**Problem:** After editing `ossec.conf` to add active response configuration, `wazuh-manager` failed to start with a cryptic error about invalid configuration elements.

**Root cause:** Used `<rule_id>` (singular) instead of `<rules_id>` (plural) in the active response block. Later discovered that `<rules_id>` is also not valid inside `<integration>` blocks for Wazuh 4.7.5 - the correct tag there is `<rule_id>`.

**Solution:** The correct tag depends on context - `<rule_id>` for integration blocks, `<rules_id>` for active response blocks. Learned to always check `journalctl -xeu wazuh-manager.service` for the exact error before guessing.

### 5. Active Response: "Cannot read 'srcip' from data"
**Problem:** The Shuffle workflow would successfully send the active response command to Wazuh (200 OK), but the firewall-drop script on the agent would fail with "Cannot read 'srcip' from data."

**Root cause:** The Wazuh active response API expects the IP to be in `alert.data.srcip`, not in the `arguments` array. The firewall-drop script specifically reads from that JSON path.

**Solution:** Changed the Wazuh node body in Shuffle from `{"arguments": ["8.8.8.8"]}` to `{"alert": {"data": {"srcip": "8.8.8.8"}}}`. Also discovered a typo where `srcip` was accidentally typed as `scrip` - a single missing letter that took hours to find.

### 6. SHA256 Hash Extraction Failing in Shuffle
**Problem:** The regex node in Shuffle would return `found: false` even though the alert clearly contained hash data.

**Root cause:** Multiple issues stacked together:
1. The input path was `$exec.all_fields.data.win.hashes`  missing `eventdata` in the path
2. The workflow was triggering on Sysmon Event ID 10 alerts (process access) which don't contain file hashes — only Event ID 1 (process creation) has hashes
3. Shuffle's dropdown menu doesn't show deeply nested fields, so the correct path had to be typed manually

**Solution:** Changed the integration to only trigger on rule 100003 (Event ID 1), and corrected the input path to `$exec.all_fields.data.win.eventdata.hashes`. The regex `SHA256=([0-9A-Fa-f]{64})` then successfully extracted the hash.

### 7. Sysmon Group Name: Dash vs Underscore
**Problem:** Custom Wazuh rule with `<if_group>sysmon-event1</if_group>` never matched any events.

**Root cause:** Wazuh uses underscores in Sysmon group names (`sysmon_event1`), not dashes (`sysmon-event1`). This is not documented prominently.

**Solution:** Changed to `<if_group>sysmon_event1</if_group>`. Discovered this by running `grep -ri "sysmon" /var/ossec/ruleset/rules/ | grep "group"` to see the exact group names Wazuh uses internally.

### 8. TheHive Status: "AlertStatus NEW not found"
**Problem:** TheHive returned a 404 error when Shuffle tried to create an alert with status "NEW".

**Root cause:** TheHive 5 is case-sensitive for status values. It expects `New` (capital N, lowercase ew), not `NEW` (all caps).

**Solution:** Changed the status field from `NEW` to `New` in the Shuffle TheHive node configuration.

### 9. SSH Port Conflict Kills Wazuh Dashboard
**Problem:** Wazuh Dashboard stopped loading after attempting to add SSH on port 443 as a workaround for ISP blocking port 22.

**Root cause:** SSH was configured to listen on port 443, which is the same port Wazuh Dashboard uses for HTTPS. The SSH daemon grabbed the port first, preventing the dashboard from binding.

**Solution:** Reverted SSH to port 22 only in `/etc/ssh/sshd_config`, restarted SSH, then restarted `wazuh-dashboard`. Lesson: always check for port conflicts before changing SSH port.

### 10. Wazuh API Authentication Chain
**Problem:** Shuffle couldn't authenticate with the Wazuh API. Default credentials `wazuh:wazuh` didn't work, and the password wasn't stored in any obvious configuration file.

**Root cause:** The all-in-one installer generates random passwords stored in `wazuh-install-files.tar` which was saved in the ubuntu home directory.

**Solution:** Extracted passwords using `tar -xf /home/ubuntu/wazuh-install-files.tar -C /tmp` then `cat /tmp/wazuh-install-files/wazuh-passwords.txt`. The Wazuh API user had a complex auto-generated password that needed to be used in both Shuffle and the dashboard configuration.

---

## Current Drawbacks & Limitations

### Things that don't work perfectly yet:

1. **VirusTotal hash lookup is inconsistent** - The regex extraction works and the hash is sent to VirusTotal, but the specific Mimikatz build used in testing may not be in VirusTotal's database, resulting in a 404. In a real environment with actual malware samples, this would return results.

2. **Only two custom detection rules** - Real SOC environments have hundreds of detection rules covering different attack techniques. This lab only detects Mimikatz and brute force SSH, which is a narrow detection surface.

3. **Brute force simulation uses internal IPs** - The brute force test attacks from the Wazuh Manager (172.31.12.1) to the Ubuntu agent, which means the "attacker" IP is the SIEM itself. In production, the attacker would be an external IP with actual threat intelligence available.

4. **No SSL certificate validation** - All internal API calls use `ssl_verify: false` or `-k` flag. Acceptable for a lab but not for production.

5. **Single point of failure** - If the Wazuh Manager instance goes down, all detection, alerting, and response stops. No redundancy or clustering.

6. **Windows VM uses NAT networking** - The Windows endpoint connects through VirtualBox NAT, which means the agent's IP shows as 10.0.2.15. In a real deployment, you'd want bridged networking or a proper VPN.

7. **No log retention policy** - Archives grow indefinitely with no rotation or lifecycle management configured.

8. **TheHive alert deduplication** - Running the same attack multiple times creates duplicate alerts. The sourceRef field prevents exact duplicates but the same attack pattern generates unique alert IDs each time.

---

## Future Plans

### Short-term (next 2 weeks):
- [ ] Add detection rules for PowerShell encoded command execution (T1059.001)
- [ ] Add detection rules for suspicious service creation (T1543)
- [ ] Add detection rules for registry modification persistence (T1547)
- [ ] Write a formal Incident Response report for the Mimikatz detection scenario
- [ ] Add LSASS credential dumping detection (T1003.001)

### Medium-term (next 1-2 months):
- [ ] Integrate Cortex with TheHive for automated IOC analysis
- [ ] Add YARA rules for file-based malware detection
- [ ] Deploy a vulnerability scanner (OpenVAS) and integrate results with TheHive
- [ ] Build a phishing email analysis workflow
- [ ] Add network-based detection using Suricata IDS

### Long-term (3+ months):
- [ ] Migrate Shuffle workflows to a self-hosted instance
- [ ] Implement Wazuh cluster for high availability
- [ ] Add ELK Stack for advanced log visualization
- [ ] Build a threat hunting dashboard with custom Kibana visualizations
- [ ] Automate the entire lab deployment using Terraform and Ansible

---

## Screenshots

### Architecture 
--
<img width="1519" height="1587" alt="13 drawio" src="https://github.com/user-attachments/assets/ab83bc25-8610-4422-8dba-0f1338792a22" />


### AWS Infrastructure
--

<img width="1917" height="536" alt="AWS_Instances" src="https://github.com/user-attachments/assets/08df6d3b-95f5-42ef-b4e2-be412a12aa46" />


### Workflow 1 — Mimikatz Detection

# Sysmon Event
--
<img width="1917" height="992" alt="Sysmon_event" src="https://github.com/user-attachments/assets/d05b776e-bc71-4773-815e-1d47c4fdf959" />


# Mimikatz Execution 
--
<img width="1072" height="330" alt="MIMIkatz" src="https://github.com/user-attachments/assets/ab0459fb-71cb-4686-98bd-5809b1b2a015" />


# Shuffle Workflow 1
--
<img width="1139" height="816" alt="hive_workflow"  src="https://github.com/user-attachments/assets/b5d4106a-e02c-407f-8194-21241ff33243" />


# Shuffle Execution
--
<img width="487" height="815" alt="stitich1" src="https://github.com/user-attachments/assets/dfc7c51a-688d-419e-ae61-31c966622c4a" />


# SHA256 Hash Extraction
--
<img width="490" height="475" alt="stitch2" src="https://github.com/user-attachments/assets/e35ce81a-bd0c-4f4d-a3aa-db586e325282" />

 <img width="1441" height="747" alt="stitch3" src="https://github.com/user-attachments/assets/2fbfba20-93cf-4cf4-8e8a-1382ba20cf02" />

<img width="1412" height="772" alt="Stitch4" src="https://github.com/user-attachments/assets/0236cb4c-de8c-4719-89f3-5ee66d5d1ab9" />


# Email Alert
--
<img width="1912" height="680" alt="email_ss" src="https://github.com/user-attachments/assets/1bc82de9-53cc-4f77-a704-9e51ad11fe8e" />


# The Hive Dashboard 
--
<img width="1912" height="825" alt="hive_dashboard_before" src="https://github.com/user-attachments/assets/fb4d4f4e-3658-4030-92de-b5f42ab193cf" />


# The hive Alert
--
<img width="1907" height="935" alt="hive_dashboard" src="https://github.com/user-attachments/assets/72ca51bb-84da-49d5-bd71-da14b77b7dbf" />


# Wazuh Dashboard 
--
<img width="1917" height="995" alt="Wazuh-Dashboard" src="https://github.com/user-attachments/assets/9fd20f7c-1b0c-411f-bf53-61e8b710f688" />


# Wazuh Alert
--
<img width="1917" height="992" alt="Mimikatz_alerts wazuh_dashboard" src="https://github.com/user-attachments/assets/6f451bee-9e2b-435b-9f72-056a4958675e" />




### Workflow 2 - Brute Force IP Blocking
# Brute Force Terminal
--
<img width="925" height="150" alt="bruteforce command" src="https://github.com/user-attachments/assets/b2ce1e09-0991-4057-aa91-7bac3181ef38" />


# Wazuh Brute Force Alert 
--
<img width="632" height="811" alt="wazuh_alert" src="https://github.com/user-attachments/assets/eff5151e-ad3d-4538-854d-2f7987d86c49" />


# Shuffle Workflow 2
--
<img width="1901" height="802" alt="workflow" src="https://github.com/user-attachments/assets/3fb35958-7023-415e-bc3a-1ee78e9ff0c4" />


# Shuffle Execution
--
<img width="482" height="731" alt="stitch1" src="https://github.com/user-attachments/assets/9065224f-741f-4708-b40e-bbf02350e2e3" />

<img width="1429" height="802" alt="stitich2" src="https://github.com/user-attachments/assets/593874c3-9a2b-4a89-9198-9d2b19108aeb" />

<img width="1415" height="804" alt="stitch3" src="https://github.com/user-attachments/assets/84a6326e-9d98-4162-a194-762704c0afb4" />

<img width="1421" height="847" alt="stitch4" src="https://github.com/user-attachments/assets/cd9eaabe-d47d-4dcb-896f-ee5a03134ce4" />


# Alert Email 
--
<img width="1591" height="644" alt="mail_userinput" src="https://github.com/user-attachments/assets/0e7334dc-21b1-46fd-8688-5cf02319bb84" />


# Block IP
--
<img width="1689" height="404" alt="userinupt" src="https://github.com/user-attachments/assets/161403a5-d63a-4ed3-aeb6-f7cc768b394b" />


# iptables Blocked 
--
<img width="710" height="261" alt="ip_table_blocked" src="https://github.com/user-attachments/assets/a1a7768c-1f1e-4f97-a872-f5ed13d3f51b" />

<img width="727" height="326" alt="tbleblock" src="https://github.com/user-attachments/assets/6cc9da74-875a-44ec-b264-f44ea229b406" />


 # Active Response Log
--
<img width="677" height="341" alt="logs" src="https://github.com/user-attachments/assets/020df949-bd82-4593-a2d9-6d1afd024e64" />

### Sysmon 
# Sysmon Event Viewer
--
<img width="1917" height="992" alt="Sysmon_event" src="https://github.com/user-attachments/assets/3d316fca-6216-4b3c-9470-beee2edf0b15" />

---

## Configuration Files

### Custom Detection Rules
See [configs/local_rules.xml](configs/local_rules.xml)

### Wazuh Integration Configuration (Shuffle webhooks)
See [configs/ossec-integrations.xml](configs/ossec-integrations.xml)

### Active Response Configuration
See [configs/active-response.xml](configs/active-response.xml)

---

## Tools & Technologies

| Category | Tool | Version | Purpose |
|----------|------|---------|---------|
| SIEM | Wazuh | 4.7.5 | Log collection, analysis, detection, active response |
| SOAR | Shuffle | Cloud | Workflow automation, API orchestration |
| Case Management | TheHive | 5.7 | Alert management, case tracking |
| Threat Intel | VirusTotal | API v3 | Hash and IP reputation lookups |
| Endpoint | Sysmon | Latest | Process-level telemetry on Windows |
| Database | Cassandra | 4.x | TheHive data storage |
| Search | Elasticsearch | 7.x | TheHive search indexing |
| Cloud | AWS EC2 | - | Infrastructure hosting |
| OS | Ubuntu | 24.04 | Server operating system |
| OS | Windows | 10 | Endpoint under monitoring |

---

## What I Learned

**Technical skills:**
- Deploying and managing a distributed SIEM architecture across multiple cloud instances
- Writing custom detection rules using PCRE2 regex and MITRE ATT&CK mapping
- Building SOAR automation workflows that chain multiple security tools via APIs
- Understanding the Wazuh active response mechanism - from API call to iptables rule
- Troubleshooting distributed systems where the error on one machine is caused by configuration on another

**Soft skills:**
- Debugging complex multi-component systems where a single typo (`scrip` vs `srcip`) can break an entire pipeline
- Reading documentation when things don't work - Wazuh 4.7.5 changed several config tags from earlier versions
- Persistence - this project had dozens of failures before each component worked correctly
- Understanding that security tools are only as good as their configuration

**Key insight:** The hardest part of building a SOC isn't installing the tools - it's making them talk to each other correctly. Every integration point (Wazuh → Shuffle, Shuffle → VirusTotal, Shuffle -> TheHive, Shuffle → Wazuh API) has its own authentication, data format, and failure modes. Real SOC engineering is debugging those connections.

---

## Author

**Ashwij Shenoy Bantwal**

Master of Cybersecurity - RMIT University, Melbourne

- 🔗 [LinkedIn](https://www.linkedin.com/in/ashwij-shenoy-bantwal)
- 📧 ashwij2142@gmail.com
- 🐙 [GitHub](https://github.com/ashwij)

---

*This project was built entirely from scratch as a portfolio project. No pre-built templates or Docker containers were used. Every component was manually deployed, configured, and debugged on AWS EC2 instances.*

