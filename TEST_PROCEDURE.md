# SIEM Test Procedure - Test Logbook

> **Document to be filled manually during live SIEM testing**

---

## 1. Test Preparation

### 1.1 Test Environment

```
Date: _______________
Tester: _______________
Target SIEM: □ LogPoint □ Splunk □ Elastic □ QRadar □ Other: _______
SIEM Version: _______________
Environment: □ Prod □ Staging □ Lab
```

### 1.2 Collector/Forwarder

```
Collector Type: □ Syslog UDP □ Syslog TCP □ Agent □ API □ S3
Collector IP: _______________
Port: _______________
Protocol: □ UDP □ TCP □ TLS
```

---

## 2. Test Commands by Source

### 2.1 Windows Events → SIEM

**Generation to Syslog:**
```bash
# Basic test - 100 EPS for 60 seconds
python3 -m soc_log_generator generate \
  --generator windows \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-protocol tcp \
  --eps 100 \
  --duration 60 \
  --syslog-format syslog
```

**Options:**
- `--eps 100` : Events per second (adjust based on SIEM capacity)
- `--duration 60` : Duration in seconds (0 = unlimited)
- `--syslog-format syslog` : Native syslog format
- `--syslog-format json` : JSON format
- `--syslog-format cef` : CEF format (for ArcSight/QRadar)

**Verify in SIEM:**
```
□ Events received: _______
□ Parsing correct: □ Yes □ No
□ Fields extracted: _______________
□ Timestamp correct: □ Yes □ No
□ Source IP identified: □ Yes □ No
□ Severity mapping correct: □ Yes □ No
```

---

### 2.2 Linux Auth → SIEM

**Generation:**
```bash
# Standard syslog format
python3 -m soc_log_generator generate \
  --generator linux \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --eps 50 \
  --duration 120
```

**Specific scenario (SSH brute force):**
```bash
# Generate many SSH failures
python3 -m soc_log_generator generate \
  --generator linux \
  --mode burst \
  --start-eps 10 \
  --eps 100 \
  --ramp-time 10 \
  --duration 60
```

**Verify:**
```
□ Events received: _______
□ Username extracted: □ Yes □ No
□ Source IP extracted: □ Yes □ No
□ Authentication type: □ Yes □ No
□ Alert triggered: □ Yes □ No (which: _______)
```

---

### 2.3 Firewall (Palo Alto) → SIEM

**CEF Generation (recommended for ArcSight/QRadar):**
```bash
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-protocol tcp \
  --syslog-format cef \
  --eps 1000 \
  --duration 300
```

**JSON Generation (for Splunk/Elastic):**
```bash
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 1000 \
  --duration 300
```

**Verify:**
```
□ App ID identified: □ Yes □ No
□ Zones (src/dst): □ Yes □ No
□ Action (allow/deny): □ Yes □ No
□ Bytes/packets counted: □ Yes □ No
□ Session ID tracking: □ Yes □ No
□ URL categorization: □ Yes □ No
```

---

### 2.4 AWS CloudTrail → SIEM

**Ingestion options:**

**A. Via Syslog (direct):**
```bash
python3 -m soc_log_generator generate \
  --generator aws \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 50 \
  --duration 600
```

**B. To file (for S3 ingestion/simulation):**
```bash
# Generate file for S3 ingestion
python3 -m soc_log_generator generate \
  --generator aws \
  --output-file /tmp/aws_cloudtrail_test.json \
  --eps 100 \
  --duration 300

# Compress like real CloudTrail
gzip /tmp/aws_cloudtrail_test.json
# Upload to test S3 bucket
aws s3 cp /tmp/aws_cloudtrail_test.json.gz s3://test-bucket/AWSLogs/123456789012/
```

**C. Multi-account (simulation):**
```bash
# Generate with multiple parallel clients
python3 -m soc_log_generator generate \
  --generator aws \
  --syslog-host <SIEM_IP> \
  --multi 5 \
  --eps 20 \
  --duration 300
```

**Verify:**
```
□ EventName parsed: □ Yes □ No
□ userIdentity recognized: □ Yes □ No
□ awsRegion identified: □ Yes □ No
□ sourceIPAddress: □ Yes □ No
□ errorCode (if error): □ Yes □ No
□ requestParameters: □ Yes □ No
□ AWS CloudTrail dashboard: □ Yes □ No
```

---

### 2.5 Azure Activity → SIEM

**Via Syslog:**
```bash
python3 -m soc_log_generator generate \
  --generator azure \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 100 \
  --duration 300
```

**Specific Alert Test:**
```bash
# Generate security alerts
python3 -m soc_log_generator generate \
  --generator azure \
  --mode burst \
  --start-eps 10 \
  --eps 200 \
  --duration 60
```

**Verify:**
```
□ Subscription ID: □ Yes □ No
□ Resource Group: □ Yes □ No
□ Operation Name: □ Yes □ No
□ Caller/User: □ Yes □ No
□ Activity Status: □ Yes □ No
□ Category (Administrative/Security): □ Yes □ No
```

---

### 2.6 Azure AD Sign-in → SIEM

```bash
python3 -m soc_log_generator generate \
  --generator azure-signin \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 50 \
  --duration 300
```

**Verify:**
```
□ UserPrincipalName: □ Yes □ No
□ AppDisplayName: □ Yes □ No
□ IP Address: □ Yes □ No
□ Location (geo): □ Yes □ No
□ Risk Level: □ Yes □ No
□ Conditional Access Status: □ Yes □ No
□ MFA Details: □ Yes □ No
```

---

### 2.7 Office 365 → SIEM

```bash
python3 -m soc_log_generator generate \
  --generator o365 \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 200 \
  --duration 300
```

**Verify:**
```
□ Workload (Exchange/SharePoint/Teams): □ Yes □ No
□ Operation: □ Yes □ No
□ UserId: □ Yes □ No
□ ClientIP: □ Yes □ No
□ Item/Subject (if email): □ Yes □ No
□ SiteUrl (if SharePoint): □ Yes □ No
```

---

### 2.8 GCP Audit → SIEM

```bash
python3 -m soc_log_generator generate \
  --generator gcp \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 50 \
  --duration 300
```

**Verify:**
```
□ protoPayload.methodName: □ Yes □ No
□ protoPayload.authenticationInfo: □ Yes □ No
□ resource.labels.project_id: □ Yes □ No
□ severity: □ Yes □ No
□ logName: □ Yes □ No
```

---

## 3. Load Tests

### 3.1 Sustained Volume Test

**Objective:** Verify SIEM handles sustained load

```bash
# 1000 EPS for 1 hour
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --eps 1000 \
  --duration 3600
```

**Metrics to measure:**
```
Start time: _______
End time: _______
Events received (SIEM): _______
Events generated: 3,600,000
Loss rate: _______%
SIEM CPU (average): _______%
SIEM CPU (peak): _______%
SIEM Memory: _______
Ingestion latency (average): _______ms
Ingestion latency (p99): _______ms
```

---

### 3.2 Burst Test (Load Spike)

**Objective:** Test reaction to spikes

```bash
# Ramp up to 5000 EPS
python3 -m soc_log_generator generate \
  --generator firewall \
  --mode ramp \
  --start-eps 100 \
  --eps 5000 \
  --ramp-time 300 \
  --duration 600
```

**Observations:**
```
□ SIEM queue: □ Stable □ Increases □ Overflows
□ Events dropped: _______
□ Latency during burst: _______
□ Recovery time: _______
```

---

## 4. Alert Validation

### 4.1 Correlation Test

**Brute Force Scenario:**
```bash
# Terminal 1 - Generate normal SSH connections
python3 -m soc_log_generator generate \
  --generator linux \
  --eps 5 \
  --duration 300

# Terminal 2 - After 2 min, add brute force
python3 -m soc_log_generator generate \
  --generator linux \
  --mode burst \
  --start-eps 10 \
  --eps 100 \
  --ramp-time 10 \
  --duration 60
```

**Validation:**
```
□ "Multiple Failed Logins" alert triggered: □ Yes □ No
□ Detection time: _______ seconds
□ False positives: _______
□ True positives: _______
```

---

### 4.2 Anomaly Detection Test

```bash
# Generate normal traffic
python3 -m soc_log_generator generate \
  --generator firewall \
  --eps 100 \
  --duration 300

# Generate data exfiltration (outbound burst)
python3 -m soc_log_generator generate \
  --generator firewall \
  --mode burst \
  --start-eps 100 \
  --eps 2000 \
  --duration 60
```

**Validation:**
```
□ Abnormal volume detection: □ Yes □ No
□ New destination detection: □ Yes □ No
□ Data Exfiltration alert: □ Yes □ No
```

---

## 5. CEF/LEEF Format

### 5.1 CEF Test (ArcSight/QRadar)

```bash
# Generate CEF format
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <SIEM_IP> \
  --syslog-port 514 \
  --syslog-format cef \
  --eps 100 \
  --duration 60

# Or to file for inspection
python3 -m soc_log_generator generate \
  --generator firewall \
  --output-file /tmp/cef_test.log \
  --eps 10 \
  --duration 10

tail -5 /tmp/cef_test.log
```

**CEF Validation:**
```
□ CEF header correct: □ Yes □ No
□ Device Vendor/Product: □ Yes □ No
□ Severity mapping: □ Yes □ No
□ Extensions parsed: □ Yes □ No (which: _______)
```

---

## 6. Global Results

### 6.1 Summary

| Source | Events | Received | % Received | Parsing | Alerts | Status |
|--------|--------|----------|------------|---------|--------|--------|
| Windows | | | | | | □ OK □ KO |
| Linux | | | | | | □ OK □ KO |
| Firewall | | | | | | □ OK □ KO |
| AWS | | | | | | □ OK □ KO |
| Azure | | | | | | □ OK □ KO |
| O365 | | | | | | □ OK □ KO |
| GCP | | | | | | □ OK □ KO |

### 6.2 Issues Identified

```
1. ___________________________________________________________

2. ___________________________________________________________

3. ___________________________________________________________
```

### 6.3 Corrections Applied

```
1. ___________________________________________________________

2. ___________________________________________________________

3. ___________________________________________________________
```

### 6.4 Final Validation

```
□ All parsers working: □ Yes □ No
□ Event loss < 1%: □ Yes □ No
□ Alerts triggered correctly: □ Yes □ No
□ Dashboards populate: □ Yes □ No
□ Ready for production: □ Yes □ No
```

---

## 7. Signatures

```
SIEM Tester: _______________ Date: _______ Signature: _______
LogGen Tester: _______________ Date: _______ Signature: _______
Manager: _______________ Date: _______ Signature: _______
```

---

## Appendices

### A. Quick Commands

```bash
# Quick 100 events test
python3 -m soc_log_generator generate --generator <TYPE> --eps 100 --duration 10

# Test to file
python3 -m soc_log_generator generate --generator <TYPE> --output-file test.log --duration 60

# Multi-generators test
python3 -m soc_log_generator generate --generator windows --eps 50 &
python3 -m soc_log_generator generate --generator linux --eps 50 &
wait
```

### B. Complete CLI Options

```
--generator {windows,linux,nxlog,firewall,proxy,dns,ids,aws,azure,o365,gcp}
--syslog-host HOST          IP or hostname of SIEM
--syslog-port PORT          Port (default: 514)
--syslog-protocol {tcp,udp} Protocol
--syslog-format {syslog,json,cef} Output format
--eps FLOAT                 Events per second
--duration INT              Duration in seconds (0 = infinite)
--mode {constant,ramp,burst} Generation mode
--multi INT                 Number of parallel clients
--output-file PATH          Output file (optional)
```

### C. Support

```
In case of issues:
- Generator logs: /tmp/soc_log_generator.log
- Check connectivity: telnet <SIEM_IP> <PORT>
- Check firewall: nc -zv <SIEM_IP> <PORT>
```
