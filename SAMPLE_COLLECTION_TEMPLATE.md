# Sample Collection Template

> **Purpose**: Standardized procedure for collecting and documenting real log samples  
> **Use Case**: When adding new sources or updating existing ones

---

## Collection Request

```yaml
request_id: SC-YYYY-NNN
source_type: [windows/linux/aws/azure/gcp/firewall/proxy/dns/ids/other]
date_requested: YYYY-MM-DD
requested_by: name@company.com
priority: [critical/high/medium/low]
purpose: |
  Brief description of why these samples are needed
  (e.g., "Need to validate new EventID 4662 implementation")
```

---

## Source Information

### Environment Details

```yaml
environment:
  type: [production/staging/lab/test_vm]
  location: [datacenter/cloud/endpoint]
  network_segment: [internal/dmz/perimeter]
  
system:
  os: [Windows Server 2022/Ubuntu 22.04/etc]
  version: "specific version"
  patches: "patch level"
  timezone: "UTC"
  
application:
  name: "Application name"
  version: "version"
  configuration: "relevant config details"
```

### Log Configuration

```yaml
log_config:
  format: [json/xml/syslog/csv/custom]
  destination: [file/syslog/api/database]
  verbosity: [minimal/standard/detailed/debug]
  filtering: "any filters applied"
  rotation: "rotation policy"
```

---

## Collection Procedure

### Step 1: Preparation

- [ ] Identify collection window (low traffic period preferred)
- [ ] Verify anonymization procedures
- [ ] Prepare collection tools
- [ ] Estimate storage requirements
- [ ] Get necessary approvals

### Step 2: Collection

```bash
# Example commands for different sources

# Windows Event Logs
wevtutil epl Security C:\temp\security_samples.evtx
# or
Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Clixml security_samples.xml

# Linux Auth Logs
tail -n 10000 /var/log/auth.log > /tmp/auth_samples.log

# AWS CloudTrail (via CLI)
aws cloudtrail lookup-events --max-results 1000 --start-time 2024-01-01T00:00:00Z

# File-based logs
cp /var/log/application/app.log /tmp/app_samples_$(date +%Y%m%d).log
```

### Step 3: Anonymization

```yaml
anonymization:
  method: [automated/manual/combination]
  tools_used: [validation/sample_collector.py/custom_script]
  
  fields_anonymized:
    - field_name: "username"
      method: "hash_and_replace"
      example: "jdoe" -> "user123"
    
    - field_name: "ip_address"
      method: "rfc1918_mapping"
      example: "203.0.113.45" -> "10.0.0.15"
    
    - field_name: "hostname"
      method: "pattern_replace"
      example: "srv-prod-01" -> "srv-001"
  
  verification:
    - checked_for_public_ips: true
    - checked_for_real_domains: true
    - checked_for_usernames: true
    - checked_for_sensitive_data: true
```

### Step 4: Validation

- [ ] Samples parse correctly
- [ ] No PII remains
- [ ] Structure matches expected format
- [ ] Timestamps are valid
- [ ] All expected fields present

---

## Sample Inventory

```yaml
total_samples: 1000
sample_period:
  start: "2024-03-01T00:00:00Z"
  end: "2024-03-01T23:59:59Z"
  duration_hours: 24

event_breakdown:
  - event_type: "authentication"
    count: 500
    percentage: 50
  
  - event_type: "process_creation"
    count: 300
    percentage: 30
  
  - event_type: "network_connection"
    count: 200
    percentage: 20

file_list:
  - filename: "windows_security_samples_20240301.jsonl"
    size_mb: 15.5
    events: 1000
    format: "jsonl"
    checksum: "sha256:abc123..."
```

---

## Quality Assessment

```yaml
quality_score: 85  # 0-100

strengths:
  - "Good coverage of normal activity"
  - "Includes edge cases (failed auth, etc.)"
  - "Complete field population"

limitations:
  - "Limited weekend activity"
  - "No high-volume burst scenarios"
  - "Missing some rare event types"

recommended_uses:
  - "Field validation"
  - "Pattern verification"
  - "Generator calibration"

not_recommended_for:
  - "Stress testing (volume too low)"
  - "Seasonal pattern validation"
```

---

## Storage and Access

```yaml
storage:
  location: "samples/{source_type}/"
  filename: "{source}_samples_{date}.{format}"
  encryption: "gpg encrypted"
  retention: "90 days"

access:
  authorized_users:
    - "research-team"
    - "generator-developers"
  
  restrictions:
    - "No external sharing"
    - "No cloud storage"
    - "Local development only"
```

---

## Research Notes

### Observed Patterns

```
# Document any interesting patterns observed

1. Timestamp format: ISO 8601 with microseconds
2. User fields: Always lowercase
3. IP addresses: IPv6 shown in compressed form
4. Event ordering: Strictly chronological
5. Missing fields: "reason" field often null for success events
```

### Deviations from Documentation

```
1. EventID 4624 includes extra field "VirtualAccount" not in docs
2. Some timestamps have timezone offset (+00:00) not documented
3. UserSid format varies between local and domain accounts
```

### Version Indicators

```
Fields that indicate format version:
- "Version": "2.1" (explicit version field)
- "VirtualAccount": presence indicates v2.1+
- "LogonType": 11 indicates v2.1+
```

---

## Sign-off

```yaml
collected_by:
  name: "Collector Name"
  date: "2024-03-01"
  signature: "Initials"

verified_by:
  name: "Verifier Name"
  date: "2024-03-02"
  signature: "Initials"
  verification_method: "spot_check"

approved_by:
  name: "Manager Name"
  date: "2024-03-02"
  signature: "Initials"
```

---

## Appendix: Quick Reference

### Sample Collection Checklist

- [ ] Source identified and documented
- [ ] Collection approved by data owner
- [ ] Anonymization plan defined
- [ ] Storage location prepared
- [ ] Collection window scheduled
- [ ] Samples collected
- [ ] Anonymization applied
- [ ] Quality verified
- [ ] Samples stored securely
- [ ] Documentation completed
- [ ] Research notes added
- [ ] Sign-off obtained

### Sample File Naming Convention

```
{source_type}_{event_category}_samples_{YYYYMMDD}_{sequence}.{format}

Examples:
- windows_security_samples_20240301_001.jsonl
- aws_cloudtrail_samples_20240301.jsonl
- linux_auth_samples_20240301.log
```

### Minimum Sample Requirements

| Use Case | Minimum Samples | Recommended |
|----------|-----------------|-------------|
| Field validation | 100 | 1000 |
| Pattern matching | 500 | 5000 |
| Distribution analysis | 1000 | 10000 |
| Stress testing | 10000 | 100000 |
| Version detection | 50 per version | 200 per version |

---

*Template version: 1.0.0*  
*Last updated: 2024-03-15*
