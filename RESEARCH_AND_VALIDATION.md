# Research and Validation Notebook - SOC Log Generator

> **Purpose**: Ensure generated logs are as close as possible to reality through rigorous research, validation, and continuous improvement.

**Version**: 1.0.0  
**Last Updated**: 2024-03-15  
**Status**: Foundation Document

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Validation Methodology](#2-validation-methodology)
3. [Reference Sources Registry](#3-reference-sources-registry)
4. [Reality Checking Framework](#4-reality-checking-framework)
5. [Version Management](#5-version-management)
6. [Continuous Improvement Process](#6-continuous-improvement-process)
7. [Source-Specific Research Notes](#7-source-specific-research-notes)
8. [Validation Tools](#8-validation-tools)
9. [Research Backlog](#9-research-backlog)
10. [Appendices](#10-appendices)

---

## 1. Introduction

### 1.1 Why This Document Matters

The foundation of a reliable log generator is **accuracy**. Without accurate log generation:
- SIEM parsers may fail on generated logs
- Detection rules may not trigger correctly
- Training scenarios become unrealistic
- Teams lose trust in the tool

### 1.2 Validation Philosophy

```
┌─────────────────────────────────────────────────────────────────┐
│                    VALIDATION PYRAMID                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                    ┌─────────────┐                              │
│                    │   L4: Live  │  Real SIEM ingestion tests   │
│                    │    SIEM     │  (final validation)          │
│                    └──────┬──────┘                              │
│              ┌────────────┼────────────┐                       │
│              ▼            ▼            ▼                       │
│        ┌─────────┐  ┌─────────┐  ┌─────────┐                  │
│        │L3:Parser│  │L3:Schema│  │L3:Sample│  Vendor parsers   │
│        │  Test   │  │ Validate│  │ Compare │  & sample matching│
│        └────┬────┘  └────┬────┘  └────┬────┘                  │\n│             └─────────────┼─────────────┘                      │
│                           ▼                                    │
│                    ┌─────────────┐                            │
│                    │ L2: Format  │  Field structure, types,    │
│                    │  Structure  │  patterns (syntactic)       │
│                    └──────┬──────┘                            │
│                           ▼                                    │
│                    ┌─────────────┐                            │
│                    │ L1: Vendor  │  Official documentation,    │
│                    │    Docs     │  API references             │
│                    └─────────────┘                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Key Principles

| Principle | Description |
|-----------|-------------|
| **Evidence-Based** | Every field, pattern, and value must be traceable to a source |
| **Version-Controlled** | Log formats evolve; we track versions explicitly |
| **Measurable** | Validation results are quantified (coverage %, accuracy %) |
| **Reproducible** | Same input → same validation results |
| **Continuous** | Regular updates as sources change |

---

## 2. Validation Methodology

### 2.1 The Four Pillars of Validation

#### Pillar 1: Documentation Research (L1)
**Goal**: Extract authoritative format specifications

**Process**:
1. Identify official vendor documentation
2. Extract field definitions, types, constraints
3. Note version/date of documentation
4. Document in `REFERENCE_SOURCES.md`

**Quality Criteria**:
- [ ] Source is official (vendor website, API docs)
- [ ] Version/date clearly identified
- [ ] Field descriptions complete
- [ ] Examples provided

#### Pillar 2: Format Structure Validation (L2)
**Goal**: Ensure syntactic correctness

**Checks**:
- Field presence (required vs optional)
- Data type conformity
- Pattern matching (regex validation)
- Enum value validation
- Timestamp format

**Tools**: `validation/schemas.py`, JSON Schema, custom validators

#### Pillar 3: Sample Comparison (L3)
**Goal**: Match real-world log samples

**Process**:
1. Collect anonymized real log samples
2. Parse and normalize both real and generated logs
3. Compare field-by-field
4. Calculate similarity metrics

**Metrics**:
- Field coverage: `% of fields present in real logs that we generate`
- Value distribution similarity: `KL divergence or histogram comparison`
- Pattern accuracy: `% of values matching expected patterns`

#### Pillar 4: Live System Validation (L4)
**Goal**: Verify actual SIEM ingestion

**Process**:
1. Generate logs to test SIEM
2. Verify parsing success rate
3. Check field extraction
4. Validate detection rule triggering
5. Document in `TEST_PROCEDURE.md`

### 2.2 Validation Workflow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Research  │────▶│   Schema    │────▶│  Generator  │
│   Sources   │     │  Definition │     │   Update    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                              │
       ┌──────────────────────────────────────┘
       ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Update    │◀────│   Compare   │◀────│   Sample    │
│   Research  │     │   Metrics   │     │  Validation │
└─────────────┘     └─────────────┘     └─────────────┘
       ▲
       └──────────────────────────────────────┐
                                              │
┌─────────────┐     ┌─────────────┐     ┌────┴─────────┐
│   Version   │◀────│   Live      │◀────│   Issue     │
│   Release   │     │   SIEM      │     │   Tracking  │
└─────────────┘     │   Test      │     └─────────────┘
                    └─────────────┘
```

---

## 3. Reference Sources Registry

### 3.1 Master Registry

All reference sources are documented in **[REFERENCE_SOURCES.md](REFERENCE_SOURCES.md)**.

**Structure**:
```yaml
source_id: unique identifier
name: human-readable name
category: endpoint/network/cloud/security/business
vendor: vendor name
product: product name
version: format version
documentation:
  - url: primary documentation URL
    type: api_reference/schema_guide/user_guide
    last_verified: YYYY-MM-DD
    format_version: version documented
samples:
  - source: internal/github/vendor
    location: path or URL
    anonymized: true/false
    count: number of samples
validation_status:
  documentation_reviewed: YYYY-MM-DD
  schema_defined: YYYY-MM-DD
  samples_compared: YYYY-MM-DD
  live_siem_tested: YYYY-MM-DD
  accuracy_score: 0-100%
```

### 3.2 Source Categories

| Category | Sources | Priority |
|----------|---------|----------|
| **Endpoint** | Windows Events, Sysmon, Linux auditd, macOS Unified Logs | P0 |
| **Network** | Palo Alto, Fortinet, Cisco ASA, Zscaler, Squid | P0 |
| **Cloud** | AWS CloudTrail, Azure Activity/SignIn, GCP Audit, O365 | P0 |
| **Security** | CrowdStrike, Defender, Splunk ES, Suricata | P1 |
| **Business** | Epic, Cerner, SWIFT, SCADA | P2 |

---

## 4. Reality Checking Framework

### 4.1 Sample Collection

**Ethical Guidelines**:
- Only use anonymized samples
- Remove/rewrite all PII (IPs, usernames, hostnames)
- Replace real domains with example.com equivalents
- Never use production data without authorization
- Store samples securely with restricted access

**Collection Sources**:
1. **Internal Labs**: Controlled test environments
2. **Vendor Documentation**: Official sample logs
3. **GitHub**: Public sample repositories (anonymized)
4. **Security Communities**: Shared IOCs and samples
5. **Generated from Real Systems**: Test VMs, isolated networks

### 4.2 Reality Checker Tool

The `validation/reality_checker.py` tool compares generated logs against real samples:

```python
# Example usage
from validation.reality_checker import RealityChecker

checker = RealityChecker()

# Load real samples
checker.load_real_samples("samples/windows_security.json", source_type="windows")

# Generate samples for comparison
checker.load_generated_samples(generated_events, source_type="windows")

# Run comparison
report = checker.compare(source_type="windows")

# Results
print(f"Field Coverage: {report.field_coverage}%")
print(f"Pattern Accuracy: {report.pattern_accuracy}%")
print(f"Value Distribution Match: {report.distribution_similarity}%")
```

### 4.3 Comparison Dimensions

| Dimension | Metric | Target |
|-----------|--------|--------|
| **Field Presence** | % of real fields present in generated | ≥ 90% |
| **Field Types** | % of fields with correct data type | 100% |
| **Value Patterns** | % of values matching regex patterns | ≥ 95% |
| **Enum Values** | % of enums matching allowed values | 100% |
| **Value Ranges** | Numeric ranges realistic | Within observed min/max |
| **Temporal Patterns** | Time distribution realistic | KL divergence < 0.1 |
| **Cardinality** | Unique values per field realistic | Within 10% of real |

---

## 5. Version Management

### 5.1 Why Version Management Matters

Log formats change:
- Vendors add new fields
- Deprecated fields removed
- Format structure changes
- New event types added
- Semantic changes to existing fields

Without version management:
- Generators become outdated
- Validation fails silently
- SIEM parsers break
- Users get inconsistent results

### 5.2 Versioning Scheme

```
┌─────────────────────────────────────────────────────────────┐
│                    VERSION IDENTIFIER                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   vendor-product-format-vMAJOR.MINOR.PATCH-build           │
│   │      │      │     │    │     │     │     │             │
│   │      │      │     │    │     │     │     └─ Build ID  │
│   │      │      │     │    │     │     └─ Patch (fixes)   │
│   │      │      │     │    │     └─ Minor (new fields)    │
│   │      │      │     │    └─ Major (breaking changes)    │
│   │      │      │     └─ Format name                      │
│   │      │      └─ Product name                           │
│   │      └─ Vendor name                                   │
│   └─ Source identifier                                    │
│                                                              │
│   Example: microsoft-windows-security-v2.1.0-20240315      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 Version Registry

**Location**: `validation/version_registry.yaml`

```yaml
sources:
  microsoft-windows-security:
    current_version: "2.1.0"
    versions:
      "2.1.0":
        released: "2024-03-01"
        changes:
          - "Added EventID 4662 (Object Access)"
          - "Updated LogonType enum with new values"
        breaking: false
        supported: true
        min_os_version: "Windows Server 2016"
        max_os_version: "Windows Server 2022"
      
      "2.0.0":
        released: "2023-06-15"
        changes:
          - "Restructured SubjectUserSid format"
        breaking: true
        supported: true
        superseded_by: "2.1.0"
      
      "1.5.0":
        released: "2022-01-10"
        breaking: false
        supported: false
        deprecated: "2023-12-31"

  aws-cloudtrail:
    current_version: "1.08"
    versions:
      "1.08":
        released: "2021-11-04"
        changes: []
        breaking: false
        supported: true
        aws_doc_url: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html"
```

### 5.4 Multi-Version Support

Users can specify which version to generate:

```bash
# Generate Windows events using format v2.0.0
python -m soc_log_generator generate \
  --generator windows \
  --format-version "2.0.0" \
  --output-file events.json

# Use latest (default)
python -m soc_log_generator generate \
  --generator windows \
  --format-version "latest"
```

### 5.5 Version Detection

```python
from validation.version_manager import VersionManager

vm = VersionManager()

# Detect version from real sample
detected = vm.detect_version(
    sample_log,
    source_type="windows"
)
print(f"Detected version: {detected.version}")
print(f"Confidence: {detected.confidence}")
```

---

## 6. Continuous Improvement Process

### 6.1 Improvement Cycle

```
        ┌─────────────────┐
        │   IDENTIFY      │
        │  (Issues/Needs) │
        └────────┬────────┘
                 │
    ┌────────────┼────────────┐
    ▼            ▼            ▼
┌───────┐   ┌───────┐   ┌───────┐
│ User  │   │ SIEM  │   │ Vendor│
│Report │   │ Test  │   │ Update│
└───┬───┘   └───┬───┘   └───┬───┘
    │           │           │
    └───────────┼───────────┘
                ▼
        ┌─────────────┐
        │   RESEARCH  │
        │  (Sources)  │
        └──────┬──────┘
               ▼
        ┌─────────────┐
        │   UPDATE    │
        │  (Schema/   │
        │  Generator) │
        └──────┬──────┘
               ▼
        ┌─────────────┐
        │   VALIDATE  │
        │  (Test/     │
        │  Compare)   │
        └──────┬──────┘
               ▼
        ┌─────────────┐
        │   RELEASE   │
        │  (New Ver.) │
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │   MONITOR   │
        │  (Feedback) │
        └─────────────┘
```

### 6.2 Issue Tracking

All validation issues are tracked in the **Research Backlog** (Section 9).

**Issue Template**:
```yaml
issue_id: RV-YYYY-NNN
title: Brief description
category: format_error/missing_field/pattern_mismatch/performance
source_type: affected source
severity: critical/high/medium/low
description: |
  Detailed description of the issue
  with examples

evidence:
  - type: sample_log
    content: "..."
  - type: siem_error
    content: "..."
  - type: documentation
    url: "..."

root_cause: |
  Analysis of why this issue exists

proposed_fix: |
  How to fix it

validation_plan: |
  How to validate the fix

status: open/in_progress/resolved/closed
assigned_to: name
created: YYYY-MM-DD
updated: YYYY-MM-DD
```

### 6.3 Research Cadence

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Vendor doc review | Monthly | Research Team |
| Sample comparison | Per release | QA Team |
| Live SIEM testing | Per major release | Integration Team |
| Community feedback review | Weekly | Community Manager |
| Accuracy metrics review | Bi-weekly | Product Owner |
| Version updates | As needed | Research Team |

### 6.4 Accuracy Scorecard

Published monthly showing accuracy metrics per source:

| Source | Field Coverage | Pattern Accuracy | Live Test | Overall | Trend |
|--------|---------------|------------------|-----------|---------|-------|
| Windows Security | 94% | 98% | ✅ Pass | 96% | ↑ +2% |
| AWS CloudTrail | 89% | 95% | ✅ Pass | 92% | → 0% |
| Palo Alto FW | 92% | 97% | ✅ Pass | 95% | ↑ +1% |
| ... | ... | ... | ... | ... | ... |

---

## 7. Source-Specific Research Notes

### 7.1 Windows Event Logs

**Research Status**: ✅ Comprehensive  
**Last Updated**: 2024-03-08  
**Accuracy Score**: 96%

**Key References**:
- [Microsoft Security Auditing Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Windows Event ID Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Sysmon Event Reference](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

**Known Gaps**:
1. EventID 4662 (Object Access) - Need more detailed field samples
2. Windows Server 2025 new events - Pending documentation release

**Version History**:
- v2.1.0 (2024-03-01): Added 15 new EventIDs from Server 2022
- v2.0.0 (2023-06-15): Major restructuring of SubjectUser fields
- v1.9.0 (2023-01-10): Initial comprehensive coverage

### 7.2 AWS CloudTrail

**Research Status**: ✅ Good Coverage  
**Last Updated**: 2024-03-05  
**Accuracy Score**: 92%

**Key References**:
- [AWS CloudTrail Record Contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)

**Known Gaps**:
1. Specialized services (IoT, GameLift) have limited coverage
2. Newer event versions (1.09+) need validation

### 7.3 Azure Activity Logs

**Research Status**: ✅ Good Coverage  
**Last Updated**: 2024-03-06  
**Accuracy Score**: 95%

**Key References**:
- [Azure Activity Log Schema](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema)
- [Azure AD Sign-in Log Schema](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)

### 7.4 [Continue for each source...]

---

## 8. Validation Tools

### 8.1 Available Tools

| Tool | Purpose | Location |
|------|---------|----------|
| `SchemaRegistry` | Define and store schemas | `validation/schemas.py` |
| `LogValidator` | Validate against schemas | `validation/validator.py` |
| `RealityChecker` | Compare with real samples | `validation/reality_checker.py` |
| `VersionManager` | Manage format versions | `validation/version_manager.py` |
| `SampleCollector` | Collect and anonymize samples | `validation/sample_collector.py` |
| `SIEMNormalizer` | Test SIEM compatibility | `siem_tests/normalizer.py` |

### 8.2 Running Validation

```bash
# Full validation suite
python -m validation.run_all

# Validate specific generator
python -m validation.validate --generator windows --samples samples/windows/

# Compare with real samples
python -m validation.compare --real samples/real/ --generated samples/gen/ --source windows

# Version detection
python -m validation.detect_version --sample samples/windows_real.json --source windows

# Generate accuracy report
python -m validation.report --output accuracy_report.html
```

---

## 9. Research Backlog

### 9.1 Open Issues

| ID | Title | Source | Severity | Status |
|----|-------|--------|----------|--------|
| RV-2024-001 | Windows Event 4662 field mismatch | windows | medium | open |
| RV-2024-002 | AWS CloudTrail eventVersion 1.09 support | aws | low | open |
| RV-2024-003 | Add Azure Resource Manager events | azure | medium | open |

### 9.2 Upcoming Research

| Source | Priority | Estimated Effort | Due Date |
|--------|----------|------------------|----------|
| macOS Unified Logs | P1 | 2 weeks | 2024-04-01 |
| CrowdStrike Falcon | P1 | 1 week | 2024-03-30 |
| Kubernetes Audit | P2 | 1 week | 2024-04-15 |
| Okta System Log | P2 | 3 days | 2024-04-10 |

---

## 10. Appendices

### Appendix A: Validation Checklist

**Before releasing a new generator**:
- [ ] Official documentation reviewed and referenced
- [ ] Schema defined with all required fields
- [ ] At least 10 real samples collected and anonymized
- [ ] Field coverage ≥ 85%
- [ ] Pattern accuracy ≥ 95%
- [ ] Live SIEM test passed
- [ ] Version number assigned
- [ ] Documentation updated

**Before releasing a new version**:
- [ ] Changes documented
- [ ] Backward compatibility assessed
- [ ] Migration guide written (if breaking)
- [ ] All tests passing
- [ ] Accuracy metrics updated

### Appendix B: Glossary

| Term | Definition |
|------|------------|
| **Field Coverage** | % of fields present in real logs that are generated |
| **Pattern Accuracy** | % of generated values matching expected patterns |
| **Reality Checker** | Tool that compares generated logs to real samples |
| **Schema** | Formal definition of log structure and field constraints |
| **Version Registry** | Database of format versions and their changes |

### Appendix C: Related Documents

- [REFERENCE_SOURCES.md](REFERENCE_SOURCES.md) - Complete source registry
- [TEST_PROCEDURE.md](TEST_PROCEDURE.md) - SIEM testing procedures
- [SPECS.md](SPECS.md) - Technical specifications
- [STATUS.md](STATUS.md) - Project status

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2024-03-15 | Security Team | Initial release |

---

*This document is a living document. Please update it as research progresses and validation methods evolve.*
