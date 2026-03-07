# Threat Intelligence Integration

This directory contains threat intelligence scenarios based on real-world reports and bulletins.

## Directory Structure

```
threat_intel/
├── cisa/           # CISA Alerts and Analysis Reports
├── ctid/           # Center for Threat-Informed Defense reports
├── mitre/          # MITRE ATT&CK based scenarios
├── campaigns/      # Multi-stage attack campaigns
└── iocs/           # Indicators of Compromise lists
```

## Sources

### CISA (Cybersecurity & Infrastructure Security Agency)
- **URL:** https://www.cisa.gov/alerts
- **Format:** Alerts (AA) and Analysis Reports (AR)
- **Update Frequency:** Weekly
- **Parser:** `parsers/cisa_parser.py`

### CTID (Center for Threat-Informed Defense)
- **URL:** https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/
- **Format:** Attack Flow, Summiting the Pyramid, Attack Stack
- **Update Frequency:** Monthly
- **Parser:** `parsers/ctid_parser.py`

### MITRE ATT&CK
- **URL:** https://attack.mitre.org/
- **Format:** STIX 2.1, JSON
- **Update Frequency:** Quarterly
- **Parser:** `parsers/mitre_parser.py`

## Scenario Format

All scenarios follow the CISA Alert Template format defined in `cisa/TEMPLATE_CISA_ALERT.yaml`.

Key sections:
- `alert`: Metadata about the threat
- `mitre_attack`: ATT&CK technique mapping
- `technical_details`: IOCs and TTPs
- `scenario`: Generator-specific configuration
- `detection`: Recommended detection rules

## Usage

### Import CISA Alert
```bash
python -m soc_log_generator.cli threat_intel import \
  --source cisa \
  --url https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a \
  --output threat_intel/cisa/
```

### Run Campaign Scenario
```bash
python -m soc_log_generator.cli campaign run \
  --scenario threat_intel/cisa/AA24-060A_APT_Living_Off_Land.yaml \
  --duration 48h \
  --output syslog://siem.company.com:514
```

### List Available Scenarios
```bash
python -m soc_log_generator.cli threat_intel list
```

## Contributing

When adding new scenarios:
1. Follow the template format
2. Include accurate MITRE ATT&CK mappings
3. Provide detection recommendations
4. Validate IOCs against production
5. Include variation modes for testing

## License

Scenarios based on public threat reports maintain original attribution.
