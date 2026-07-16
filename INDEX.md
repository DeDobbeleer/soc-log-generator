# SOC Log Generator - Documentation Index

**Quick Navigation:** [Project](#project-management) | [Technical](#technical-documentation) | [Configuration](#configuration) | [Business](#business-verticals) | [Development](#development)

---

## Project Management

| Document | Description | Audience | Status |
|----------|-------------|----------|--------|
| [PROJECT_PLAN.md](PROJECT_PLAN.md) | Complete 40-week roadmap with 16 phases, milestones, and deliverables | Project managers, stakeholders | ✅ Complete |
| [STATUS.md](STATUS.md) | Real-time progress tracking, task completion, metrics | Developers, PMs | ✅ Updated daily |
| [SPECS.md](SPECS.md) | Technical specifications (35KB): architecture, APIs, data models, AI integration | Architects, developers | ✅ Complete |
| [README.md](README.md) | Quick start guide, usage examples, feature overview | End users, evaluators | 📝 Draft |

## Research & Validation

| Document | Description | Audience | Status |
|----------|-------------|----------|--------|
| [RESEARCH_AND_VALIDATION.md](RESEARCH_AND_VALIDATION.md) | **Cahier de recherche et validation** - Methodology for ensuring log accuracy, version management, continuous improvement | Researchers, developers, QA | ✅ Complete |
| [REFERENCE_SOURCES.md](REFERENCE_SOURCES.md) | Registry of authoritative sources for all log formats with documentation links and version history | Researchers, developers | ✅ Complete |
| [SAMPLE_COLLECTION_TEMPLATE.md](SAMPLE_COLLECTION_TEMPLATE.md) | Standardized template for collecting and documenting real log samples | Researchers, analysts | ✅ Complete |

### Validation Tools

| Tool | Path | Purpose | Status |
|------|------|---------|--------|
| **Reality Checker** | [validation/reality_checker.py](validation/reality_checker.py) | Compare generated logs with real samples | ✅ Complete |
| **Version Manager** | [validation/version_manager.py](validation/version_manager.py) | Track and manage format versions | ✅ Complete |
| **Sample Collector** | [validation/sample_collector.py](validation/sample_collector.py) | Collect and anonymize real samples | ✅ Complete |
| **Report Generator** | [validation/report_generator.py](validation/report_generator.py) | Generate accuracy reports | ✅ Complete |
| **Validation Runner** | [validation/run_all.py](validation/run_all.py) | Run complete validation suite | ✅ Complete |

---

## Configuration

| File | Purpose | Format |
|------|---------|--------|
| [config/default.yaml](config/default.yaml) | Main generator configuration: sources, outputs, scenarios | YAML |
| [config/ai.yaml](config/ai.yaml) | AI/LLM settings: Ollama, OpenAI, Anthropic, Google | YAML |

### Configuration Sections
- **Generators**: Windows, Linux, Network, Cloud, Security, Business
- **Scenarios**: Attack campaigns, threat intel integration
- **Outputs**: File, Syslog, Kafka, HTTP, S3
- **AI Providers**: Local (Ollama) and Cloud APIs
- **Performance**: Rate limiting, threading, batching

---

## Technical Documentation

### Architecture

| Component | Path | Description |
|-----------|------|-------------|
| **Core Engine** | [core.py](core.py) | Event model, Asset inventory, Rate limiter, Output handlers |
| **Generators** | [generators/](generators/) | Source-specific log generators |
| **Scenarios** | [scenarios/](scenarios/) | Attack campaign definitions |
| **Threat Intel** | [threat_intel/](threat_intel/) | CISA, CTID, MITRE scenarios |
| **AI Module** | [ai/](ai/) *(planned)* | LLM integration, learning system |
| **Parsers** | [parsers/](parsers/) *(planned)* | Log parsing framework |
| **Research** | [research/](research/) *(planned)* | Web research, format discovery |
| **Business** | [business/](business/) *(planned)* | Industry-specific sources |

### Generator Catalog

#### Endpoint
| Generator | Path | Events | Status |
|-----------|------|--------|--------|
| Windows Event Log | [generators/endpoint/windows_generator.py](generators/endpoint/windows_generator.py) | 4624, 4625, 4688, 4728, etc. | 📝 Skeleton |
| Windows Sysmon | [generators/endpoint/windows_generator.py](generators/endpoint/windows_generator.py) | 1-26 (Process, Network, File, DNS) | 📝 Skeleton |
| Linux Auth | [generators/endpoint/linux_generator.py](generators/endpoint/linux_generator.py) | SSH, sudo, auditd | 📝 Skeleton |
| **Linux Sysmon** | [generators/endpoint/linux_sysmon.py](generators/endpoint/linux_sysmon.py) | 1, 3, 9, 11 (eBPF-based) | ⚠️ In Progress |

#### Network
| Generator | Path | Vendors | Status |
|-----------|------|---------|--------|
| Firewall | [generators/network/firewall_generator.py](generators/network/firewall_generator.py) | PaloAlto, Fortinet, Cisco ASA | 📝 Skeleton |
| Proxy | *(planned)* | BlueCoat, Zscaler, Squid | ⏸️ Not Started |
| DNS | *(planned)* | Infoblox, BIND, Windows DNS | ⏸️ Not Started |
| IDS/IPS | *(planned)* | Suricata, Snort | ⏸️ Not Started |

#### Cloud
| Generator | Path | Services | Status |
|-----------|------|----------|--------|
| AWS | *(planned)* | CloudTrail, VPC Flow, GuardDuty | ⏸️ Not Started |
| Azure | *(planned)* | Activity Logs, Sign-in Logs | ⏸️ Not Started |
| Office 365 | *(planned)* | Exchange, SharePoint, Azure AD | ⏸️ Not Started |
| GCP | *(planned)* | Audit Logs, VPC Flow | ⏸️ Not Started |

#### Security Tools
| Generator | Path | Products | Status |
|-----------|------|----------|--------|
| EDR | *(planned)* | CrowdStrike, MS Defender | ⏸️ Not Started |
| NIDS | *(planned)* | Suricata, Snort | ⏸️ Not Started |
| Vulnerability | *(planned)* | Qualys, Nessus, Rapid7 | ⏸️ Not Started |

### Scenario Catalog

#### Templates
| File | Description | MITRE Techniques |
|------|-------------|------------------|
| [TEMPLATE_CISA_ALERT.yaml](threat_intel/cisa/TEMPLATE_CISA_ALERT.yaml) | Standard CISA Alert scenario template | Configurable |
| [AA24-060A_APT_Living_Off_Land.yaml](threat_intel/cisa/AA24-060A_APT_Living_Off_Land.yaml) | APT Living Off The Land example | T1059, T1078, T1003, T1021 |

#### Scenario Types
| Category | Examples | Status |
|----------|----------|--------|
| **Basic** | Brute Force SSH, Malware Execution, Data Exfiltration | 📝 Planned |
| **Advanced** | Lateral Movement, Kerberoasting, Golden Ticket, Ransomware | 📝 Planned |
| **Campaigns** | APT Simulation, Supply Chain Attack, Insider Threat | 📝 Planned |

---

## Business Verticals

| Industry | Sources | Document | Status |
|----------|---------|----------|--------|
| **Healthcare** | Epic EHR, Cerner, HL7/FHIR, DICOM, Medical Devices | [docs/verticals/HEALTHCARE.md](docs/verticals/HEALTHCARE.md) *(planned)* | 📝 Specs |
| **Financial** | SWIFT, FIX Protocol, Core Banking, Anti-Fraud, ATM/POS | [docs/verticals/FINANCE.md](docs/verticals/FINANCE.md) *(planned)* | 📝 Specs |
| **Manufacturing** | SCADA, DCS, PLC, HMI, OPC-UA, Modbus, DNP3 | [docs/verticals/MANUFACTURING.md](docs/verticals/MANUFACTURING.md) *(planned)* | 📝 Specs |
| **Retail** | POS, E-commerce, Payment Gateway, CRM | [docs/verticals/RETAIL.md](docs/verticals/RETAIL.md) *(planned)* | 📝 Specs |
| **Telecommunications** | SS7/Diameter, SIP/VoIP, 5G Core (AMF, SMF, UPF), GTP | [docs/verticals/TELECOM.md](docs/verticals/TELECOM.md) *(planned)* | 📝 Specs |

---

## Development

### Source Code Structure
```
soc-log-generator/
├── core.py                 # Main engine (7KB)
├── main.py                 # CLI entry point (2KB)
├── generators/             # Log generators
│   ├── endpoint/           # Windows, Linux, macOS
│   ├── network/            # Firewall, Proxy, DNS
│   ├── cloud/              # AWS, Azure, GCP
│   ├── security/           # EDR, IDS, Vuln
│   └── application/        # Web, DB, Custom
├── scenarios/              # Attack scenarios
├── threat_intel/           # CISA, CTID, MITRE
├── ai/                     # *(planned)* LLM integration
├── parsers/                # *(planned)* Log parsers
├── research/               # *(planned)* Web research
├── business/               # *(planned)* Vertical sources
├── outputs/                # Output handlers
├── tests/                  # Test suite
└── config/                 # Configuration files
```

### Code Metrics
- **Total Lines**: ~1,600 (Python)
- **Generators**: 3 (Windows, Linux, Linux Sysmon)
- **Test Coverage**: 0%
- **Documentation**: 35KB+

### Build & Deployment
| File | Purpose |
|------|---------|
| `pyproject.toml` *(planned)* | Python packaging |
| `requirements.txt` *(planned)* | Dependencies |
| `Dockerfile` *(planned)* | Container image |
| `docker-compose.yml` *(planned)* | Local deployment |
| `.github/workflows/` *(planned)* | CI/CD pipelines |

---

## AI & Automation

### Features
| Feature | Description | Phase | Status |
|---------|-------------|-------|--------|
| **Log Learning** | Learn from real samples to improve generators | 12 | 📝 Specs |
| **Parser Generation** | Auto-generate parsers from samples | 10-11 | 📝 Specs |
| **Scenario Generation** | Create scenarios from natural language | 11 | 📝 Specs |
| **Web Research** | Auto-discover new log formats | 13 | 📝 Specs |
| **Format Analysis** | LLM-powered log format understanding | 11 | 📝 Specs |

### AI Providers
| Provider | Local/Cloud | Models | Use Case |
|----------|-------------|--------|----------|
| **Ollama** | Local | Llama 3, Mistral, CodeLlama | Privacy-first, offline |
| **OpenAI** | Cloud | GPT-4, GPT-3.5 | Complex generation |
| **Anthropic** | Cloud | Claude 3 (Opus/Sonnet/Haiku) | Document analysis |
| **Google** | Cloud | Gemini 1.5 Pro | Multi-modal |

### Configuration
See [config/ai.yaml](config/ai.yaml) for detailed AI settings.

---

## External Resources

### Threat Intelligence
| Source | URL | Format |
|--------|-----|--------|
| CISA Alerts | https://www.cisa.gov/alerts | HTML, RSS |
| MITRE ATT&CK | https://attack.mitre.org/ | STIX 2.1, JSON |
| CTID | https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/ | Reports |
| MISP | https://www.misp-project.org/ | JSON API |

### Log Format References
| Vendor | Documentation |
|--------|---------------|
| Microsoft Sysmon | https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon |
| Palo Alto | https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/monitoring/use-syslog-messages |
| Fortinet | https://docs.fortinet.com/document/fortigate/7.2.0/handbook/986892/sample-logs-by-log-type |
| Elastic ECS | https://www.elastic.co/guide/en/ecs/current/index.html |

---

## Quick Links by Use Case

### I want to...
| Goal | Go To |
|------|-------|
| **Understand the project** | [README.md](README.md) → [PROJECT_PLAN.md](PROJECT_PLAN.md) |
| **Check progress** | [STATUS.md](STATUS.md) |
| **Understand architecture** | [SPECS.md](SPECS.md) Section 2 |
| **Add a new generator** | [SPECS.md](SPECS.md) Section 4, [generators/README.md](generators/README.md) *(planned)* |
| **Configure AI features** | [config/ai.yaml](config/ai.yaml), [SPECS.md](SPECS.md) Section 6 |
| **Add business sources** | [SPECS.md](SPECS.md) Section 8, [business/](business/) |
| **Create scenarios** | [threat_intel/README.md](threat_intel/README.md), [scenarios/](scenarios/) |
| **Use the CLI** | [README.md](README.md) Section "Utilisation" |
| **Contribute code** | [CONTRIBUTING.md](CONTRIBUTING.md) *(planned)* |
| **Report bugs** | [issues/](https://github.com/.../issues) *(external)* |

---

## Document Status Legend

| Icon | Status | Meaning |
|------|--------|---------|
| ✅ | Complete | Ready for use |
| ⚠️ | In Progress | Being worked on |
| 📝 | Draft/Specs | Planned, not implemented |
| ⏸️ | Not Started | Future work |

---

**Last Updated:** 2024-03-07  
**Version:** 1.0-alpha  
**Maintainer:** SOC Log Generator Team

---

*For questions or contributions, see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue.*
