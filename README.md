# SOC Log Generator

> 📚 **[Documentation Index](INDEX.md)** - Navigate all project documentation  
> 📊 **[Project Status](STATUS.md)** - Current progress and roadmap  
> 📋 **[Technical Specs](SPECS.md)** - Architecture and design details

Professional log generator for SOC (Security Operations Center) and MSSP (Managed Security Service Provider).

## Objective

Simulate a complete enterprise environment with realistic security logs from multiple sources, including attack scenarios for testing SIEMs and detection rules.

## Architecture

```
soc-log-generator/
├── core.py                          # Core engine
├── main.py                          # Entry point
├── config/
│   └── default.yaml                 # Default configuration
├── generators/
│   ├── endpoint/
│   │   ├── windows.py               # Windows Event Logs + Sysmon
│   │   └── linux_generator.py       # Auth, Syslog, Auditd
│   ├── network/
│   │   ├── firewall.py              # PaloAlto, Fortinet, Cisco
│   │   ├── proxy.py                 # Web Proxy
│   │   └── dns.py                   # DNS logs
│   ├── cloud/
│   │   ├── aws_cloudtrail.py        # CloudTrail
│   │   ├── azure_activity.py        # Azure Activity Logs
│   │   └── o365.py                  # Office 365
├── validation/                       # Quality control
├── siem_tests/                       # SIEM compatibility tests
└── stress_tests/                     # Performance testing
```

## Quick Start

### Installation

```bash
git clone https://github.com/DeDobbeleer/soc-log-generator.git
cd soc-log-generator
pip install -r requirements.txt
```

### Generate Logs

```bash
# Windows Events to file
python3 -m soc_log_generator generate --generator windows --output-file events.json --duration 60

# AWS CloudTrail to syslog
python3 -m soc_log_generator generate --generator aws --syslog-host 192.168.1.100 --eps 100

# Firewall logs with burst mode
python3 -m soc_log_generator generate --generator firewall --mode burst --start-eps 100 --eps 5000
```

### Available Generators

| Source | Generator | CLI |
|--------|-----------|-----|
| Windows | Windows Event Logs | `--generator windows` |
| Linux | Auth/Syslog | `--generator linux` |
| Firewall | Palo Alto/Fortinet/Cisco | `--generator firewall` |
| Proxy | BlueCoat/Zscaler/Squid | `--generator proxy` |
| DNS | Infoblox/BIND | `--generator dns` |
| IDS/IPS | Suricata/Snort | `--generator ids` |
| AWS | CloudTrail | `--generator aws` |
| Azure | Activity Logs | `--generator azure` |
| Azure AD | Sign-in Logs | `--generator azure-signin` |
| Office 365 | Audit Logs | `--generator o365` |
| GCP | Audit Logs | `--generator gcp` |

## CLI Options

```
--generator {windows,linux,firewall,proxy,dns,ids,aws,azure,o365,gcp}
  Log generator to use
  
--syslog-host HOST
  SIEM server IP or hostname
  
--syslog-port PORT (default: 514)
  Syslog server port
  
--syslog-protocol {tcp,udp}
  Transport protocol
  
--syslog-format {syslog,json,cef}
  Output format (syslog=RFC5424, json=ECS, cef=ArcSight)
  
--eps FLOAT (default: 100)
  Events per second target
  
--duration SECONDS (default: 0=unlimited)
  Generation duration
  
--mode {constant,ramp,burst}
  Generation mode:
    - constant: Fixed EPS
    - ramp: Gradual increase
    - burst: Traffic spikes
  
--multi N (default: 1)
  Number of parallel clients
  
--output-file PATH
  Output file (if not using syslog)
```

## Testing on SIEM

### Test Scripts

```bash
# Test Windows Events on SIEM
./test_scripts/test_windows.sh 192.168.1.100 514

# Test AWS CloudTrail
./test_scripts/test_aws.sh 192.168.1.100 514

# Stress test
./test_scripts/test_stress.sh 192.168.1.100 514
```

### Test Procedure

Fill in the [TEST_PROCEDURE.md](TEST_PROCEDURE.md) logbook with:
- Events received
- Parsing validation
- Alert triggering
- Performance metrics

## Project Status

**Current Phase:** Testing Framework Ready

- ✅ 12 log generators (Phases 1-3 complete)
- ✅ Quality control system (validation, schemas)
- ✅ Testing framework (SIEM compatibility, stress tests)
- ⏸️ Awaiting live SIEM validation
- ⏸️ Phase 4: Security scenarios (pending)

See [STATUS.md](STATUS.md) for complete details.

## Documentation

| Document | Description |
|----------|-------------|
| [INDEX.md](INDEX.md) | Documentation index |
| [STATUS.md](STATUS.md) | Project status and roadmap |
| [SPECS.md](SPECS.md) | Technical specifications |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guide |
| [TEST_PROCEDURE.md](TEST_PROCEDURE.md) | SIEM testing procedures |

## License

MIT License - See LICENSE file
