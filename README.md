# SOC Log Generator

> 📚 **[Documentation Index](INDEX.md)** - Navigate all project documentation  
> 📊 **[Project Status](STATUS.md)** - Current progress and roadmap  
> 📋 **[Technical Specs](SPECS.md)** - Architecture and design details

Generateur professionnel de logs pour SOC (Security Operations Center) et MSSP (Managed Security Service Provider).

## Objectif

Simuler un environnement d'entreprise complet avec des logs realistes provenant de multiples sources de securite, incluant des scenarios d'attaque pour tester les SIEM et les regles de detection.

## Architecture

```
soc-log-generator/
├── core.py                          # Moteur principal
├── main.py                          # Point d'entree
├── config/
│   └── default.yaml                 # Configuration par defaut
├── generators/
│   ├── endpoint/
│   │   ├── windows_generator.py     # Windows Event Logs + Sysmon
│   │   └── linux_generator.py       # Auth, Syslog, Auditd
│   ├── network/
│   │   ├── firewall_generator.py    # PaloAlto, Fortinet, Cisco
│   │   ├── proxy_generator.py       # Proxy Web
│   │   └── dns_generator.py         # DNS logs
│   ├── cloud/
│   │   ├── aws_generator.py         # CloudTrail
│   │   ├── azure_generator.py       # Azure Sentinel
│   │   └── o365_generator.py        # Office 365
│   └── security/
│       ├── crowdstrike_generator.py # EDR CrowdStrike
│       └── defender_generator.py    # MS Defender
├── scenarios/
│   ├── brute_force.py
│   ├── lateral_movement.py
│   └── data_exfiltration.py
└── outputs/
    ├── syslog_output.py
    ├── file_output.py
    └── kafka_output.py
```

## Sources Supportees

### Endpoint
| Source | Formats | Evenements |
|--------|---------|------------|
| **Windows Security** | XML, JSON, CEF | 4624/4625 (Logon), 4688 (Process), 4728 (Group), 49+ events |
| **Linux Auth** | Syslog | SSH auth, sudo commands, cron jobs, systemd |
| **Linux Auditd** | Syslog | Syscalls (execve, connect, open), file integrity |
| **Linux Sysmon** | JSON | Process Create (1), Network Connect (3), File Create (11), Raw Access (9) |

### Network
| Source | Vendors | Types |
|--------|---------|-------|
| **Firewall** | PaloAlto NGFW, Fortinet FortiGate, Cisco ASA | TRAFFIC, THREAT (22KB) |
| **Proxy** | Blue Coat ProxySG, Zscaler, Squid | Web access, blocked, DLP |
| **DNS** | Infoblox NIOS, BIND, CoreDNS | Queries, DNS tunneling detection |
| **IDS/IPS** | Suricata, Snort | EVE JSON, Snort alerts |

### Cloud
| Source | Services |
|--------|----------|
| **AWS** | CloudTrail, VPC Flow, GuardDuty |
| **Azure** | Sentinel, Activity Logs, Sign-ins |
| **Office 365** | Exchange, SharePoint, Azure AD |

### Security Tools
| Source | Types |
|--------|-------|
| **EDR** | CrowdStrike, MS Defender, Carbon Black |
| **NIDS** | Suricata, Snort |
| **Vulnerability** | Qualys, Nessus, Rapid7 |

## Utilisation

### Demarrage rapide

```bash
# Mode fichier local
python3 main.py -o /var/log/soc/logs.json

# Envoi vers rsyslog/SIEM
python3 main.py -t 10.0.0.1 -p 514 --protocol tcp

# Configuration personnalisee
python3 main.py -c config/production.yaml
```

### Arguments

| Argument | Description | Defaut |
|----------|-------------|--------|
| `-c, --config` | Fichier YAML de configuration | `config/default.yaml` |
| `-t, --target` | Destination syslog | - |
| `-p, --port` | Port syslog | 514 |
| `--protocol` | tcp/udp | tcp |
| `-o, --output` | Fichier de sortie | - |
| `--eps` | Events per second global | 100 |
| `--duration` | Duree en secondes | 0 (infini) |

### Configuration YAML

```yaml
generators:
  windows:
    enabled: true
    eps: 150
    weight: 1.0
    channels: [Security, Sysmon, System]
  
  linux:
    enabled: true
    eps: 80
    weight: 0.8
  
  firewall:
    enabled: true
    vendor: paloalto
    eps: 300
    weight: 1.5

outputs:
  - type: file
    path: /var/log/soc/logs.json
  
  - type: syslog
    host: 10.0.0.1
    port: 514
    protocol: tcp
```

## Scenarios d'Attaque

Le generateur peut injecter des scenarios d'attaque realistes:

### 1. Brute Force SSH
```yaml
scenarios:
  brute_force_ssh:
    enabled: true
    duration: 300
    attempts: 50
    target: 10.0.10.15
```

Evenements generees:
- Multiple `Failed password` dans auth.log
- `Connection closed` apres echecs
- Eventuellement `Accepted password` si succes

### 2. Lateral Movement
```yaml
scenarios:
  lateral_movement:
    enabled: true
    techniques: [psexec, wmi_exec, scheduled_task]
```

Evenements:
- Windows Event 4624 (logon type 3)
- Windows Event 4688 (psexec.exe)
- Sysmon Event 1 (creation process)
- Firewall logs entre segments

### 3. Data Exfiltration via DNS
```yaml
scenarios:
  dns_tunneling:
    enabled: true
    volume: "10MB"
    domain: "evil.com"
```

Evenements:
- Requetes DNS avec gros payload
- Sous-domaines encodes base64
- Volume anormal de requetes

### 4. Ransomware Behavior
- Creation de fichiers `.encrypted`
- Modification massive de fichiers
- Suppression des shadows copies
- Communication C2

## Formats de Sortie

### JSON (ECS)
```json
{
  "@timestamp": "2024-01-15T10:30:45.123Z",
  "source_type": "windows",
  "source_ip": "10.0.10.15",
  "source_host": "WK-WIN-015",
  "message": "An account was successfully logged on",
  "severity": "LOW",
  "fields": {
    "EventID": 4624,
    "Channel": "Security",
    "TargetUserName": "jdoe",
    "LogonType": 3
  },
  "tags": ["windows", "security", "logon"]
}
```

### CEF
```
CEF:0|Microsoft|Windows|1.0|4624|Logon|1|src=10.0.10.15 dst=10.0.30.1 suser=jdoe duser=admin outcome=success
```

### Syslog RFC 5424
```
<86>1 2024-01-15T10:30:45.123Z WK-WIN-015 Security - - - An account was successfully logged on
```

## Patterns Temporels Realistes

Le generateur simule des patterns d'activite realistes:

- **Heures de bureau**: 2x plus de logs (9h-12h, 14h-18h)
- **Pause dejeuner**: -30% de logs (12h-14h)
- **Nuit**: -80% de logs (23h-6h)
- **Week-end**: -60% de logs
- **Variations aleatoires**: +/- 10%

## Performance

| EPS | CPU | Memoire | Disque (JSON) |
|-----|-----|---------|---------------|
| 100 | 5%  | 50 MB   | 15 MB/heure   |
| 1000| 20% | 200 MB  | 150 MB/heure  |
| 5000| 60% | 800 MB  | 750 MB/heure  |
| 10000| 100%| 1.5 GB | 1.5 GB/heure  |

*Tests sur Intel i7, SSD NVMe*

## Integration SIEM

### Splunk
```bash
# Forwarder vers Splunk
python3 main.py -t splunk-indexer -p 9997 --protocol tcp

# Ou fichier + monitor
python3 main.py -o /opt/splunk/logs/soc-generator.json
```

### ELK Stack
```bash
# Directement vers Logstash
python3 main.py -t logstash -p 5044

# Ou fichier + Filebeat
python3 main.py -o /var/log/soc-generator/
```

### QRadar
```bash
# Format CEF pour QRadar
python3 main.py -t qradar -p 514 --format cef
```

### Sentinel / Log Analytics
```bash
# Format JSON vers Azure
python3 main.py --format json | az monitor log-analytics create ...
```

## Roadmap

- [ ] Generateurs Cloud (AWS, Azure, GCP)
- [ ] Generateurs EDR (CrowdStrike, Defender)
- [ ] Plus de scenarios d'attaque (APT, insider threat)
- [ ] Support Kafka / Kinesis
- [ ] Interface Web de controle
- [ ] Metriques Prometheus
- [ ] Tests de detection automatises

## Licence

MIT License - Usage libre pour SOC, MSSP, tests de SIEM
