#!/usr/bin/env python3
"""
Network Firewall Log Generator

Generates logs for enterprise firewalls:
- Palo Alto Networks (PAN-OS)
- Fortinet (FortiGate)
- Cisco ASA/FTD

Log types:
- TRAFFIC: Allowed/denied connections
- THREAT: Malware, vulnerabilities, suspicious activity
- URL: Web filtering logs
- DATA: Data filtering logs

Reference:
- Palo Alto: https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/monitoring/use-syslog-messages
- Fortinet: https://docs.fortinet.com/document/fortigate/7.2.0/log-message-reference
- Cisco ASA: https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html
"""

import json
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from ..base import BaseGenerator
    from ...core import LogEvent, EventSeverity, AssetInventory
except (ImportError, ValueError):
    from generators.base import BaseGenerator
    from core import LogEvent, EventSeverity, AssetInventory


class FirewallGenerator(BaseGenerator):
    """
    Multi-vendor firewall log generator.
    
    Supports Palo Alto, Fortinet, and Cisco ASA with realistic
    traffic patterns and threat detection events.
    """
    
    VENDORS = ['paloalto', 'fortinet', 'cisco_asa']
    
    # Application categories for next-gen firewalls
    APPLICATIONS = {
        'business': [
            'web-browsing', 'ssl', 'dns', 'ntp', 'ms-exchange', 'ms-ds-smb',
            'msrpc', 'netbios-ssn', 'kerberos', 'ldap', 'winrm', 'ms-update',
            'ms-office365', 'ms-lync', 'activesync', 'ms-dhcp'
        ],
        'productivity': [
            'gmail-base', 'google-base', 'google-docs', 'google-drive',
            'dropbox-base', 'onedrive', 'sharepoint-online', 'teams',
            'slack-base', 'zoom', 'webex', 'gotomeeting'
        ],
        'social': [
            'facebook-base', 'twitter-base', 'linkedin-base', 'instagram',
            'youtube-base', 'tiktok', 'snapchat'
        ],
        'infrastructure': [
            'ping', 'icmp', 'traceroute', 'ssh', 'telnet', 'snmp'
        ],
        'suspicious': [
            'unknown-tcp', 'unknown-udp', 'tor', 'bitcoin-mining',
            'teamviewer', 'anydesk', 'chrome-remote-desktop'
        ]
    }
    
    # URL categories
    URL_CATEGORIES = [
        'computer-and-internet-info', 'business-and-economy', 'search-engines',
        'web-based-email', 'social-networking', 'games', 'entertainment-and-arts',
        'streaming-media', 'travel', 'health-and-medicine', 'malware',
        'phishing', 'adult', 'weapons', 'hacking', 'proxy-avoidance',
        'peer-to-peer', 'shareware-and-freeware', 'financial-services'
    ]
    
    # Threat signatures (real CVEs and malware)
    THREAT_SIGNATURES = [
        # Critical CVEs
        ('CVE-2021-44228', 'Apache Log4j Remote Code Execution', 'vulnerability', EventSeverity.CRITICAL),
        ('CVE-2021-34527', 'Windows PrintNightmare', 'vulnerability', EventSeverity.CRITICAL),
        ('CVE-2020-1472', 'Zerologon Netlogon Elevation', 'vulnerability', EventSeverity.CRITICAL),
        ('CVE-2019-19781', 'Citrix ADC Remote Code Execution', 'vulnerability', EventSeverity.CRITICAL),
        ('MS17-010', 'EternalBlue SMB Exploit', 'vulnerability', EventSeverity.CRITICAL),
        
        # Malware families
        ('TrickBot.C2', 'TrickBot Banking Trojan C2', 'spyware', EventSeverity.HIGH),
        ('Emotet.C2', 'Emotet Malware C2', 'spyware', EventSeverity.HIGH),
        ('CobaltStrike.Beacon', 'Cobalt Strike Beacon', 'spyware', EventSeverity.CRITICAL),
        ('Metasploit.Payload', 'Metasploit Payload Detected', 'vulnerability', EventSeverity.HIGH),
        ('Mimikatz.Tool', 'Credential Dumping Tool', 'vulnerability', EventSeverity.HIGH),
        
        # Suspicious behavior
        ('Suspicious.DNS', 'Suspicious DNS Query Pattern', 'dns-signature', EventSeverity.MEDIUM),
        ('Port.Scan', 'Port Scan Detected', 'scan', EventSeverity.MEDIUM),
        ('Brute.Force', 'Brute Force Login Attempts', 'brute-force', EventSeverity.MEDIUM),
        ('Data.Exfil', 'Large Data Transfer Detected', 'data-theft', EventSeverity.HIGH),
        ('Cryptomining', 'Cryptocurrency Mining Activity', 'cryptominer', EventSeverity.MEDIUM),
        
        # Common attacks
        ('SQL.Injection', 'SQL Injection Attempt', 'sql-injection', EventSeverity.HIGH),
        ('XSS.Attack', 'Cross-Site Scripting Attempt', 'code-execution', EventSeverity.MEDIUM),
        ('LFI.Attack', 'Local File Inclusion', 'code-execution', EventSeverity.MEDIUM),
    ]
    
    # Common ports
    WELL_KNOWN_PORTS = {
        22: ('ssh', 'tcp'),
        23: ('telnet', 'tcp'),
        25: ('smtp', 'tcp'),
        53: ('dns', 'udp'),
        80: ('http', 'tcp'),
        110: ('pop3', 'tcp'),
        143: ('imap', 'tcp'),
        443: ('ssl', 'tcp'),
        445: ('smb', 'tcp'),
        3389: ('rdp', 'tcp'),
        5985: ('winrm', 'tcp'),
        5986: ('winrm', 'tcp'),
    }
    
    # Geolocation data for source IPs
    COUNTRIES = [
        ('US', 'United States', 0.60),
        ('CN', 'China', 0.15),
        ('RU', 'Russia', 0.10),
        ('BR', 'Brazil', 0.05),
        ('IN', 'India', 0.05),
        ('DE', 'Germany', 0.03),
        ('GB', 'United Kingdom', 0.02),
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.vendor = config.get('vendor', 'paloalto')
        self.threat_ratio = config.get('threat_ratio', 0.05)  # 5% threat logs
        
        # Get firewall assets
        self.firewalls = {k: v for k, v in inventory.assets.items() 
                         if v.get('type') == 'firewall'}
        if not self.firewalls:
            self.firewalls = {'FW-01': {'vendor': 'PaloAlto', 'ip': '192.168.1.1'}}
    
    def _get_firewall(self) -> Tuple[str, Dict]:
        """Get a random firewall device."""
        hostname = random.choice(list(self.firewalls.keys()))
        return hostname, self.firewalls[hostname]
    
    def _generate_ip(self, internal: bool = True) -> str:
        """Generate realistic IP address."""
        if internal:
            # Internal RFC 1918
            if random.random() < 0.7:
                return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif random.random() < 0.8:
                return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            # External - weighted by country
            country = random.choices(
                [c[0] for c in self.COUNTRIES],
                weights=[c[2] for c in self.COUNTRIES]
            )[0]
            
            # Country-specific IP ranges (simplified)
            if country == 'CN':
                return f"{random.choice([58, 59, 60, 61, 110, 111, 112, 113, 114])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif country == 'RU':
                return f"{random.choice([5, 31, 37, 46, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 178])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _generate_paloalto_traffic(self) -> LogEvent:
        """Generate Palo Alto PAN-OS traffic log."""
        fw_name, fw_info = self._get_firewall()
        
        # Determine traffic direction
        if random.random() < 0.6:
            # Internal to External
            src_ip = self._generate_ip(internal=True)
            dst_ip = self._generate_ip(internal=False)
            src_zone = 'Trust'
            dst_zone = 'Untrust'
        elif random.random() < 0.8:
            # External to DMZ
            src_ip = self._generate_ip(internal=False)
            dst_ip = self._generate_ip(internal=True)
            src_zone = 'Untrust'
            dst_zone = 'DMZ'
        else:
            # Internal lateral
            src_ip = self._generate_ip(internal=True)
            dst_ip = self._generate_ip(internal=True)
            src_zone = 'Trust'
            dst_zone = 'Trust'
        
        # Port and protocol
        if random.random() < 0.7:
            dst_port = random.choice(list(self.WELL_KNOWN_PORTS.keys()))
            proto, proto_name = self.WELL_KNOWN_PORTS[dst_port]
        else:
            dst_port = random.randint(1024, 65535)
            proto_name = 'tcp'
        
        src_port = random.randint(1024, 65535)
        
        # Application
        app_category = random.choices(
            ['business', 'productivity', 'social', 'infrastructure', 'suspicious'],
            weights=[50, 20, 10, 15, 5]
        )[0]
        app = random.choice(self.APPLICATIONS[app_category])
        
        # Action
        action = random.choices(
            ['allow', 'deny', 'drop', 'reset-both'],
            weights=[85, 10, 3, 2]
        )[0]
        
        # Bytes and packets
        bytes_sent = random.randint(100, 1000000)
        bytes_received = random.randint(100, 500000)
        pkts_sent = bytes_sent // random.randint(100, 1500)
        pkts_received = bytes_received // random.randint(100, 1500)
        
        # Session ID
        session_id = random.randint(100000, 999999)
        
        fields = {
            'vendor': 'paloalto',
            'type': 'TRAFFIC',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto_name,
            'action': action,
            'app': app,
            'category': random.choice(self.URL_CATEGORIES),
            'session_id': session_id,
            'bytes_sent': bytes_sent,
            'bytes_received': bytes_received,
            'pkts_sent': pkts_sent,
            'pkts_received': pkts_received,
            'src_zone': src_zone,
            'dst_zone': dst_zone,
            'src_intf': f'ethernet1/{random.randint(1, 4)}',
            'dst_intf': f'ethernet1/{random.randint(5, 8)}',
        }
        
        # Get interface values from fields
        src_intf = fields['src_intf']
        dst_intf = fields['dst_intf']
        category = fields['category']
        
        # Severity based on action
        if action == 'allow':
            severity = EventSeverity.LOW
            tags = ['firewall', 'traffic', 'paloalto', 'allowed']
        else:
            severity = EventSeverity.MEDIUM
            tags = ['firewall', 'traffic', 'paloalto', 'blocked']
        
        if app in ['tor', 'bitcoin-mining']:
            severity = EventSeverity.HIGH
            tags.append('suspicious_app')
        
        # Palo Alto CSV format
        ts = datetime.now(timezone.utc).strftime('%Y/%m/%d %H:%M:%S')
        raw = f"{ts},TRAFFIC,log,{action},,{src_zone},{dst_zone},,{src_intf},{dst_intf},,{src_ip},{dst_ip},,{proto_name},,{src_port},{dst_port},,{app},,{category},,,,,{session_id},,{bytes_sent},{bytes_received},{pkts_sent},{pkts_received},,,,,,,,,"
        
        msg = f"Traffic {action}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({app})"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='firewall',
            source_ip=fw_info.get('ip', '192.168.1.1'),
            source_host=fw_name,
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_paloalto_threat(self) -> LogEvent:
        """Generate Palo Alto threat log."""
        fw_name, fw_info = self._get_firewall()
        
        # Select threat
        sig_id, sig_name, threat_type, severity = random.choice(self.THREAT_SIGNATURES)
        
        # Source/Destination
        src_ip = self._generate_ip(internal=True)
        dst_ip = random.choice([
            '185.220.101.42', '192.42.116.203', '91.219.237.183',
            '45.142.214.89', '185.234.72.142', '23.254.200.56'
        ])
        
        # Action
        action = random.choice(['alert', 'block', 'reset-both'])
        
        fields = {
            'vendor': 'paloalto',
            'type': 'THREAT',
            'subtype': threat_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(40000, 65000),
            'dst_port': random.choice([443, 8080, 8443, 5555, 6666]),
            'protocol': 'tcp',
            'action': action,
            'threat_id': sig_id,
            'threat_name': sig_name,
            'category': threat_type,
            'severity': severity.name,
        }
        
        ts = datetime.now(timezone.utc).strftime('%Y/%m/%d %H:%M:%S')
        raw = f"{ts},THREAT,{threat_type},{action},,Trust,Untrust,,ethernet1/1,ethernet1/2,,{src_ip},{dst_ip},,tcp,,{fields['src_port']},{fields['dst_port']},,{sig_name},{threat_type},{severity.value},,"
        
        msg = f"Threat detected: {sig_name} from {src_ip} to {dst_ip}"
        
        tags = ['firewall', 'threat', 'paloalto', sig_id.lower().replace('.', '_')]
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='firewall',
            source_ip=fw_info.get('ip', '192.168.1.1'),
            source_host=fw_name,
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_fortinet_traffic(self) -> LogEvent:
        """Generate Fortinet FortiGate traffic log."""
        fw_name, fw_info = self._get_firewall()
        
        src_ip = self._generate_ip(internal=True)
        dst_ip = self._generate_ip(internal=False)
        
        action = random.choices(['accept', 'deny', 'drop'], weights=[85, 10, 5])[0]
        
        dst_port = random.choice([80, 443, 53, 22, 445, 3389]) if random.random() < 0.7 else random.randint(1024, 65535)
        proto_num = 6 if dst_port in [22, 80, 443, 445, 3389] else 17 if dst_port == 53 else random.choice([6, 17, 1])
        
        app = random.choice(self.APPLICATIONS['business'])
        
        bytes_sent = random.randint(1000, 1000000)
        bytes_received = random.randint(1000, 500000)
        
        policy_id = random.randint(1, 100)
        session_id = random.randint(10000000, 99999999)
        
        fields = {
            'vendor': 'fortinet',
            'type': 'traffic',
            'subtype': 'forward',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': dst_port,
            'proto': proto_num,
            'service': app,
            'app': app,
            'action': action,
            'policyid': policy_id,
            'sessionid': session_id,
            'sentbyte': bytes_sent,
            'rcvdbyte': bytes_received,
        }
        
        # Fortinet syslog format
        ts = int(datetime.now(timezone.utc).timestamp())
        raw = f"logver=2 timestamp={ts} devname=\"{fw_name}\" devid=\"FGT001\" vd=\"root\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip={src_ip} srcport={fields['src_port']} dstip={dst_ip} dstport={dst_port} proto={proto_num} service=\"{app}\" app=\"{app}\" appcat=\"{random.choice(self.URL_CATEGORIES)}\" apprisk=\"medium\" action=\"{action}\" policyid={policy_id} sessionid={session_id} sentbyte={bytes_sent} rcvdbyte={bytes_received}"
        
        msg = f"Traffic {action}: {src_ip} -> {dst_ip}:{dst_port}"
        
        severity = EventSeverity.LOW if action == 'accept' else EventSeverity.MEDIUM
        tags = ['firewall', 'traffic', 'fortinet', action]
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='firewall',
            source_ip=fw_info.get('ip', '192.168.1.1'),
            source_host=fw_name,
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_fortinet_threat(self) -> LogEvent:
        """Generate Fortinet threat log."""
        fw_name, fw_info = self._get_firewall()
        
        sig_id, sig_name, threat_type, severity = random.choice(self.THREAT_SIGNATURES)
        
        src_ip = self._generate_ip(internal=True)
        dst_ip = '185.220.101.42'
        
        action = random.choice(['block', 'monitor', 'reset'])
        
        fields = {
            'vendor': 'fortinet',
            'type': 'utm',
            'subtype': threat_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'action': action,
            'threat': sig_name,
            'threat_id': sig_id,
        }
        
        ts = int(datetime.now(timezone.utc).timestamp())
        raw = f"type=\"utm\" subtype=\"{threat_type}\" eventtype=\"signature\" level=\"warning\" vd=\"root\" eventtime={ts} msg=\"{sig_name}\" action=\"{action}\" srcip={src_ip} dstip={dst_ip} srcport={random.randint(10000, 60000)} dstport={random.choice([443, 80])}"
        
        msg = f"Threat: {sig_name} from {src_ip}"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='firewall',
            source_ip=fw_info.get('ip', '192.168.1.1'),
            source_host=fw_name,
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=['firewall', 'threat', 'fortinet'],
            severity=severity
        )
    
    def _generate_cisco_asa_traffic(self) -> LogEvent:
        """Generate Cisco ASA connection log."""
        fw_name, fw_info = self._get_firewall()
        
        src_ip = self._generate_ip(internal=True)
        dst_ip = self._generate_ip(internal=False)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53])
        
        proto = 'tcp' if dst_port in [22, 80, 443] else 'udp' if dst_port == 53 else 'icmp'
        
        action = random.choices(['built', 'teardown'], weights=[70, 30])[0]
        
        fields = {
            'vendor': 'cisco_asa',
            'type': 'connection',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto,
            'action': action,
        }
        
        # Cisco ASA syslog format
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        
        if action == 'built':
            session_id = random.randint(1000000000, 9999999999)
            raw = f"{ts} {fw_name} %ASA-6-302013: Built {proto} connection {session_id} for outside:{dst_ip}/{dst_port} ({dst_ip}/{dst_port}) to inside:{src_ip}/{src_port} ({src_ip}/{src_port})"
            msg = f"Connection built: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            severity = EventSeverity.LOW
        else:
            duration = random.randint(1, 3600)
            bytes_total = random.randint(1000, 10000000)
            raw = f"{ts} {fw_name} %ASA-6-302014: Teardown {proto} connection {random.randint(1000000000, 9999999999)} for outside:{dst_ip}/{dst_port} to inside:{src_ip}/{src_port} duration 0:{duration//60:02d}:{duration%60:02d} bytes {bytes_total}"
            msg = f"Connection teardown: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            severity = EventSeverity.LOW
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='firewall',
            source_ip=fw_info.get('ip', '192.168.1.1'),
            source_host=fw_name,
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=['firewall', 'traffic', 'cisco_asa', action],
            severity=severity
        )
    
    def _generate_cisco_asa_threat(self) -> LogEvent:
        """Generate Cisco ASA threat detection log."""
        fw_name, fw_info = self._get_firewall()
        
        src_ip = self._generate_ip(internal=False)
        dst_ip = self._generate_ip(internal=True)
        
        # Different threat types
        threat_types = [
            ('106021', 'Deny protocol src outside', EventSeverity.MEDIUM),
            ('106023', 'Deny tcp src outside', EventSeverity.MEDIUM),
            ('419002', 'Duplicate TCP SYN', EventSeverity.HIGH),
            ('500004', 'Invalid transport', EventSeverity.MEDIUM),
        ]
        
        code, desc, severity = random.choice(threat_types)
        
        fields = {
            'vendor': 'cisco_asa',
            'type': 'threat',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'code': code,
        }
        
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        raw = f"{ts} {fw_name} %ASA-4-{code}: {desc}:{src_ip}/{random.randint(1000, 65535)} to inside:{dst_ip}/{random.choice([22, 80, 443, 3389])}"
        
        msg = f"Threat detected from {src_ip}: {desc}"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='firewall',
            source_ip=fw_info.get('ip', '192.168.1.1'),
            source_host=fw_name,
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=['firewall', 'threat', 'cisco_asa'],
            severity=severity
        )
    
    def generate_event(self) -> LogEvent:
        """Generate a firewall event based on vendor and type."""
        # Determine if threat or traffic
        is_threat = random.random() < self.threat_ratio
        
        if self.vendor == 'paloalto':
            if is_threat:
                return self._generate_paloalto_threat()
            else:
                return self._generate_paloalto_traffic()
        
        elif self.vendor == 'fortinet':
            if is_threat:
                return self._generate_fortinet_threat()
            else:
                return self._generate_fortinet_traffic()
        
        elif self.vendor == 'cisco_asa':
            if is_threat:
                return self._generate_cisco_asa_threat()
            else:
                return self._generate_cisco_asa_traffic()
        
        else:
            # Default to Palo Alto
            return self._generate_paloalto_traffic()
