#!/usr/bin/env python3
"""
Generateur de logs Firewall (Palo Alto, Fortinet, Cisco ASA)
"""

import random
from datetime import datetime, timezone
from typing import Dict, List, Any
try:
    from ..base import BaseGenerator
    from ...core import LogEvent, EventSeverity, AssetInventory
except (ImportError, ValueError):
    from generators.base import BaseGenerator
    from core import LogEvent, EventSeverity, AssetInventory


class FirewallGenerator(BaseGenerator):
    """Generateur de logs Firewall multi-vendors"""
    
    VENDORS = ['paloalto', 'fortinet', 'cisco_asa']
    ACTIONS = ['allow', 'deny', 'drop', 'reset-both']
    
    APPLICATIONS = [
        'web-browsing', 'ssl', 'dns', 'dhcp', 'ntp', 'icmp', 'ssh', 'telnet',
        'ms-ds-smb', 'netbios-ssn', 'kerberos', 'ldap', 'msrpc', 'winrm',
        'ms-update', 'ms-office365', 'ms-exchange', 'activesync', 'ms-lync',
        'facebook-base', 'twitter-base', 'linkedin-base', 'youtube-base',
        'gmail-base', 'google-base', 'dropbox-base', 'onedrive-base',
        'teamviewer', 'anydesk', 'chrome-remote-desktop',
        'bitcoin-mining', 'tor', 'unknown-udp', 'unknown-tcp',
    ]
    
    URL_CATEGORIES = [
        'computer-and-internet-info', 'business-and-economy', 'search-engines',
        'web-based-email', 'social-networking', 'games', 'entertainment-and-arts',
        'streaming-media', 'travel', 'health-and-medicine', 'malware',
        'phishing', 'adult', 'weapons', 'hacking', 'proxy-avoidance',
    ]
    
    THREAT_TYPES = ['virus', 'spyware', 'vulnerability', 'filetype', 'data-filtering', 'url-filtering', 'wildfire-virus', 'wildfire']
    
    THREAT_SIGNATURES = [
        ('CVE-2021-44228 Log4j RCE', '40000', EventSeverity.CRITICAL),
        ('MS17-010 EternalBlue SMB Exploit', '38607', EventSeverity.CRITICAL),
        ('Lazarus Group Activity', '39000', EventSeverity.HIGH),
        ('TrickBot C2 Communication', '38420', EventSeverity.HIGH),
        ('Emotet C2 Beacon', '38200', EventSeverity.HIGH),
        ('Suspicious DNS Query', '10000', EventSeverity.MEDIUM),
        ('Brute Force Login Attempt', '10001', EventSeverity.MEDIUM),
        ('Port Scan Detected', '10002', EventSeverity.MEDIUM),
        ('Large File Transfer', '10003', EventSeverity.LOW),
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.vendor = config.get('vendor', 'paloalto')
        
    def _get_random_firewall(self) -> Dict:
        firewalls = {k: v for k, v in self.inventory.assets.items() if v.get("type") == "firewall"}
        if not firewalls:
            return {"hostname": "FW-01", "ip": "192.168.1.1", "vendor": "PaloAlto"}
        hostname = random.choice(list(firewalls.keys()))
        asset = firewalls[hostname].copy()
        asset["hostname"] = hostname
        return asset
    
    def _generate_traffic_log(self) -> LogEvent:
        fw = self._get_random_firewall()
        timestamp = datetime.now(timezone.utc)
        
        if random.random() < 0.6:
            src_asset = self.inventory.get_random_asset()
            src_ip = src_asset['ip']
            dst_ip = random.choice(['8.8.8.8', '1.1.1.1', '13.107.42.14', '142.250.185.78'])
        elif random.random() < 0.8:
            src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            dst_asset = self.inventory.get_random_asset('server')
            dst_ip = dst_asset['ip']
        else:
            src_asset = self.inventory.get_random_asset()
            src_ip = src_asset['ip']
            dst_asset = self.inventory.get_random_asset()
            dst_ip = dst_asset['ip']
        
        dst_port = random.choice([80, 443, 53, 123, 445, 3389, 5985, 22, 25, 993]) if random.random() < 0.7 else random.randint(1024, 65535)
        src_port = random.randint(1024, 65535)
        action = random.choices(self.ACTIONS, weights=[85, 10, 3, 2])[0]
        app = random.choices(self.APPLICATIONS, weights=[30, 20, 10, 5, 3, 2, 2, 2, 2, 2] + [1]*16)[0]
        proto = 'tcp' if dst_port in [80, 443, 22, 25, 993, 3389, 445] else 'udp' if dst_port == 53 else random.choice(['tcp', 'udp', 'icmp'])
        
        bytes_sent = random.randint(100, 1000000)
        bytes_received = random.randint(100, 5000000) if app in ['youtube-base', 'streaming-media'] else random.randint(100, 100000)
        pkts_sent = bytes_sent // random.randint(100, 1500)
        pkts_received = bytes_received // random.randint(100, 1500)
        
        severity = EventSeverity.LOW
        tags = ['firewall', 'traffic', self.vendor]
        
        if action in ['deny', 'drop', 'reset-both']:
            severity = EventSeverity.MEDIUM
            tags.extend(['blocked', 'policy_violation'])
        
        if app in ['tor', 'bitcoin-mining']:
            severity = EventSeverity.HIGH
            tags.append('suspicious_app')
        
        fields = {
            'vendor': self.vendor,
            'log_type': 'TRAFFIC',
            'action': action,
            'application': app,
            'protocol': proto,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'src_zone': random.choice(['Trust', 'Internal', 'DMZ']),
            'dst_zone': random.choice(['Untrust', 'External', 'Internet']),
            'bytes_sent': bytes_sent,
            'bytes_received': bytes_received,
            'packets_sent': pkts_sent,
            'packets_received': pkts_received,
            'category': random.choice(self.URL_CATEGORIES),
            'session_id': random.randint(100000, 999999),
        }
        
        return LogEvent(
            timestamp=timestamp,
            source_type='firewall',
            source_ip=fw['ip'],
            source_host=fw['hostname'],
            message=f"Traffic {action}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({app})",
            raw_log=f"TRAFFIC,{action},{src_ip},{dst_ip},{proto},{src_port},{dst_port},{app}",
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_threat_log(self) -> LogEvent:
        fw = self._get_random_firewall()
        timestamp = datetime.now(timezone.utc)
        sig_name, sig_id, severity = random.choice(self.THREAT_SIGNATURES)
        threat_type = random.choice(self.THREAT_TYPES)
        
        src_asset = self.inventory.get_random_asset()
        src_ip = src_asset['ip']
        dst_ip = random.choice(['185.220.101.0', '192.42.116.0', '45.142.214.0'])
        dst_port = random.choice([443, 8080, 8443, 5555, 6666])
        action = random.choice(['alert', 'block', 'allow', 'reset-both'])
        
        fields = {
            'vendor': self.vendor,
            'log_type': 'THREAT',
            'subtype': threat_type,
            'action': action,
            'severity': severity.name,
            'signature': sig_name,
            'signature_id': sig_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': 'tcp',
        }
        
        tags = ['firewall', 'threat', self.vendor]
        
        return LogEvent(
            timestamp=timestamp,
            source_type='firewall',
            source_ip=fw['ip'],
            source_host=fw['hostname'],
            message=f"Threat detected: {sig_name}",
            raw_log=f"THREAT,{sig_name},{src_ip},{dst_ip}",
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def generate_event(self) -> LogEvent:
        if random.random() < 0.9:
            return self._generate_traffic_log()
        else:
            return self._generate_threat_log()
