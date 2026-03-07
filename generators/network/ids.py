#!/usr/bin/env python3
"""
IDS/IPS Log Generator

Generates logs for network intrusion detection systems:
- Suricata (EVE JSON format)
- Snort (Unified2, syslog)

Alert categories:
- Malware detection
- Network scans
- Exploit attempts
- Policy violations
"""

import json
import random
from datetime import datetime, timezone
from typing import Any, Dict

try:
    from ..base import BaseGenerator
    from ...core import LogEvent, EventSeverity, AssetInventory
except (ImportError, ValueError):
    from generators.base import BaseGenerator
    from core import LogEvent, EventSeverity, AssetInventory


class IDSensorGenerator(BaseGenerator):
    """IDS/IPS log generator for Suricata and Snort."""
    
    VENDORS = ['suricata', 'snort']
    
    # Suricata/Snort rule categories
    CATEGORIES = {
        ' malware': [
            ('ET MALWARE Possible Cobalt Strike Beacon', 1, EventSeverity.CRITICAL),
            ('ET MALWARE TrickBot Banking Trojan C2', 2, EventSeverity.HIGH),
            ('ET MALWARE Emotet Malicious Document', 3, EventSeverity.HIGH),
        ],
        'attack': [
            ('ET EXPLOIT Possible EternalBlue SMB Exploit', 4, EventSeverity.CRITICAL),
            ('ET EXPLOIT Apache Log4j RCE Attempt', 5, EventSeverity.CRITICAL),
            ('ET EXPLOIT MS17-010 SMB RCE', 6, EventSeverity.CRITICAL),
        ],
        'scan': [
            ('ET SCAN Suspicious Port Scan', 7, EventSeverity.MEDIUM),
            ('ET SCAN NMAP OS Detection Probe', 8, EventSeverity.LOW),
        ],
        'policy': [
            ('ET POLICY SMB2 NT Create AndX Request', 9, EventSeverity.LOW),
            ('ET POLICY curl User-Agent', 10, EventSeverity.LOW),
        ],
    }
    
    # Protocols
    PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.vendor = config.get('vendor', 'suricata')
    
    def _generate_suricata_event(self) -> LogEvent:
        """Generate Suricata EVE JSON alert."""
        src_ip = f"10.0.{random.randint(10,30)}.{random.randint(11,254)}"
        dst_ip = random.choice(['185.220.101.42', '45.142.214.89', '192.168.1.100'])
        
        category = random.choice(list(self.CATEGORIES.keys()))
        msg, sid, severity = random.choice(self.CATEGORIES[category])
        
        proto = random.choice(self.PROTOCOLS)
        src_port = random.randint(40000, 65000)
        dst_port = random.choice([443, 80, 445, 3389, 22])
        
        fields = {
            'vendor': 'suricata',
            'event_type': 'alert',
            'src_ip': src_ip,
            'dest_ip': dst_ip,
            'src_port': src_port,
            'dest_port': dst_port,
            'proto': proto,
            'alert': {
                'action': 'allowed',
                'gid': 1,
                'signature_id': sid,
                'rev': 1,
                'signature': msg,
                'category': category.strip(),
                'severity': severity.value,
            },
        }
        
        eve = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'alert',
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'proto': proto,
            'alert': fields['alert'],
        }
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='ids',
            source_ip=src_ip,
            source_host='suricata-sensor-01',
            message=msg,
            raw_log=json.dumps(eve),
            fields=fields,
            tags=['ids', 'suricata', 'alert', category.strip()],
            severity=severity
        )
    
    def _generate_snort_event(self) -> LogEvent:
        """Generate Snort syslog alert."""
        src_ip = f"10.0.{random.randint(10,30)}.{random.randint(11,254)}"
        dst_ip = '192.168.1.1'
        
        msg, sid, severity = random.choice(self.CATEGORIES['attack'])
        
        fields = {
            'vendor': 'snort',
            'msg': msg,
            'sid': sid,
            'classification': 'Attempted Administrator Privilege Gain',
            'priority': severity.value,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1000, 65535),
            'dst_port': 445,
        }
        
        ts = datetime.now(timezone.utc).strftime('%m/%d-%H:%M:%S')
        raw = f"[**] [{sid}:1:1] {msg} [**] [Classification: {fields['classification']}] [Priority: {severity.value}] {{{random.choice(['TCP','UDP'])}}} {src_ip}:{fields['src_port']} -> {dst_ip}:{fields['dst_port']}"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='ids',
            source_ip=src_ip,
            source_host='snort-sensor-01',
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=['ids', 'snort', 'alert'],
            severity=severity
        )
    
    def generate_event(self) -> LogEvent:
        """Generate IDS/IPS event."""
        if self.vendor == 'suricata':
            return self._generate_suricata_event()
        elif self.vendor == 'snort':
            return self._generate_snort_event()
        else:
            return self._generate_suricata_event()
