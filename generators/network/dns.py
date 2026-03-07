#!/usr/bin/env python3
"""
DNS Server Log Generator

Generates logs for DNS servers:
- Infoblox (NIOS)
- BIND
- Windows DNS
- CoreDNS (Kubernetes)

Log types:
- Query/Response logs
- DNSSEC validation
- Zone transfers
- DNS Tunneling detection
"""

import random
from datetime import datetime, timezone
from typing import Any, Dict

try:
    from ..base import BaseGenerator
    from ...core import LogEvent, EventSeverity, AssetInventory
except (ImportError, ValueError):
    from generators.base import BaseGenerator
    from core import LogEvent, EventSeverity, AssetInventory


class DNSGenerator(BaseGenerator):
    """DNS server log generator."""
    
    VENDORS = ['infoblox', 'bind', 'windows', 'coredns']
    
    # Query types
    QUERY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'DNSKEY']
    TYPE_WEIGHTS = [50, 15, 10, 5, 3, 8, 2, 4, 2, 1]
    
    # Response codes
    RESPONSE_CODES = {
        0: 'NOERROR',
        1: 'FORMERR',
        2: 'SERVFAIL',
        3: 'NXDOMAIN',
        4: 'NOTIMP',
        5: 'REFUSED',
        9: 'NOTAUTH',
    }
    
    # Domains
    INTERNAL_DOMAINS = [
        'corp.local', 'dmz.corp.local', 'admin.corp.local',
        'dc-01.corp.local', 'mail.corp.local', 'www.corp.local'
    ]
    
    EXTERNAL_DOMAINS = [
        'www.google.com', 'www.microsoft.com', 'outlook.office365.com',
        'teams.microsoft.com', 'cdn.jsdelivr.net', 'fonts.googleapis.com',
        'api.github.com', 'www.linkedin.com', 'slack.com', 'zoom.us',
        'www.youtube.com', 'www.facebook.com', 'www.reddit.com',
    ]
    
    # Suspicious domains for tunneling simulation
    TUNNEL_DOMAINS = [
        'aHR0cHM6Ly9leGFtcGxlLmNvbQ.c2VjcmV0LmNvbQ.tunnel.evil.com',
        'YmFzZTY0LmVuY29kZWQuZGF0YQ.tunnel.evil.com',
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.vendor = config.get('vendor', 'infoblox')
        self.tunnel_ratio = config.get('tunnel_ratio', 0.01)  # 1% DNS tunneling
    
    def _generate_infoblox_event(self) -> LogEvent:
        """Generate Infoblox NIOS log."""
        src_ip = f"10.0.{random.randint(10,30)}.{random.randint(11,254)}"
        
        # Determine if internal or external query
        if random.random() < 0.3:
            domain = random.choice(self.INTERNAL_DOMAINS)
        elif random.random() < self.tunnel_ratio:
            domain = random.choice(self.TUNNEL_DOMAINS)
        else:
            domain = random.choice(self.EXTERNAL_DOMAINS)
        
        qtype = random.choices(self.QUERY_TYPES, weights=self.TYPE_WEIGHTS)[0]
        
        # Response
        if random.random() < 0.95:
            rcode = 0
            rcode_name = 'NOERROR'
        else:
            rcode = random.choice([3, 5])
            rcode_name = self.RESPONSE_CODES[rcode]
        
        # Check for tunneling (long subdomain)
        is_tunnel = len(domain) > 50 or domain.count('.') > 5
        
        fields = {
            'vendor': 'infoblox',
            'src_ip': src_ip,
            'query': domain,
            'qtype': qtype,
            'rcode': rcode,
            'rcode_name': rcode_name,
            'answer': '10.0.0.1' if rcode == 0 else None,
        }
        
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')
        raw = f"{ts} client @{src_ip} {domain} {qtype}: {rcode_name}"
        
        msg = f"DNS query: {src_ip} -> {domain} ({qtype})"
        
        severity = EventSeverity.HIGH if is_tunnel else EventSeverity.LOW
        tags = ['dns', 'infoblox', 'tunneling' if is_tunnel else 'normal']
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='dns',
            source_ip='10.0.30.5',
            source_host='infoblox-dns-01',
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_bind_event(self) -> LogEvent:
        """Generate BIND named log."""
        src_ip = f"10.0.{random.randint(10,30)}.{random.randint(11,254)}"
        domain = random.choice(self.EXTERNAL_DOMAINS)
        qtype = random.choice(['A', 'AAAA'])
        
        fields = {
            'vendor': 'bind',
            'src_ip': src_ip,
            'query': domain,
            'qtype': qtype,
        }
        
        ts = datetime.now(timezone.utc).strftime('%d-%b-%Y %H:%M:%S')
        raw = f"{ts}.000 client {src_ip} query: {domain} IN {qtype} + (8.8.8.8)"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='dns',
            source_ip='10.0.30.6',
            source_host='bind-dns-01',
            message=f"BIND query: {src_ip} -> {domain}",
            raw_log=raw,
            fields=fields,
            tags=['dns', 'bind'],
            severity=EventSeverity.LOW
        )
    
    def generate_event(self) -> LogEvent:
        """Generate DNS event."""
        if self.vendor == 'infoblox':
            return self._generate_infoblox_event()
        elif self.vendor == 'bind':
            return self._generate_bind_event()
        else:
            return self._generate_infoblox_event()
