#!/usr/bin/env python3
"""
Web Proxy Log Generator

Generates logs for web proxy servers:
- Blue Coat ProxySG (Symantec)
- Zscaler Internet Access
- Squid Proxy
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


class ProxyGenerator(BaseGenerator):
    """Web proxy log generator."""
    
    VENDORS = ['bluecoat', 'zscaler', 'squid']
    
    METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT']
    METHOD_WEIGHTS = [70, 20, 3, 1, 3, 1, 2]
    
    RESPONSE_CODES = [200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]
    CODE_WEIGHTS = [60, 5, 3, 5, 10, 8, 2, 1, 2, 3, 1, 1, 1]
    
    CATEGORIES = {
        'allowed': ['Search Engines', 'Business', 'Web-based Email', 'Finance'],
        'blocked': ['Adult', 'Gambling', 'Weapons'],
        'suspicious': ['Proxy Avoidance', 'Malware', 'Phishing'],
    }
    
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    ]
    
    TOP_DOMAINS = [
        'www.google.com', 'www.youtube.com', 'www.microsoft.com',
        'www.linkedin.com', 'outlook.office365.com', 'teams.microsoft.com',
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.vendor = config.get('vendor', 'bluecoat')
        self.block_ratio = config.get('block_ratio', 0.05)
    
    def _get_user(self):
        """Get random user from inventory."""
        return self.inventory.get_random_user()
    
    def _generate_bluecoat_event(self) -> LogEvent:
        """Generate Blue Coat ProxySG log."""
        user = self._get_user()
        src_ip = f"10.0.10.{random.randint(11, 30)}"
        
        method = random.choices(self.METHODS, weights=self.METHOD_WEIGHTS)[0]
        code = random.choices(self.RESPONSE_CODES, weights=self.CODE_WEIGHTS)[0]
        
        domain = random.choice(self.TOP_DOMAINS)
        url = f"https://{domain}/path{random.randint(1, 100)}"
        
        bytes_sent = random.randint(500, 50000)
        bytes_received = random.randint(1000, 500000)
        
        is_blocked = code == 403 or random.random() < self.block_ratio
        action = 'DENIED' if is_blocked else 'ALLOWED'
        category = random.choice(self.CATEGORIES['blocked'] if is_blocked else self.CATEGORIES['allowed'])
        
        fields = {
            'vendor': 'bluecoat',
            'src_ip': src_ip,
            'user': user['username'],
            'method': method,
            'url': url,
            'code': code,
            'action': action,
            'category': category,
            'bytes_sent': bytes_sent,
            'bytes_received': bytes_received,
        }
        
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        raw = f"{ts} {code} {method} {bytes_received} {action} {category} {user['username']} {src_ip} {url}"
        
        msg = f"Web {action}: {user['username']} -> {url}"
        severity = EventSeverity.HIGH if is_blocked else EventSeverity.LOW
        tags = ['proxy', 'bluecoat', action.lower()]
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='proxy',
            source_ip=src_ip,
            source_host=f"PROXY-{random.randint(1,3):02d}",
            message=msg,
            raw_log=raw,
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_zscaler_event(self) -> LogEvent:
        """Generate Zscaler NSS log."""
        user = self._get_user()
        src_ip = f"10.0.10.{random.randint(11, 30)}"
        
        method = random.choice(self.METHODS)
        code = random.choices(self.RESPONSE_CODES, weights=self.CODE_WEIGHTS)[0]
        
        domain = random.choice(self.TOP_DOMAINS)
        url = f"https://{domain}/api/data"
        
        fields = {
            'vendor': 'zscaler',
            'src_ip': src_ip,
            'user': user['username'],
            'method': method,
            'url': url,
            'code': code,
            'action': 'BLOCKED' if code == 403 else 'ALLOWED',
            'category': 'Business',
            'risk': 'LOW',
        }
        
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        raw = f"{ts} ZSCALER method={method} url={url} user={user['username']} srcip={src_ip} respcode={code}"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='proxy',
            source_ip=src_ip,
            source_host=f"ZSCALER-{random.randint(1,3)}",
            message=f"Zscaler: {user['username']} -> {domain}",
            raw_log=raw,
            fields=fields,
            tags=['proxy', 'zscaler'],
            severity=EventSeverity.LOW
        )
    
    def _generate_squid_event(self) -> LogEvent:
        """Generate Squid native log."""
        user = self._get_user()
        src_ip = f"10.0.20.{random.randint(11, 30)}"
        
        elapsed = random.randint(10, 5000)
        code = random.choices(self.RESPONSE_CODES, weights=self.CODE_WEIGHTS)[0]
        bytes_sent = random.randint(1000, 500000)
        method = random.choices(self.METHODS, weights=self.METHOD_WEIGHTS)[0]
        
        domain = random.choice(self.TOP_DOMAINS)
        url = f"http://{domain}/content"
        
        fields = {
            'vendor': 'squid',
            'src_ip': src_ip,
            'user': user['username'],
            'elapsed': elapsed,
            'code': code,
            'bytes': bytes_sent,
            'method': method,
            'url': url,
        }
        
        ts = int(datetime.now(timezone.utc).timestamp())
        raw = f"{ts}.{random.randint(100, 999)} {elapsed} {src_ip} {code}/{random.choice([200, 304, 404])} {bytes_sent} {method} {url} - HIER_DIRECT/{domain} -"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type='proxy',
            source_ip=src_ip,
            source_host='squid-proxy-01',
            message=f"Squid: {method} {url}",
            raw_log=raw,
            fields=fields,
            tags=['proxy', 'squid'],
            severity=EventSeverity.LOW
        )
    
    def generate_event(self) -> LogEvent:
        """Generate proxy event."""
        if self.vendor == 'bluecoat':
            return self._generate_bluecoat_event()
        elif self.vendor == 'zscaler':
            return self._generate_zscaler_event()
        elif self.vendor == 'squid':
            return self._generate_squid_event()
        else:
            return self._generate_bluecoat_event()
