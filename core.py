#!/usr/bin/env python3
"""
SOC Log Generator - Core Engine

This module provides the foundational components for the SOC Log Generator:
- Event model and serialization
- Asset inventory management
- Rate limiting and timing control
- Output handlers

Author: SOC Log Generator Team
Version: 1.0.0
"""

import json
import logging
import random
import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Union

# Configure module logger
logger = logging.getLogger("soc_log_generator.core")


class EventSeverity(Enum):
    """
    Standardized event severity levels for security events.
    
    Maps to common SIEM severity scales:
    - LOW (1): Informational, routine activity
    - MEDIUM (2): Policy violations, suspicious patterns
    - HIGH (3): Confirmed threats, policy breaches  
    - CRITICAL (4): Active attacks, data exfiltration
    """
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class LogEvent:
    """
    Standardized log event structure.
    
    This dataclass represents a single log event with all fields necessary
    for SIEM ingestion. It supports multiple output formats including
    JSON (ECS), CEF, and Syslog RFC 5424.
    
    Attributes:
        timestamp: Event occurrence time (UTC)
        source_type: Source category (windows, linux, firewall, etc.)
        source_ip: Source asset IP address
        source_host: Source asset hostname
        message: Human-readable event description
        raw_log: Original/vendor-specific log format
        fields: Structured key-value fields (ECS-compatible)
        tags: Classification tags for filtering
        severity: Event severity level
    """
    timestamp: datetime
    source_type: str
    source_ip: str
    source_host: str
    message: str
    raw_log: str
    fields: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    severity: EventSeverity = EventSeverity.LOW
    
    def to_json(self) -> str:
        """
        Export event as JSON in ECS (Elastic Common Schema) format.
        
        Returns:
            JSON string with ECS-compliant field mapping
        """
        data = {
            "@timestamp": self.timestamp.isoformat(),
            "source_type": self.source_type,
            "source": {
                "ip": self.source_ip,
                "hostname": self.source_host
            },
            "message": self.message,
            "event": {
                "original": self.raw_log,
                "severity": self.severity.value,
                "severity_label": self.severity.name
            },
            "fields": self.fields,
            "tags": self.tags,
            "ecs": {
                "version": "8.11.0"
            }
        }
        return json.dumps(data, default=str, ensure_ascii=False)
    
    def to_cef(self, device_vendor: str = "SOCGen", device_product: str = "LogGenerator") -> str:
        """
        Export event as CEF (Common Event Format).
        
        CEF format: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|
                   SignatureID|Name|Severity|Extension
        
        Args:
            device_vendor: CEF device vendor field
            device_product: CEF device product field
            
        Returns:
            CEF-formatted string
        """
        # CEF severity is 0-10, our severity is 1-4
        cef_severity = self.severity.value * 2
        
        # Build extension key-value pairs
        extensions = []
        for key, value in self.fields.items():
            # CEF extension keys are limited, map common ones
            if key in ["src_ip", "source_ip", "src"]:
                extensions.append(f"src={value}")
            elif key in ["dst_ip", "dest_ip", "dst"]:
                extensions.append(f"dst={value}")
            elif key in ["src_port", "spt"]:
                extensions.append(f"spt={value}")
            elif key in ["dst_port", "dpt"]:
                extensions.append(f"dpt={value}")
            elif key == "user":
                extensions.append(f"suser={value}")
            else:
                # Sanitize key (no spaces, special chars)
                safe_key = key.replace(" ", "_").replace("=", "_")
                extensions.append(f"{safe_key}={value}")
        
        extension_str = " ".join(extensions)
        
        # Get event name from fields or use source_type
        event_name = self.fields.get("event_name", self.fields.get("EventID", self.source_type))
        
        return (
            f"CEF:0|{device_vendor}|{device_product}|1.0|"
            f"{self.source_type}|{event_name}|{cef_severity}|{extension_str}"
        )
    
    def to_syslog(self, facility: int = 1, rfc: str = "5424") -> str:
        """
        Export event as Syslog format.
        
        Supports RFC 3164 (legacy) and RFC 5424 (modern) formats.
        
        Args:
            facility: Syslog facility code (0-23)
            rfc: RFC version ("3164" or "5424")
            
        Returns:
            Syslog-formatted string
        """
        # Map severity to syslog priority (0-7)
        severity_map = {
            EventSeverity.LOW: 6,      # INFO
            EventSeverity.MEDIUM: 5,   # NOTICE
            EventSeverity.HIGH: 4,     # WARNING
            EventSeverity.CRITICAL: 3  # ERROR
        }
        severity = severity_map.get(self.severity, 6)
        priority = facility * 8 + severity
        
        timestamp = self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        if rfc == "5424":
            # RFC 5424 format
            return (
                f"<{priority}>1 {timestamp} {self.source_host} "
                f"{self.source_type} - - - {self.message}"
            )
        else:
            # RFC 3164 format (legacy)
            ts = self.timestamp.strftime("%b %d %H:%M:%S")
            return f"<{priority}>{ts} {self.source_host} {self.message}"
    
    def __repr__(self) -> str:
        return (
            f"LogEvent(source={self.source_type}, host={self.source_host}, "
            f"severity={self.severity.name}, ts={self.timestamp.isoformat()})"
        )


@dataclass
class TimeProfile:
    """
    Temporal profile for realistic event rate variation.
    
    Simulates realistic enterprise activity patterns:
    - Business hours: Higher activity (9AM-6PM weekdays)
    - Lunch dip: Reduced activity (12PM-2PM)
    - Night hours: Very low activity (10PM-6AM)
    - Weekends: Reduced activity
    
    Attributes:
        base_eps: Base events per second
        business_hours_multiplier: Activity multiplier during business hours
        lunch_dip: Activity reduction during lunch (0.0-1.0)
        night_dip: Activity reduction at night (0.0-1.0)
        weekend_multiplier: Activity multiplier on weekends
    """
    base_eps: float = 100.0
    business_hours_multiplier: float = 2.0
    lunch_dip: float = 0.7
    night_dip: float = 0.2
    weekend_multiplier: float = 0.4
    
    def get_current_eps(self) -> float:
        """
        Calculate current EPS based on time of day and day of week.
        
        Returns:
            Adjusted EPS value with random variation
        """
        now = datetime.now(timezone.utc)
        hour = now.hour
        weekday = now.weekday()  # 0=Monday, 6=Sunday
        
        # Start with base EPS
        eps = self.base_eps
        
        # Apply weekend reduction
        if weekday >= 5:  # Saturday or Sunday
            eps *= self.weekend_multiplier
        else:
            # Weekday patterns
            if 9 <= hour < 12 or 14 <= hour < 18:
                # Business hours (morning or afternoon)
                eps *= self.business_hours_multiplier
            elif 12 <= hour < 14:
                # Lunch time
                eps *= self.lunch_dip
            elif 18 <= hour < 22:
                # Evening
                eps *= 0.5
            else:
                # Night (22:00 - 09:00)
                eps *= self.night_dip
        
        # Add random variation (±10%)
        eps *= random.uniform(0.9, 1.1)
        
        return max(0.1, eps)
    
    def __repr__(self) -> str:
        return f"TimeProfile(base={self.base_eps} EPS)"


class AssetInventory:
    """
    Manages network asset inventory for coherent log generation.
    
    Maintains consistency across log sources by tracking:
    - IP addresses and subnets
    - Hostnames and domains
    - Users and groups
    - Asset relationships
    
    This ensures that logs reference consistent assets (e.g., the same
    workstation IP appears across Windows, firewall, and proxy logs).
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize asset inventory.
        
        Args:
            config: Optional configuration dict with domains, subnets, etc.
        """
        self.config = config or {}
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.users: List[Dict[str, Any]] = []
        self.domains: List[str] = []
        self.subnets: List[str] = []
        
        # Initialize from config or generate defaults
        if config:
            self._load_from_config(config)
        else:
            self._generate_default_inventory()
    
    def _generate_default_inventory(self):
        """Generate realistic default enterprise inventory."""
        # Domains
        self.domains = ["corp.local", "dmz.corp.local", "admin.corp.local"]
        
        # Subnets
        self.subnets = [
            "10.0.10.0/24",  # Workstations
            "10.0.20.0/24",  # Linux servers
            "10.0.30.0/24",  # Windows servers
            "192.168.1.0/24" # Network equipment
        ]
        
        # Users with realistic roles
        self.users = [
            {"username": "jdoe", "domain": "corp.local", "dept": "IT", "role": "admin"},
            {"username": "asmith", "domain": "corp.local", "dept": "HR", "role": "user"},
            {"username": "mrobert", "domain": "corp.local", "dept": "Finance", "role": "user"},
            {"username": "kwilliams", "domain": "corp.local", "dept": "Sales", "role": "user"},
            {"username": "tjohnson", "domain": "corp.local", "dept": "Marketing", "role": "user"},
            {"username": "admin", "domain": "admin.corp.local", "dept": "IT", "role": "admin"},
            {"username": "svc_backup", "domain": "corp.local", "dept": "IT", "role": "service"},
            {"username": "svc_sql", "domain": "corp.local", "dept": "IT", "role": "service"},
            {"username": "SYSTEM", "domain": "NT AUTHORITY", "dept": "System", "role": "system"},
        ]
        
        # Windows Workstations
        for i in range(1, 21):
            self.assets[f"WK-WIN-{i:03d}"] = {
                "type": "workstation",
                "os": "Windows 10/11",
                "ip": f"10.0.10.{10 + i}",
                "domain": "corp.local",
                "subnet": "10.0.10.0/24",
                "active_users": random.sample(
                    [u["username"] for u in self.users if u["role"] == "user"], 
                    k=random.randint(1, 3)
                )
            }
        
        # Linux Servers
        for i in range(1, 11):
            services = ["ssh", "apache", "mysql"] if i <= 5 else ["ssh", "docker", "kubernetes"]
            self.assets[f"SRV-LNX-{i:03d}"] = {
                "type": "server",
                "os": "Ubuntu 22.04 LTS",
                "ip": f"10.0.20.{10 + i}",
                "domain": "corp.local",
                "subnet": "10.0.20.0/24",
                "services": services
            }
        
        # Windows Servers
        windows_servers = [
            ("DC-01", "domain_controller", ["AD", "DNS", "DHCP"]),
            ("DC-02", "domain_controller", ["AD", "DNS"]),
            ("EXCHANGE-01", "mail_server", ["Exchange", "IIS"]),
            ("FILE-01", "file_server", ["SMB", "DFS"]),
            ("SQL-01", "database", ["SQL Server", "SSAS"]),
        ]
        for i, (name, role, services) in enumerate(windows_servers):
            self.assets[f"SRV-{name}"] = {
                "type": "server",
                "os": "Windows Server 2022",
                "ip": f"10.0.30.{10 + i}",
                "domain": "corp.local",
                "subnet": "10.0.30.0/24",
                "role": role,
                "services": services
            }
        
        # Network Equipment
        for i in range(1, 4):
            self.assets[f"FW-{i:02d}"] = {
                "type": "firewall",
                "vendor": random.choice(["PaloAlto", "Fortinet", "Cisco"]),
                "ip": f"192.168.1.{i}",
                "subnet": "192.168.1.0/24",
                "zone": "perimeter"
            }
        
        for i in range(1, 6):
            self.assets[f"SW-{i:02d}"] = {
                "type": "switch",
                "vendor": random.choice(["Cisco", "Aruba", "Juniper"]),
                "ip": f"192.168.1.{10 + i}",
                "subnet": "192.168.1.0/24",
                "zone": "internal"
            }
        
        logger.info(f"Generated default inventory: {len(self.assets)} assets, {len(self.users)} users")
    
    def _load_from_config(self, config: Dict[str, Any]):
        """Load inventory from configuration dictionary."""
        self.assets = config.get("assets", {})
        self.users = config.get("users", [])
        self.domains = config.get("domains", [])
        self.subnets = config.get("subnets", [])
        logger.info(f"Loaded inventory from config: {len(self.assets)} assets")
    
    def get_random_asset(self, asset_type: Optional[str] = None, 
                         subnet: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a random asset, optionally filtered by type or subnet.
        
        Args:
            asset_type: Filter by asset type (workstation, server, firewall, etc.)
            subnet: Filter by subnet
            
        Returns:
            Asset dictionary with hostname added
        """
        candidates = self.assets.copy()
        
        if asset_type:
            candidates = {k: v for k, v in candidates.items() if v.get("type") == asset_type}
        
        if subnet:
            candidates = {k: v for k, v in candidates.items() if v.get("subnet") == subnet}
        
        if not candidates:
            logger.warning(f"No assets found for type={asset_type}, subnet={subnet}")
            return {"hostname": "UNKNOWN", "ip": "127.0.0.1", "type": "unknown"}
        
        hostname = random.choice(list(candidates.keys()))
        asset = candidates[hostname].copy()
        asset["hostname"] = hostname
        return asset
    
    def get_random_user(self, role: Optional[str] = None, 
                       dept: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a random user, optionally filtered by role or department.
        
        Args:
            role: Filter by role (admin, user, service, system)
            dept: Filter by department
            
        Returns:
            User dictionary
        """
        candidates = self.users.copy()
        
        if role:
            candidates = [u for u in candidates if u.get("role") == role]
        
        if dept:
            candidates = [u for u in candidates if u.get("dept") == dept]
        
        if not candidates:
            return {"username": "unknown", "domain": "corp.local", "role": "user"}
        
        return random.choice(candidates)
    
    def get_asset_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Find asset by IP address."""
        for hostname, asset in self.assets.items():
            if asset.get("ip") == ip:
                result = asset.copy()
                result["hostname"] = hostname
                return result
        return None
    
    def __repr__(self) -> str:
        return f"AssetInventory(assets={len(self.assets)}, users={len(self.users)})"


class RateLimiter:
    """
    Token bucket rate limiter for precise event rate control.
    
    Implements a token bucket algorithm for smooth rate limiting
    without burst artifacts. Supports dynamic rate adjustment.
    
    Attributes:
        eps: Current events per second target
        interval: Time between events (seconds)
    """
    
    def __init__(self, eps: float = 100.0):
        """
        Initialize rate limiter.
        
        Args:
            eps: Target events per second
        """
        self.eps = eps
        self.interval = 1.0 / eps if eps > 0 else 0
        self._next_time = time.perf_counter()
        self._lock = threading.Lock()
    
    def acquire(self) -> None:
        """
        Wait until next event slot is available.
        
        Blocks until the appropriate time has elapsed since the last call.
        """
        with self._lock:
            now = time.perf_counter()
            if now < self._next_time:
                time.sleep(self._next_time - now)
            # Update next slot from current time to avoid drift
            self._next_time = time.perf_counter() + self.interval
    
    def update_rate(self, eps: float) -> None:
        """
        Dynamically update the target rate.
        
        Args:
            eps: New events per second target
        """
        with self._lock:
            self.eps = eps
            self.interval = 1.0 / eps if eps > 0 else 0
            # Recalculate next time from now to avoid accumulation
            self._next_time = time.perf_counter() + self.interval
    
    def __repr__(self) -> str:
        return f"RateLimiter({self.eps:.1f} EPS)"


class OutputHandler(ABC):
    """
    Abstract base class for output handlers.
    
    Output handlers write generated events to various destinations:
    files, syslog servers, message queues, etc.
    """
    
    @abstractmethod
    def write(self, event: LogEvent) -> bool:
        """
        Write a single event.
        
        Args:
            event: LogEvent to write
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def write_batch(self, events: List[LogEvent]) -> int:
        """
        Write multiple events.
        
        Args:
            events: List of LogEvents to write
            
        Returns:
            Number of successfully written events
        """
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close the output handler and release resources."""
        pass
    
    @abstractmethod
    def health_check(self) -> bool:
        """
        Check if output handler is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        pass


class FileOutput(OutputHandler):
    """
    Output handler for writing to files.
    
    Supports file rotation based on size and automatic compression
    of archived files.
    
    Attributes:
        filepath: Base file path
        rotation_size: Maximum file size before rotation (bytes)
        current_size: Current file size
    """
    
    def __init__(self, filepath: str, rotation_size: int = 100 * 1024 * 1024):
        """
        Initialize file output handler.
        
        Args:
            filepath: Output file path
            rotation_size: Rotation threshold in bytes (default: 100MB)
        """
        self.filepath = filepath
        self.rotation_size = rotation_size
        self.current_size = 0
        self.file_index = 0
        self._file = None
        self._lock = threading.Lock()
        
        self._open_file()
        logger.info(f"FileOutput initialized: {filepath}")
    
    def _open_file(self) -> None:
        """Open current output file."""
        if self._file:
            self._file.close()
        
        if self.file_index > 0:
            filename = f"{self.filepath}.{self.file_index}"
        else:
            filename = self.filepath
        
        self._file = open(filename, 'a', encoding='utf-8')
        self.current_size = self._file.tell()
        logger.debug(f"Opened output file: {filename}")
    
    def _rotate_if_needed(self, data_size: int) -> None:
        """Rotate file if size threshold would be exceeded."""
        if self.current_size + data_size > self.rotation_size:
            self.file_index += 1
            self._open_file()
    
    def write(self, event: LogEvent) -> bool:
        """
        Write single event to file.
        
        Args:
            event: LogEvent to write
            
        Returns:
            True if successful
        """
        try:
            with self._lock:
                msg = event.to_json() + "\n"
                data_size = len(msg.encode('utf-8'))
                
                self._rotate_if_needed(data_size)
                self._file.write(msg)
                self._file.flush()
                self.current_size += data_size
                return True
        except Exception as e:
            logger.error(f"Failed to write to file: {e}")
            return False
    
    def write_batch(self, events: List[LogEvent]) -> int:
        """
        Write multiple events to file.
        
        Args:
            events: List of LogEvents
            
        Returns:
            Number of events written
        """
        count = 0
        for event in events:
            if self.write(event):
                count += 1
        return count
    
    def close(self) -> None:
        """Close file handle."""
        if self._file:
            self._file.close()
            self._file = None
            logger.info("FileOutput closed")
    
    def health_check(self) -> bool:
        """Check if file is writable."""
        return self._file is not None and not self._file.closed
    
    def __repr__(self) -> str:
        return f"FileOutput({self.filepath})"


class SyslogOutput(OutputHandler):
    """
    Output handler for Syslog servers.
    
    Supports TCP and UDP protocols with automatic reconnection
    for TCP connections.
    
    Attributes:
        host: Syslog server hostname
        port: Syslog server port
        protocol: Transport protocol (tcp or udp)
    """
    
    def __init__(self, host: str, port: int = 514, protocol: str = "tcp",
                 format: str = "syslog", tls: bool = False):
        """
        Initialize syslog output handler.
        
        Args:
            host: Syslog server hostname/IP
            port: Syslog server port
            protocol: 'tcp' or 'udp'
            format: Output format ('syslog', 'json', 'cef')
            tls: Use TLS encryption (TCP only)
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.format = format.lower()
        self.tls = tls
        self._socket = None
        self._connected = False
        self._lock = threading.Lock()
        self._error_count = 0
        
        self._connect()
        logger.info(f"SyslogOutput initialized: {host}:{port} ({protocol})")
    
    def _connect(self) -> bool:
        """Establish connection to syslog server."""
        try:
            if self._socket:
                try:
                    self._socket.close()
                except:
                    pass
            
            if self.protocol == "tcp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(5)
                if self.tls:
                    import ssl
                    context = ssl.create_default_context()
                    self._socket = context.wrap_socket(self._socket, server_hostname=self.host)
                self._socket.connect((self.host, self.port))
            else:  # UDP
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            self._connected = True
            self._error_count = 0
            logger.debug(f"Connected to syslog server: {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to syslog server: {e}")
            self._connected = False
            return False
    
    def write(self, event: LogEvent) -> bool:
        """
        Write event to syslog server.
        
        Args:
            event: LogEvent to write
            
        Returns:
            True if successful
        """
        try:
            with self._lock:
                # Format message according to configuration
                if self.format == "json":
                    msg = event.to_json()
                elif self.format == "cef":
                    msg = event.to_cef()
                else:  # syslog
                    msg = event.to_syslog()
                
                data = (msg + "\n").encode('utf-8')
                
                if self.protocol == "tcp":
                    if not self._connected:
                        if not self._connect():
                            return False
                    self._socket.sendall(data)
                else:  # UDP
                    self._socket.sendto(data, (self.host, self.port))
                
                return True
                
        except Exception as e:
            self._error_count += 1
            if self._error_count % 100 == 0:
                logger.error(f"Syslog write errors: {self._error_count}")
            self._connected = False
            return False
    
    def write_batch(self, events: List[LogEvent]) -> int:
        """
        Write multiple events to syslog.
        
        Args:
            events: List of LogEvents
            
        Returns:
            Number of events written
        """
        count = 0
        for event in events:
            if self.write(event):
                count += 1
        return count
    
    def close(self) -> None:
        """Close socket connection."""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
            self._connected = False
            logger.info("SyslogOutput closed")
    
    def health_check(self) -> bool:
        """Check connection status."""
        if self.protocol == "udp":
            return True  # UDP is connectionless
        return self._connected
    
    def __repr__(self) -> str:
        return f"SyslogOutput({self.host}:{self.port}/{self.protocol})"


class MultiOutput(OutputHandler):
    """
    Composite output handler that writes to multiple destinations.
    
    Useful for writing to both file and syslog simultaneously.
    """
    
    def __init__(self, handlers: List[OutputHandler]):
        """
        Initialize with multiple handlers.
        
        Args:
            handlers: List of OutputHandler instances
        """
        self.handlers = handlers
        logger.info(f"MultiOutput initialized with {len(handlers)} handlers")
    
    def write(self, event: LogEvent) -> bool:
        """Write to all handlers."""
        results = [h.write(event) for h in self.handlers]
        return any(results)  # Success if at least one succeeded
    
    def write_batch(self, events: List[LogEvent]) -> int:
        """Write batch to all handlers."""
        counts = [h.write_batch(events) for h in self.handlers]
        return max(counts) if counts else 0
    
    def close(self) -> None:
        """Close all handlers."""
        for handler in self.handlers:
            handler.close()
    
    def health_check(self) -> bool:
        """Check all handlers."""
        return all(h.health_check() for h in self.handlers)
    
    def __repr__(self) -> str:
        return f"MultiOutput({len(self.handlers)} handlers)"


# Export public API
__all__ = [
    'EventSeverity',
    'LogEvent',
    'TimeProfile',
    'AssetInventory',
    'RateLimiter',
    'OutputHandler',
    'FileOutput',
    'SyslogOutput',
    'MultiOutput',
]


if __name__ == "__main__":
    # Simple demonstration
    logging.basicConfig(level=logging.INFO)
    
    print("SOC Log Generator - Core Engine Demo")
    print("=" * 50)
    
    # Create inventory
    inventory = AssetInventory()
    print(f"\nAsset Inventory: {inventory}")
    
    # Sample random assets
    print("\nSample Assets:")
    for _ in range(3):
        asset = inventory.get_random_asset()
        print(f"  - {asset['hostname']}: {asset['ip']} ({asset['type']})")
    
    # Create event
    event = LogEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="demo",
        source_ip="10.0.0.1",
        source_host="DEMO-01",
        message="Demo event for testing",
        raw_log="DEMO: Test log entry",
        fields={"test": True, "count": 42},
        tags=["demo", "test"],
        severity=EventSeverity.LOW
    )
    
    print("\nEvent Formats:")
    print(f"JSON: {event.to_json()[:100]}...")
    print(f"CEF: {event.to_cef()[:100]}...")
    print(f"Syslog: {event.to_syslog()}")
    
    # Test rate limiter
    print("\nRate Limiter Test (10 EPS):")
    limiter = RateLimiter(eps=10)
    start = time.perf_counter()
    for i in range(5):
        limiter.acquire()
        print(f"  Event {i+1} at {time.perf_counter() - start:.3f}s")
    
    print("\nCore Engine Demo Complete!")
