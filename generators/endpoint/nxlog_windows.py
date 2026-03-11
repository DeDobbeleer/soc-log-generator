#!/usr/bin/env python3
"""
NXLog Windows Event Generator

Specific generator for NXLog JSON format with CEE (Common Event Expression)
structure compatible with LogPoint.

Imported from nxlog_simulator.py - Native NXLog format (im_msvistalog + xm_json)
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


class NXLogWindowsGenerator(BaseGenerator):
    """
    Windows Event Log generator in native NXLog JSON format.
    
    This format is specifically designed to be compatible with:
    - NXLog (im_msvistalog + xm_json)
    - LogPoint SIEM
    - CEE (Common Event Expression) structure
    """
    
    HOSTS = [
        "WS-DC-01.ad.local", 
        "WS-FILE-01.ad.local", 
        "WK-IT-042.ad.local", 
        "WK-HR-015.ad.local", 
        "WS-WEB-01.ad.local"
    ]
    
    USERS = [
        "administrator", 
        "jdoe@ad.local", 
        "asmith", 
        "SYSTEM", 
        "NETWORK SERVICE", 
        "LOCAL SERVICE"
    ]
    
    IPS = [
        "10.0.1.15", 
        "10.0.2.42", 
        "192.168.1.100", 
        "10.0.5.8", 
        "172.16.0.5"
    ]
    
    PROCESSES = [
        "svchost.exe", 
        "lsass.exe", 
        "services.exe", 
        "explorer.exe", 
        "powershell.exe", 
        "cmd.exe"
    ]
    
    EVENTS = {
        "Security": [
            (4624, "An account was successfully logged on", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4625, "An account failed to log on", "AUDIT_FAILURE", "Microsoft-Windows-Security-Auditing"),
            (4634, "An account was logged off", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4648, "A logon was attempted using explicit credentials", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4672, "Special privileges assigned to new logon", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4688, "A new process has been created", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4689, "A process has exited", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4720, "A user account was created", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4732, "A member was added to a security-enabled local group", "AUDIT_SUCCESS", "Microsoft-Windows-Security-Auditing"),
            (4740, "A user account was locked out", "AUDIT_FAILURE", "Microsoft-Windows-Security-Auditing"),
        ],
        "System": [
            (7036, "The %1 service entered the %2 state", "INFO", "Service Control Manager"),
            (7034, "The %1 service terminated unexpectedly", "ERROR", "Service Control Manager"),
            (7040, "The start type of the %1 service was changed from %2 to %3", "WARNING", "Service Control Manager"),
            (6005, "The Event log service was started", "INFO", "EventLog"),
            (6006, "The Event log service was stopped", "INFO", "EventLog"),
            (1074, "The process %1 has initiated the restart of computer %2", "INFO", "USER32"),
        ],
        "Application": [
            (1000, "Faulting application name: %1, version: %2, time stamp: 0x%3", "ERROR", "Application Error"),
            (1002, "The program %1 stopped interacting with Windows and was closed", "ERROR", "Application Hang"),
            (1026, ".NET Runtime version %1 - Fatal application exit", "ERROR", ".NET Runtime"),
        ],
        "Microsoft-Windows-Sysmon/Operational": [
            (1, "Process Create: %1", "INFO", "Microsoft-Windows-Sysmon"),
            (3, "Network connection detected: %1", "INFO", "Microsoft-Windows-Sysmon"),
            (7, "Image loaded: %1", "INFO", "Microsoft-Windows-Sysmon"),
        ]
    }
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        # Realistic distribution: Security 60%, System 25%, Application 10%, Sysmon 5%
        self.channel_weights = config.get('channel_weights', [60, 25, 10, 5])
    
    def generate_event(self) -> LogEvent:
        """Generate an event in native NXLog JSON format."""
        hostname = random.choice(self.HOSTS)
        user = random.choice(self.USERS)
        ip = random.choice(self.IPS)
        process = random.choice(self.PROCESSES)
        
        # Channel selection
        channel = random.choices(
            list(self.EVENTS.keys()), 
            weights=self.channel_weights
        )[0]
        
        event_id, msg_template, event_type, provider = random.choice(self.EVENTS[channel])
        
        # Timestamp format NXLog: YYYY-MM-DD HH:MM:SS (UTC)
        event_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        
        # Message customization
        msg = msg_template.replace("%1", process).replace("%2", "running").replace("%3", "0x0000")
        
        # Exact NXLog JSON structure (im_msvistalog + xm_json)
        nxlog_event = {
            # Core fields
            "EventTime": event_time,
            "Hostname": hostname,
            "EventType": event_type,
            "SeverityValue": "INFO" if event_type in ["AUDIT_SUCCESS", "INFO"] else "WARNING" if event_type == "AUDIT_FAILURE" else "ERROR",
            "Severity": random.choice([0, 1, 2, 3, 4]) if event_type == "ERROR" else random.choice([5, 6, 7, 8]),
            
            # Windows Event fields
            "SourceName": provider,
            "Channel": channel,
            "EventID": event_id,
            "Message": msg,
            
            # Security fields
            "SubjectUserName": user,
            "TargetUserName": user if event_id in [4624, 4625, 4634] else "-",
            "IpAddress": ip,
            "IpPort": random.randint(49152, 65535),
            
            # Process fields
            "NewProcessName": process if event_id == 4688 else "-",
            "ProcessName": process,
            "ProcessId": random.randint(1000, 9999),
            "ThreadID": random.randint(1000, 9999),
            
            # Account metadata
            "AccountName": user,
            "AccountType": "User" if user not in ["SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE"] else "System",
            "Domain": "AD" if "@" in user else "NT AUTHORITY",
            "LogonType": random.choice([2, 3, 7, 10]) if channel == "Security" else 0,
            "Status": "0x0" if event_type == "AUDIT_SUCCESS" else "0xC000006D",
            "SubStatus": "0x0" if event_type == "AUDIT_SUCCESS" else "0xC000006A",
            
            # CEE structured (standard NXLog)
            "cee": {
                "event_id": event_id,
                "message": msg,
                "source": {
                    "ip": ip,
                    "user": user,
                    "host": hostname
                },
                "process": {
                    "name": process,
                    "id": random.randint(1000, 9999)
                }
            }
        }
        
        raw_log = json.dumps(nxlog_event, ensure_ascii=False)
        
        # Mapping severity
        severity_map = {
            "AUDIT_SUCCESS": EventSeverity.LOW,
            "INFO": EventSeverity.LOW,
            "AUDIT_FAILURE": EventSeverity.MEDIUM,
            "WARNING": EventSeverity.MEDIUM,
            "ERROR": EventSeverity.HIGH
        }
        severity = severity_map.get(event_type, EventSeverity.LOW)
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="nxlog_windows",
            source_ip=ip,
            source_host=hostname,
            message=msg,
            raw_log=raw_log,
            fields=nxlog_event,
            tags=["windows", "nxlog", "json", f"event_id_{event_id}"],
            severity=severity
        )
