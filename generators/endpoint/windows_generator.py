#!/usr/bin/env python3
"""
Generateur de logs Windows Event Log
Supporte: Security, System, Application, Sysmon, PowerShell
"""

import json
import random
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
try:
    from ..base import BaseGenerator
    from ...core import LogEvent, EventSeverity, AssetInventory
except (ImportError, ValueError):
    from generators.base import BaseGenerator
    from core import LogEvent, EventSeverity, AssetInventory


class WindowsEventGenerator(BaseGenerator):
    """Generateur de logs Windows complet pour SOC"""
    
    # Evenements Windows critiques pour SOC
    SECURITY_EVENTS = {
        4624: ("An account was successfully logged on", "AUDIT_SUCCESS", EventSeverity.LOW),
        4625: ("An account failed to log on", "AUDIT_FAILURE", EventSeverity.HIGH),
        4634: ("An account was logged off", "AUDIT_SUCCESS", EventSeverity.LOW),
        4648: ("A logon was attempted using explicit credentials", "AUDIT_SUCCESS", EventSeverity.MEDIUM),
        4672: ("Special privileges assigned to new logon", "AUDIT_SUCCESS", EventSeverity.MEDIUM),
        4688: ("A new process has been created", "AUDIT_SUCCESS", EventSeverity.LOW),
        4689: ("A process has exited", "AUDIT_SUCCESS", EventSeverity.LOW),
        4720: ("A user account was created", "AUDIT_SUCCESS", EventSeverity.HIGH),
        4728: ("A member was added to a security-enabled global group", "AUDIT_SUCCESS", EventSeverity.CRITICAL),
        4732: ("A member was added to a security-enabled local group", "AUDIT_SUCCESS", EventSeverity.HIGH),
        4738: ("A user account was changed", "AUDIT_SUCCESS", EventSeverity.MEDIUM),
        4740: ("A user account was locked out", "AUDIT_FAILURE", EventSeverity.MEDIUM),
        4768: ("A Kerberos authentication ticket was requested", "AUDIT_SUCCESS", EventSeverity.LOW),
        4769: ("A Kerberos service ticket was requested", "AUDIT_SUCCESS", EventSeverity.LOW),
        4771: ("Kerberos pre-authentication failed", "AUDIT_FAILURE", EventSeverity.MEDIUM),
        4776: ("The domain controller attempted to validate credentials", "AUDIT_SUCCESS", EventSeverity.LOW),
        7045: ("A service was installed in the system", "INFO", EventSeverity.HIGH),
    }
    
    POWERSHELL_EVENTS = {
        4103: ("Module logging", "ModulePipeLineExecution", EventSeverity.MEDIUM),
        4104: ("Script Block Logging", "Execute a Remote Command", EventSeverity.HIGH),
        4105: ("Command Invocation", "CommandInvocation", EventSeverity.LOW),
        4106: ("Script Block Logging Detail", "ScriptBlockText", EventSeverity.MEDIUM),
    }
    
    SYSMON_EVENTS = {
        1: ("Process Create", "ProcessCreate", EventSeverity.LOW),
        2: ("File creation time changed", "FileCreateTime", EventSeverity.MEDIUM),
        3: ("Network connection detected", "NetworkConnect", EventSeverity.LOW),
        5: ("Process terminated", "ProcessTerminate", EventSeverity.LOW),
        6: ("Driver loaded", "DriverLoad", EventSeverity.MEDIUM),
        7: ("Image loaded", "ImageLoad", EventSeverity.LOW),
        8: ("CreateRemoteThread detected", "CreateRemoteThread", EventSeverity.HIGH),
        9: ("RawAccessRead detected", "RawAccessRead", EventSeverity.HIGH),
        10: ("ProcessAccess", "ProcessAccess", EventSeverity.MEDIUM),
        11: ("FileCreate", "FileCreate", EventSeverity.LOW),
        12: ("Registry object added/deleted", "RegistryEvent", EventSeverity.MEDIUM),
        13: ("Registry value set", "RegistryEvent", EventSeverity.MEDIUM),
        15: ("FileCreateStreamHash", "FileCreateStreamHash", EventSeverity.MEDIUM),
        16: ("Sysmon config state changed", "SysmonConfigChange", EventSeverity.HIGH),
        17: ("Pipe Created", "PipeEvent", EventSeverity.MEDIUM),
        18: ("Pipe Connected", "PipeEvent", EventSeverity.MEDIUM),
        19: ("WmiEventFilter activity detected", "WmiEvent", EventSeverity.HIGH),
        20: ("WmiEventConsumer activity detected", "WmiEvent", EventSeverity.HIGH),
        21: ("WmiEventConsumerToFilter activity detected", "WmiEvent", EventSeverity.HIGH),
        22: ("DNS query", "DnsQuery", EventSeverity.LOW),
        23: ("File deleted", "FileDelete", EventSeverity.LOW),
        25: ("Process tampering", "ProcessTampering", EventSeverity.HIGH),
        26: ("FileDeleteDetected", "FileDeleteDetected", EventSeverity.MEDIUM),
    }
    
    COMMON_PROCESSES = [
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "Microsoft Corporation"),
        ("lsass.exe", "C:\\Windows\\System32\\lsass.exe", "Microsoft Corporation"),
        ("services.exe", "C:\\Windows\\System32\\services.exe", "Microsoft Corporation"),
        ("explorer.exe", "C:\\Windows\\explorer.exe", "Microsoft Corporation"),
        ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Google LLC"),
        ("firefox.exe", "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "Mozilla Corporation"),
        ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "Microsoft Corporation"),
        ("winword.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Microsoft Corporation"),
        ("excel.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "Microsoft Corporation"),
    ]
    
    SUSPICIOUS_PROCESSES = [
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Microsoft Corporation"),
        ("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "Microsoft Corporation"),
        ("wscript.exe", "C:\\Windows\\System32\\wscript.exe", "Microsoft Corporation"),
        ("cscript.exe", "C:\\Windows\\System32\\cscript.exe", "Microsoft Corporation"),
        ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "Microsoft Corporation"),
        ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "Microsoft Corporation"),
        ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "Microsoft Corporation"),
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.channels = config.get('channels', ['Security', 'System', 'Application', 'Sysmon'])
        self.channel_weights = config.get('channel_weights', [60, 20, 10, 10])
        
    def _get_random_windows_asset(self) -> Dict:
        """Recupere un asset Windows aleatoire"""
        workstations = {k: v for k, v in self.inventory.assets.items() if v.get("type") == "workstation"}
        if not workstations:
            return {"hostname": "WK-WIN-001", "ip": "10.0.10.11", "domain": "corp.local"}
        hostname = random.choice(list(workstations.keys()))
        asset = workstations[hostname].copy()
        asset["hostname"] = hostname
        return asset
    
    def _generate_security_event(self) -> LogEvent:
        """Genere un evenement de securite Windows"""
        asset = self._get_random_windows_asset()
        event_id = random.choices(list(self.SECURITY_EVENTS.keys()), weights=[
            30, 5, 20, 10, 5, 15, 10, 2, 1, 2, 3, 2, 5, 5, 3, 5, 2
        ])[0]
        
        msg, event_type, severity = self.SECURITY_EVENTS[event_id]
        user = self.inventory.get_random_user()
        
        timestamp = datetime.now(timezone.utc)
        
        fields = {
            "EventID": event_id,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "EventType": event_type,
            "SubjectUserName": user["username"],
            "SubjectDomainName": user["domain"],
            "TargetUserName": user["username"],
            "TargetDomainName": user["domain"],
            "IpAddress": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "IpPort": random.randint(1024, 65535),
            "LogonType": random.choice([2, 3, 7, 10]),
            "Status": "0x0" if event_type == "AUDIT_SUCCESS" else "0xC000006D",
            "SubStatus": "0x0" if event_type == "AUDIT_SUCCESS" else "0xC000006A",
        }
        
        # Ajouter des champs specifiques selon l'event ID
        if event_id == 4688:
            proc_name, proc_path, company = random.choice(self.COMMON_PROCESSES + self.SUSPICIOUS_PROCESSES)
            fields["NewProcessName"] = proc_path
            fields["CommandLine"] = proc_path
            fields["ParentProcessName"] = "explorer.exe"
        
        if event_id == 4728:
            fields["TargetUserName"] = "Domain Admins"
            fields["MemberName"] = user["username"]
        
        raw_log = f"{timestamp.isoformat()} {asset['hostname']} Security {event_id}: {msg}"
        
        return LogEvent(
            timestamp=timestamp,
            source_type="windows",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=raw_log,
            fields=fields,
            tags=["windows", "security", f"event_id_{event_id}"],
            severity=severity
        )
    
    def _generate_sysmon_event(self) -> LogEvent:
        """Genere un evenement Sysmon"""
        asset = self._get_random_windows_asset()
        event_id = random.choices(list(self.SYSMON_EVENTS.keys()), weights=[
            40, 2, 20, 10, 2, 5, 2, 3, 2, 10, 3, 3, 2, 2, 2, 1, 1, 2, 1, 1, 1, 5, 3, 2, 1, 1
        ])[0]
        
        msg, rule_name, severity = self.SYSMON_EVENTS[event_id]
        timestamp = datetime.now(timezone.utc)
        
        fields = {
            "EventID": event_id,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "RuleName": rule_name,
            "UtcTime": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "ProcessGuid": "{" + "".join([random.choice("0123456789abcdef") for _ in range(32)]) + "}",
            "ProcessId": random.randint(1000, 9999),
        }
        
        if event_id == 1:  # Process Create
            if random.random() < 0.1:  # 10% chance de processus suspect
                proc_name, proc_path, company = random.choice(self.SUSPICIOUS_PROCESSES)
                cmdline = f'{proc_path} -enc { "".join([random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") for _ in range(100)])}'
                severity = EventSeverity.HIGH
                tags = ["windows", "sysmon", "process_create", "suspicious", "encoded_command"]
            else:
                proc_name, proc_path, company = random.choice(self.COMMON_PROCESSES)
                cmdline = proc_path
                tags = ["windows", "sysmon", "process_create"]
            
            fields["Image"] = proc_path
            fields["CommandLine"] = cmdline
            fields["CurrentDirectory"] = "C:\\Users\\" + self.inventory.get_random_user()["username"] + "\\"
            fields["User"] = f"{asset['domain']}\\{self.inventory.get_random_user()['username']}"
            fields["LogonGuid"] = "{00000000-0000-0000-0000-000000000000}"
            fields["LogonId"] = "0x" + "".join([random.choice("0123456789abcdef") for _ in range(8)])
            fields["TerminalSessionId"] = 1
            fields["IntegrityLevel"] = random.choice(["Low", "Medium", "High", "System"])
            fields["Hashes"] = f"MD5={''.join([random.choice('0123456789abcdef') for _ in range(32)])},SHA256={''.join([random.choice('0123456789abcdef') for _ in range(64)])}"
            fields["ParentProcessGuid"] = "{" + "".join([random.choice("0123456789abcdef") for _ in range(32)]) + "}"
            fields["ParentProcessId"] = random.randint(100, 9999)
            fields["ParentImage"] = "C:\\Windows\\explorer.exe"
            fields["ParentCommandLine"] = "C:\\Windows\\Explorer.EXE"
            fields["ParentUser"] = fields["User"]
        
        elif event_id == 3:  # Network connection
            fields["Image"] = random.choice([p[1] for p in self.COMMON_PROCESSES])
            fields["User"] = f"{asset['domain']}\\{self.inventory.get_random_user()['username']}"
            fields["Protocol"] = random.choice(["tcp", "udp"])
            fields["Initiated"] = True
            fields["SourceIsIpv6"] = False
            fields["SourceIp"] = asset["ip"]
            fields["SourceHostname"] = asset["hostname"]
            fields["SourcePort"] = random.randint(49152, 65535)
            fields["SourcePortName"] = "-"
            fields["DestinationIsIpv6"] = False
            # IPs externes diverses
            if random.random() < 0.3:
                fields["DestinationIp"] = random.choice([
                    "8.8.8.8", "1.1.1.1", "208.67.222.222",  # DNS
                    "13.107.42.14", "52.96.0.0",  # Microsoft
                    "142.250.0.0",  # Google
                ])
            else:
                fields["DestinationIp"] = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            fields["DestinationHostname"] = "-"
            fields["DestinationPort"] = random.choice([53, 80, 443, 445, 3389, 5985, 9389])
            fields["DestinationPortName"] = random.choice(["dns", "http", "https", "smb", "rdp", "winrm", "adws"])
            tags = ["windows", "sysmon", "network_connection"]
        
        elif event_id == 22:  # DNS query
            fields["QueryName"] = random.choice([
                "www.google.com", "outlook.office365.com", "login.microsoftonline.com",
                "update.microsoft.com", "cdn.jsdelivr.net", "raw.githubusercontent.com",
                "api.ipify.org", "checkip.amazonaws.com",
            ])
            fields["QueryStatus"] = 0
            fields["QueryResults"] = f"type:  5 {fields['QueryName']};"
            fields["Image"] = random.choice([p[1] for p in self.COMMON_PROCESSES])
            tags = ["windows", "sysmon", "dns_query"]
        
        raw_log = f"{timestamp.isoformat()} {asset['hostname']} Sysmon {event_id}: {msg}"
        
        return LogEvent(
            timestamp=timestamp,
            source_type="sysmon",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=raw_log,
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_system_event(self) -> LogEvent:
        """Genere un evenement System"""
        asset = self._get_random_windows_asset()
        timestamp = datetime.now(timezone.utc)
        
        system_events = [
            (7036, "The %1 service entered the %2 state", "Service Control Manager", "INFO"),
            (7034, "The %1 service terminated unexpectedly", "Service Control Manager", "ERROR"),
            (7040, "The start type of the %1 service was changed", "Service Control Manager", "WARNING"),
            (6005, "The Event log service was started", "EventLog", "INFO"),
            (6006, "The Event log service was stopped", "EventLog", "INFO"),
        ]
        
        event_id, msg_template, provider, level = random.choice(system_events)
        services = ["Windows Update", "BITS", "DHCP Client", "DNS Client", "Workstation", "Server"]
        states = ["running", "stopped", "paused", "start pending", "stop pending"]
        
        msg = msg_template.replace("%1", random.choice(services)).replace("%2", random.choice(states))
        
        fields = {
            "EventID": event_id,
            "Channel": "System",
            "ProviderName": provider,
            "Level": level,
        }
        
        severity = EventSeverity.LOW if level == "INFO" else EventSeverity.MEDIUM if level == "WARNING" else EventSeverity.HIGH
        
        return LogEvent(
            timestamp=timestamp,
            source_type="windows",
            source_ip=asset["ip"],
            source_host=asset["hostname"],
            message=msg,
            raw_log=f"{timestamp.isoformat()} {asset['hostname']} System {event_id}: {msg}",
            fields=fields,
            tags=["windows", "system"],
            severity=severity
        )
    
    def generate_event(self) -> LogEvent:
        """Genere un evenement Windows aleatoire selon la distribution configuree"""
        channel = random.choices(self.channels, weights=self.channel_weights)[0]
        
        if channel == "Security":
            return self._generate_security_event()
        elif channel == "Sysmon":
            return self._generate_sysmon_event()
        elif channel == "System":
            return self._generate_system_event()
        else:  # Application
            return self._generate_security_event()  # Fallback pour l'instant
