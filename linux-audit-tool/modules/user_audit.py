#!/usr/bin/env python3
"""
User Audit Module
=================
Comprehensive user activity auditing including logins, sudo usage,
shell commands, and user modifications.
"""

import os
import re
import pwd
import grp
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict
import gzip

logger = logging.getLogger('LinuxAuditTool.UserAudit')


class UserAuditor:
    """Auditor for user activities and accounts."""
    
    def __init__(self, config: Dict):
        """Initialize user auditor."""
        self.config = config
        self.user_config = config.get('user_audit', {})
        self.log_paths = config.get('log_paths', {})
        self.timeline_events = []
        self.alerts = []
        
    def audit(self, days: int = 30) -> Dict:
        """Run comprehensive user audit."""
        logger.info("Starting comprehensive user audit...")
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        audit_result = {
            'user_list': self._get_all_users(),
            'system_users': self._get_system_users(),
            'user_groups': self._get_user_groups(),
            'login_history': self._get_login_history(cutoff_date),
            'failed_logins': self._get_failed_logins(cutoff_date),
            'sudo_usage': self._get_sudo_usage(cutoff_date),
            'ssh_sessions': self._get_ssh_sessions(cutoff_date),
            'user_commands': self._get_user_commands(),
            'user_modifications': self._get_user_modifications(cutoff_date),
            'password_changes': self._get_password_changes(cutoff_date),
            'group_changes': self._get_group_changes(cutoff_date),
            'currently_logged_in': self._get_currently_logged_in(),
            'last_logins': self._get_last_logins(),
            'cron_jobs': self._get_user_cron_jobs(),
            'ssh_keys': self._get_ssh_authorized_keys(),
            'user_activity_summary': {},
            'statistics': {}
        }
        
        # Generate per-user activity summary
        audit_result['user_activity_summary'] = self._generate_user_summary(audit_result)
        
        # Calculate statistics
        audit_result['statistics'] = self._calculate_statistics(audit_result)
        
        return audit_result
    
    def _get_all_users(self) -> List[Dict]:
        """Get list of all user accounts."""
        users = []
        try:
            for user in pwd.getpwall():
                users.append({
                    'username': user.pw_name,
                    'uid': user.pw_uid,
                    'gid': user.pw_gid,
                    'gecos': user.pw_gecos,
                    'home_dir': user.pw_dir,
                    'shell': user.pw_shell,
                    'is_system': user.pw_uid < 1000 or user.pw_shell in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']
                })
        except Exception as e:
            logger.error(f"Error getting user list: {e}")
        return users
    
    def _get_system_users(self) -> List[str]:
        """Get list of system users (non-human accounts)."""
        system_users = []
        for user in pwd.getpwall():
            if user.pw_uid < 1000 or user.pw_shell in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                system_users.append(user.pw_name)
        return system_users
    
    def _get_user_groups(self) -> Dict[str, List[str]]:
        """Get all groups and their members."""
        groups = {}
        try:
            for group in grp.getgrall():
                groups[group.gr_name] = {
                    'gid': group.gr_gid,
                    'members': group.gr_mem
                }
        except Exception as e:
            logger.error(f"Error getting groups: {e}")
        return groups
    
    def _get_login_history(self, cutoff_date: datetime) -> List[Dict]:
        """Parse login history from auth logs."""
        logins = []
        patterns = {
            'accepted': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)'
            ),
            'session_opened': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(?:sshd|login|systemd-logind)\[\d+\]:\s+(?:pam_unix\(.*\):\s+)?session\s+opened\s+for\s+user\s+(\S+)'
            ),
            'session_closed': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(?:sshd|login|systemd-logind)\[\d+\]:\s+(?:pam_unix\(.*\):\s+)?session\s+closed\s+for\s+user\s+(\S+)'
            )
        }
        
        log_files = self._get_auth_log_files()
        
        for log_file in log_files:
            try:
                content = self._read_log_file(log_file)
                for line in content.split('\n'):
                    # Parse accepted SSH connections
                    match = patterns['accepted'].search(line)
                    if match:
                        timestamp = self._parse_log_timestamp(match.group(1))
                        if timestamp and timestamp >= cutoff_date:
                            login = {
                                'timestamp': timestamp.isoformat(),
                                'hostname': match.group(2),
                                'auth_method': match.group(3),
                                'username': match.group(4),
                                'source_ip': match.group(5),
                                'source_port': match.group(6),
                                'type': 'ssh_login',
                                'status': 'success'
                            }
                            logins.append(login)
                            self._add_timeline_event(
                                timestamp, 
                                'USER_LOGIN', 
                                f"SSH login: {login['username']} from {login['source_ip']}",
                                login
                            )
                    
                    # Parse session opened
                    match = patterns['session_opened'].search(line)
                    if match:
                        timestamp = self._parse_log_timestamp(match.group(1))
                        if timestamp and timestamp >= cutoff_date:
                            login = {
                                'timestamp': timestamp.isoformat(),
                                'hostname': match.group(2),
                                'username': match.group(3),
                                'type': 'session_opened',
                                'status': 'success'
                            }
                            logins.append(login)
                            
            except Exception as e:
                logger.warning(f"Error parsing {log_file}: {e}")
        
        return logins
    
    def _get_failed_logins(self, cutoff_date: datetime) -> List[Dict]:
        """Parse failed login attempts."""
        failed_logins = []
        patterns = {
            'failed_password': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)'
            ),
            'invalid_user': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Invalid\s+user\s+(\S+)\s+from\s+(\S+)'
            ),
            'authentication_failure': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+(?:pam_unix\(.*\):\s+)?authentication\s+failure.*\s+user=(\S+)'
            ),
            'maximum_exceeded': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+error:\s+maximum\s+authentication\s+attempts\s+exceeded\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)'
            )
        }
        
        log_files = self._get_auth_log_files()
        
        for log_file in log_files:
            try:
                content = self._read_log_file(log_file)
                for line in content.split('\n'):
                    for pattern_name, pattern in patterns.items():
                        match = pattern.search(line)
                        if match:
                            timestamp = self._parse_log_timestamp(match.group(1))
                            if timestamp and timestamp >= cutoff_date:
                                groups = match.groups()
                                failed = {
                                    'timestamp': timestamp.isoformat(),
                                    'hostname': groups[1],
                                    'username': groups[2],
                                    'source_ip': groups[3] if len(groups) > 3 else 'unknown',
                                    'type': pattern_name,
                                    'raw_log': line[:200]
                                }
                                failed_logins.append(failed)
                                
                                # Alert on multiple failures
                                self._add_timeline_event(
                                    timestamp,
                                    'FAILED_LOGIN',
                                    f"Failed login: {failed['username']} from {failed['source_ip']}",
                                    failed
                                )
                            break
                            
            except Exception as e:
                logger.warning(f"Error parsing {log_file}: {e}")
        
        # Check for brute force attempts
        self._detect_brute_force(failed_logins)
        
        return failed_logins
    
    def _detect_brute_force(self, failed_logins: List[Dict]):
        """Detect potential brute force attacks."""
        from collections import Counter
        
        # Count failures per IP
        ip_counts = Counter(f['source_ip'] for f in failed_logins)
        for ip, count in ip_counts.items():
            if count >= 10:
                self.alerts.append({
                    'severity': 'HIGH' if count >= 50 else 'WARNING',
                    'type': 'BRUTE_FORCE_ATTEMPT',
                    'message': f"Potential brute force attack from {ip}: {count} failed attempts",
                    'source_ip': ip,
                    'count': count,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Count failures per user
        user_counts = Counter(f['username'] for f in failed_logins)
        for user, count in user_counts.items():
            if count >= 20:
                self.alerts.append({
                    'severity': 'WARNING',
                    'type': 'USER_TARGETED',
                    'message': f"User {user} targeted with {count} failed login attempts",
                    'username': user,
                    'count': count,
                    'timestamp': datetime.now().isoformat()
                })
    
    def _get_sudo_usage(self, cutoff_date: datetime) -> List[Dict]:
        """Parse sudo command usage."""
        sudo_events = []
        patterns = {
            'sudo_command': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sudo(?:\[\d+\])?:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)'
            ),
            'sudo_auth_failure': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sudo(?:\[\d+\])?:\s+(?:pam_unix\(sudo:auth\):\s+)?authentication\s+failure.*\s+user=(\S+)'
            )
        }
        
        log_files = self._get_auth_log_files()
        
        for log_file in log_files:
            try:
                content = self._read_log_file(log_file)
                for line in content.split('\n'):
                    match = patterns['sudo_command'].search(line)
                    if match:
                        timestamp = self._parse_log_timestamp(match.group(1))
                        if timestamp and timestamp >= cutoff_date:
                            sudo_event = {
                                'timestamp': timestamp.isoformat(),
                                'hostname': match.group(2),
                                'username': match.group(3),
                                'tty': match.group(4),
                                'pwd': match.group(5),
                                'run_as': match.group(6),
                                'command': match.group(7),
                                'type': 'command'
                            }
                            sudo_events.append(sudo_event)
                            
                            # Alert on dangerous commands
                            dangerous_commands = [
                                'rm -rf', 'dd if=', 'mkfs', 'fdisk', 
                                'chmod 777', 'visudo', 'passwd', 'useradd',
                                'userdel', 'groupadd', 'groupdel', 'usermod'
                            ]
                            for cmd in dangerous_commands:
                                if cmd in sudo_event['command'].lower():
                                    self._add_timeline_event(
                                        timestamp,
                                        'SUDO_DANGEROUS',
                                        f"Dangerous sudo command: {sudo_event['username']} ran {sudo_event['command'][:100]}",
                                        sudo_event
                                    )
                                    break
                            else:
                                self._add_timeline_event(
                                    timestamp,
                                    'SUDO_COMMAND',
                                    f"Sudo: {sudo_event['username']} ran {sudo_event['command'][:50]}",
                                    sudo_event
                                )
                    
                    match = patterns['sudo_auth_failure'].search(line)
                    if match:
                        timestamp = self._parse_log_timestamp(match.group(1))
                        if timestamp and timestamp >= cutoff_date:
                            sudo_event = {
                                'timestamp': timestamp.isoformat(),
                                'hostname': match.group(2),
                                'username': match.group(3),
                                'type': 'auth_failure'
                            }
                            sudo_events.append(sudo_event)
                            self.alerts.append({
                                'severity': 'WARNING',
                                'type': 'SUDO_AUTH_FAILURE',
                                'message': f"Sudo authentication failure for user {sudo_event['username']}",
                                'timestamp': timestamp.isoformat()
                            })
                            
            except Exception as e:
                logger.warning(f"Error parsing {log_file}: {e}")
        
        return sudo_events
    
    def _get_ssh_sessions(self, cutoff_date: datetime) -> List[Dict]:
        """Parse SSH session information."""
        sessions = []
        patterns = {
            'disconnect': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Disconnected\s+from\s+(?:user\s+)?(\S+)\s+(\S+)\s+port\s+(\d+)'
            ),
            'connection_closed': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Connection\s+closed\s+by\s+(?:authenticating\s+user\s+)?(\S+)?\s*(\S+)\s+port\s+(\d+)'
            ),
            'received_disconnect': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Received\s+disconnect\s+from\s+(\S+)\s+port\s+(\d+)'
            )
        }
        
        log_files = self._get_auth_log_files()
        
        for log_file in log_files:
            try:
                content = self._read_log_file(log_file)
                for line in content.split('\n'):
                    for pattern_name, pattern in patterns.items():
                        match = pattern.search(line)
                        if match:
                            timestamp = self._parse_log_timestamp(match.group(1))
                            if timestamp and timestamp >= cutoff_date:
                                session = {
                                    'timestamp': timestamp.isoformat(),
                                    'hostname': match.group(2),
                                    'type': pattern_name,
                                    'raw_log': line[:200]
                                }
                                sessions.append(session)
                            break
                            
            except Exception as e:
                logger.warning(f"Error parsing {log_file}: {e}")
        
        return sessions
    
    def _get_user_commands(self) -> Dict[str, List[Dict]]:
        """Get command history for each user."""
        user_commands = {}
        history_files = self.user_config.get('history_files', ['.bash_history', '.zsh_history'])
        max_lines = self.user_config.get('max_history_lines', 10000)
        
        for user in pwd.getpwall():
            if user.pw_uid >= 1000 or user.pw_name == 'root':
                home_dir = user.pw_dir
                commands = []
                
                for hist_file in history_files:
                    hist_path = os.path.join(home_dir, hist_file)
                    if os.path.exists(hist_path):
                        try:
                            with open(hist_path, 'r', errors='ignore') as f:
                                lines = f.readlines()[-max_lines:]
                                for i, line in enumerate(lines):
                                    line = line.strip()
                                    if line and not line.startswith('#'):
                                        commands.append({
                                            'command': line,
                                            'source': hist_file,
                                            'line_number': i + 1
                                        })
                        except PermissionError:
                            logger.debug(f"Permission denied for {hist_path}")
                        except Exception as e:
                            logger.warning(f"Error reading {hist_path}: {e}")
                
                if commands:
                    user_commands[user.pw_name] = {
                        'total_commands': len(commands),
                        'recent_commands': commands[-100:],  # Last 100 commands
                        'suspicious_commands': self._find_suspicious_commands(commands)
                    }
        
        return user_commands
    
    def _find_suspicious_commands(self, commands: List[Dict]) -> List[Dict]:
        """Find potentially suspicious commands."""
        suspicious = []
        suspicious_patterns = [
            (r'curl.*\|.*sh', 'Pipe to shell'),
            (r'wget.*\|.*sh', 'Pipe to shell'),
            (r'nc\s+-l', 'Netcat listener'),
            (r'ncat\s+-l', 'Ncat listener'),
            (r'/dev/tcp/', 'Bash TCP'),
            (r'base64\s+-d', 'Base64 decode'),
            (r'python.*-c.*exec', 'Python exec'),
            (r'perl.*-e', 'Perl execution'),
            (r'rm\s+-rf\s+/', 'Dangerous rm'),
            (r'chmod\s+777', 'World writable'),
            (r'chmod\s+\+s', 'Set SUID'),
            (r'iptables\s+-F', 'Flush firewall'),
            (r'history\s+-c', 'Clear history'),
            (r'shred', 'File shredding'),
            (r'mkfifo', 'Named pipe'),
            (r'crontab\s+-e', 'Cron edit'),
            (r'/etc/passwd', 'Password file access'),
            (r'/etc/shadow', 'Shadow file access'),
            (r'ssh.*-R', 'SSH reverse tunnel'),
            (r'ssh.*-D', 'SSH SOCKS proxy'),
            (r'tcpdump', 'Packet capture'),
            (r'wireshark', 'Packet capture'),
            (r'nmap', 'Network scanning'),
            (r'hydra', 'Brute force tool'),
            (r'john', 'Password cracking'),
            (r'hashcat', 'Password cracking')
        ]
        
        for cmd in commands:
            command = cmd['command'].lower()
            for pattern, description in suspicious_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    suspicious.append({
                        'command': cmd['command'],
                        'source': cmd['source'],
                        'pattern_matched': pattern,
                        'description': description
                    })
                    break
        
        return suspicious
    
    def _get_user_modifications(self, cutoff_date: datetime) -> List[Dict]:
        """Parse user account modifications."""
        modifications = []
        patterns = {
            'useradd': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+useradd\[\d+\]:\s+new\s+user:\s+name=(\S+),\s+UID=(\d+)'
            ),
            'userdel': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+userdel\[\d+\]:\s+delete\s+user\s+[\'"]?(\S+)'
            ),
            'usermod': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+usermod\[\d+\]:\s+change\s+user\s+[\'"]?(\S+)'
            ),
            'groupadd': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+groupadd\[\d+\]:\s+(?:new\s+)?group:\s+name=(\S+)'
            ),
            'groupdel': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+groupdel\[\d+\]:\s+(?:removed\s+)?group\s+[\'"]?(\S+)'
            ),
            'gpasswd': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+gpasswd\[\d+\]:\s+user\s+(\S+)\s+added.*to.*group\s+(\S+)'
            )
        }
        
        log_files = self._get_auth_log_files()
        
        for log_file in log_files:
            try:
                content = self._read_log_file(log_file)
                for line in content.split('\n'):
                    for mod_type, pattern in patterns.items():
                        match = pattern.search(line)
                        if match:
                            timestamp = self._parse_log_timestamp(match.group(1))
                            if timestamp and timestamp >= cutoff_date:
                                modification = {
                                    'timestamp': timestamp.isoformat(),
                                    'hostname': match.group(2),
                                    'type': mod_type,
                                    'details': match.groups()[2:],
                                    'raw_log': line[:200]
                                }
                                modifications.append(modification)
                                
                                self._add_timeline_event(
                                    timestamp,
                                    f'USER_MODIFICATION',
                                    f"User modification: {mod_type} - {line[:100]}",
                                    modification
                                )
                                
                                if mod_type in ['useradd', 'userdel']:
                                    self.alerts.append({
                                        'severity': 'WARNING',
                                        'type': f'USER_{mod_type.upper()}',
                                        'message': f"User account {mod_type}: {match.groups()[2]}",
                                        'timestamp': timestamp.isoformat()
                                    })
                            break
                            
            except Exception as e:
                logger.warning(f"Error parsing {log_file}: {e}")
        
        return modifications
    
    def _get_password_changes(self, cutoff_date: datetime) -> List[Dict]:
        """Parse password change events."""
        password_changes = []
        patterns = {
            'passwd_change': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+passwd\[\d+\]:\s+(?:pam_unix\(passwd:chauthtok\):\s+)?password\s+changed\s+for\s+(\S+)'
            ),
            'password_changed': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+password\s+for\s+[\'"]?(\S+)[\'"]?\s+changed\s+by\s+[\'"]?(\S+)'
            )
        }
        
        log_files = self._get_auth_log_files()
        
        for log_file in log_files:
            try:
                content = self._read_log_file(log_file)
                for line in content.split('\n'):
                    for pattern_name, pattern in patterns.items():
                        match = pattern.search(line)
                        if match:
                            timestamp = self._parse_log_timestamp(match.group(1))
                            if timestamp and timestamp >= cutoff_date:
                                change = {
                                    'timestamp': timestamp.isoformat(),
                                    'hostname': match.group(2),
                                    'username': match.group(3),
                                    'type': pattern_name
                                }
                                password_changes.append(change)
                                
                                self._add_timeline_event(
                                    timestamp,
                                    'PASSWORD_CHANGE',
                                    f"Password changed for user: {change['username']}",
                                    change
                                )
                            break
                            
            except Exception as e:
                logger.warning(f"Error parsing {log_file}: {e}")
        
        return password_changes
    
    def _get_group_changes(self, cutoff_date: datetime) -> List[Dict]:
        """Parse group membership changes."""
        group_changes = []
        patterns = {
            'add_member': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+add\s+[\'"]?(\S+)[\'"]?\s+to\s+(?:group\s+)?[\'"]?(\S+)'
            ),
            'remove_member': re.compile(
                r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+remove\s+[\'"]?(\S+)[\'"]?\s+from\s+(?:group\s+)?[\'"]?(\S+)'
            )
        }
        
        log_files = self._get_auth_log_files()
        
        for log_file in log_files:
            try:
                content = self._read_log_file(log_file)
                for line in content.split('\n'):
                    for pattern_name, pattern in patterns.items():
                        match = pattern.search(line)
                        if match:
                            timestamp = self._parse_log_timestamp(match.group(1))
                            if timestamp and timestamp >= cutoff_date:
                                change = {
                                    'timestamp': timestamp.isoformat(),
                                    'hostname': match.group(2),
                                    'username': match.group(3),
                                    'group': match.group(4),
                                    'type': pattern_name
                                }
                                group_changes.append(change)
                                
                                # Alert on sensitive group changes
                                sensitive_groups = ['root', 'sudo', 'wheel', 'admin', 'docker']
                                if change['group'] in sensitive_groups:
                                    self.alerts.append({
                                        'severity': 'HIGH',
                                        'type': 'SENSITIVE_GROUP_CHANGE',
                                        'message': f"User {change['username']} {pattern_name.replace('_', ' ')} {change['group']}",
                                        'timestamp': timestamp.isoformat()
                                    })
                            break
                            
            except Exception as e:
                logger.warning(f"Error parsing {log_file}: {e}")
        
        return group_changes
    
    def _get_currently_logged_in(self) -> List[Dict]:
        """Get currently logged in users."""
        logged_in = []
        try:
            result = subprocess.run(['who'], capture_output=True, text=True)
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 3:
                        logged_in.append({
                            'username': parts[0],
                            'terminal': parts[1],
                            'login_time': ' '.join(parts[2:4]) if len(parts) >= 4 else parts[2],
                            'source': parts[4].strip('()') if len(parts) >= 5 else 'local'
                        })
        except Exception as e:
            logger.warning(f"Error getting logged in users: {e}")
        
        return logged_in
    
    def _get_last_logins(self) -> List[Dict]:
        """Get last login information for all users."""
        last_logins = []
        try:
            result = subprocess.run(['lastlog'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    if '**Never logged in**' not in line:
                        last_logins.append({
                            'username': parts[0],
                            'port': parts[1] if len(parts) > 1 else 'N/A',
                            'from': parts[2] if len(parts) > 2 else 'N/A',
                            'last_login': ' '.join(parts[3:]) if len(parts) > 3 else 'N/A'
                        })
        except Exception as e:
            logger.warning(f"Error getting last logins: {e}")
        
        return last_logins
    
    def _get_user_cron_jobs(self) -> Dict[str, List[str]]:
        """Get cron jobs for each user."""
        cron_jobs = {}
        
        # User crontabs
        crontab_dir = '/var/spool/cron/crontabs'
        if os.path.exists(crontab_dir):
            try:
                for username in os.listdir(crontab_dir):
                    crontab_path = os.path.join(crontab_dir, username)
                    if os.path.isfile(crontab_path):
                        try:
                            with open(crontab_path, 'r') as f:
                                jobs = [line.strip() for line in f 
                                       if line.strip() and not line.startswith('#')]
                                if jobs:
                                    cron_jobs[username] = jobs
                        except PermissionError:
                            pass
            except PermissionError:
                pass
        
        # Also check /var/spool/cron (RHEL-based)
        crontab_dir_rhel = '/var/spool/cron'
        if os.path.exists(crontab_dir_rhel) and crontab_dir_rhel != crontab_dir:
            try:
                for username in os.listdir(crontab_dir_rhel):
                    crontab_path = os.path.join(crontab_dir_rhel, username)
                    if os.path.isfile(crontab_path):
                        try:
                            with open(crontab_path, 'r') as f:
                                jobs = [line.strip() for line in f 
                                       if line.strip() and not line.startswith('#')]
                                if jobs:
                                    if username in cron_jobs:
                                        cron_jobs[username].extend(jobs)
                                    else:
                                        cron_jobs[username] = jobs
                        except PermissionError:
                            pass
            except PermissionError:
                pass
        
        return cron_jobs
    
    def _get_ssh_authorized_keys(self) -> Dict[str, List[Dict]]:
        """Get SSH authorized keys for each user."""
        ssh_keys = {}
        
        for user in pwd.getpwall():
            if user.pw_uid >= 1000 or user.pw_name == 'root':
                auth_keys_path = os.path.join(user.pw_dir, '.ssh', 'authorized_keys')
                if os.path.exists(auth_keys_path):
                    try:
                        with open(auth_keys_path, 'r') as f:
                            keys = []
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    parts = line.split()
                                    key_info = {
                                        'type': parts[0] if parts else 'unknown',
                                        'key_fingerprint': self._get_key_fingerprint(line),
                                        'comment': parts[-1] if len(parts) > 2 else 'no comment'
                                    }
                                    keys.append(key_info)
                            if keys:
                                ssh_keys[user.pw_name] = keys
                    except PermissionError:
                        pass
                    except Exception as e:
                        logger.debug(f"Error reading {auth_keys_path}: {e}")
        
        return ssh_keys
    
    def _get_key_fingerprint(self, key_line: str) -> str:
        """Calculate SSH key fingerprint."""
        try:
            result = subprocess.run(
                ['ssh-keygen', '-lf', '-'],
                input=key_line,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return 'Unable to calculate fingerprint'
    
    def _generate_user_summary(self, audit_result: Dict) -> Dict[str, Dict]:
        """Generate per-user activity summary."""
        summary = {}
        
        # Get all users from various sources
        users_set = set()
        for user in audit_result.get('user_list', []):
            users_set.add(user['username'])
        
        for username in users_set:
            user_summary = {
                'username': username,
                'logins': [],
                'failed_logins': [],
                'sudo_commands': [],
                'commands_count': 0,
                'suspicious_commands': [],
                'source_ips': set()
            }
            
            # Aggregate login history
            for login in audit_result.get('login_history', []):
                if login.get('username') == username:
                    user_summary['logins'].append(login)
                    if login.get('source_ip'):
                        user_summary['source_ips'].add(login['source_ip'])
            
            # Aggregate failed logins
            for failed in audit_result.get('failed_logins', []):
                if failed.get('username') == username:
                    user_summary['failed_logins'].append(failed)
            
            # Aggregate sudo usage
            for sudo in audit_result.get('sudo_usage', []):
                if sudo.get('username') == username:
                    user_summary['sudo_commands'].append(sudo)
            
            # Get command history
            user_cmds = audit_result.get('user_commands', {}).get(username, {})
            user_summary['commands_count'] = user_cmds.get('total_commands', 0)
            user_summary['suspicious_commands'] = user_cmds.get('suspicious_commands', [])
            
            # Convert set to list for JSON serialization
            user_summary['source_ips'] = list(user_summary['source_ips'])
            
            summary[username] = user_summary
        
        return summary
    
    def _calculate_statistics(self, audit_result: Dict) -> Dict:
        """Calculate audit statistics."""
        return {
            'total_users': len(audit_result.get('user_list', [])),
            'system_users': len(audit_result.get('system_users', [])),
            'human_users': len(audit_result.get('user_list', [])) - len(audit_result.get('system_users', [])),
            'total_logins': len(audit_result.get('login_history', [])),
            'failed_logins': len(audit_result.get('failed_logins', [])),
            'sudo_events': len(audit_result.get('sudo_usage', [])),
            'user_modifications': len(audit_result.get('user_modifications', [])),
            'password_changes': len(audit_result.get('password_changes', [])),
            'group_changes': len(audit_result.get('group_changes', [])),
            'currently_logged_in': len(audit_result.get('currently_logged_in', [])),
            'users_with_ssh_keys': len(audit_result.get('ssh_keys', {})),
            'users_with_cron_jobs': len(audit_result.get('cron_jobs', {}))
        }
    
    def _get_auth_log_files(self) -> List[str]:
        """Get list of auth log files to parse."""
        log_files = []
        
        # Primary auth log locations
        auth_paths = [
            self.log_paths.get('auth_log', '/var/log/auth.log'),
            self.log_paths.get('auth_log_alt', '/var/log/secure'),
            '/var/log/auth.log',
            '/var/log/secure'
        ]
        
        for path in auth_paths:
            if os.path.exists(path):
                log_files.append(path)
                # Also check for rotated logs
                for i in range(1, 5):
                    rotated = f"{path}.{i}"
                    rotated_gz = f"{path}.{i}.gz"
                    if os.path.exists(rotated):
                        log_files.append(rotated)
                    if os.path.exists(rotated_gz):
                        log_files.append(rotated_gz)
        
        return list(set(log_files))
    
    def _read_log_file(self, filepath: str) -> str:
        """Read log file, handling gzip compression."""
        try:
            if filepath.endswith('.gz'):
                with gzip.open(filepath, 'rt', errors='ignore') as f:
                    return f.read()
            else:
                with open(filepath, 'r', errors='ignore') as f:
                    return f.read()
        except Exception as e:
            logger.warning(f"Error reading {filepath}: {e}")
            return ""
    
    def _parse_log_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp from log entry."""
        try:
            # Add current year since syslog doesn't include year
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            return datetime.strptime(timestamp_with_year, '%Y %b %d %H:%M:%S')
        except ValueError:
            try:
                # Try without year
                return datetime.strptime(timestamp_str, '%b %d %H:%M:%S').replace(
                    year=datetime.now().year
                )
            except ValueError:
                return None
    
    def _add_timeline_event(self, timestamp: datetime, event_type: str, 
                           description: str, data: Dict = None):
        """Add event to timeline."""
        self.timeline_events.append({
            'timestamp': timestamp.isoformat() if timestamp else datetime.now().isoformat(),
            'type': event_type,
            'description': description,
            'category': 'user',
            'data': data or {}
        })
