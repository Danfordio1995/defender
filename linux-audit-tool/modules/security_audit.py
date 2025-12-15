#!/usr/bin/env python3
"""Security audit module for Linux hosts."""

import logging
import os
import pwd
import grp
import stat
import subprocess
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger('LinuxAuditTool.SecurityAudit')


class SecurityAuditor:
    """Runs host-level security checks and collects findings."""

    def __init__(self, config: Dict):
        self.config = config
        self.security_config = config.get('security_audit', {})
        self.alerts: List[Dict] = []
        self.timeline_events: List[Dict] = []

    def audit(self) -> Dict:
        """Execute enabled security checks and return findings."""
        logger.info("Running security checks...")

        findings = {
            'rootkit_indicators': [],
            'setuid_files': [],
            'world_writable_files': [],
            'unowned_files': [],
            'hidden_processes': [],
            'suspicious_crons': [],
            'ssh_key_issues': [],
            'network_state': {},
            'statistics': {},
        }

        if self.security_config.get('check_rootkits', True):
            findings['rootkit_indicators'] = self._check_rootkit_indicators()
        if self.security_config.get('check_setuid_files', True):
            findings['setuid_files'] = self._find_setuid_files()
        if self.security_config.get('check_world_writable', True):
            findings['world_writable_files'] = self._find_world_writable_files()
        if self.security_config.get('check_unowned_files', True):
            findings['unowned_files'] = self._find_unowned_files()
        if self.security_config.get('check_hidden_processes', True):
            findings['hidden_processes'] = self._find_hidden_processes()
        if self.security_config.get('check_suspicious_crons', True):
            findings['suspicious_crons'] = self._find_suspicious_crons()
        if self.security_config.get('check_ssh_keys', True):
            findings['ssh_key_issues'] = self._check_ssh_keys()
        if self.security_config.get('check_open_ports', True) or self.security_config.get('check_listening_services', True):
            findings['network_state'] = self._snapshot_network_state()

        findings['statistics'] = {
            'rootkit_hits': len(findings['rootkit_indicators']),
            'setuid_files': len(findings['setuid_files']),
            'world_writable_files': len(findings['world_writable_files']),
            'unowned_files': len(findings['unowned_files']),
            'hidden_processes': len(findings['hidden_processes']),
            'suspicious_crons': len(findings['suspicious_crons']),
            'ssh_key_issues': len(findings['ssh_key_issues']),
            'listening_services': len(findings.get('network_state', {}).get('listening', [])),
            'active_connections': len(findings.get('network_state', {}).get('connections', [])),
        }

        return findings

    def _check_rootkit_indicators(self) -> List[Dict]:
        """Look for common rootkit artifact locations."""
        suspicious_paths = [
            '/dev/.tty', '/dev/.lib', '/dev/.static', '/etc/ld.so.hash',
            '/usr/lib/libproc.a', '/usr/lib/libproc.so', '/dev/.golf',
            '/dev/.kbd', '/usr/bin/aliens', '/usr/lib/.fx', '/usr/lib/security/.config',
        ]
        hits = []
        for path in suspicious_paths:
            if os.path.exists(path):
                hits.append({'path': path, 'description': 'Known rootkit artifact'})
                self._add_alert('CRITICAL', f"Potential rootkit artifact found: {path}", {'path': path})
        return hits

    def _find_setuid_files(self) -> List[Dict]:
        """Collect setuid binaries from common directories."""
        paths_to_scan = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']
        setuid_files: List[Dict] = []
        for directory in paths_to_scan:
            for root, _, files in os.walk(directory):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    try:
                        st = os.stat(full_path)
                        if st.st_mode & stat.S_ISUID:
                            entry = {
                                'path': full_path,
                                'owner': st.st_uid,
                                'group': st.st_gid,
                                'permissions': stat.filemode(st.st_mode),
                            }
                            setuid_files.append(entry)
                            if directory.startswith('/tmp'):
                                self._add_alert('HIGH', f"Setuid file in /tmp: {full_path}", entry)
                    except FileNotFoundError:
                        continue
                    except Exception as exc:  # pragma: no cover - best effort
                        logger.debug("Error inspecting %s: %s", full_path, exc)
        return setuid_files

    def _find_world_writable_files(self) -> List[Dict]:
        """Locate world-writable files in sensitive locations."""
        sensitive_dirs = ['/etc', '/usr', '/var', '/opt']
        world_writable: List[Dict] = []
        for directory in sensitive_dirs:
            for root, _, files in os.walk(directory):
                for filename in files:
                    path = os.path.join(root, filename)
                    try:
                        st = os.lstat(path)
                        if st.st_mode & stat.S_IWOTH:
                            entry = {
                                'path': path,
                                'permissions': stat.filemode(st.st_mode),
                            }
                            world_writable.append(entry)
                            if not (st.st_mode & stat.S_ISVTX):
                                self._add_alert('WARNING', f"World-writable file without sticky bit: {path}", entry)
                    except (FileNotFoundError, PermissionError):
                        continue
                    except Exception as exc:  # pragma: no cover
                        logger.debug("Error checking permissions for %s: %s", path, exc)
        return world_writable

    def _find_unowned_files(self) -> List[Dict]:
        """Find files owned by non-existent users or groups."""
        search_dirs = ['/etc', '/usr/local', '/var/www', '/home']
        unowned: List[Dict] = []
        for directory in search_dirs:
            for root, _, files in os.walk(directory):
                for filename in files:
                    path = os.path.join(root, filename)
                    try:
                        st = os.lstat(path)
                        try:
                            pwd.getpwuid(st.st_uid)
                            grp.getgrgid(st.st_gid)
                        except KeyError:
                            entry = {
                                'path': path,
                                'uid': st.st_uid,
                                'gid': st.st_gid,
                            }
                            unowned.append(entry)
                            self._add_alert('WARNING', f"File with missing owner/group: {path}", entry)
                    except (FileNotFoundError, PermissionError):
                        continue
        return unowned

    def _find_hidden_processes(self) -> List[Dict]:
        """Detect processes with suspicious hidden-style names."""
        hidden: List[Dict] = []
        try:
            output = subprocess.check_output(['ps', '-eo', 'pid,comm,args'], text=True)
            for line in output.splitlines()[1:]:
                parts = line.strip().split(None, 2)
                if len(parts) < 2:
                    continue
                pid, command = parts[0], parts[1]
                args = parts[2] if len(parts) > 2 else ''
                if command.startswith('.') or '/.' in args:
                    entry = {'pid': pid, 'command': command, 'args': args}
                    hidden.append(entry)
                    self._add_alert('HIGH', f"Hidden-like process name detected: PID {pid}", entry)
        except Exception as exc:  # pragma: no cover
            logger.debug("Unable to enumerate processes: %s", exc)
        return hidden

    def _find_suspicious_crons(self) -> List[Dict]:
        """Scan cron definitions for suspicious commands."""
        cron_paths = [
            '/etc/crontab', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
            '/etc/cron.weekly', '/etc/cron.monthly'
        ]
        indicators = ['curl', 'wget', 'nc ', 'bash -i', 'socat', 'python -c', 'perl -e', 'sh -i']
        findings: List[Dict] = []
        for path in cron_paths:
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for filename in files:
                        findings.extend(self._parse_cron_file(os.path.join(root, filename), indicators))
            elif os.path.exists(path):
                findings.extend(self._parse_cron_file(path, indicators))
        return findings

    def _parse_cron_file(self, path: str, indicators: List[str]) -> List[Dict]:
        entries: List[Dict] = []
        try:
            with open(path, 'r', errors='ignore') as handle:
                for line in handle:
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith('#'):
                        continue
                    hit = next((indicator for indicator in indicators if indicator in line_stripped), None)
                    if hit:
                        entry = {'path': path, 'line': line_stripped, 'indicator': hit}
                        entries.append(entry)
                        self._add_alert('WARNING', f"Suspicious cron entry in {path}", entry)
        except (FileNotFoundError, PermissionError):
            return []
        return entries

    def _check_ssh_keys(self) -> List[Dict]:
        """Check SSH authorized_keys for weak permissions."""
        issues: List[Dict] = []
        for user in pwd.getpwall():
            home_dir = user.pw_dir
            auth_path = os.path.join(home_dir, '.ssh', 'authorized_keys')
            if not os.path.exists(auth_path):
                continue
            try:
                st = os.stat(auth_path)
                if st.st_mode & stat.S_IWOTH:
                    entry = {'user': user.pw_name, 'path': auth_path, 'permissions': stat.filemode(st.st_mode)}
                    issues.append(entry)
                    self._add_alert('WARNING', f"World-writable authorized_keys for {user.pw_name}", entry)
            except Exception as exc:  # pragma: no cover
                logger.debug("Could not inspect %s: %s", auth_path, exc)
        return issues

    def _snapshot_network_state(self) -> Dict[str, List[Dict]]:
        """Capture listening sockets and active connections."""
        network_state = {'listening': [], 'connections': []}
        try:
            listen_output = subprocess.check_output(['ss', '-tuln'], text=True, stderr=subprocess.DEVNULL)
            for line in listen_output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    network_state['listening'].append({
                        'protocol': parts[0],
                        'local_address': parts[4],
                        'state': parts[1] if len(parts) > 1 else 'UNKNOWN',
                    })
        except Exception as exc:  # pragma: no cover
            logger.debug("Could not capture listening sockets: %s", exc)

        try:
            conn_output = subprocess.check_output(['ss', '-tan'], text=True, stderr=subprocess.DEVNULL)
            for line in conn_output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    network_state['connections'].append({
                        'state': parts[0],
                        'local_address': parts[3],
                        'peer_address': parts[4],
                    })
        except Exception as exc:  # pragma: no cover
            logger.debug("Could not capture active connections: %s", exc)

        return network_state

    def _add_alert(self, severity: str, message: str, data: Dict):
        self.alerts.append({
            'severity': severity,
            'message': message,
            'category': 'security',
            'timestamp': datetime.now().isoformat(),
            'data': data,
        })
        self.timeline_events.append({
            'timestamp': datetime.now().isoformat(),
            'type': 'security',
            'description': message,
            'category': 'security',
            'data': data,
        })
