#!/usr/bin/env python3
"""System audit module for file, package, and service state."""

import logging
import os
import stat
import subprocess
from datetime import datetime, timedelta
from glob import glob
from typing import Dict, List, Optional

from log_parser import LogParser

logger = logging.getLogger('LinuxAuditTool.SystemAudit')


class SystemAuditor:
    """Audits critical system changes and configuration."""

    def __init__(self, config: Dict):
        self.config = config
        self.system_config = config.get('system_audit', {})
        self.log_paths = config.get('log_paths', {})
        self.timeline_events: List[Dict] = []
        self.alerts: List[Dict] = []
        self.log_parser = LogParser(config)

    def audit(self, days: int = 30) -> Dict:
        """Run system audit and return collected data."""
        cutoff = datetime.now() - timedelta(days=days)

        file_integrity = self._check_critical_files(cutoff)
        package_changes = self._get_package_changes(cutoff)
        service_status = self._get_running_services()
        cron_jobs = self._get_cron_jobs()

        statistics = {
            'file_changes': len([f for f in file_integrity if f.get('recent_change')]),
            'package_changes': len(package_changes),
            'running_services': len(service_status.get('running', [])),
            'cron_entries': sum(len(v) for v in cron_jobs.values()),
        }

        return {
            'file_integrity': file_integrity,
            'package_changes': package_changes,
            'service_status': service_status,
            'cron_jobs': cron_jobs,
            'statistics': statistics,
        }

    def _check_critical_files(self, cutoff: datetime) -> List[Dict]:
        """Check existence and metadata for configured critical files."""
        results: List[Dict] = []
        files = self.system_config.get('critical_files', [])
        directories = self.system_config.get('critical_directories', [])

        # Expand glob patterns
        candidates: List[str] = []
        for path in files + directories:
            candidates.extend(glob(path))

        for path in sorted(set(candidates)):
            entry = {'path': path, 'exists': os.path.exists(path)}
            if not entry['exists']:
                results.append(entry)
                continue

            try:
                stat_result = os.stat(path)
                entry.update({
                    'size': stat_result.st_size,
                    'permissions': stat.filemode(stat_result.st_mode),
                    'owner_uid': stat_result.st_uid,
                    'owner_gid': stat_result.st_gid,
                    'last_modified': datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
                })

                recent_change = stat_result.st_mtime >= cutoff.timestamp()
                entry['recent_change'] = recent_change
                if recent_change:
                    self._add_timeline_event(
                        datetime.fromtimestamp(stat_result.st_mtime),
                        'file_change',
                        f"Recent change detected for {path}",
                        {'path': path},
                    )
            except Exception as exc:  # pragma: no cover - best-effort logging
                logger.warning("Unable to stat %s: %s", path, exc)
            results.append(entry)

        return results

    def _get_package_changes(self, cutoff: datetime) -> List[Dict]:
        """Parse package manager logs for recent installs or removals."""
        entries: List[Dict] = []
        history_paths = self.log_parser.resolve_paths(['apt_log', 'dpkg_log', 'yum_log', 'dnf_log'])
        for path in history_paths:
            for line in self.log_parser.read_lines(path):
                if 'install' not in line.lower() and 'remove' not in line.lower():
                    continue
                timestamp = self._extract_timestamp(line)
                if cutoff and timestamp and timestamp < cutoff:
                    continue
                entries.append({'path': path, 'timestamp': timestamp.isoformat() if timestamp else None, 'entry': line.strip()})
                if 'install' in line.lower():
                    self._add_alert('INFO', f"Package installation logged in {os.path.basename(path)}", {'entry': line.strip()})
        return entries

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Best-effort timestamp extraction from package logs."""
        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S,%f', '%b %d %H:%M:%S']:
            try:
                return datetime.strptime(line[:19], fmt)
            except ValueError:
                continue
        return None

    def _get_running_services(self) -> Dict:
        """List currently running services."""
        running: List[str] = []
        failed: List[str] = []
        try:
            output = subprocess.check_output(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend'],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in output.strip().splitlines():
                parts = line.split()
                if parts:
                    running.append(parts[0])
        except Exception:
            try:
                output = subprocess.check_output(['service', '--status-all'], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    if line.strip().startswith('[ + ]'):
                        running.append(line.split()[-1])
            except Exception as exc:  # pragma: no cover - fallback
                logger.warning("Could not determine running services: %s", exc)

        return {'running': running, 'failed': failed}

    def _get_cron_jobs(self) -> Dict[str, List[str]]:
        """Collect cron definitions from common locations."""
        cron_sources = {
            'crontab': ['/etc/crontab'],
            'cron.d': glob('/etc/cron.d/*'),
            'cron.daily': glob('/etc/cron.daily/*'),
            'cron.hourly': glob('/etc/cron.hourly/*'),
            'cron.weekly': glob('/etc/cron.weekly/*'),
            'cron.monthly': glob('/etc/cron.monthly/*'),
        }

        cron_jobs: Dict[str, List[str]] = {}
        for key, paths in cron_sources.items():
            entries: List[str] = []
            for path in paths:
                if os.path.isdir(path):
                    continue
                try:
                    with open(path, 'r', errors='ignore') as handle:
                        entries.extend([line.strip() for line in handle.readlines() if line.strip() and not line.startswith('#')])
                except Exception:
                    continue
            if entries:
                cron_jobs[key] = entries
        return cron_jobs

    def _add_timeline_event(self, timestamp: datetime, event_type: str, description: str, data: Dict):
        self.timeline_events.append({
            'timestamp': timestamp.isoformat(),
            'type': event_type,
            'description': description,
            'category': 'system',
            'data': data,
        })

    def _add_alert(self, severity: str, message: str, data: Dict):
        self.alerts.append({
            'severity': severity,
            'message': message,
            'category': 'system',
            'timestamp': datetime.now().isoformat(),
            'data': data,
        })
