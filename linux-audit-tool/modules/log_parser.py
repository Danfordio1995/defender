#!/usr/bin/env python3
"""Utility helpers for parsing common Linux log formats."""

import gzip
import logging
import os
import re
from datetime import datetime
from glob import glob
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger('LinuxAuditTool.LogParser')


class LogParser:
    """Lightweight parser for syslog-style files and rotated logs."""

    def __init__(self, config: Dict):
        self.config = config
        self.log_paths = config.get('log_paths', {})

    def resolve_paths(self, keys: Iterable[str]) -> List[str]:
        """Resolve log paths from config keys and include rotated variants."""
        paths: List[str] = []
        for key in keys:
            base = self.log_paths.get(key)
            if not base:
                continue
            paths.extend(self._expand_rotations(base))
        return paths

    def _expand_rotations(self, base_path: str) -> List[str]:
        """Return base path plus common rotation patterns."""
        candidates = [base_path]
        for suffix in ['.*', '.1', '.1.gz', '.2', '.2.gz', '.3', '.3.gz', '.4', '.4.gz']:
            candidates.extend(glob(f"{base_path}{suffix}"))
        return [p for p in candidates if os.path.exists(p)]

    def read_lines(self, path: str) -> List[str]:
        """Read a log file (plain or gzipped) and return raw lines."""
        try:
            if path.endswith('.gz'):
                with gzip.open(path, 'rt', errors='ignore') as handle:
                    return handle.readlines()
            with open(path, 'r', errors='ignore') as handle:
                return handle.readlines()
        except Exception as exc:  # pragma: no cover - best-effort logging
            logger.warning("Could not read %s: %s", path, exc)
            return []

    def parse_syslog_lines(self, path: str, since: Optional[datetime] = None) -> List[Dict]:
        """Parse syslog-style lines into structured records."""
        entries: List[Dict] = []
        pattern = re.compile(r'^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s+(.*)$')
        for raw_line in self.read_lines(path):
            match = pattern.match(raw_line.strip())
            if not match:
                continue

            timestamp_str, host, process, message = match.groups()
            ts = self._parse_timestamp(timestamp_str)
            if since and ts and ts < since:
                continue

            entries.append({
                'timestamp': ts.isoformat() if ts else None,
                'host': host,
                'process': process,
                'message': message,
                'raw': raw_line.strip(),
            })
        return entries

    def _parse_timestamp(self, timestamp: str) -> Optional[datetime]:
        """Convert a syslog timestamp (no year) into a datetime."""
        try:
            current_year = datetime.now().year
            return datetime.strptime(f"{current_year} {timestamp}", '%Y %b %d %H:%M:%S')
        except ValueError:
            return None
