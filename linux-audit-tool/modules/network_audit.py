#!/usr/bin/env python3
"""Network audit module for connections, listeners, and DNS info."""

import logging
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Set

logger = logging.getLogger('LinuxAuditTool.NetworkAudit')


class NetworkAuditor:
    """Audits current network posture and highlights suspicious ports."""

    def __init__(self, config: Dict):
        self.config = config
        self.network_config = config.get('network_audit', {})
        self.timeline_events: List[Dict] = []
        self.alerts: List[Dict] = []

    def audit(self, days: int = 30) -> Dict:
        """Run network audit (snapshot-based)."""
        connections = self._get_connections()
        listeners = self._get_listeners()
        dns_servers = self._get_dns_servers()

        unique_ips: Set[str] = set()
        suspicious_ips: Set[str] = set()
        suspicious_ports_config = set(self.network_config.get('suspicious_ports', []))

        for conn in connections:
            remote_ip = conn.get('remote_ip')
            if remote_ip:
                unique_ips.add(remote_ip)
            local_port = conn.get('local_port')
            remote_port = conn.get('remote_port')
            if local_port in suspicious_ports_config or remote_port in suspicious_ports_config:
                suspicious_ips.add(remote_ip or '')
                self._add_timeline_event(
                    datetime.now(),
                    'suspicious_network',
                    f"Connection on suspicious port {local_port or remote_port}",
                    conn,
                )
                self._add_alert('HIGH', f"Suspicious port activity on {local_port or remote_port}", {'connection': conn})

        statistics = {
            'connections': len(connections),
            'listening_ports': len(listeners),
            'unique_ips': len(unique_ips),
            'suspicious_ports': len(suspicious_ports_config.intersection({c.get('local_port') for c in listeners})),
        }

        return {
            'connections': connections,
            'listening_ports': listeners,
            'dns_servers': dns_servers,
            'unique_ips': sorted(ip for ip in unique_ips if ip),
            'suspicious_ips': sorted(ip for ip in suspicious_ips if ip),
            'statistics': statistics,
        }

    def _get_connections(self) -> List[Dict]:
        """Capture active TCP/UDP connections using ss."""
        connections: List[Dict] = []
        try:
            output = subprocess.check_output(['ss', '-tuna'], text=True, stderr=subprocess.DEVNULL)
        except Exception as exc:  # pragma: no cover - environment dependent
            logger.warning("Could not run ss: %s", exc)
            return connections

        lines = output.strip().splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue
            state, recv_q, send_q, local, remote = parts[:5]
            local_ip, local_port = self._split_host_port(local)
            remote_ip, remote_port = self._split_host_port(remote)
            connections.append({
                'state': state,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
            })
        return connections

    def _get_listeners(self) -> List[Dict]:
        """Get listening sockets."""
        listeners: List[Dict] = []
        try:
            output = subprocess.check_output(['ss', '-tuln'], text=True, stderr=subprocess.DEVNULL)
        except Exception as exc:  # pragma: no cover - environment dependent
            logger.warning("Could not list listeners: %s", exc)
            return listeners

        lines = output.strip().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[4]
            local_ip, local_port = self._split_host_port(local)
            listeners.append({'protocol': proto, 'local_ip': local_ip, 'local_port': local_port})
        return listeners

    def _get_dns_servers(self) -> List[str]:
        servers: List[str] = []
        resolv_conf = '/etc/resolv.conf'
        if os.path.exists(resolv_conf):
            with open(resolv_conf, 'r', errors='ignore') as handle:
                for line in handle:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        return servers

    def _split_host_port(self, address: str):
        """Split address into host and port components."""
        if '[' in address and ']' in address:
            # IPv6 address format [addr]:port
            host_part = address.split(']')[0].strip('[]')
            port_part = address.split(']:')[-1]
            return host_part, self._safe_port(port_part)
        if ':' not in address:
            return address, None
        if address.count(':') > 1:
            # IPv6 without brackets
            return address, None
        host_part, port_part = address.rsplit(':', 1)
        return host_part, self._safe_port(port_part)

    def _safe_port(self, port: str):
        try:
            return int(port)
        except (TypeError, ValueError):
            return None

    def _add_timeline_event(self, timestamp: datetime, event_type: str, description: str, data: Dict):
        self.timeline_events.append({
            'timestamp': timestamp.isoformat(),
            'type': event_type,
            'description': description,
            'category': 'network',
            'data': data,
        })

    def _add_alert(self, severity: str, message: str, data: Dict):
        self.alerts.append({
            'severity': severity,
            'message': message,
            'category': 'network',
            'timestamp': datetime.now().isoformat(),
            'data': data,
        })
