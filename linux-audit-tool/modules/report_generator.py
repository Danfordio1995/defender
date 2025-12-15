#!/usr/bin/env python3
"""Report generation utilities for Linux audit tool."""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List
import csv

logger = logging.getLogger('LinuxAuditTool.ReportGenerator')


class ReportGenerator:
    """Render audit results to a chosen output format."""

    def __init__(self, config: Dict, audit_data: Dict):
        self.config = config
        self.audit_data = audit_data
        self.output_dir = config.get('general', {}).get('output_dir', '/var/log/linux-audit-tool')
        os.makedirs(os.path.join(self.output_dir, 'reports'), exist_ok=True)

    def generate(self, output_format: str = 'html') -> str:
        """Generate a report in the specified format."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"audit_report_{timestamp}.{output_format}"
        report_path = os.path.join(self.output_dir, 'reports', filename)

        if output_format == 'json':
            with open(report_path, 'w') as handle:
                json.dump(self.audit_data, handle, indent=2, default=str)
        elif output_format == 'txt':
            self._write_text_report(report_path)
        elif output_format == 'csv':
            self._write_csv_report(report_path)
        else:
            self._write_html_report(report_path)

        return report_path

    def _write_text_report(self, path: str):
        summary = self._build_summary()
        lines: List[str] = ["LINUX AUDIT REPORT", "=" * 60]
        for key, value in summary.items():
            lines.append(f"{key.replace('_', ' ').title()}: {value}")
        lines.append("\nALERTS")
        lines.append("-" * 60)
        for alert in self.audit_data.get('alerts', []):
            lines.append(f"[{alert.get('severity','INFO')}] {alert.get('timestamp','')} - {alert.get('message','')}")
        with open(path, 'w') as handle:
            handle.write("\n".join(lines))

    def _write_csv_report(self, path: str):
        alerts = self.audit_data.get('alerts', [])
        with open(path, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'severity', 'category', 'message']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for alert in alerts:
                writer.writerow({
                    'timestamp': alert.get('timestamp', ''),
                    'severity': alert.get('severity', ''),
                    'category': alert.get('category', ''),
                    'message': alert.get('message', ''),
                })

    def _write_html_report(self, path: str):
        summary = self._build_summary()
        alerts = self.audit_data.get('alerts', [])
        timeline = self.audit_data.get('timeline', [])
        html_parts = [
            "<html><head><title>Linux Audit Report</title>",
            "<style>body{font-family:Arial,sans-serif;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;}th{background:#f4f4f4;}</style>",
            "</head><body>",
            "<h1>Linux Audit Report</h1>",
            "<h2>Summary</h2>",
            "<table>",
        ]
        for key, value in summary.items():
            html_parts.append(f"<tr><th>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>")
        html_parts.extend([
            "</table>",
            "<h2>Alerts</h2>",
            "<table><tr><th>Timestamp</th><th>Severity</th><th>Category</th><th>Message</th></tr>",
        ])
        for alert in alerts:
            html_parts.append(
                f"<tr><td>{alert.get('timestamp','')}</td><td>{alert.get('severity','')}</td><td>{alert.get('category','')}</td><td>{alert.get('message','')}</td></tr>"
            )
        html_parts.extend([
            "</table>",
            "<h2>Timeline</h2>",
            "<table><tr><th>Timestamp</th><th>Type</th><th>Description</th></tr>",
        ])
        for event in timeline:
            html_parts.append(
                f"<tr><td>{event.get('timestamp','')}</td><td>{event.get('type','')}</td><td>{event.get('description','')}</td></tr>"
            )
        html_parts.append("</table></body></html>")

        with open(path, 'w') as handle:
            handle.write("".join(html_parts))

    def _build_summary(self) -> Dict:
        """Create a compact summary mirroring the CLI summary output."""
        users = self.audit_data.get('users', {})
        network = self.audit_data.get('network', {})
        system = self.audit_data.get('system', {})
        alerts = self.audit_data.get('alerts', [])

        summary = {
            'hostname': self.audit_data.get('metadata', {}).get('hostname', 'Unknown'),
            'audit_timestamp': self.audit_data.get('metadata', {}).get('audit_timestamp', 'Unknown'),
            'total_users_analyzed': len(users.get('user_list', [])),
            'total_login_events': users.get('statistics', {}).get('total_logins', 0),
            'total_failed_logins': users.get('statistics', {}).get('failed_logins', 0),
            'total_sudo_events': users.get('statistics', {}).get('sudo_events', 0),
            'unique_source_ips': len(network.get('unique_ips', [])),
            'suspicious_ips': len(network.get('suspicious_ips', [])),
            'file_changes': system.get('statistics', {}).get('file_changes', 0),
            'package_changes': system.get('statistics', {}).get('package_changes', 0),
            'total_alerts': len(alerts),
            'critical_alerts': len([a for a in alerts if a.get('severity') == 'CRITICAL']),
            'high_alerts': len([a for a in alerts if a.get('severity') == 'HIGH']),
        }
        return summary
