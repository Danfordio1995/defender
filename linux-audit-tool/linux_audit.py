#!/usr/bin/env python3
"""
Linux Comprehensive Audit Tool
==============================
A comprehensive security auditing tool for Linux servers that analyzes logs,
tracks user activities, monitors system changes, and generates detailed reports.

Author: Linux Security Team
Version: 1.0.0
"""

import os
import sys
import argparse
import logging
import yaml
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import subprocess
import pwd
import grp
import socket
import platform

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from user_audit import UserAuditor
from system_audit import SystemAuditor
from network_audit import NetworkAuditor
from log_parser import LogParser
from report_generator import ReportGenerator
from security_audit import SecurityAuditor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('LinuxAuditTool')


class LinuxAuditTool:
    """Main class for Linux server auditing."""
    
    def __init__(self, config_path: str = None):
        """Initialize the audit tool."""
        self.config = self._load_config(config_path)
        self.audit_data = {
            'metadata': {},
            'users': {},
            'system': {},
            'network': {},
            'security': {},
            'timeline': [],
            'alerts': []
        }
        self._setup_logging()
        self._setup_output_dir()
        
    def _load_config(self, config_path: str = None) -> Dict:
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), 
                'config', 
                'audit_config.yaml'
            )
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except FileNotFoundError:
            logger.warning(f"Config file not found at {config_path}, using defaults")
            return self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Return default configuration."""
        return {
            'general': {
                'output_dir': '/var/log/linux-audit-tool',
                'report_format': 'html',
                'log_level': 'INFO',
                'date_format': '%Y-%m-%d %H:%M:%S'
            },
            'user_audit': {'enabled': True},
            'system_audit': {'enabled': True},
            'network_audit': {'enabled': True},
            'security_audit': {'enabled': True}
        }
    
    def _setup_logging(self):
        """Configure logging based on config."""
        log_level = getattr(
            logging, 
            self.config.get('general', {}).get('log_level', 'INFO')
        )
        logger.setLevel(log_level)
    
    def _setup_output_dir(self):
        """Create output directory if it doesn't exist."""
        output_dir = self.config.get('general', {}).get(
            'output_dir', 
            '/var/log/linux-audit-tool'
        )
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'reports'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'data'), exist_ok=True)
        self.output_dir = output_dir
    
    def collect_metadata(self):
        """Collect system metadata."""
        logger.info("Collecting system metadata...")
        
        self.audit_data['metadata'] = {
            'audit_timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'fqdn': socket.getfqdn(),
            'platform': platform.platform(),
            'kernel': platform.release(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'uptime': self._get_uptime(),
            'boot_time': self._get_boot_time(),
            'timezone': self._get_timezone(),
            'audit_tool_version': '1.0.0'
        }
        
        # Get OS info
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_info[key] = value.strip('"')
                self.audit_data['metadata']['os_info'] = os_info
        except Exception:
            pass
        
        logger.info("System metadata collected")
    
    def _get_uptime(self) -> str:
        """Get system uptime."""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                return f"{days}d {hours}h {minutes}m"
        except Exception:
            return "Unknown"
    
    def _get_boot_time(self) -> str:
        """Get system boot time."""
        try:
            with open('/proc/stat', 'r') as f:
                for line in f:
                    if line.startswith('btime'):
                        btime = int(line.split()[1])
                        return datetime.fromtimestamp(btime).isoformat()
        except Exception:
            return "Unknown"
    
    def _get_timezone(self) -> str:
        """Get system timezone."""
        try:
            return subprocess.check_output(
                ['timedatectl', 'show', '--property=Timezone', '--value'],
                text=True
            ).strip()
        except Exception:
            try:
                return os.readlink('/etc/localtime').split('/')[-1]
            except Exception:
                return "Unknown"
    
    def run_user_audit(self, days: int = 30):
        """Run user activity audit."""
        if not self.config.get('user_audit', {}).get('enabled', True):
            logger.info("User audit disabled in config")
            return
        
        logger.info("Starting user audit...")
        auditor = UserAuditor(self.config)
        self.audit_data['users'] = auditor.audit(days=days)
        self.audit_data['timeline'].extend(auditor.timeline_events)
        self.audit_data['alerts'].extend(auditor.alerts)
        logger.info("User audit completed")
    
    def run_system_audit(self, days: int = 30):
        """Run system audit."""
        if not self.config.get('system_audit', {}).get('enabled', True):
            logger.info("System audit disabled in config")
            return
        
        logger.info("Starting system audit...")
        auditor = SystemAuditor(self.config)
        self.audit_data['system'] = auditor.audit(days=days)
        self.audit_data['timeline'].extend(auditor.timeline_events)
        self.audit_data['alerts'].extend(auditor.alerts)
        logger.info("System audit completed")
    
    def run_network_audit(self, days: int = 30):
        """Run network audit."""
        if not self.config.get('network_audit', {}).get('enabled', True):
            logger.info("Network audit disabled in config")
            return
        
        logger.info("Starting network audit...")
        auditor = NetworkAuditor(self.config)
        self.audit_data['network'] = auditor.audit(days=days)
        self.audit_data['timeline'].extend(auditor.timeline_events)
        self.audit_data['alerts'].extend(auditor.alerts)
        logger.info("Network audit completed")
    
    def run_security_audit(self):
        """Run security audit."""
        if not self.config.get('security_audit', {}).get('enabled', True):
            logger.info("Security audit disabled in config")
            return
        
        logger.info("Starting security audit...")
        auditor = SecurityAuditor(self.config)
        self.audit_data['security'] = auditor.audit()
        self.audit_data['timeline'].extend(auditor.timeline_events)
        self.audit_data['alerts'].extend(auditor.alerts)
        logger.info("Security audit completed")
    
    def run_full_audit(self, days: int = 30):
        """Run complete audit."""
        logger.info("="*60)
        logger.info("Starting Full Linux Server Audit")
        logger.info("="*60)
        
        self.collect_metadata()
        self.run_user_audit(days=days)
        self.run_system_audit(days=days)
        self.run_network_audit(days=days)
        self.run_security_audit()
        
        # Sort timeline by timestamp
        self.audit_data['timeline'].sort(
            key=lambda x: x.get('timestamp', ''), 
            reverse=True
        )
        
        # Sort alerts by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'WARNING': 2, 'INFO': 3}
        self.audit_data['alerts'].sort(
            key=lambda x: severity_order.get(x.get('severity', 'INFO'), 4)
        )
        
        logger.info("="*60)
        logger.info("Full Audit Completed")
        logger.info("="*60)
    
    def generate_report(self, output_format: str = None) -> str:
        """Generate audit report."""
        if output_format is None:
            output_format = self.config.get('general', {}).get('report_format', 'html')
        
        logger.info(f"Generating {output_format} report...")
        generator = ReportGenerator(self.config, self.audit_data)
        report_path = generator.generate(output_format)
        logger.info(f"Report generated: {report_path}")
        return report_path
    
    def save_raw_data(self) -> str:
        """Save raw audit data to JSON file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"audit_data_{timestamp}.json"
        filepath = os.path.join(self.output_dir, 'data', filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.audit_data, f, indent=2, default=str)
        
        logger.info(f"Raw data saved to {filepath}")
        return filepath
    
    def get_summary(self) -> Dict:
        """Get audit summary."""
        return {
            'metadata': self.audit_data.get('metadata', {}),
            'total_users_analyzed': len(self.audit_data.get('users', {}).get('user_list', [])),
            'total_login_events': self.audit_data.get('users', {}).get('statistics', {}).get('total_logins', 0),
            'total_failed_logins': self.audit_data.get('users', {}).get('statistics', {}).get('failed_logins', 0),
            'total_sudo_events': self.audit_data.get('users', {}).get('statistics', {}).get('sudo_events', 0),
            'unique_source_ips': len(self.audit_data.get('network', {}).get('unique_ips', [])),
            'suspicious_ips': len(self.audit_data.get('network', {}).get('suspicious_ips', [])),
            'file_changes': self.audit_data.get('system', {}).get('statistics', {}).get('file_changes', 0),
            'package_changes': self.audit_data.get('system', {}).get('statistics', {}).get('package_changes', 0),
            'total_alerts': len(self.audit_data.get('alerts', [])),
            'critical_alerts': len([a for a in self.audit_data.get('alerts', []) if a.get('severity') == 'CRITICAL']),
            'high_alerts': len([a for a in self.audit_data.get('alerts', []) if a.get('severity') == 'HIGH'])
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Linux Comprehensive Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --full                    Run full audit with default settings
  %(prog)s --full --days 7           Audit last 7 days
  %(prog)s --users                   Run only user audit
  %(prog)s --network                 Run only network audit
  %(prog)s --full --format json      Generate JSON report
  %(prog)s --full --output /tmp/     Save reports to /tmp/
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file',
        default=None
    )
    parser.add_argument(
        '--full', '-f',
        action='store_true',
        help='Run full audit (all modules)'
    )
    parser.add_argument(
        '--users', '-u',
        action='store_true',
        help='Run user audit only'
    )
    parser.add_argument(
        '--system', '-s',
        action='store_true',
        help='Run system audit only'
    )
    parser.add_argument(
        '--network', '-n',
        action='store_true',
        help='Run network audit only'
    )
    parser.add_argument(
        '--security',
        action='store_true',
        help='Run security audit only'
    )
    parser.add_argument(
        '--days', '-d',
        type=int,
        default=30,
        help='Number of days to analyze (default: 30)'
    )
    parser.add_argument(
        '--format',
        choices=['html', 'json', 'csv', 'txt'],
        default='html',
        help='Report format (default: html)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output directory for reports'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress output except errors'
    )
    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip report generation'
    )
    parser.add_argument(
        '--summary-only',
        action='store_true',
        help='Only show summary, no detailed report'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not any([args.full, args.users, args.system, args.network, args.security]):
        parser.error("Please specify at least one audit type (--full, --users, --system, --network, --security)")
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    
    # Check root privileges
    if os.geteuid() != 0:
        logger.warning("Running without root privileges. Some audit features may be limited.")
    
    # Initialize audit tool
    audit_tool = LinuxAuditTool(config_path=args.config)
    
    # Override output directory if specified
    if args.output:
        audit_tool.output_dir = args.output
        os.makedirs(args.output, exist_ok=True)
    
    # Run selected audits
    try:
        if args.full:
            audit_tool.run_full_audit(days=args.days)
        else:
            audit_tool.collect_metadata()
            if args.users:
                audit_tool.run_user_audit(days=args.days)
            if args.system:
                audit_tool.run_system_audit(days=args.days)
            if args.network:
                audit_tool.run_network_audit(days=args.days)
            if args.security:
                audit_tool.run_security_audit()
        
        # Generate summary
        summary = audit_tool.get_summary()
        
        if not args.quiet:
            print("\n" + "="*60)
            print("AUDIT SUMMARY")
            print("="*60)
            print(f"Hostname: {summary['metadata'].get('hostname', 'Unknown')}")
            print(f"Platform: {summary['metadata'].get('platform', 'Unknown')}")
            print(f"Audit Time: {summary['metadata'].get('audit_timestamp', 'Unknown')}")
            print("-"*60)
            print(f"Users Analyzed: {summary['total_users_analyzed']}")
            print(f"Total Logins: {summary['total_login_events']}")
            print(f"Failed Logins: {summary['total_failed_logins']}")
            print(f"Sudo Events: {summary['total_sudo_events']}")
            print(f"Unique Source IPs: {summary['unique_source_ips']}")
            print(f"Suspicious IPs: {summary['suspicious_ips']}")
            print(f"File Changes: {summary['file_changes']}")
            print(f"Package Changes: {summary['package_changes']}")
            print("-"*60)
            print(f"Total Alerts: {summary['total_alerts']}")
            print(f"  Critical: {summary['critical_alerts']}")
            print(f"  High: {summary['high_alerts']}")
            print("="*60)
        
        # Save raw data
        data_path = audit_tool.save_raw_data()
        
        # Generate report
        if not args.no_report and not args.summary_only:
            report_path = audit_tool.generate_report(output_format=args.format)
            if not args.quiet:
                print(f"\nReport saved to: {report_path}")
                print(f"Raw data saved to: {data_path}")
        
        return 0
        
    except PermissionError as e:
        logger.error(f"Permission denied: {e}")
        logger.error("Try running with sudo for full audit capabilities")
        return 1
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
