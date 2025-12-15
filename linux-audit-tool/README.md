# Linux Audit Tool Status

## Project Overview
This repository contains a prototype for a comprehensive Linux audit tool intended to gather metadata, run user/system/network/security audits, and generate reports based on a YAML configuration. The main entrypoint is [`linux_audit.py`](linux_audit.py), which orchestrates the auditing workflow using specialized modules and configuration in `config/audit_config.yaml`.

## Current Completion Status
Core audit modules are present (`user_audit.py`, `system_audit.py`, `network_audit.py`, `security_audit.py`) along with shared helpers (`log_parser.py`) and a `report_generator.py` utility. The tool can execute end-to-end audits, generate reports, and emit alerts and timeline events, but remains **prototype-quality** and untested in production-like environments.

### How to Run (prototype)
1. Install Python 3.9+ and ensure you can run with sufficient privileges to read system logs and sockets.
2. From the repository root, invoke `python linux_audit.py` (or `python linux_audit.py --help` for options). The default configuration is loaded from `config/audit_config.yaml`.
3. Reports and collected data are written under `/var/log/linux-audit-tool` by default. Adjust the `general.output_dir` in the YAML config if you prefer a different path.

## Next Steps to Complete
1. Harden and review the prototype modules against production workloads (e.g., large log volumes, permission edge cases, SELinux/AppArmor contexts).
2. Add automated tests or validation scripts to exercise each audit pathway (user, system, network, and security) and the reporting pipeline.
3. Document operational requirements and provide examples for cron-based runs, report rotation, and secure handling of collected artifacts.
