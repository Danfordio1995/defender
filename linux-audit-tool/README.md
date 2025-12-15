# Linux Audit Tool Status

## Project Overview
This repository contains a prototype for a comprehensive Linux audit tool intended to gather metadata, run user/system/network/security audits, and generate reports based on a YAML configuration. The main entrypoint is [`linux_audit.py`](linux_audit.py), which orchestrates the auditing workflow using specialized modules and configuration in `config/audit_config.yaml`.

## Current Completion Status
Core audit modules are present (`user_audit.py`, `system_audit.py`, `network_audit.py`, `security_audit.py`) along with shared helpers (`log_parser.py`) and a `report_generator.py` utility. The tool can execute end-to-end audits, generate reports, and emit alerts and timeline events, but remains **prototype-quality** and untested in production-like environments.

### How to Run (prototype)
<<<<<< codex/locate-linux-audit-tool-7l5dpk
1. Install Python 3.9+ and dependencies: `python3 -m pip install -r requirements.txt`.
2. Ensure you can run with sufficient privileges to read system logs and sockets.
3. From the repository root, invoke `python3 linux_audit.py --full --days 1 --output /tmp/audit_out --summary-only` to produce a quick summary without generating full reports. Use `--help` for more options.
4. Reports and collected data are written under `/var/log/linux-audit-tool` by default. Adjust `general.output_dir` in the YAML config or pass `--output <path>` to override; subdirectories for `data/` and `reports/` are created automatically.

### Troubleshooting
- The network audit requires the `ss` command (often provided by `iproute2`). Install it or place it on your `PATH` to avoid missing-utility warnings.
- Some system metadata (e.g., services via systemd) will be unavailable if the target host is not running systemd as PID 1.
=======
####codex/locate-linux-audit-tool-rneqlr
1. Install Python 3.9+ and dependencies: `python -m pip install -r requirements.txt`.
2. Ensure you can run with sufficient privileges to read system logs and sockets.
3. From the repository root, invoke `python linux_audit.py --full --days 1 --output /tmp/audit_out --summary-only` to produce a quick summary without generating full reports. Use `--help` for more options.
4. Reports and collected data are written under `/var/log/linux-audit-tool` by default. Adjust `general.output_dir` in the YAML config or pass `--output <path>` to override; subdirectories for `data/` and `reports/` are created automatically.
=======
1. Install Python 3.9+ and ensure you can run with sufficient privileges to read system logs and sockets.
2. From the repository root, invoke `python linux_audit.py` (or `python linux_audit.py --help` for options). The default configuration is loaded from `config/audit_config.yaml`.
3. Reports and collected data are written under `/var/log/linux-audit-tool` by default. Adjust the `general.output_dir` in the YAML config if you prefer a different path.
#####
>>>>>> main

## Next Steps to Complete
1. Harden and review the prototype modules against production workloads (e.g., large log volumes, permission edge cases, SELinux/AppArmor contexts).
2. Add automated tests or validation scripts to exercise each audit pathway (user, system, network, and security) and the reporting pipeline.
3. Document operational requirements and provide examples for cron-based runs, report rotation, and secure handling of collected artifacts.
