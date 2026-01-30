# LogSentinel – Authentication Log Analyzer

LogSentinel is a small **Python CLI** tool that parses authentication logs (CSV primary; JSON optional) and flags suspicious patterns commonly investigated in **Incident Response / SOC** workflows.

It’s intentionally lightweight (standard library only) and designed as a portfolio project that demonstrates log parsing, basic detection engineering, and report generation.

---

## Features

### Detection Rules
- **R1: Repeated failed logins (by IP)**
  - Flags when **more than N** failed logins occur from the **same IP** within a **time window**.
  - Optional: flag **all failed events in the burst window** when the threshold is crossed.

- **R2: Successful login after multiple failures (by user)**
  - Flags a **successful login** if it’s preceded by **M or more failures** for the same user within a **recent window**.

- **R3: “Impossible travel” (by user)**
  - Flags **consecutive successful logins** for the same user from **different countries** within an unrealistically short time window.

All thresholds and windows are configurable via CLI arguments.

---

## Input Format (CSV)

CSV is the primary format. Each row is one authentication event.

Required columns:
- `timestamp` — ISO 8601 recommended (e.g., `2025-12-30T12:00:00Z`)
- `username`
- `ip`
- `country` — 2-letter code recommended (e.g., `US`, `FR`)
- `success` — boolean or `0/1` (accepts values like `true/false`, `yes/no`, `1/0`)

Example row:
```csv
timestamp,username,ip,country,success
2025-12-30T12:05:00Z,alice,1.2.3.4,US,1
```
## Installation
No third-party dependencies are required (standard library only).

Recommended (optional) virtual environment:
```
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows PowerShell
```

## Usage
Basic run:
```
python3 logsentinel.py auth_logs.csv
```

Custom thresholds/windows + output report:
```
python3 logsentinel.py auth_logs.csv \
  --r1-fail-threshold 10 --r1-window-minutes 10 \
  --r1-flag-all-in-window \
  --r2-fail-threshold 5  --r2-window-minutes 30 \
  --r3-window-minutes 30 \
  -o reports/logsentinel_report.csv
```
Help:
```
python3 logsentinel.py --help
```
## Output
Console Summary
   * Top suspicious IPs and the reasons they were flagged
   * Flagged users and which rules were triggered

## CSV Report
Writes a CSV containing:
   * core event fields (timestamp, username, ip, country, success)
   * rules column listing triggered rule IDs (e.g., R2,R3)
   * metadata_json containing per-rule details in JSON

## Notes / Future Enhancements (optional ideas)
   * Add IP reputation scoring (offline allow/deny lists)
   * Add per-user baseline behavior (new country / new IP alerts)
   * Add JSON output and optional JUnit-style report for CI demos
   * Add unit tests with sample datasets

## Disclaimer
This tool is for learning and portfolio purposes. It is not a replacement for production SIEM/UEBA systems.

---

### `requirements.txt`
```txt
# LogSentinel uses only the Python standard library.
# This file is intentionally empty to keep dependencies minimal.
