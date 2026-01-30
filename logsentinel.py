#!/usr/bin/env python3
"""
LogSentinel – Authentication Log Analyzer

A small security-focused Python CLI tool that parses authentication logs (CSV primary, JSON optional)
and flags suspicious patterns:
  - R1: Repeated failed logins from the same IP within a time window
  - R2: Successful login after multiple failures for the same user within a time window
  - R3: “Impossible travel” between consecutive successful logins from different countries
        within an unrealistically short time

This is intentionally simple and dependency-light (standard library only).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Tuple
from collections import defaultdict, deque


# -----------------------------
# Configuration / Parsing
# -----------------------------

@dataclass(frozen=True)
class Config:
    # Rule 1: failures from same IP within window
    r1_fail_threshold: int = 10
    r1_window_minutes: int = 10
    r1_flag_all_in_window: bool = False  # NEW: flag entire failure burst in the window

    # Rule 2: success after M failures for same user within window
    r2_fail_threshold: int = 5
    r2_window_minutes: int = 30

    # Rule 3: consecutive successful logins different countries within window
    r3_window_minutes: int = 30

    # Output / summary
    top_k_ips: int = 10


REQUIRED_FIELDS = {"timestamp", "username", "ip", "country", "success"}


def parse_timestamp(ts: str) -> datetime:
    """
    Parse an ISO-8601-ish timestamp string into a datetime.
    Supports:
      - "2025-12-30T12:34:56Z"
      - "2025-12-30T12:34:56+00:00"
      - "2025-12-30 12:34:56"
      - "2025-12-30T12:34:56"
    If no timezone is provided, the datetime is treated as UTC (naive -> UTC).
    """
    if not ts or not isinstance(ts, str):
        raise ValueError(f"Invalid timestamp: {ts!r}")

    t = ts.strip()

    # Handle trailing 'Z'
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(t)
    except ValueError as e:
        raise ValueError(f"Could not parse timestamp {ts!r}: {e}")

    # Normalize timezone: treat naive as UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def parse_success(value: Any) -> bool:
    """
    Parse success field into a boolean.
    Accepts: True/False, 1/0, "1"/"0", "true"/"false", "yes"/"no", "success"/"fail"
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False

    if isinstance(value, (int, float)):
        return bool(int(value))

    s = str(value).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "success", "succeeded", "ok"}:
        return True
    if s in {"0", "false", "f", "no", "n", "fail", "failed", "error"}:
        return False

    raise ValueError(f"Unrecognized success value: {value!r}")


def normalize_event(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalize one event row into a standard dict.
    Raises ValueError if required fields are missing or invalid.
    """
    missing = REQUIRED_FIELDS - set(row.keys())
    if missing:
        raise ValueError(f"Missing required fields: {sorted(missing)}")

    event = {
        "timestamp": parse_timestamp(str(row["timestamp"])),
        "username": str(row["username"]).strip(),
        "ip": str(row["ip"]).strip(),
        "country": str(row["country"]).strip().upper(),
        "success": parse_success(row["success"]),
        "raw": dict(row),
    }

    if not event["username"]:
        raise ValueError("Empty username")
    if not event["ip"]:
        raise ValueError("Empty ip")
    if not event["country"]:
        raise ValueError("Empty country")

    return event


# -----------------------------
# Loading (CSV primary, JSON optional)
# -----------------------------

def load_logs(path: str) -> List[Dict[str, Any]]:
    """
    Load authentication logs from a CSV (primary) or JSON (optional convenience).
    Returns a list of normalized event dicts, sorted by timestamp.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Input file not found: {path}")

    _, ext = os.path.splitext(path.lower())
    events: List[Dict[str, Any]] = []
    errors: List[str] = []

    if ext in {".csv"}:
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise ValueError("CSV has no header row.")

            header_map = {h: h.strip().lower() for h in reader.fieldnames}
            for idx, row in enumerate(reader, start=1):
                lowered = {header_map[k]: v for k, v in row.items() if k is not None}
                try:
                    events.append(normalize_event(lowered))
                except Exception as e:
                    errors.append(f"Row {idx}: {e}")

    elif ext in {".json"}:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            iterable = data
        elif isinstance(data, dict) and "events" in data and isinstance(data["events"], list):
            iterable = data["events"]
        else:
            raise ValueError("JSON must be a list of events or an object with an 'events' list.")

        for idx, obj in enumerate(iterable, start=1):
            if not isinstance(obj, dict):
                errors.append(f"Item {idx}: not an object")
                continue
            lowered = {str(k).strip().lower(): v for k, v in obj.items()}
            try:
                events.append(normalize_event(lowered))
            except Exception as e:
                errors.append(f"Item {idx}: {e}")

    elif ext in {".jsonl", ".ndjson"}:
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if not isinstance(obj, dict):
                        raise ValueError("not an object")
                    lowered = {str(k).strip().lower(): v for k, v in obj.items()}
                    events.append(normalize_event(lowered))
                except Exception as e:
                    errors.append(f"Line {idx}: {e}")
    else:
        raise ValueError("Unsupported input format. Use .csv (primary) or .json/.jsonl.")

    if not events:
        msg = "No valid events loaded."
        if errors:
            msg += " Errors:\n  - " + "\n  - ".join(errors[:10])
            if len(errors) > 10:
                msg += f"\n  ... and {len(errors) - 10} more"
        raise ValueError(msg)

    events.sort(key=lambda e: e["timestamp"])

    if errors:
        print(f"[!] Loaded {len(events)} events with {len(errors)} parse error(s). Showing up to 5:")
        for line in errors[:5]:
            print(f"    - {line}")
        if len(errors) > 5:
            print(f"    ... and {len(errors) - 5} more")

    return events


# -----------------------------
# Rules Engine
# -----------------------------

def _window_trim(q: Deque[int], timestamps: List[datetime], now_idx: int, window: timedelta) -> None:
    """Trim indices from left of deque while they are older than (current_time - window)."""
    now_ts = timestamps[now_idx]
    cutoff = now_ts - window
    while q and timestamps[q[0]] < cutoff:
        q.popleft()


def _flag_event(
    flagged_by_event_id: Dict[int, Dict[str, Any]],
    event_id: int,
    ev: Dict[str, Any],
    rule: str,
    metadata: Dict[str, Any],
) -> bool:
    """
    Merge a rule flag into an event record (so multiple rules can attach to same event).
    Returns True if this call newly added the rule to the event, False if it was already present.
    """
    rec = flagged_by_event_id.get(event_id)
    if rec is None:
        rec = {
            "event_id": event_id,
            "timestamp": ev["timestamp"].isoformat(),
            "username": ev["username"],
            "ip": ev["ip"],
            "country": ev["country"],
            "success": int(bool(ev["success"])),
            "rules": [],
            "metadata": {},
        }
        flagged_by_event_id[event_id] = rec

    newly_added = False
    if rule not in rec["rules"]:
        rec["rules"].append(rule)
        newly_added = True

    # Store/overwrite per-rule metadata (keeps report compact and consistent)
    rec.setdefault("metadata", {})
    rec["metadata"].setdefault("by_rule", {})
    rec["metadata"]["by_rule"][rule] = metadata

    return newly_added


def apply_rules(
    events: List[Dict[str, Any]],
    cfg: Config
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """
    Apply detection rules over events (sorted by timestamp).
    Returns:
      - flagged_events: list of flattened event dicts with rule labels & metadata
      - ip_summary: per-IP rollup with reasons/counters
      - user_summary: per-user rollup with triggered rules
    """
    timestamps = [e["timestamp"] for e in events]

    flagged_by_event_id: Dict[int, Dict[str, Any]] = {}
    ip_summary: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"rules": defaultdict(int), "reasons": set()})
    user_summary: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"rules": defaultdict(int), "reasons": set()})

    # -----------------
    # Rule 1: repeated failures from same IP within window
    # NEW: optional flagging of ALL failures in window on threshold crossing
    # -----------------
    r1_window = timedelta(minutes=cfg.r1_window_minutes)
    fail_idxs_by_ip: Dict[str, Deque[int]] = defaultdict(deque)

    for i, ev in enumerate(events):
        if ev["success"]:
            continue

        ip = ev["ip"]
        q = fail_idxs_by_ip[ip]
        q.append(i)
        _window_trim(q, timestamps, i, r1_window)

        # Fire R1 only on threshold crossing to avoid repetitive alerts for the same burst
        # Example: threshold=10 => crossing happens when len(q) == 11 ("> 10 failures")
        if len(q) == cfg.r1_fail_threshold + 1:
            burst_start = events[q[0]]["timestamp"].isoformat()
            burst_end = ev["timestamp"].isoformat()
            base_meta = {
                "failures_in_window": len(q),
                "window_minutes": cfg.r1_window_minutes,
                "threshold": cfg.r1_fail_threshold,
                "burst_start": burst_start,
                "burst_end": burst_end,
            }

            newly_flagged_count = 0
            if cfg.r1_flag_all_in_window:
                for idx in list(q):
                    added = _flag_event(
                        flagged_by_event_id,
                        event_id=idx,
                        ev=events[idx],
                        rule="R1",
                        metadata=base_meta,
                    )
                    newly_flagged_count += int(added)
            else:
                added = _flag_event(
                    flagged_by_event_id,
                    event_id=i,
                    ev=ev,
                    rule="R1",
                    metadata=base_meta,
                )
                newly_flagged_count += int(added)

            ip_summary[ip]["rules"]["R1"] += newly_flagged_count
            ip_summary[ip]["reasons"].add(
                f"R1: >{cfg.r1_fail_threshold} failures in {cfg.r1_window_minutes}m"
            )

    # -----------------
    # Rule 2: success after multiple failures for same user within window
    # -----------------
    r2_window = timedelta(minutes=cfg.r2_window_minutes)
    fail_idxs_by_user: Dict[str, Deque[int]] = defaultdict(deque)

    for i, ev in enumerate(events):
        user = ev["username"]
        q = fail_idxs_by_user[user]
        _window_trim(q, timestamps, i, r2_window)

        if ev["success"]:
            if len(q) >= cfg.r2_fail_threshold:
                added = _flag_event(
                    flagged_by_event_id,
                    event_id=i,
                    ev=ev,
                    rule="R2",
                    metadata={
                        "user_failures_before_success": len(q),
                        "window_minutes": cfg.r2_window_minutes,
                        "threshold": cfg.r2_fail_threshold,
                    },
                )
                user_summary[user]["rules"]["R2"] += int(added)
                user_summary[user]["reasons"].add(
                    f"R2: success after >= {cfg.r2_fail_threshold} failures in {cfg.r2_window_minutes}m"
                )
        else:
            q.append(i)

    # -----------------
    # Rule 3: Impossible travel (consecutive successful logins with country change quickly)
    # -----------------
    r3_window = timedelta(minutes=cfg.r3_window_minutes)
    last_success_by_user: Dict[str, Tuple[int, Dict[str, Any]]] = {}

    for i, ev in enumerate(events):
        if not ev["success"]:
            continue

        user = ev["username"]
        prev = last_success_by_user.get(user)
        if prev:
            prev_idx, prev_ev = prev
            time_delta = ev["timestamp"] - prev_ev["timestamp"]
            if timedelta(0) <= time_delta <= r3_window and ev["country"] != prev_ev["country"]:
                meta_prev = {
                    "other_event_id": i,
                    "other_country": ev["country"],
                    "minutes_between": int(time_delta.total_seconds() // 60),
                    "window_minutes": cfg.r3_window_minutes,
                    "note": "Consecutive successes from different countries in short time",
                }
                meta_now = {
                    "other_event_id": prev_idx,
                    "other_country": prev_ev["country"],
                    "minutes_between": int(time_delta.total_seconds() // 60),
                    "window_minutes": cfg.r3_window_minutes,
                    "note": "Consecutive successes from different countries in short time",
                }

                added_prev = _flag_event(flagged_by_event_id, prev_idx, prev_ev, "R3", meta_prev)
                added_now = _flag_event(flagged_by_event_id, i, ev, "R3", meta_now)

                # Count R3 once per "pair" in user summary (based on new addition on current event)
                if added_now or added_prev:
                    user_summary[user]["rules"]["R3"] += 1
                    user_summary[user]["reasons"].add(
                        f"R3: country change within {cfg.r3_window_minutes}m"
                    )

        last_success_by_user[user] = (i, ev)

    flagged_events = [flagged_by_event_id[k] for k in sorted(flagged_by_event_id.keys())]

    for ip, d in ip_summary.items():
        d["reasons"] = sorted(d["reasons"])
        d["rules"] = dict(d["rules"])
    for user, d in user_summary.items():
        d["reasons"] = sorted(d["reasons"])
        d["rules"] = dict(d["rules"])

    return flagged_events, dict(ip_summary), dict(user_summary)


# -----------------------------
# Reporting
# -----------------------------

def write_report_csv(flagged_events: List[Dict[str, Any]], out_path: str) -> None:
    """
    Write flagged events to a CSV report.
    metadata is stored as JSON in a single column.
    """
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    fieldnames = [
        "event_id",
        "timestamp",
        "username",
        "ip",
        "country",
        "success",
        "rules",
        "metadata_json",
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in flagged_events:
            writer.writerow({
                "event_id": rec["event_id"],
                "timestamp": rec["timestamp"],
                "username": rec["username"],
                "ip": rec["ip"],
                "country": rec["country"],
                "success": rec["success"],
                "rules": ",".join(rec["rules"]),
                "metadata_json": json.dumps(rec["metadata"], ensure_ascii=False),
            })


def print_summary(ip_summary: Dict[str, Dict[str, Any]], user_summary: Dict[str, Dict[str, Any]], top_k: int) -> None:
    """Print a human-readable console summary."""
    print("\n=== LogSentinel Summary ===")

    ranked_ips = sorted(
        ip_summary.items(),
        key=lambda kv: sum(kv[1].get("rules", {}).values()),
        reverse=True
    )

    print("\nTop suspicious IPs:")
    if not ranked_ips:
        print("  (none)")
    else:
        for ip, info in ranked_ips[:top_k]:
            total = sum(info["rules"].values())
            reasons = "; ".join(info["reasons"]) if info["reasons"] else "No reasons recorded"
            print(f"  - {ip}  (flags: {total})  => {reasons}")

    ranked_users = sorted(
        user_summary.items(),
        key=lambda kv: sum(kv[1].get("rules", {}).values()),
        reverse=True
    )

    print("\nFlagged users:")
    if not ranked_users:
        print("  (none)")
    else:
        for user, info in ranked_users:
            rules_counts = ", ".join([f"{r}:{c}" for r, c in sorted(info["rules"].items())])
            reasons = "; ".join(info["reasons"]) if info["reasons"] else "No reasons recorded"
            print(f"  - {user}  ({rules_counts})  => {reasons}")

    print("")


# -----------------------------
# CLI
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentinel",
        description="LogSentinel – Authentication Log Analyzer (CSV primary). Flags suspicious auth patterns.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("input", help="Path to input log file (.csv primary; .json/.jsonl optional).")
    p.add_argument(
        "-o", "--output",
        default=None,
        help="Path to output CSV report. Default: <input_basename>_logsentinel_report.csv",
    )

    p.add_argument("--r1-fail-threshold", type=int, default=Config.r1_fail_threshold,
                   help="R1: flag when failures from same IP exceed this count within the window.")
    p.add_argument("--r1-window-minutes", type=int, default=Config.r1_window_minutes,
                   help="R1: sliding window size (minutes) for IP failures.")
    p.add_argument("--r1-flag-all-in-window", action="store_true",
                   help="R1: when threshold is crossed, flag ALL failure events currently in the window (burst context).")

    p.add_argument("--r2-fail-threshold", type=int, default=Config.r2_fail_threshold,
                   help="R2: flag a success if preceded by at least this many failures for same user within window.")
    p.add_argument("--r2-window-minutes", type=int, default=Config.r2_window_minutes,
                   help="R2: sliding window size (minutes) for user failures before success.")

    p.add_argument("--r3-window-minutes", type=int, default=Config.r3_window_minutes,
                   help="R3: flag consecutive successes from different countries within this many minutes.")

    p.add_argument("--top-k-ips", type=int, default=Config.top_k_ips,
                   help="How many suspicious IPs to show in the console summary.")

    return p


def default_output_path(input_path: str) -> str:
    base, _ = os.path.splitext(input_path)
    return f"{base}_logsentinel_report.csv"


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    cfg = Config(
        r1_fail_threshold=args.r1_fail_threshold,
        r1_window_minutes=args.r1_window_minutes,
        r1_flag_all_in_window=args.r1_flag_all_in_window,
        r2_fail_threshold=args.r2_fail_threshold,
        r2_window_minutes=args.r2_window_minutes,
        r3_window_minutes=args.r3_window_minutes,
        top_k_ips=args.top_k_ips,
    )

    out_path = args.output or default_output_path(args.input)

    events = load_logs(args.input)
    flagged_events, ip_summary, user_summary = apply_rules(events, cfg)

    print_summary(ip_summary, user_summary, top_k=cfg.top_k_ips)
    write_report_csv(flagged_events, out_path)

    print(f"Wrote report: {out_path}")
    print(f"Flagged events: {len(flagged_events)} / Total events: {len(events)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
