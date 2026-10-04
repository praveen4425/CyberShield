"""
Log Parser & Normalizer for CyberShield.
Supports CSV and JSON security logs, normalizing raw data into SecurityEvent structures.
Handles malformed rows, missing fields, multiple timestamp formats gracefully.
"""

import csv
import io
import json
import uuid
from datetime import datetime
from typing import List, Tuple, Dict, Any
from .models import SecurityEvent


TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d-%m-%Y %H:%M:%S",
    "%b %d %H:%M:%S",
]


def parse_timestamp(ts_str: str) -> Tuple[str, float]:
    """Parse various timestamp formats into normalized ISO string and unix epoch."""
    if not ts_str:
        now = datetime.utcnow()
        return now.strftime("%Y-%m-%d %H:%M:%S"), now.timestamp()
    
    clean_ts = ts_str.strip()
    
    # Try float timestamp directly
    try:
        val = float(clean_ts)
        # Check if in milliseconds
        if val > 1e11:
            val = val / 1000.0
        dt = datetime.utcfromtimestamp(val)
        return dt.strftime("%Y-%m-%d %H:%M:%S"), val
    except ValueError:
        pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(clean_ts, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S"), dt.timestamp()
        except ValueError:
            continue

    # Fallback to current time if unparseable
    now = datetime.utcnow()
    return clean_ts, now.timestamp()


def normalize_event_dict(raw_dict: Dict[str, Any], line_num: int = 0) -> SecurityEvent:
    """Normalize a raw key-value dictionary into a typed SecurityEvent."""
    # Find matching fields flexibly (case-insensitive keys)
    keys_lower = {k.lower().strip(): v for k, v in raw_dict.items() if k}
    
    ts_raw = str(
        keys_lower.get("timestamp") or 
        keys_lower.get("time") or 
        keys_lower.get("datetime") or 
        keys_lower.get("@timestamp") or 
        keys_lower.get("date") or ""
    )
    norm_ts, epoch = parse_timestamp(ts_raw)
    
    source_ip = str(
        keys_lower.get("source_ip") or 
        keys_lower.get("ip") or 
        keys_lower.get("src_ip") or 
        keys_lower.get("client_ip") or 
        keys_lower.get("remote_addr") or "127.0.0.1"
    ).strip()
    
    username = str(
        keys_lower.get("username") or 
        keys_lower.get("user") or 
        keys_lower.get("user_id") or 
        keys_lower.get("account") or 
        keys_lower.get("login") or "anonymous"
    ).strip()
    
    action = str(
        keys_lower.get("action") or 
        keys_lower.get("event") or 
        keys_lower.get("event_type") or 
        keys_lower.get("activity") or 
        keys_lower.get("method") or "unknown"
    ).strip().lower()
    
    # Standardize action names
    if "fail" in action or "invalid" in action:
        if "login" in action or "auth" in action:
            action = "login_failed"
    elif "succ" in action or "ok" in action:
        if "login" in action or "auth" in action:
            action = "login_success"
    
    status = str(
        keys_lower.get("status") or 
        keys_lower.get("result") or 
        keys_lower.get("outcome") or ""
    ).strip().upper()
    
    if not status:
        if "fail" in action or "deny" in action or "block" in action:
            status = "FAILED"
        elif "succ" in action:
            status = "SUCCESS"
        else:
            status = "INFO"
            
    resource = str(
        keys_lower.get("resource") or 
        keys_lower.get("url") or 
        keys_lower.get("path") or 
        keys_lower.get("uri") or 
        keys_lower.get("target") or 
        keys_lower.get("file") or "/"
    ).strip()
    
    method = str(keys_lower.get("method") or "GET").strip().upper()
    
    try:
        status_code = int(keys_lower.get("status_code") or keys_lower.get("code") or (200 if status == "SUCCESS" else 401))
    except (ValueError, TypeError):
        status_code = 200 if status == "SUCCESS" else 401
        
    user_agent = str(keys_lower.get("user_agent") or keys_lower.get("agent") or "Standard Browser/Client").strip()
    
    event_id = str(keys_lower.get("id") or keys_lower.get("event_id") or f"EVT-{line_num:04d}-{str(uuid.uuid4())[:6]}")
    
    details = {k: v for k, v in raw_dict.items() if k.lower() not in [
        "timestamp", "time", "source_ip", "ip", "username", "user", "action", "status", "resource"
    ]}

    return SecurityEvent(
        id=event_id,
        timestamp=norm_ts,
        epoch=epoch,
        source_ip=source_ip,
        username=username,
        action=action,
        status=status,
        resource=resource,
        method=method,
        status_code=status_code,
        user_agent=user_agent,
        details=details,
        raw_log=json.dumps(raw_dict)
    )


def parse_csv_content(content: str) -> List[SecurityEvent]:
    """Parse CSV text into SecurityEvent list."""
    events: List[SecurityEvent] = []
    stream = io.StringIO(content.strip())
    reader = csv.DictReader(stream)
    
    if not reader.fieldnames:
        return []
        
    for idx, row in enumerate(reader, start=1):
        if not any(row.values()):
            continue  # skip completely blank rows
        try:
            event = normalize_event_dict(row, line_num=idx)
            events.append(event)
        except Exception:
            continue  # Gracefully skip malformed rows

    # Sort events chronologically by epoch
    events.sort(key=lambda x: x.epoch)
    return events


def parse_json_content(content: str) -> List[SecurityEvent]:
    """Parse JSON (list of objects or NDJSON) into SecurityEvent list."""
    events: List[SecurityEvent] = []
    content = content.strip()
    
    # Try as full JSON array
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for idx, item in enumerate(data, start=1):
                if isinstance(item, dict):
                    events.append(normalize_event_dict(item, line_num=idx))
            events.sort(key=lambda x: x.epoch)
            return events
        elif isinstance(data, dict):
            # Maybe inside an "events" or "logs" key
            for key in ["events", "logs", "records", "data"]:
                if key in data and isinstance(data[key], list):
                    for idx, item in enumerate(data[key], start=1):
                        if isinstance(item, dict):
                            events.append(normalize_event_dict(item, line_num=idx))
                    events.sort(key=lambda x: x.epoch)
                    return events
            events.append(normalize_event_dict(data, line_num=1))
            return events
    except json.JSONDecodeError:
        pass

    # Try as newline-delimited JSON (NDJSON)
    for idx, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                events.append(normalize_event_dict(item, line_num=idx))
        except Exception:
            continue

    events.sort(key=lambda x: x.epoch)
    return events


def parse_logs(content: str, filename: str = "") -> List[SecurityEvent]:
    """Auto-detect format and parse logs safely."""
    if not content or not content.strip():
        return []
        
    clean_content = content.strip()
    if filename.endswith(".json") or clean_content.startswith("[") or clean_content.startswith("{"):
        parsed = parse_json_content(clean_content)
        if parsed:
            return parsed
            
    # Default to CSV parser
    return parse_csv_content(clean_content)
