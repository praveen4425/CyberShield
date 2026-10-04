"""
Generator for realistic synthetic security logs tailored for ALG-CYBER-01 'Find the Intruder'.
Normal business traffic clearly dominates (~80%+), embedding the 3 core intruder incidents:
1. Repeated failed authentication (Brute force on admin_backup from 45.33.32.156)
2. Failed -> successful login -> post-auth activity (Compromise of sysadmin from 198.51.100.89)
3. Multiple-account suspicious authentication (Password spray across 4 accounts from 203.0.113.42)
"""

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent

# Ground-truth definitions for validation testing
GROUND_TRUTH = {
    "total_events": 90,
    "suspicious_events": 16,
    "normal_events": 74,
    "suspicious_percentage": 17.8,
    "expected_incidents_count": 3,
    "scenarios": [
        {
            "scenario_id": "SCENARIO-01-NORMAL-BASELINE",
            "description": "Legitimate enterprise workday activities across multiple accounts (alice, bob, carol, david, emma, frank, grace, henry) from standard internal IPs.",
            "expected_flag": False,
            "entities": ["alice", "bob", "carol", "david", "emma", "frank", "grace", "henry"]
        },
        {
            "scenario_id": "SCENARIO-02-BRUTE-FORCE-FAILED",
            "description": "Repeated failed login attempts against account 'admin_backup' from suspicious external IP 45.33.32.156 with no breakthrough.",
            "expected_flag": True,
            "expected_rule": "RULE-AUTH-BRUTEFORCE-01",
            "risk_level": "HIGH",
            "intruder_ip": "45.33.32.156",
            "target_user": "admin_backup",
            "event_count": 5
        },
        {
            "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE",
            "description": "Multiple failed logins against account 'sysadmin' followed immediately by successful authentication and subsequent resource navigation from IP 198.51.100.89.",
            "expected_flag": True,
            "expected_rule": "RULE-AUTH-COMPROMISE-02",
            "risk_level": "CRITICAL",
            "intruder_ip": "198.51.100.89",
            "target_user": "sysadmin",
            "event_count": 7
        },
        {
            "scenario_id": "SCENARIO-04-PASSWORD-SPRAYING",
            "description": "Horizontal password spray across multiple distinct employee usernames (finance_lead, dev_ops, hr_manager, qa_lead) originating from single external IP 203.0.113.42.",
            "expected_flag": True,
            "expected_rule": "RULE-AUTH-SPRAY-03",
            "risk_level": "CRITICAL",
            "intruder_ip": "203.0.113.42",
            "targeted_users": ["finance_lead", "dev_ops", "hr_manager", "qa_lead"],
            "event_count": 4
        },
        {
            "scenario_id": "SCENARIO-05-EDGE-CASES",
            "description": "Robustness testing: duplicate event, out-of-order timestamp, missing optional fields (user-agent, resource).",
            "expected_flag": False,
            "note": "Parser and normalizer must gracefully ingest and chronologically order these without crashing."
        }
    ]
}

# The clean, realistic synthetic dataset
LOG_ROWS = [
    # =========================================================================
    # PHASE 1: MORNING NORMAL WORKDAY RUSH (08:00 - 08:45)
    # =========================================================================
    {"timestamp": "2026-10-04 08:00:15", "user": "alice", "source_ip": "192.168.1.10", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:00:45", "user": "alice", "source_ip": "192.168.1.10", "event_type": "file_read", "status": "SUCCESS", "resource": "/dashboard/overview", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:02:10", "user": "alice", "source_ip": "192.168.1.10", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/projects", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:05:00", "user": "bob", "source_ip": "192.168.1.25", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:05:35", "user": "bob", "source_ip": "192.168.1.25", "event_type": "file_read", "status": "SUCCESS", "resource": "/documents/tech_specs.pdf", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:08:12", "user": "carol", "source_ip": "192.168.1.42", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:09:00", "user": "carol", "source_ip": "192.168.1.42", "event_type": "view_page", "status": "SUCCESS", "resource": "/wiki/engineering-guidelines", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:12:30", "user": "frank", "source_ip": "192.168.1.70", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:13:15", "user": "frank", "source_ip": "192.168.1.70", "event_type": "file_read", "status": "SUCCESS", "resource": "/code/repository/main", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:15:00", "user": "grace", "source_ip": "192.168.1.80", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:16:20", "user": "grace", "source_ip": "192.168.1.80", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/metrics/builds", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:20:10", "user": "henry", "source_ip": "192.168.1.90", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:21:05", "user": "henry", "source_ip": "192.168.1.90", "event_type": "file_read", "status": "SUCCESS", "resource": "/design/mockups_v2", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:25:00", "user": "david", "source_ip": "192.168.1.55", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"}, # Normal single typo
    {"timestamp": "2026-10-04 08:25:15", "user": "david", "source_ip": "192.168.1.55", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:26:00", "user": "david", "source_ip": "192.168.1.55", "event_type": "file_read", "status": "SUCCESS", "resource": "/reports/weekly_status", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:30:00", "user": "emma", "source_ip": "192.168.1.60", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:31:15", "user": "emma", "source_ip": "192.168.1.60", "event_type": "file_read", "status": "SUCCESS", "resource": "/marketing/assets", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:35:10", "user": "alice", "source_ip": "192.168.1.10", "event_type": "file_write", "status": "SUCCESS", "resource": "/dashboard/updates", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:38:40", "user": "bob", "source_ip": "192.168.1.25", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/tasks", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:42:15", "user": "carol", "source_ip": "192.168.1.42", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/calendar", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},

    # =========================================================================
    # INCIDENT 1: HORIZONTAL PASSWORD SPRAY FROM 203.0.113.42 (08:45:00 - 08:45:30)
    # =========================================================================
    {"timestamp": "2026-10-04 08:45:01", "user": "finance_lead", "source_ip": "203.0.113.42", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-04-PASSWORD-SPRAYING"},
    {"timestamp": "2026-10-04 08:45:08", "user": "dev_ops", "source_ip": "203.0.113.42", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-04-PASSWORD-SPRAYING"},
    {"timestamp": "2026-10-04 08:45:15", "user": "hr_manager", "source_ip": "203.0.113.42", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-04-PASSWORD-SPRAYING"},
    {"timestamp": "2026-10-04 08:45:22", "user": "qa_lead", "source_ip": "203.0.113.42", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-04-PASSWORD-SPRAYING"},

    # =========================================================================
    # PHASE 2: MID-MORNING ENTERPRISE WORKFLOW (08:46 - 09:04)
    # =========================================================================
    {"timestamp": "2026-10-04 08:48:00", "user": "frank", "source_ip": "192.168.1.70", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/pull_requests", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:50:30", "user": "grace", "source_ip": "192.168.1.80", "event_type": "file_write", "status": "SUCCESS", "resource": "/ci/pipeline/configs", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:52:10", "user": "henry", "source_ip": "192.168.1.90", "event_type": "view_page", "status": "SUCCESS", "resource": "/design/library/tokens", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:55:00", "user": "alice", "source_ip": "192.168.1.10", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/messages", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 08:58:20", "user": "bob", "source_ip": "192.168.1.25", "event_type": "file_read", "status": "SUCCESS", "resource": "/documents/meeting_notes.docx", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:00:15", "user": "carol", "source_ip": "192.168.1.42", "event_type": "file_read", "status": "SUCCESS", "resource": "/dashboard/stats", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:02:40", "user": "david", "source_ip": "192.168.1.55", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/issues/assigned", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},

    # =========================================================================
    # INCIDENT 2: BRUTE FORCE ATTEMPTS AGAINST admin_backup FROM 45.33.32.156 (09:05:00 - 09:05:20)
    # =========================================================================
    {"timestamp": "2026-10-04 09:05:01", "user": "admin_backup", "source_ip": "45.33.32.156", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-02-BRUTE-FORCE-FAILED"},
    {"timestamp": "2026-10-04 09:05:04", "user": "admin_backup", "source_ip": "45.33.32.156", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-02-BRUTE-FORCE-FAILED"},
    {"timestamp": "2026-10-04 09:05:08", "user": "admin_backup", "source_ip": "45.33.32.156", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-02-BRUTE-FORCE-FAILED"},
    {"timestamp": "2026-10-04 09:05:12", "user": "admin_backup", "source_ip": "45.33.32.156", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-02-BRUTE-FORCE-FAILED"},
    {"timestamp": "2026-10-04 09:05:17", "user": "admin_backup", "source_ip": "45.33.32.156", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-02-BRUTE-FORCE-FAILED"},

    # =========================================================================
    # PHASE 3: NORMAL TEAM COLLABORATION (09:08 - 09:24)
    # =========================================================================
    {"timestamp": "2026-10-04 09:08:10", "user": "emma", "source_ip": "192.168.1.60", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/campaigns/active", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:10:00", "user": "frank", "source_ip": "192.168.1.70", "event_type": "file_write", "status": "SUCCESS", "resource": "/code/branches/feature-x", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:12:30", "user": "alice", "source_ip": "192.168.1.10", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/tasks", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:14:00", "user": "grace", "source_ip": "192.168.1.80", "event_type": "view_page", "status": "SUCCESS", "resource": "/ci/dashboard/runners", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:15:10", "user": "bob", "source_ip": "192.168.1.25", "event_type": "file_write", "status": "SUCCESS", "resource": "/documents/tech_specs.pdf", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:17:25", "user": "henry", "source_ip": "192.168.1.90", "event_type": "file_read", "status": "SUCCESS", "resource": "/design/components/header", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:18:00", "user": "carol", "source_ip": "192.168.1.42", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/notifications", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:20:15", "user": "david", "source_ip": "192.168.1.55", "event_type": "file_read", "status": "SUCCESS", "resource": "/reports/q3_summary", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:22:45", "user": "emma", "source_ip": "192.168.1.60", "event_type": "file_read", "status": "SUCCESS", "resource": "/marketing/press_kit", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},

    # =========================================================================
    # INCIDENT 3: MULTI-STAGE CREDENTIAL COMPROMISE AGAINST sysadmin FROM 198.51.100.89 (09:25:00 - 09:27:00)
    # =========================================================================
    {"timestamp": "2026-10-04 09:25:10", "user": "sysadmin", "source_ip": "198.51.100.89", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE"},
    {"timestamp": "2026-10-04 09:25:16", "user": "sysadmin", "source_ip": "198.51.100.89", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE"},
    {"timestamp": "2026-10-04 09:25:22", "user": "sysadmin", "source_ip": "198.51.100.89", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE"},
    {"timestamp": "2026-10-04 09:25:29", "user": "sysadmin", "source_ip": "198.51.100.89", "event_type": "login_failed", "status": "FAILED", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE"},
    {"timestamp": "2026-10-04 09:25:48", "user": "sysadmin", "source_ip": "198.51.100.89", "event_type": "login_success", "status": "SUCCESS", "resource": "/api/v1/auth/login", "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE"},
    {"timestamp": "2026-10-04 09:26:15", "user": "sysadmin", "source_ip": "198.51.100.89", "event_type": "view_dashboard", "status": "SUCCESS", "resource": "/admin/dashboard", "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE"},
    {"timestamp": "2026-10-04 09:26:40", "user": "sysadmin", "source_ip": "198.51.100.89", "event_type": "view_settings", "status": "SUCCESS", "resource": "/admin/system-settings", "scenario_id": "SCENARIO-03-CREDENTIAL-COMPROMISE"},

    # =========================================================================
    # PHASE 4: EXTENDED NORMAL ENTERPRISE WORKFLOW (09:28 - 10:15)
    # =========================================================================
    {"timestamp": "2026-10-04 09:28:10", "user": "alice", "source_ip": "192.168.1.10", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/projects/active", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:30:00", "user": "alice", "source_ip": "192.168.1.10", "event_type": "file_read", "status": "SUCCESS", "resource": "/dashboard/reports", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:32:15", "user": "frank", "source_ip": "192.168.1.70", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/git/commit_history", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:35:12", "user": "emma", "source_ip": "192.168.1.60", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/messages", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:37:45", "user": "bob", "source_ip": "192.168.1.25", "event_type": "file_read", "status": "SUCCESS", "resource": "/dashboard/analytics", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:40:00", "user": "david", "source_ip": "192.168.1.55", "event_type": "file_read", "status": "SUCCESS", "resource": "/dashboard/calendar", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:42:30", "user": "grace", "source_ip": "192.168.1.80", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/metrics/coverage", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:45:00", "user": "henry", "source_ip": "192.168.1.90", "event_type": "file_write", "status": "SUCCESS", "resource": "/design/tokens/dark_theme.json", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:47:15", "user": "carol", "source_ip": "192.168.1.42", "event_type": "view_page", "status": "SUCCESS", "resource": "/wiki/security_policy", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:50:00", "user": "frank", "source_ip": "192.168.1.70", "event_type": "file_read", "status": "SUCCESS", "resource": "/code/tests/unit_tests", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:52:40", "user": "bob", "source_ip": "192.168.1.25", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/sync", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:55:10", "user": "alice", "source_ip": "192.168.1.10", "event_type": "file_read", "status": "SUCCESS", "resource": "/dashboard/feed", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 09:58:00", "user": "david", "source_ip": "192.168.1.55", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/audit/my_logs", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 10:00:20", "user": "emma", "source_ip": "192.168.1.60", "event_type": "view_page", "status": "SUCCESS", "resource": "/marketing/leads", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 10:03:45", "user": "grace", "source_ip": "192.168.1.80", "event_type": "file_read", "status": "SUCCESS", "resource": "/ci/logs/build-1049", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 10:06:15", "user": "henry", "source_ip": "192.168.1.90", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/components/export", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 10:08:30", "user": "carol", "source_ip": "192.168.1.42", "event_type": "file_write", "status": "SUCCESS", "resource": "/wiki/notes_2026.md", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 10:10:00", "user": "frank", "source_ip": "192.168.1.70", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/notifications", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 10:12:15", "user": "alice", "source_ip": "192.168.1.10", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/ping", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},
    {"timestamp": "2026-10-04 10:15:00", "user": "bob", "source_ip": "192.168.1.25", "event_type": "file_read", "status": "SUCCESS", "resource": "/documents/roadmap.pdf", "scenario_id": "SCENARIO-01-NORMAL-BASELINE"},

    # =========================================================================
    # PHASE 5: EDGE CASES (Out-of-order, Duplicate, Missing optional)
    # =========================================================================
    # Out of order timestamp (earlier timestamp occurring later in ingestion)
    {"timestamp": "2026-10-04 08:32:00", "user": "alice", "source_ip": "192.168.1.10", "event_type": "query", "status": "SUCCESS", "resource": "/api/v1/ping", "scenario_id": "SCENARIO-05-EDGE-CASES"},
    # Duplicate event
    {"timestamp": "2026-10-04 09:40:00", "user": "david", "source_ip": "192.168.1.55", "event_type": "file_read", "status": "SUCCESS", "resource": "/dashboard/calendar", "scenario_id": "SCENARIO-05-EDGE-CASES"},
    # Missing resource field (handled gracefully)
    {"timestamp": "2026-10-04 10:18:00", "user": "carol", "source_ip": "192.168.1.42", "event_type": "heartbeat", "status": "SUCCESS", "resource": "", "scenario_id": "SCENARIO-05-EDGE-CASES"}
]


def generate_files():
    # 1. Generate clean CSV for CyberShield ingestion
    csv_path = DATA_DIR / "sample_security_logs.csv"
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("timestamp,source_ip,username,action,status,status_code,resource,user_agent\n")
        for row in LOG_ROWS:
            code = 200 if row["status"] == "SUCCESS" else 401
            res = row["resource"] if row["resource"] else "/"
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" if "192.168" in row["source_ip"] else "Mozilla/5.0 (X11; Linux x86_64)"
            f.write(f'{row["timestamp"]},{row["source_ip"]},{row["user"]},{row["event_type"]},{row["status"]},{code},{res},{ua}\n')

    # 2. Generate JSON version with same data
    json_path = DATA_DIR / "sample_security_logs.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json_rows = []
        for row in LOG_ROWS:
            code = 200 if row["status"] == "SUCCESS" else 401
            json_rows.append({
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "username": row["user"],
                "action": row["event_type"],
                "status": row["status"],
                "status_code": code,
                "resource": row["resource"] or "/",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" if "192.168" in row["source_ip"] else "Mozilla/5.0 (X11; Linux x86_64)"
            })
        json.dump(json_rows, f, indent=2)

    # 3. Update ground truth metadata
    GROUND_TRUTH["total_events"] = len(LOG_ROWS)
    suspicious_count = sum(1 for r in LOG_ROWS if r.get("scenario_id") in [
        "SCENARIO-02-BRUTE-FORCE-FAILED",
        "SCENARIO-03-CREDENTIAL-COMPROMISE",
        "SCENARIO-04-PASSWORD-SPRAYING"
    ])
    GROUND_TRUTH["suspicious_events"] = suspicious_count
    GROUND_TRUTH["normal_events"] = len(LOG_ROWS) - suspicious_count
    GROUND_TRUTH["suspicious_percentage"] = round((suspicious_count / len(LOG_ROWS)) * 100, 1)

    gt_path = DATA_DIR / "ground_truth.json"
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(GROUND_TRUTH, f, indent=2)

    print(f"Generated: {csv_path} ({len(LOG_ROWS)} rows)")
    print(f"Generated: {json_path}")
    print(f"Generated: {gt_path}")
    print(f"Stats: {len(LOG_ROWS)} Total | {suspicious_count} Suspicious ({GROUND_TRUTH['suspicious_percentage']}%) | {GROUND_TRUTH['normal_events']} Normal ({round(100 - GROUND_TRUTH['suspicious_percentage'], 1)}%)")


if __name__ == "__main__":
    generate_files()
