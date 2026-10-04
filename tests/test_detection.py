"""
Automated validation tests for CyberShield.
Tests Problem Statement requirements:
TEST 1: Normal login activity -> no false high-risk incident
TEST 2: Repeated failed logins -> brute force detected
TEST 3: Failed logins followed by successful login -> high/critical compromise incident
TEST 4: Related suspicious events -> grouped into one incident
TEST 5: Incident detail -> evidence and timeline correctly displayed
TEST 6: Empty/invalid log file -> graceful error handling
TEST 7: Multiple users/IPs -> correct attribution
TEST 8: Pre-packaged sample log file -> end-to-end integration
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.parser import parse_logs
from backend.detector import run_all_detections
from backend.correlator import correlate_incidents, generate_analysis_summary


def test_1_normal_traffic():
    print("[TEST 1] Testing normal login activity (No false positive high incidents)...")
    csv_data = """timestamp,source_ip,username,action,status,status_code,resource,user_agent
2026-10-04 10:00:00,192.168.1.50,john,login_success,SUCCESS,200,/api/v1/auth/login,Chrome/120.0
2026-10-04 10:05:00,192.168.1.50,john,file_read,SUCCESS,200,/dashboard,Chrome/120.0
2026-10-04 10:10:00,192.168.1.51,sarah,login_success,SUCCESS,200,/api/v1/auth/login,Firefox/115.0
"""
    events = parse_logs(csv_data)
    detections = run_all_detections(events)
    incidents = correlate_incidents(events, detections)
    
    assert len(incidents) == 0, f"Expected 0 incidents for normal traffic, got {len(incidents)}"
    print("  -> PASSED: Normal traffic produced 0 alerts.\n")


def test_2_brute_force():
    print("[TEST 2] Testing repeated failed logins (Brute force detection)...")
    csv_data = """timestamp,source_ip,username,action,status,status_code,resource,user_agent
2026-10-04 11:00:01,10.0.0.99,admin,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 11:00:03,10.0.0.99,admin,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 11:00:05,10.0.0.99,admin,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 11:00:07,10.0.0.99,admin,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
"""
    events = parse_logs(csv_data)
    detections = run_all_detections(events)
    incidents = correlate_incidents(events, detections)
    
    assert len(incidents) == 1, f"Expected 1 incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc.source_ip == "10.0.0.99"
    assert inc.user == "admin"
    assert any("Brute Force" in r for r in inc.triggered_rules)
    print(f"  -> PASSED: Detected {inc.title} with risk score {inc.risk_score}.\n")


def test_3_failed_then_success():
    print("[TEST 3] Testing failed logins followed by successful login (Credential Compromise)...")
    csv_data = """timestamp,source_ip,username,action,status,status_code,resource,user_agent
2026-10-04 12:00:01,172.16.0.4,victim_user,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 12:00:03,172.16.0.4,victim_user,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 12:00:06,172.16.0.4,victim_user,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 12:00:15,172.16.0.4,victim_user,login_success,SUCCESS,200,/api/v1/auth/login,Mozilla/5.0
"""
    events = parse_logs(csv_data)
    detections = run_all_detections(events)
    incidents = correlate_incidents(events, detections)
    
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc.risk_level in ["HIGH", "CRITICAL"], f"Expected HIGH/CRITICAL, got {inc.risk_level}"
    assert any("Followed by Successful" in r for r in inc.triggered_rules)
    print(f"  -> PASSED: Compromise flagged as {inc.risk_level} (Score {inc.risk_score}).\n")


def test_4_event_correlation_and_attack_sequence():
    print("[TEST 4] Testing event correlation across multiple stages into ONE incident...")
    csv_data = """timestamp,source_ip,username,action,status,status_code,resource,user_agent
2026-10-04 14:00:00,185.220.101.5,root,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 14:00:02,185.220.101.5,root,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 14:00:04,185.220.101.5,root,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 14:00:10,185.220.101.5,root,login_success,SUCCESS,200,/api/v1/auth/login,Mozilla/5.0
2026-10-04 14:00:20,185.220.101.5,root,view_dashboard,SUCCESS,200,/admin/dashboard,Mozilla/5.0
2026-10-04 14:00:30,185.220.101.5,root,modify_account,SUCCESS,200,/admin/account,Mozilla/5.0
"""
    events = parse_logs(csv_data)
    detections = run_all_detections(events)
    incidents = correlate_incidents(events, detections)
    
    # Must be grouped into ONE correlated incident
    assert len(incidents) == 1, f"Expected 1 correlated incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc.total_events == 6
    assert inc.risk_level == "CRITICAL"
    assert len(inc.likely_attack_sequence) >= 2, f"Attack sequence too short: {inc.likely_attack_sequence}"
    print(f"  -> PASSED: Correlated 6 events into 1 Incident with {len(inc.likely_attack_sequence)} attack sequence steps.\n")


def test_5_incident_evidence_and_timeline():
    print("[TEST 5] Testing evidence items and timeline display...")
    csv_data = """timestamp,source_ip,username,action,status,status_code,resource,user_agent
2026-10-04 15:00:00,1.2.3.4,target_acc,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 15:00:05,1.2.3.4,target_acc,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 15:00:10,1.2.3.4,target_acc,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
"""
    events = parse_logs(csv_data)
    detections = run_all_detections(events)
    incidents = correlate_incidents(events, detections)
    
    inc = incidents[0]
    assert len(inc.evidence) > 0, "Evidence list must not be empty"
    assert inc.first_detected_time == "2026-10-04 15:00:00"
    assert inc.last_detected_time == "2026-10-04 15:00:10"
    print(f"  -> PASSED: Evidence count: {len(inc.evidence)}, Timeline: {inc.first_detected_time} -> {inc.last_detected_time}.\n")


def test_6_empty_and_malformed():
    print("[TEST 6] Testing empty and malformed logs (graceful handling)...")
    empty_events = parse_logs("")
    assert len(empty_events) == 0
    
    malformed = """junk line without commas
,,,,,,,,,
another bad row with missing columns
"""
    malformed_events = parse_logs(malformed)
    # Should not crash and return gracefully
    assert isinstance(malformed_events, list)
    print("  -> PASSED: Handled empty and malformed content cleanly without crashing.\n")


def test_7_multiple_entities_attribution():
    print("[TEST 7] Testing multiple users and IPs correct attribution...")
    csv_data = """timestamp,source_ip,username,action,status,status_code,resource,user_agent
2026-10-04 16:00:00,192.168.10.1,userA,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 16:00:01,192.168.10.1,userA,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 16:00:02,192.168.10.1,userA,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 16:01:00,10.20.30.40,userB,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 16:01:01,10.20.30.40,userB,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
2026-10-04 16:01:02,10.20.30.40,userB,login_failed,FAILED,401,/api/v1/auth/login,Mozilla/5.0
"""
    events = parse_logs(csv_data)
    detections = run_all_detections(events)
    incidents = correlate_incidents(events, detections)
    
    assert len(incidents) == 2, f"Expected 2 separate incidents for 2 distinct IPs/users, got {len(incidents)}"
    ips = {i.source_ip for i in incidents}
    assert "192.168.10.1" in ips and "10.20.30.40" in ips
    print(f"  -> PASSED: Correctly separated incidents for entities: {ips}.\n")


def test_8_sample_data_file():
    print("[TEST 8] Testing pre-packaged sample_security_logs.csv file...")
    sample_path = PROJECT_ROOT / "data" / "sample_security_logs.csv"
    with open(sample_path, "r", encoding="utf-8") as f:
        content = f.read()
    events = parse_logs(content)
    assert len(events) >= 20, f"Expected 20+ events, got {len(events)}"
    
    detections = run_all_detections(events)
    incidents = correlate_incidents(events, detections)
    summary = generate_analysis_summary(events, incidents)
    
    assert summary.total_incidents >= 2
    assert summary.critical_incidents >= 1
    print(f"  -> PASSED: Sample logs yielded {summary.total_incidents} incidents ({summary.critical_incidents} CRITICAL).")


if __name__ == "__main__":
    test_1_normal_traffic()
    test_2_brute_force()
    test_3_failed_then_success()
    test_4_event_correlation_and_attack_sequence()
    test_5_incident_evidence_and_timeline()
    test_6_empty_and_malformed()
    test_7_multiple_entities_attribution()
    test_8_sample_data_file()
    print("==================================================")
    print("ALL 8 VERIFICATION TESTS PASSED SUCCESSFULLY! 100%")
    print("==================================================")
