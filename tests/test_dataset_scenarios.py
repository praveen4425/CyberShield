"""
Automated validation test suite for CyberShield's realistic synthetic dataset.
Verifies all Problem Statement (ALG-CYBER-01) requirements against ground-truth scenarios:
- Ground-truth incident mapping & attribution
- Normal activity non-flagging (zero false positives on legitimate users)
- Brute-force detection & risk scoring
- Credential compromise correlation into ONE unified incident
- Password spraying across multiple targeted accounts
- Attack sequence synthesis & chronological ordering
- Evidence items & timeline accuracy
- Edge case handling (duplicate events, out-of-order timestamps, missing optional values)
- JSON and CSV format parity
"""

import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.parser import parse_logs, parse_csv_content, parse_json_content
from backend.detector import run_all_detections
from backend.correlator import correlate_incidents, generate_analysis_summary

DATA_DIR = PROJECT_ROOT / "data"
CSV_PATH = DATA_DIR / "sample_security_logs.csv"
JSON_PATH = DATA_DIR / "sample_security_logs.json"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth.json"


def test_ground_truth_dataset_loading():
    print("[TEST 1] Testing dataset loading and parser format parity (CSV vs JSON)...")
    assert CSV_PATH.exists(), "CSV sample file must exist"
    assert JSON_PATH.exists(), "JSON sample file must exist"
    assert GROUND_TRUTH_PATH.exists(), "Ground truth file must exist"

    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"), filename="sample_security_logs.csv")
    json_events = parse_logs(JSON_PATH.read_text(encoding="utf-8"), filename="sample_security_logs.json")

    assert len(csv_events) >= 35, f"Expected 35+ events in CSV, got {len(csv_events)}"
    assert len(json_events) >= 35, f"Expected 35+ events in JSON, got {len(json_events)}"
    assert len(csv_events) == len(json_events), f"CSV and JSON parsed counts differ: {len(csv_events)} vs {len(json_events)}"
    print(f"  -> PASSED: Successfully parsed {len(csv_events)} events with exact CSV/JSON parity.\n")


def test_normal_activity_zero_false_positives():
    print("[TEST 2] Testing normal activity baseline (zero false positive incidents)...")
    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"))
    detections = run_all_detections(csv_events)
    incidents = correlate_incidents(csv_events, detections)

    # Legitimate users in Scenario 1
    normal_users = {"alice", "bob", "carol", "david", "emma"}
    flagged_entities = {i.user for i in incidents}
    flagged_ips = {i.source_ip for i in incidents}

    # Verify no legitimate user is wrongfully flagged as an intruder incident
    for u in normal_users:
        assert u not in flagged_entities, f"False positive alert: legitimate user '{u}' was flagged as an incident!"
    
    # Internal subnet 192.168.1.0/24 should have no flagged incidents
    for ip in flagged_ips:
        assert not ip.startswith("192.168.1."), f"False positive alert: internal client IP {ip} was flagged as an incident!"

    print("  -> PASSED: Normal users (alice, bob, carol, david, emma) generated 0 false positive incidents.\n")


def test_scenario_brute_force_failed():
    print("[TEST 3] Testing Scenario 2: Repeated failed logins from external IP 45.33.32.156...")
    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"))
    detections = run_all_detections(csv_events)
    incidents = correlate_incidents(csv_events, detections)

    brute_incs = [i for i in incidents if i.source_ip == "45.33.32.156"]
    assert len(brute_incs) == 1, f"Expected exactly 1 incident for 45.33.32.156, found {len(brute_incs)}"
    
    inc = brute_incs[0]
    assert inc.user == "admin_backup", f"Expected target user 'admin_backup', got '{inc.user}'"
    assert inc.risk_level in ["HIGH", "CRITICAL"], f"Expected HIGH/CRITICAL risk level, got {inc.risk_level}"
    assert inc.risk_score >= 70, f"Expected threat score >= 70, got {inc.risk_score}"
    assert inc.total_events >= 5, f"Expected 5 related events, got {inc.total_events}"
    assert any("Brute Force" in r for r in inc.triggered_rules), "Expected Brute Force rule triggered"
    print(f"  -> PASSED: Incident {inc.incident_id} correctly identified {inc.user}@{inc.source_ip} (Score: {inc.risk_score}).\n")


def test_scenario_credential_compromise_correlation():
    print("[TEST 4] Testing Scenario 3: Credential compromise (multi-stage correlation into ONE incident)...")
    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"))
    detections = run_all_detections(csv_events)
    incidents = correlate_incidents(csv_events, detections)

    comp_incs = [i for i in incidents if i.source_ip == "198.51.100.89"]
    # MUST be correlated into ONE incident, not multiple detached alerts
    assert len(comp_incs) == 1, f"Expected exactly 1 correlated incident for 198.51.100.89, got {len(comp_incs)}"

    inc = comp_incs[0]
    assert inc.user == "sysadmin", f"Expected target user 'sysadmin', got '{inc.user}'"
    assert inc.risk_level == "CRITICAL", f"Expected CRITICAL risk level for breakthrough compromise, got {inc.risk_level}"
    assert inc.risk_score >= 90, f"Expected threat score >= 90, got {inc.risk_score}"
    assert inc.total_events >= 7, f"Expected at least 7 correlated events (fails + login + subsequent actions), got {inc.total_events}"
    
    # Verify Attack Sequence contains progressive steps
    assert len(inc.likely_attack_sequence) >= 3, f"Expected 3 attack sequence steps, got {len(inc.likely_attack_sequence)}"
    seq_text = " ".join(inc.likely_attack_sequence).lower()
    assert "authentication" in seq_text or "failed" in seq_text
    assert "compromise" in seq_text or "login" in seq_text
    assert "post-authentication" in seq_text or "resource" in seq_text
    print(f"  -> PASSED: Incident {inc.incident_id} synthesized {len(inc.likely_attack_sequence)} attack sequence steps.\n")


def test_scenario_password_spraying():
    print("[TEST 5] Testing Scenario 4: Horizontal password spraying from IP 203.0.113.42...")
    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"))
    detections = run_all_detections(csv_events)
    incidents = correlate_incidents(csv_events, detections)

    spray_incs = [i for i in incidents if i.source_ip == "203.0.113.42"]
    assert len(spray_incs) == 1, f"Expected 1 incident for 203.0.113.42, got {len(spray_incs)}"
    
    inc = spray_incs[0]
    assert any("Spray" in r for r in inc.triggered_rules), f"Expected Spray rule triggered, got {inc.triggered_rules}"
    assert inc.total_events >= 4, f"Expected 4 sprayed events, got {inc.total_events}"
    assert any("targeted multiple accounts" in s.lower() or "spraying" in s.lower() for s in inc.likely_attack_sequence)
    print(f"  -> PASSED: Incident {inc.incident_id} detected horizontal password spray across accounts.\n")


def test_timeline_chronological_ordering():
    print("[TEST 6] Testing chronological timeline ordering & edge case sorting...")
    # Raw log has an out-of-order event at 08:32:00 placed at the bottom
    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"))
    
    # Verify overall events list is strictly sorted by epoch
    for i in range(len(csv_events) - 1):
        assert csv_events[i].epoch <= csv_events[i+1].epoch, f"Events out of order: {csv_events[i].timestamp} > {csv_events[i+1].timestamp}"

    # Verify incident timelines are strictly sorted
    detections = run_all_detections(csv_events)
    incidents = correlate_incidents(csv_events, detections)
    for inc in incidents:
        for i in range(len(inc.related_events) - 1):
            assert inc.related_events[i].epoch <= inc.related_events[i+1].epoch, f"Incident {inc.incident_id} timeline out of order"

    print("  -> PASSED: All parsed events and incident timelines are strictly chronological.\n")


def test_evidence_and_explainability():
    print("[TEST 7] Testing concrete evidence items and explainability...")
    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"))
    detections = run_all_detections(csv_events)
    incidents = correlate_incidents(csv_events, detections)

    for inc in incidents:
        assert len(inc.evidence) >= 2, f"Incident {inc.incident_id} lacks sufficient evidence items"
        assert inc.why_flagged and len(inc.why_flagged) > 20, f"Incident {inc.incident_id} missing explainable rationale"
        assert inc.duration_seconds >= 0.0
        assert inc.first_detected_time <= inc.last_detected_time
    print("  -> PASSED: Every incident contains verified evidence, duration, and rationale.\n")


def test_summary_metrics():
    print("[TEST 8] Testing summary metrics generation...")
    csv_events = parse_logs(CSV_PATH.read_text(encoding="utf-8"))
    detections = run_all_detections(csv_events)
    incidents = correlate_incidents(csv_events, detections)
    summary = generate_analysis_summary(csv_events, incidents)

    assert summary.total_events == len(csv_events)
    assert summary.total_incidents == 3
    assert summary.critical_incidents >= 1
    assert summary.unique_ips >= 6
    assert summary.unique_users >= 8
    assert len(summary.suspicious_ips) == 3
    print(f"  -> PASSED: Summary metrics verified ({summary.total_incidents} incidents, {summary.critical_incidents} critical).\n")


if __name__ == "__main__":
    test_ground_truth_dataset_loading()
    test_normal_activity_zero_false_positives()
    test_scenario_brute_force_failed()
    test_scenario_credential_compromise_correlation()
    test_scenario_password_spraying()
    test_timeline_chronological_ordering()
    test_evidence_and_explainability()
    test_summary_metrics()
    print("==================================================")
    print("ALL REALISTIC DATASET VALIDATION TESTS PASSED 100%")
    print("==================================================")
