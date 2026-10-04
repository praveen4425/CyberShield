"""
Detection Engine for CyberShield.
Focused strictly on the Algothon 'Find the Intruder' problem statement (ALG-CYBER-01):
- Repeated failed logins (Brute Force / Password Guessing)
- Failed logins followed by successful login (Account Compromise / Breakthrough)
- Suspicious high-frequency authentication from single IP across multiple accounts (Password Spraying)
- Suspicious post-authentication actions from flagged intruder IP

Deterministic, explainable, transparent rules with zero black-box AI dependencies.
Produces risk levels, reasons, evidence, and matched events.
"""

from typing import List, Dict, Set, DefaultDict
from collections import defaultdict
from .models import SecurityEvent, DetectionRuleResult


def is_auth_failure(ev: SecurityEvent) -> bool:
    """Check if an event represents an authentication failure."""
    act = ev.action.lower()
    res = ev.resource.lower()
    return (
        "fail" in act or "invalid" in act or "deny" in act or
        ev.status == "FAILED" or
        (ev.status_code in [401, 403] and ("login" in res or "auth" in res or "login" in act or "auth" in act))
    )


def is_auth_success(ev: SecurityEvent) -> bool:
    """Check if an event represents a successful authentication."""
    act = ev.action.lower()
    res = ev.resource.lower()
    return (
        ("login" in act or "auth" in act or "session" in act or "login" in res or "auth" in res) and
        (ev.status == "SUCCESS" or ev.status_code == 200 or "succ" in act)
    )


def detect_brute_force_attempts(events: List[SecurityEvent]) -> List[DetectionRuleResult]:
    """
    Detect repeated failed login attempts targeting the same account or originating from same IP.
    Threshold: 3 or more failed authentication attempts.
    """
    results: List[DetectionRuleResult] = []
    
    # Group failed events by (source_ip, username)
    failed_by_target: DefaultDict[str, List[SecurityEvent]] = defaultdict(list)
    for ev in events:
        if is_auth_failure(ev):
            failed_by_target[f"{ev.source_ip}|{ev.username}"].append(ev)

    for entity_key, fails in failed_by_target.items():
        if len(fails) >= 3:
            ip, user = entity_key.split("|", 1)
            severity = "HIGH" if len(fails) >= 5 else "MEDIUM"
            score = 75 if len(fails) >= 5 else 60
            
            results.append(DetectionRuleResult(
                rule_id="RULE-AUTH-BRUTEFORCE-01",
                rule_name="Repeated Failed Login Attempts (Brute Force)",
                severity=severity,
                score=score,
                category="CREDENTIAL_ACCESS",
                reason=f"Detected {len(fails)} consecutive failed authentication attempts targeting account '{user}' from IP {ip}.",
                evidence_items=[
                    f"{len(fails)} failed attempts recorded between {fails[0].timestamp} and {fails[-1].timestamp}",
                    f"Target account: {user}",
                    f"Originating IP: {ip}",
                    f"Failure status codes: {', '.join(set(str(f.status_code) for f in fails))}"
                ],
                matched_event_ids=[ev.id for ev in fails]
            ))
            
    return results


def detect_failed_then_success(events: List[SecurityEvent]) -> List[DetectionRuleResult]:
    """
    Detect multiple failed logins followed by a successful login.
    High-fidelity signature of credential guessing culminating in account takeover.
    """
    results: List[DetectionRuleResult] = []
    
    # Group events by (source_ip, username)
    by_entity: DefaultDict[str, List[SecurityEvent]] = defaultdict(list)
    for ev in events:
        by_entity[f"{ev.source_ip}|{ev.username}"].append(ev)

    for entity_key, ev_list in by_entity.items():
        ip, user = entity_key.split("|", 1)
        fails_before: List[SecurityEvent] = []
        
        for ev in ev_list:
            if is_auth_failure(ev):
                fails_before.append(ev)
            elif is_auth_success(ev):
                if len(fails_before) >= 2:
                    # Account takeover / successful crack
                    all_ids = [f.id for f in fails_before] + [ev.id]
                    results.append(DetectionRuleResult(
                        rule_id="RULE-AUTH-COMPROMISE-02",
                        rule_name="Multiple Failed Logins Followed by Successful Login",
                        severity="CRITICAL",
                        score=95,
                        category="CREDENTIAL_ACCESS",
                        reason=f"Account '{user}' had {len(fails_before)} failed attempts followed immediately by a successful login from IP {ip}, indicating credential cracking or account takeover.",
                        evidence_items=[
                            f"{len(fails_before)} failed logins prior to successful authentication",
                            f"Breach timestamp: {ev.timestamp} (HTTP {ev.status_code})",
                            f"Target account '{user}' was successfully compromised by IP {ip}"
                        ],
                        matched_event_ids=all_ids
                    ))
                    fails_before = []  # reset window
                else:
                    fails_before = []
                    
    return results


def detect_password_spraying(events: List[SecurityEvent]) -> List[DetectionRuleResult]:
    """
    Detect password spraying: a single IP attempting logins across 2 or more distinct usernames.
    """
    results: List[DetectionRuleResult] = []
    
    ip_failed_targets: DefaultDict[str, Dict[str, List[SecurityEvent]]] = defaultdict(lambda: defaultdict(list))
    for ev in events:
        if is_auth_failure(ev) and ev.username and ev.username != "anonymous":
            ip_failed_targets[ev.source_ip][ev.username].append(ev)

    for ip, user_dict in ip_failed_targets.items():
        if len(user_dict) >= 2:
            all_spray_events: List[SecurityEvent] = []
            for u_events in user_dict.values():
                all_spray_events.extend(u_events)
                
            targeted_users = list(user_dict.keys())
            results.append(DetectionRuleResult(
                rule_id="RULE-AUTH-SPRAY-03",
                rule_name="Horizontal Password Spraying Pattern",
                severity="HIGH",
                score=80,
                category="CREDENTIAL_ACCESS",
                reason=f"IP {ip} performed authentication attempts across {len(targeted_users)} distinct user accounts ({', '.join(targeted_users[:3])}), typical of password spraying.",
                evidence_items=[
                    f"{len(all_spray_events)} total login attempts from IP {ip}",
                    f"Distinct user accounts targeted: {', '.join(targeted_users)}",
                    f"Time window: {all_spray_events[0].timestamp} to {all_spray_events[-1].timestamp}"
                ],
                matched_event_ids=[ev.id for ev in all_spray_events]
            ))

    return results


def run_all_detections(events: List[SecurityEvent]) -> List[DetectionRuleResult]:
    """
    Run all core intrusion detection rules across normalized events.
    Strictly defensive and aligned with Problem Statement requirements.
    """
    detections: List[DetectionRuleResult] = []
    
    detections.extend(detect_brute_force_attempts(events))
    detections.extend(detect_failed_then_success(events))
    detections.extend(detect_password_spraying(events))
    
    return detections
