"""
Correlation & Incident Engine for CyberShield.
Groups related suspicious events by entity (source IP, targeted user, and temporal proximity).
Builds correlated incidents, synthesizes likely attack sequences, and computes explainable risk scores.
"""

from typing import List, Dict, Set, DefaultDict
from collections import defaultdict
from .models import SecurityEvent, DetectionRuleResult, CorrelatedIncident, AnalysisSummary
from .detector import is_auth_failure, is_auth_success


def build_attack_sequence(events: List[SecurityEvent], rules: List[DetectionRuleResult]) -> List[str]:
    """
    Construct a logical, step-by-step human-readable attack sequence based on 
    chronological progression of actions and triggered rules.
    Strictly defensive and focused on authentication and intruder behavior.
    """
    sequence: List[str] = []
    
    # Sort events chronologically
    sorted_events = sorted(events, key=lambda e: e.epoch)
    
    failed_logins = [e for e in sorted_events if is_auth_failure(e)]
    success_logins = [e for e in sorted_events if is_auth_success(e)]
    post_auth_actions = [e for e in sorted_events if not is_auth_failure(e) and not is_auth_success(e)]
    
    # Unique accounts targeted
    targeted_accounts = list(dict.fromkeys([e.username for e in failed_logins if e.username and e.username != "anonymous"]))

    step_num = 1
    
    if len(targeted_accounts) >= 2:
        sequence.append(f"Step {step_num}: Account Enumeration / Password Spraying -> Attacker targeted multiple accounts ({', '.join(targeted_accounts[:3])}) from the same origin IP.")
        step_num += 1
    elif failed_logins:
        sequence.append(f"Step {step_num}: Repeated Authentication Attempts -> Attacker initiated {len(failed_logins)} failed login attempt(s) targeting account '{failed_logins[0].username}'.")
        step_num += 1

    if success_logins:
        sequence.append(f"Step {step_num}: Compromise / Successful Login -> Attacker successfully authenticated to account '{success_logins[0].username}' following the failed attempts.")
        step_num += 1

    if post_auth_actions:
        resources_accessed = list(dict.fromkeys([e.resource for e in post_auth_actions]))
        sequence.append(f"Step {step_num}: Post-Authentication Activity -> Authenticated session performed actions across system resources ({', '.join(resources_accessed[:3])}).")
        step_num += 1

    # Fallback if specific stages don't meet thresholds but events are suspicious
    if not sequence:
        sequence.append("Step 1: Anomalous authentication pattern detected violating normal baseline.")
        sequence.append("Step 2: Multiple correlated security events recorded from suspect entity.")
        sequence.append("Step 3: Activity flagged for SOC review and entity containment.")

    return sequence


def correlate_incidents(
    events: List[SecurityEvent], 
    detections: List[DetectionRuleResult]
) -> List[CorrelatedIncident]:
    """
    Correlates individual detection rule results and related raw events into unified Incidents.
    Entities are correlated by (IP + User) and shared time clusters.
    """
    if not detections:
        return []

    # Map event ID to SecurityEvent object
    events_map: Dict[str, SecurityEvent] = {e.id: e for e in events}
    
    # Group detections by entity (IP and/or User)
    entity_detections: DefaultDict[str, List[DetectionRuleResult]] = defaultdict(list)
    for det in detections:
        # Find which IPs/users are in the matched events
        det_events = [events_map[eid] for eid in det.matched_event_ids if eid in events_map]
        if not det_events:
            continue
        
        # Primary entity key: Source IP
        primary_ip = det_events[0].source_ip
        primary_user = next((e.username for e in det_events if e.username and e.username != "anonymous"), det_events[0].username)
        
        # Cluster key
        cluster_key = f"{primary_ip}|{primary_user}"
        entity_detections[cluster_key].append(det)

    incidents: List[CorrelatedIncident] = []
    inc_counter = 1

    for entity_key, rule_results in entity_detections.items():
        ip, user = entity_key.split("|", 1)
        
        # Collect all related events for this cluster
        matched_event_ids: Set[str] = set()
        for r in rule_results:
            matched_event_ids.update(r.matched_event_ids)
            
        cluster_events = [events_map[eid] for eid in matched_event_ids if eid in events_map]
        
        # ALSO pull in nearby contextual events from the same IP or user
        # (provides full timeline context)
        context_events = [
            e for e in events 
            if (e.source_ip == ip or (e.username == user and user != "anonymous"))
            and e.id not in matched_event_ids
        ]
        all_related_events = sorted(cluster_events + context_events, key=lambda x: x.epoch)
        
        first_time = all_related_events[0].timestamp if all_related_events else "N/A"
        last_time = all_related_events[-1].timestamp if all_related_events else "N/A"
        duration_sec = (all_related_events[-1].epoch - all_related_events[0].epoch) if all_related_events else 0.0

        # Calculate composite risk score
        max_score = max((r.score for r in rule_results), default=50)
        # Bonus weight for multi-stage attacks (correlation adds confidence)
        multi_rule_boost = min(len(rule_results) * 5, 20)
        final_score = min(max_score + multi_rule_boost, 100)
        
        if final_score >= 85:
            risk_level = "CRITICAL"
        elif final_score >= 70:
            risk_level = "HIGH"
        elif final_score >= 45:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Synthesize Why Flagged & Evidence
        why_parts = [r.reason for r in rule_results]
        why_flagged = " | ".join(why_parts)
        
        evidence: List[str] = []
        for r in rule_results:
            evidence.extend(r.evidence_items)
            
        # Deduplicate evidence
        evidence = list(dict.fromkeys(evidence))
        
        attack_seq = build_attack_sequence(all_related_events, rule_results)
        
        # Attack Phase summary
        categories = list({r.category for r in rule_results})
        phase_str = " -> ".join([c.replace("_", " ").title() for c in categories]) if categories else "Credential Access"

        rule_names = [r.rule_name for r in rule_results]
        
        title = f"Intrusion Compromise Detected: {user}@{ip}" if len(rule_results) > 1 else f"{rule_names[0]}: {ip}"

        incidents.append(CorrelatedIncident(
            incident_id=f"INC-{inc_counter:04d}",
            title=title,
            risk_level=risk_level,
            risk_score=final_score,
            status="New",
            user=user,
            source_ip=ip,
            first_detected_time=first_time,
            last_detected_time=last_time,
            duration_seconds=round(duration_sec, 1),
            total_events=len(all_related_events),
            attack_phase=phase_str,
            summary=f"Automated correlation correlated {len(all_related_events)} security events from IP {ip} involving account '{user}' triggering {len(rule_results)} detection rule(s).",
            why_flagged=why_flagged,
            evidence=evidence,
            likely_attack_sequence=attack_seq,
            triggered_rules=rule_names,
            related_events=all_related_events
        ))
        inc_counter += 1

    # Sort incidents by risk score descending
    incidents.sort(key=lambda x: x.risk_score, reverse=True)
    return incidents


def generate_analysis_summary(
    events: List[SecurityEvent], 
    incidents: List[CorrelatedIncident]
) -> AnalysisSummary:
    """Generate high-level metrics for dashboard header and summary cards."""
    suspicious_event_ids: Set[str] = set()
    for inc in incidents:
        for ev in inc.related_events:
            suspicious_event_ids.add(ev.id)

    unique_ips = len({e.source_ip for e in events})
    unique_users = len({e.username for e in events if e.username})

    critical = sum(1 for i in incidents if i.risk_level == "CRITICAL")
    high = sum(1 for i in incidents if i.risk_level == "HIGH")
    medium = sum(1 for i in incidents if i.risk_level == "MEDIUM")
    low = sum(1 for i in incidents if i.risk_level == "LOW")

    # Aggregate suspicious IPs
    ip_counter: DefaultDict[str, int] = defaultdict(int)
    for inc in incidents:
        ip_counter[inc.source_ip] += inc.risk_score

    suspicious_ips = [
        {"ip": ip, "threat_score": score, "incident_count": sum(1 for i in incidents if i.source_ip == ip)}
        for ip, score in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
    ]

    # Aggregate suspicious Users
    user_counter: DefaultDict[str, int] = defaultdict(int)
    for inc in incidents:
        if inc.user and inc.user != "anonymous":
            user_counter[inc.user] += inc.risk_score

    suspicious_users = [
        {"user": u, "threat_score": score, "incident_count": sum(1 for i in incidents if i.user == u)}
        for u, score in sorted(user_counter.items(), key=lambda x: x[1], reverse=True)
    ]

    return AnalysisSummary(
        total_events=len(events),
        total_suspicious_events=len(suspicious_event_ids),
        total_incidents=len(incidents),
        critical_incidents=critical,
        high_incidents=high,
        medium_incidents=medium,
        low_incidents=low,
        unique_ips=unique_ips,
        unique_users=unique_users,
        suspicious_ips=suspicious_ips,
        suspicious_users=suspicious_users
    )
