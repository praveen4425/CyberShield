"""
Data models for CyberShield Log Analysis & Intrusion Detection.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    id: str
    timestamp: str  # ISO 8601 string or standard YYYY-MM-DD HH:MM:SS
    epoch: float    # Unix timestamp in seconds for fast time-window math
    source_ip: str
    username: str
    action: str     # login_failed, login_success, file_access, admin_escalate, port_scan, etc.
    status: str     # SUCCESS, FAILED, BLOCKED, ATTEMPT
    resource: str   # /api/v1/auth, /etc/shadow, database_dump, /finance/payroll.csv, etc.
    method: str = "POST"
    status_code: int = 200
    user_agent: str = "Unknown"
    details: Dict[str, Any] = Field(default_factory=dict)
    raw_log: str = ""


class DetectionRuleResult(BaseModel):
    rule_id: str
    rule_name: str
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    score: int       # 0 - 100
    category: str    # CREDENTIAL_ACCESS, PRIVILEGE_ESCALATION, EXFILTRATION, RECONNAISSANCE, ANOMALOUS_ACCESS
    reason: str
    evidence_items: List[str]
    matched_event_ids: List[str]


class CorrelatedIncident(BaseModel):
    incident_id: str
    title: str
    risk_level: str   # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int   # 0 - 100
    status: str       # New, Investigating, Resolved
    user: str
    source_ip: str
    first_detected_time: str
    last_detected_time: str
    duration_seconds: float
    total_events: int
    attack_phase: str # e.g. "Credential Access -> Privilege Escalation -> Sensitive Data Access"
    summary: str
    why_flagged: str
    evidence: List[str]
    likely_attack_sequence: List[str]
    triggered_rules: List[str]
    related_events: List[SecurityEvent]


class AnalysisSummary(BaseModel):
    total_events: int
    total_suspicious_events: int
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    unique_ips: int
    unique_users: int
    suspicious_ips: List[Dict[str, Any]]
    suspicious_users: List[Dict[str, Any]]


class AnalysisResponse(BaseModel):
    success: bool
    message: str
    summary: AnalysisSummary
    incidents: List[CorrelatedIncident]
    events: List[SecurityEvent]
