"""
Pydantic models for the SOC platform (shared type definitions)
"""
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime


class Alert(BaseModel):
    alert_id: str
    endpoint_id: str
    hostname: str
    alert_type: str
    severity: str
    title: str
    description: str
    process_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    acknowledged: bool = False
    created_at: str


class Endpoint(BaseModel):
    endpoint_id: str
    hostname: str
    ip_address: str
    os_version: str
    status: str
    threat_level: str
    last_seen: str


class ThreatEvent(BaseModel):
    event_id: str
    endpoint_id: str
    event_type: str
    severity: str
    data: Dict
    timestamp: str


class Policy(BaseModel):
    policy_id: str
    policy_name: str
    rules: Dict
    endpoints: List[str]


class SIEMLog(BaseModel):
    log_id: str
    endpoint_id: str
    log_type: str
    content: str
    created_at: str
