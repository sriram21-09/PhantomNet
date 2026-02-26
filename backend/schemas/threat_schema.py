from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class ThreatInput(BaseModel):
    """
    Input schema for threat scoring.
    Contains raw packet metadata required to extract features.
    """
    # Core Packet Info
    src_ip: str = Field(..., description="Source IP address", example="192.168.1.105")
    dst_ip: str = Field(..., description="Destination IP address", example="10.0.0.5")
    dst_port: int = Field(..., description="Destination Port", example=80)
    protocol: str = Field(..., description="Protocol (TCP, UDP, ICMP)", example="TCP")
    length: int = Field(..., description="Packet Length in bytes", example=64)
    
    # Context/Enrichment (Optional/Defaults)
    timestamp: Optional[str] = Field(None, description="ISO 8601 Timestamp. Defaults to now.", example="2026-02-11T12:00:00Z")
    
    # Pre-existing signals (fed from other components involved in the pipeline)
    threat_score: float = Field(0.0, description="Baseline threat score from firewall/rules", example=10.0)
    is_malicious: bool = Field(False, description="Known malicious flag (e.g. from blacklist)", example=False)
    attack_type: str = Field("UNKNOWN", description="Preliminary attack classification", example="UNKNOWN")
    honeypot_type: str = Field("NONE", description="Honeypot type interaction", example="HTTP")

class ThreatResponse(BaseModel):
    """
    Output schema for threat scoring analysis.
    """
    score: float = Field(..., description="Calculated Threat Probability (0-100)")
    threat_level: str = Field(..., description="Categorical Level: LOW, MEDIUM, HIGH")
    confidence: float = Field(..., description="Model Confidence (0.0-1.0)")
    decision: str = Field(..., description="Recommended Action: ALLOW, ALERT, BLOCK")
