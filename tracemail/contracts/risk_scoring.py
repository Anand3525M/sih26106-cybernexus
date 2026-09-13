"""
Module 4 Data Contract: Multi-Signal Risk Fusion Engine
Deterministic Composite Threat Scoring & Verdict Tier Classification.
"""
from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict

VerdictTier = Literal[
    "BENIGN / LEGITIMATE",
    "SUSPICIOUS / ELEVATED",
    "MALICIOUS / HIGH CONFIDENCE SPOOF"
]

class RiskSignalContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal_id: str = Field(..., description="Unique machine-readable signal identifier")
    category: Literal["protocol", "origin", "timing"] = Field(..., description="Signal source category")
    penalty_points: int = Field(..., description="Weight contribution of this signal (0-100)")
    description: str = Field(..., description="Human-readable forensic justification")
    evidence: Optional[Dict[str, str]] = Field(default_factory=dict, description="Contextual telemetry evidence")

class RiskFusionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    composite_threat_score: int = Field(..., ge=0, le=100, description="Final deterministic threat score clamped between 0 and 100")
    verdict_tier: VerdictTier = Field(..., description="Strict classification tier based on score range")
    triggered_signals: List[RiskSignalContract] = Field(default_factory=list, description="List of all forensic penalties triggered")
    protocol_subtotal: int = Field(0, description="Unclamped subtotal of protocol violation penalties")
    origin_subtotal: int = Field(0, description="Unclamped subtotal of origin intelligence penalties")
    timing_subtotal: int = Field(0, description="Unclamped subtotal of hop timing anomaly penalties")
    summary: str = Field(..., description="Executive forensic summary explaining the threat evaluation")
