"""Data models for Campaign Correlation Engine (Stage 6).

Defines structured verdict objects (Stages 2-5 input contract),
signal breakdowns, weights configuration, and correlation results.
"""

from typing import Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class CorrelationWeights(BaseModel):
    """Configurable weights for each correlation signal.

    Must sum to 1.0. These weights are explicitly displayed in every correlation
    output so analysts can inspect and adjust them.
    """
    shared_url: float = Field(
        default=0.35,
        description="Weight for identical or domain/path overlapping URLs."
    )
    shared_domain: float = Field(
        default=0.20,
        description="Weight for matching sender domain or organizational root domain."
    )
    text_similarity: float = Field(
        default=0.25,
        description="Weight for TF-IDF cosine similarity of subject and body (threshold >= 0.80)."
    )
    shared_ip: float = Field(
        default=0.15,
        description="Weight for identical sending IP or shared /24 subnet."
    )
    temporal_clustering: float = Field(
        default=0.05,
        description="Weight for proximity in arrival timestamp within time window."
    )

    def total_weight(self) -> float:
        return (
            self.shared_url
            + self.shared_domain
            + self.text_similarity
            + self.shared_ip
            + self.temporal_clustering
        )


class EmailVerdict(BaseModel):
    """Input contract: Structured verdict object from Stages 2-5."""
    email_id: str = Field(..., description="Unique email identifier (e.g., hash or message-id)")
    timestamp: str = Field(..., description="ISO 8601 formatted timestamp string")
    sender: str = Field(..., description="Sender email address (From header)")
    sender_ip: Optional[str] = Field(None, description="Originating sending IP from relay trace")
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Email plain text body")
    extracted_urls: List[str] = Field(default_factory=list, description="List of URLs found in body/headers")
    stage_verdict: Optional[str] = Field("phishing", description="Verdict from stages 2-5 (e.g. phishing, clean)")
    threat_score: Optional[float] = Field(0.9, description="Confidence score from earlier stages [0.0 - 1.0]")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Additional headers or metadata")


class SignalBreakdown(BaseModel):
    """Per-signal similarity scores and metadata for an email pair."""
    shared_ip_score: float = Field(..., description="Score [0.0 - 1.0] for shared IP / subnet")
    shared_domain_score: float = Field(..., description="Score [0.0 - 1.0] for matching sending domain")
    text_similarity_score: float = Field(..., description="Cosine similarity [0.0 - 1.0] for subject/body")
    shared_url_score: float = Field(..., description="Score [0.0 - 1.0] for matching URLs/domains")
    temporal_score: float = Field(..., description="Score [0.0 - 1.0] for temporal proximity")

    # Diagnostic details for explanation
    details: Dict[str, str] = Field(default_factory=dict, description="Human-readable notes on matched signals")


class CorrelatedEmailMatch(BaseModel):
    """Match details between the target email and a previously seen email."""
    prior_email_id: str = Field(..., description="ID of the previously processed email")
    prior_subject: str = Field(..., description="Subject of the matched email")
    prior_sender: str = Field(..., description="Sender of the matched email")
    prior_timestamp: str = Field(..., description="Timestamp of the matched email")
    signal_scores: SignalBreakdown = Field(..., description="Individual similarity score per signal")
    fused_campaign_confidence: float = Field(
        ...,
        description="Weighted fused campaign confidence score [0.0 - 1.0]"
    )
    is_campaign_match: bool = Field(
        ...,
        description="True if fused confidence exceeds campaign correlation threshold"
    )


class CampaignCorrelationOutput(BaseModel):
    """Full output of the campaign correlation module for an incoming email."""
    email_id: str = Field(..., description="ID of the analyzed email")
    assigned_campaign_id: Optional[str] = Field(
        None,
        description="Identifier of the campaign cluster this email is attached to"
    )
    highest_confidence: float = Field(
        0.0,
        description="Highest fused confidence score among all matched prior emails"
    )
    correlated_prior_emails: List[CorrelatedEmailMatch] = Field(
        default_factory=list,
        description="Ranked list of correlated prior emails with per-signal breakdown"
    )
    weights_applied: Dict[str, float] = Field(
        ...,
        description="Explicit display of exact weights applied to each signal"
    )
    correlation_threshold: float = Field(
        ...,
        description="Confidence threshold used to declare a coordinated campaign link"
    )
    graph_summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Current state of correlation graph (total_nodes, total_edges, total_campaigns)"
    )
