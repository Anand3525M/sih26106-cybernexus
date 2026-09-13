"""
Module 3 Data Contract: Case Management & Hash Chain Integrity
Court-Admissible Evidence: Immutable SHA-256 forward-linked audit trail.
Zero Tampering Tolerance: Cryptographic chain verification pinpointing block-level modifications.
"""
from typing import List, Dict, Optional, Any, Literal
from pydantic import BaseModel, Field, ConfigDict

class CaseCreateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    title: str = Field(..., description="Descriptive case title (e.g. 'Coordinated CEO Wire Transfer BEC')")
    description: str = Field("", description="Detailed background and investigative hypothesis")
    investigator: str = Field(..., description="Username or ID of assigned investigator")
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field("MEDIUM", description="Case severity level")
    initial_email_ids: List[str] = Field(default_factory=list, description="List of email SHA-256 IDs to link")
    tags: List[str] = Field(default_factory=list, description="Forensic taxonomy tags (e.g. ['BEC', 'Phishing'])")

class CaseUpdateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    status: Optional[Literal["OPEN", "INVESTIGATING", "ESCALATED", "CLOSED"]] = Field(None)
    priority: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]] = Field(None)
    added_email_ids: List[str] = Field(default_factory=list)
    added_iocs: List[str] = Field(default_factory=list)
    new_note: Optional[str] = Field(None)
    investigator: str = Field(..., description="Actor committing the case modification")

class AuditEventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    event_type: Literal[
        "EMAIL_INGESTED",
        "PROTOCOL_EVALUATED",
        "ORIGIN_ATTRIBUTED",
        "CASE_CREATED",
        "CASE_MODIFIED",
        "IOC_ADDED",
        "REPORT_GENERATED",
        "TAMPER_DETECTED"
    ] = Field(..., description="Forensic event classification")
    actor: str = Field(..., description="System process or investigator identifier")
    entity_id: str = Field(..., description="Primary identifier (e.g. email_id or case_id)")
    entity_type: str = Field(..., description="Entity category (e.g. 'email', 'case', 'ioc')")
    payload: Dict[str, Any] = Field(..., description="Structured event payload to be hashed")

class AuditBlockContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    index: int = Field(..., description="Sequential block index (0 = Genesis Block)")
    timestamp_utc: str = Field(..., description="ISO-8601 UTC timestamp of block creation")
    event_type: str = Field(..., description="Event type identifier")
    actor: str = Field(..., description="Investigator or system service")
    entity_id: str = Field(..., description="Entity ID associated with this entry")
    entity_type: str = Field(..., description="Type of entity")
    payload_hash: str = Field(..., description="SHA-256 hash of canonical JSON event payload")
    prev_hash: str = Field(..., description="SHA-256 block hash of immediate predecessor")
    block_hash: str = Field(..., description="Computed block hash: SHA-256(index + ts + event + actor + entity + payload_hash + prev_hash)")

class AuditIntegrityContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    chain_valid: bool = Field(..., description="True if every block in sequence passes cryptographic verification")
    total_blocks: int = Field(..., description="Total count of blocks in the ledger")
    verified_blocks: int = Field(..., description="Number of contiguous blocks successfully validated")
    genesis_hash: str = Field(..., description="Hash of the genesis anchor block")
    latest_block_hash: str = Field(..., description="Cryptographic head of the ledger")
    tampered_block_index: Optional[int] = Field(None, description="Index of first detected block mismatch if corrupted")
    tamper_reason: Optional[str] = Field(None, description="Diagnostic reason for verification failure")
    verification_timestamp_utc: str = Field(..., description="ISO-8601 timestamp when audit validation ran")

class CaseNoteContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    note_id: str = Field(...)
    author: str = Field(...)
    timestamp_utc: str = Field(...)
    content: str = Field(...)

class CaseDetailContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    case_id: str = Field(..., description="Unique case identifier (e.g. CASE-2026-001)")
    title: str = Field(..., description="Case title")
    description: str = Field("")
    status: Literal["OPEN", "INVESTIGATING", "ESCALATED", "CLOSED"] = Field("OPEN")
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field("MEDIUM")
    investigator: str = Field(...)
    created_at_utc: str = Field(...)
    updated_at_utc: str = Field(...)
    linked_email_ids: List[str] = Field(default_factory=list)
    ioc_watchlist: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    notes: List[CaseNoteContract] = Field(default_factory=list)
    audit_chain_head: Optional[str] = Field(None, description="Latest block hash anchoring this case's history")
