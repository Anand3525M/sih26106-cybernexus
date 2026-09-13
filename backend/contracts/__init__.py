"""
TraceMail Rigid JSON Data Contracts (Pydantic v2 Models)
Module 1: Protocol Forensics
Module 2: Origin Intelligence & Hop Timing
Module 3: Case Management & Hash Chain Integrity
"""
from backend.contracts.protocol_forensics import (
    RawEmlInput,
    MessageHeaders,
    SpfContract,
    DkimContract,
    DmarcAlignmentContract,
    DmarcContract,
    ArcContract,
    RelayHopContract,
    ProtocolForensicsResult,
)
from backend.contracts.origin_intelligence import (
    OriginIntelInput,
    GeoLocationContract,
    AsnContract,
    HopTimingContract,
    DomainIntelContract,
    OriginThreatContract,
    CacheStatusContract,
    OriginIntelligenceResult,
)
from backend.contracts.case_management import (
    CaseCreateInput,
    CaseUpdateInput,
    AuditEventInput,
    AuditBlockContract,
    AuditIntegrityContract,
    CaseDetailContract,
)

__all__ = [
    "RawEmlInput",
    "MessageHeaders",
    "SpfContract",
    "DkimContract",
    "DmarcAlignmentContract",
    "DmarcContract",
    "ArcContract",
    "RelayHopContract",
    "ProtocolForensicsResult",
    "OriginIntelInput",
    "GeoLocationContract",
    "AsnContract",
    "HopTimingContract",
    "DomainIntelContract",
    "OriginThreatContract",
    "CacheStatusContract",
    "OriginIntelligenceResult",
    "CaseCreateInput",
    "CaseUpdateInput",
    "AuditEventInput",
    "AuditBlockContract",
    "AuditIntegrityContract",
    "CaseDetailContract",
]
