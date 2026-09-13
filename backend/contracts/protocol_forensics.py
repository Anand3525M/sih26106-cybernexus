"""
Module 1 Data Contract: Protocol Forensics
RFC Standards: RFC 5322 (MIME/Headers), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8617 (ARC)
Zero Custom Crypto: All cryptographic validations driven by dkimpy, pyspf, and checkdmarc.
"""
from typing import List, Dict, Optional, Any, Literal
from pydantic import BaseModel, Field, ConfigDict

class RawEmlInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    source_filename: str = Field(..., description="Original filename of the ingested .eml")
    raw_bytes_base64: Optional[str] = Field(None, description="Base64 encoded raw bytes for JSON transport")
    raw_content: Optional[str] = Field(None, description="Raw EML string content if text decoded")
    file_path: Optional[str] = Field(None, description="Local path to EML file on disk")

class MessageHeaders(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    message_id: Optional[str] = Field(None, description="RFC 5322 Message-ID header")
    from_address: str = Field(..., description="Cleaned email address from From header")
    from_domain: str = Field(..., description="Extracted sender domain")
    from_display_name: Optional[str] = Field(None, description="Friendly display name")
    reply_to: Optional[str] = Field(None, description="Reply-To header address")
    return_path: Optional[str] = Field(None, description="Envelope sender / Return-Path")
    to_addresses: List[str] = Field(default_factory=list, description="List of recipient addresses")
    subject: str = Field("", description="Normalized email subject line")
    date_header: Optional[str] = Field(None, description="Raw Date header string")
    timestamp_utc: Optional[str] = Field(None, description="ISO-8601 converted timestamp")
    all_headers: Dict[str, str] = Field(default_factory=dict, description="Normalized dictionary of all header keys/values")

class SpfContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    verdict: Literal["pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"] = Field(
        ..., description="RFC 7208 SPF evaluation verdict"
    )
    domain: str = Field(..., description="Domain evaluated for SPF")
    client_ip: Optional[str] = Field(None, description="Client connecting IP evaluated against SPF")
    sender: str = Field(..., description="Envelope sender address")
    raw_record: Optional[str] = Field(None, description="DNS TXT SPF record retrieved")
    details: str = Field(..., description="Human-readable explanation of the SPF evaluation")
    score_penalty: int = Field(0, description="Deduction points assessed for SPF verdict (0-40)")

class DkimContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    verdict: Literal["pass", "invalid", "none", "fail"] = Field(
        ..., description="RFC 6376 DKIM verification verdict via dkimpy"
    )
    selector: Optional[str] = Field(None, description="DKIM selector key (s= tag)")
    domain: Optional[str] = Field(None, description="DKIM signing domain (d= tag)")
    identity: Optional[str] = Field(None, description="DKIM identity (i= tag)")
    algorithm: Optional[str] = Field(None, description="Signature algorithm (e.g. rsa-sha256)")
    canonicalization: Optional[str] = Field(None, description="Header/body canonicalization algorithms (c= tag)")
    headers_signed: List[str] = Field(default_factory=list, description="List of headers covered by DKIM signature")
    public_key_dns: Optional[str] = Field(None, description="Public key retrieved from selector._domainkey DNS")
    details: str = Field(..., description="Forensic details from cryptographic signature evaluation")
    score_penalty: int = Field(0, description="Deduction points assessed for DKIM verdict (0-35)")

class DmarcAlignmentContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    spf_aligned: bool = Field(..., description="Whether SPF domain aligns with From header domain (strict or relaxed)")
    dkim_aligned: bool = Field(..., description="Whether DKIM domain aligns with From header domain (strict or relaxed)")

class DmarcContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    verdict: Literal["pass", "fail", "none"] = Field(
        ..., description="RFC 7489 DMARC policy validation verdict"
    )
    policy: Optional[Literal["reject", "quarantine", "none"]] = Field(
        None, description="Sender published DMARC policy (p= tag)"
    )
    subdomain_policy: Optional[Literal["reject", "quarantine", "none"]] = Field(
        None, description="Sender published subdomain policy (sp= tag)"
    )
    percentage: int = Field(100, description="Percentage of messages to which policy applies (pct= tag)")
    domain: str = Field(..., description="From header domain checked for DMARC")
    alignment: DmarcAlignmentContract = Field(..., description="Alignment status of SPF and DKIM")
    raw_record: Optional[str] = Field(None, description="Raw _dmarc TXT record from DNS")
    details: str = Field(..., description="Forensic reasoning regarding DMARC verdict")
    score_penalty: int = Field(0, description="Deduction points assessed for DMARC verdict (0-35)")

class ArcContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    verdict: Literal["pass", "fail", "none"] = Field(
        ..., description="RFC 8617 Authenticated Received Chain (ARC) verification status"
    )
    instance_count: int = Field(0, description="Number of ARC instances/hops present")
    latest_instance_verdict: Optional[str] = Field(None, description="Verdict of most recent ARC seal (cv= tag)")
    seal_valid: bool = Field(False, description="Cryptographic validity of ARC-Seal signature via dkimpy")
    details: str = Field(..., description="Forensic evaluation of intermediate forwarding authentication")

class RelayHopContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    hop_number: int = Field(..., description="Hop index in chronological transmission order (1 = Originating MTA)")
    from_host: Optional[str] = Field(None, description="MTA reported in from token")
    by_host: Optional[str] = Field(None, description="MTA reported in by token")
    ip: Optional[str] = Field(None, description="Extracted IPv4 or IPv6 address")
    rdns: Optional[str] = Field(None, description="Reverse DNS pointer for the hop IP")
    timestamp_utc: Optional[str] = Field(None, description="ISO-8601 converted timestamp of the hop")
    transit_delay_seconds: int = Field(0, description="Transit delay in seconds between hops")
    is_private_ip: bool = Field(False, description="True if IP is non-routable (RFC 1918 / loopback)")
    anomalies: List[str] = Field(default_factory=list, description="Anomalies detected (e.g. clock skew, spoofed by)")

class ProtocolForensicsResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    email_id: str = Field(..., description="Cryptographic SHA-256 hash of the entire raw EML file")
    source_filename: str = Field(..., description="Original filename")
    headers: MessageHeaders = Field(..., description="Parsed RFC 5322 headers")
    spf: SpfContract = Field(..., description="SPF verification result")
    dkim: DkimContract = Field(..., description="DKIM cryptographic verification result")
    dmarc: DmarcContract = Field(..., description="DMARC policy alignment result")
    arc: ArcContract = Field(..., description="ARC authentication results")
    relay_hops: List[RelayHopContract] = Field(default_factory=list, description="Chronological transmission hops")
    origin_ip: Optional[str] = Field(None, description="Identified true public originating IP")
    protocol_risk_subtotal: int = Field(..., description="Calculated protocol risk score (0-100, 100 = critical spoofing)")
    subscore_deductions: Dict[str, int] = Field(default_factory=dict, description="Itemized penalties breakdown")
