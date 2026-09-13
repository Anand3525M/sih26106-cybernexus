"""
Module 2 Data Contract: Origin Intelligence & Hop Timing
Offline First: MaxMind GeoLite2 City & ASN local databases with autonomous SQLite caching.
Zero external paid APIs. Deterministic hop latency calculation and spoofed domain detection.
"""
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, ConfigDict

class OriginIntelInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    ip: Optional[str] = Field(None, description="IP address to locate and attribute")
    domain: str = Field(..., description="From-header domain or sender domain to inspect")
    relay_hops: List[Dict[str, Any]] = Field(default_factory=list, description="Raw relay hops for timing analysis")
    allow_network_fallback: bool = Field(False, description="Strictly false for 100% offline air-gapped demo")

class GeoLocationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    country_code: Optional[str] = Field(None, description="Two-letter ISO 3166-1 alpha-2 country code")
    country_name: Optional[str] = Field(None, description="Full country name")
    city: Optional[str] = Field(None, description="City name resolved offline")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    postal_code: Optional[str] = Field(None, description="Postal/ZIP code if recorded in GeoLite2")
    accuracy_radius_km: Optional[int] = Field(None, description="Estimated accuracy radius in kilometers")
    source_database: str = Field("GeoLite2-City-Offline", description="Underlying offline database version")

class AsnContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    asn: Optional[int] = Field(None, description="Autonomous System Number (e.g. 15169)")
    as_name: Optional[str] = Field(None, description="Short Autonomous System Name")
    as_org: Optional[str] = Field(None, description="Organization managing the AS")
    network_prefix: Optional[str] = Field(None, description="Subnet CIDR route prefix")
    source: str = Field("GeoLite2-ASN-Offline", description="Attribution data source")

class HopTimingContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    total_transit_seconds: int = Field(0, description="Total seconds from initial dispatch to recipient mailbox")
    hop_count: int = Field(0, description="Total number of transit MTA hops")
    average_hop_delay_seconds: float = Field(0.0, description="Mean delay across all transit stages")
    max_delay_hop_number: Optional[int] = Field(None, description="Hop index where largest bottleneck/delay occurred")
    max_delay_seconds: int = Field(0, description="Maximum single-hop delay in seconds")
    timing_anomalies: List[str] = Field(default_factory=list, description="Clock skew, negative delays, or holding anomalies")

class DomainIntelContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    domain: str = Field(..., description="Query domain")
    normalized_domain: str = Field(..., description="Lowercased, stripped domain name")
    is_punycode: bool = Field(False, description="True if domain contains IDN xn-- prefix")
    decoded_punycode: Optional[str] = Field(None, description="Unicode representation of punycode")
    homoglyph_detected: bool = Field(False, description="True if Cyrillic/Greek lookalike characters detected")
    typosquat_suspect: bool = Field(False, description="True if domain resembles major brands (e.g. paypaI, goog1e)")
    created_date_utc: Optional[str] = Field(None, description="Domain registration date if cached")
    domain_age_days: Optional[int] = Field(None, description="Age of domain in days")
    is_recently_registered: bool = Field(False, description="True if domain was registered < 30 days ago")

class OriginThreatContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    is_tor_exit_node: bool = Field(False, description="True if originating IP matches known Tor exits")
    is_known_proxy_vpn: bool = Field(False, description="True if originating IP matches hosting/VPN ASNs")
    ioc_watchlist_hit: bool = Field(False, description="True if IP or domain is in active case IOC watchlist")
    matched_ioc_id: Optional[str] = Field(None, description="ID of matched IOC entry")
    threat_reputation_score: int = Field(0, description="Threat reputation penalty score (0-100)")

class CacheStatusContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    from_cache: bool = Field(..., description="True if origin data was served from local SQLite cache")
    cache_key: str = Field(..., description="Cache key used (ip:domain)")
    cached_at_utc: Optional[str] = Field(None, description="Timestamp when record was cached")

class OriginIntelligenceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    target_ip: Optional[str] = Field(None, description="Target IP evaluated")
    target_domain: str = Field(..., description="Target domain evaluated")
    geolocation: GeoLocationContract = Field(..., description="Offline geolocation details")
    asn: AsnContract = Field(..., description="ASN and organizational attribution")
    hop_timing: HopTimingContract = Field(..., description="Transit latency and timing analysis")
    domain_intel: DomainIntelContract = Field(..., description="Domain authenticity and homoglyph evaluation")
    threat_assessment: OriginThreatContract = Field(..., description="Infrastructure threat attribution")
    cache_status: CacheStatusContract = Field(..., description="Cache provenance")
    origin_risk_subtotal: int = Field(0, description="Origin risk contribution score (0-100)")
