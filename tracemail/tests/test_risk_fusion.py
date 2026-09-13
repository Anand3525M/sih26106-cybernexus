"""
Unit Test Suite for Module 4: Multi-Signal Risk Fusion Engine
Validates deterministic threat scoring, boundary conditions, signal contributions,
score clamping (0-100), and strict verdict tier classifications.
"""
import pytest
from pathlib import Path

from backend.config import settings
from backend.ingestion.parser import parse_eml_file
from backend.forensics.protocols import evaluate_email_protocols
from backend.intelligence.geoip import analyze_origin_intelligence
from backend.scoring.fusion import evaluate_risk_fusion
from backend.contracts.protocol_forensics import (
    ProtocolForensicsResult, MessageHeaders, SpfContract, DkimContract,
    DmarcContract, DmarcAlignmentContract, ArcContract, RelayHopContract
)
from backend.contracts.origin_intelligence import (
    OriginIntelligenceResult, GeoLocationContract, AsnContract,
    HopTimingContract, DomainIntelContract, OriginThreatContract, CacheStatusContract
)

def _create_mock_baseline():
    """Creates clean zero-penalty baseline Protocol and Origin results."""
    proto = ProtocolForensicsResult(
        email_id="a" * 64,
        source_filename="clean_test.eml",
        headers=MessageHeaders(
            from_address="admin@legit-corp.org",
            from_domain="legit-corp.org",
            subject="Clean Report",
            to_addresses=["user@target.org"]
        ),
        spf=SpfContract(
            verdict="pass",
            domain="legit-corp.org",
            sender="admin@legit-corp.org",
            details="SPF pass",
            score_penalty=0
        ),
        dkim=DkimContract(
            verdict="pass",
            selector="s1",
            domain="legit-corp.org",
            details="DKIM pass",
            score_penalty=0
        ),
        dmarc=DmarcContract(
            verdict="pass",
            policy="reject",
            percentage=100,
            domain="legit-corp.org",
            alignment=DmarcAlignmentContract(spf_aligned=True, dkim_aligned=True),
            details="DMARC pass",
            score_penalty=0
        ),
        arc=ArcContract(verdict="none", details="No ARC"),
        relay_hops=[
            RelayHopContract(
                hop_number=1,
                from_host="mail.legit-corp.org",
                by_host="mx.target.org",
                ip="209.85.220.41",
                transit_delay_seconds=3,
                is_private_ip=False,
                anomalies=[]
            )
        ],
        origin_ip="209.85.220.41",
        protocol_risk_subtotal=0,
        subscore_deductions={}
    )

    origin = OriginIntelligenceResult(
        target_ip="209.85.220.41",
        target_domain="legit-corp.org",
        geolocation=GeoLocationContract(
            country_code="US",
            country_name="United States",
            city="Mountain View",
            latitude=37.4,
            longitude=-122.08,
            source_database="GeoLite2-City-Offline"
        ),
        asn=AsnContract(
            asn=15169,
            as_name="GOOGLE",
            as_org="Google LLC",
            network_prefix="209.85.220.0/24"
        ),
        hop_timing=HopTimingContract(
            total_transit_seconds=3,
            hop_count=1,
            average_hop_delay_seconds=3.0,
            max_delay_hop_number=1,
            max_delay_seconds=3,
            timing_anomalies=[]
        ),
        domain_intel=DomainIntelContract(
            domain="legit-corp.org",
            normalized_domain="legit-corp.org",
            is_punycode=False,
            homoglyph_detected=False,
            typosquat_suspect=False
        ),
        threat_assessment=OriginThreatContract(
            is_tor_exit_node=False,
            is_known_proxy_vpn=False,
            threat_reputation_score=0
        ),
        cache_status=CacheStatusContract(
            from_cache=False,
            cache_key="209.85.220.41:legit-corp.org"
        ),
        origin_risk_subtotal=0
    )

    return proto, origin

class TestRiskFusionEngine:

    def test_clean_baseline_zero_score_benign_tier(self):
        """Clean email baseline must have 0 threat score and 'BENIGN / LEGITIMATE' tier."""
        proto, origin = _create_mock_baseline()
        result = evaluate_risk_fusion(proto, origin)

        assert result.composite_threat_score == 0
        assert result.verdict_tier == "BENIGN / LEGITIMATE"
        assert len(result.triggered_signals) == 0
        assert result.protocol_subtotal == 0
        assert result.origin_subtotal == 0
        assert result.timing_subtotal == 0

    def test_legit_google_eml_boundary_condition_under_20(self):
        """Legitimate Google alert email must score < 20 and be classified BENIGN."""
        eml_path = settings.SAMPLES_DIR / "legit_google.eml"
        assert eml_path.exists(), f"Sample missing: {eml_path}"

        ingested = parse_eml_file(eml_path)
        proto = evaluate_email_protocols(ingested)
        origin = analyze_origin_intelligence(proto.origin_ip, ingested.headers.from_domain, proto.relay_hops)
        result = evaluate_risk_fusion(proto, origin)

        assert result.composite_threat_score < 20, f"Expected < 20, got {result.composite_threat_score}"
        assert result.verdict_tier == "BENIGN / LEGITIMATE"

    def test_spoofed_paypal_eml_boundary_condition_over_80(self):
        """Spoofed PayPal credential phishing sample must score > 80 and be MALICIOUS."""
        eml_path = settings.SAMPLES_DIR / "spoof_paypal.eml"
        assert eml_path.exists(), f"Sample missing: {eml_path}"

        ingested = parse_eml_file(eml_path)
        proto = evaluate_email_protocols(ingested)
        origin = analyze_origin_intelligence(proto.origin_ip, ingested.headers.from_domain, proto.relay_hops)
        result = evaluate_risk_fusion(proto, origin)

        assert result.composite_threat_score > 80, f"Expected > 80, got {result.composite_threat_score}"
        assert result.verdict_tier == "MALICIOUS / HIGH CONFIDENCE SPOOF"
        # Verify critical signals were triggered
        signal_ids = [s.signal_id for s in result.triggered_signals]
        assert "PROTO_DMARC_FAIL" in signal_ids
        assert "PROTO_SPF_UNALIGNED" in signal_ids
        assert "PROTO_DKIM_MISMATCH" in signal_ids
        assert "ORIGIN_TOR_OR_BULLETPROOF" in signal_ids

    def test_protocol_signal_dmarc_fail_penalty(self):
        """DMARC policy reject/fail triggers +35 penalty."""
        proto, origin = _create_mock_baseline()
        proto.dmarc.verdict = "fail"

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 35
        assert result.verdict_tier == "SUSPICIOUS / ELEVATED"
        assert any(s.signal_id == "PROTO_DMARC_FAIL" and s.penalty_points == 35 for s in result.triggered_signals)

    def test_protocol_signal_spf_hardfail_penalty(self):
        """SPF hardfail / unaligned triggers +25 penalty."""
        proto, origin = _create_mock_baseline()
        proto.spf.verdict = "fail"
        proto.dmarc.alignment.spf_aligned = False

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 25
        assert result.verdict_tier == "BENIGN / LEGITIMATE"  # Boundary check: 25 is BENIGN
        assert any(s.signal_id == "PROTO_SPF_UNALIGNED" and s.penalty_points == 25 for s in result.triggered_signals)

    def test_protocol_signal_dkim_missing_penalty(self):
        """DKIM signature missing / mismatch triggers +25 penalty."""
        proto, origin = _create_mock_baseline()
        proto.dkim.verdict = "none"
        proto.dmarc.alignment.dkim_aligned = False

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 25
        assert any(s.signal_id == "PROTO_DKIM_MISMATCH" and s.penalty_points == 25 for s in result.triggered_signals)

    def test_origin_signal_tor_or_bulletproof_penalty(self):
        """Tor exit node or bulletproof ASN triggers +25 penalty."""
        proto, origin = _create_mock_baseline()
        origin.threat_assessment.is_tor_exit_node = True

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 25
        assert any(s.signal_id == "ORIGIN_TOR_OR_BULLETPROOF" and s.penalty_points == 25 for s in result.triggered_signals)

    def test_origin_signal_homoglyph_typosquat_penalty(self):
        """Domain homoglyph or typosquat triggers +20 penalty."""
        proto, origin = _create_mock_baseline()
        origin.domain_intel.homoglyph_detected = True

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 20
        assert any(s.signal_id == "ORIGIN_DECEPTIVE_DOMAIN" and s.penalty_points == 20 for s in result.triggered_signals)

    def test_origin_signal_rfc1918_bypass_penalty(self):
        """Private RFC1918 bypass anomaly triggers +15 penalty."""
        proto, origin = _create_mock_baseline()
        proto.relay_hops[0].anomalies.append("Internal RFC1918 bypass anomaly: hop 1 leaks private routing")

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 15
        assert any(s.signal_id == "ORIGIN_RFC1918_BYPASS" and s.penalty_points == 15 for s in result.triggered_signals)

    def test_timing_signal_negative_transit_latency_penalty(self):
        """Negative hop transit latency / clock tampering triggers +15 penalty."""
        proto, origin = _create_mock_baseline()
        proto.relay_hops[0].transit_delay_seconds = -5

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 15
        assert any(s.signal_id == "TIMING_CLOCK_INVERSION" and s.penalty_points == 15 for s in result.triggered_signals)

    def test_timing_signal_hop_latency_over_120s_penalty(self):
        """Relay hop latency > 120s triggers +10 penalty."""
        proto, origin = _create_mock_baseline()
        proto.relay_hops[0].transit_delay_seconds = 180
        origin.hop_timing.max_delay_seconds = 180

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 10
        assert any(s.signal_id == "TIMING_HOLDING_DELAY" and s.penalty_points == 10 for s in result.triggered_signals)

    def test_verdict_tiers_boundary_transitions(self):
        """
        Verify strict verdict tier classification boundaries:
        - 0 - 25: BENIGN / LEGITIMATE
        - 26 - 60: SUSPICIOUS / ELEVATED
        - 61 - 100: MALICIOUS / HIGH CONFIDENCE SPOOF
        """
        proto, origin = _create_mock_baseline()

        # Score 25: SPF fail (+25) -> BENIGN
        proto.spf.verdict = "fail"
        proto.dmarc.alignment.spf_aligned = False
        res25 = evaluate_risk_fusion(proto, origin)
        assert res25.composite_threat_score == 25
        assert res25.verdict_tier == "BENIGN / LEGITIMATE"

        # Score 26-60: SPF (+25) + Latency > 120s (+10) = 35 -> SUSPICIOUS
        proto.relay_hops[0].transit_delay_seconds = 150
        origin.hop_timing.max_delay_seconds = 150
        res35 = evaluate_risk_fusion(proto, origin)
        assert res35.composite_threat_score == 35
        assert res35.verdict_tier == "SUSPICIOUS / ELEVATED"

        # Score 60: DMARC fail (+35) + SPF (+25) = 60 -> SUSPICIOUS
        proto.dmarc.verdict = "fail"
        proto.relay_hops[0].transit_delay_seconds = 2  # reset latency
        origin.hop_timing.max_delay_seconds = 2
        res60 = evaluate_risk_fusion(proto, origin)
        assert res60.composite_threat_score == 60
        assert res60.verdict_tier == "SUSPICIOUS / ELEVATED"

        # Score 61+: DMARC fail (+35) + SPF (+25) + Latency (+10) = 70 -> MALICIOUS
        proto.relay_hops[0].transit_delay_seconds = 150
        origin.hop_timing.max_delay_seconds = 150
        res70 = evaluate_risk_fusion(proto, origin)
        assert res70.composite_threat_score == 70
        assert res70.verdict_tier == "MALICIOUS / HIGH CONFIDENCE SPOOF"

    def test_score_clamping_at_100(self):
        """Cumulative penalties exceeding 100 must be clamped to 100."""
        proto, origin = _create_mock_baseline()
        # Trigger multiple high-penalty signals: 35 + 25 + 25 + 25 + 20 + 15 = 145
        proto.dmarc.verdict = "fail"
        proto.spf.verdict = "fail"
        proto.dmarc.alignment.spf_aligned = False
        proto.dkim.verdict = "fail"
        proto.dmarc.alignment.dkim_aligned = False
        origin.threat_assessment.is_tor_exit_node = True
        origin.domain_intel.homoglyph_detected = True
        proto.relay_hops[0].anomalies.append("Internal RFC1918 bypass anomaly")

        result = evaluate_risk_fusion(proto, origin)
        assert result.composite_threat_score == 100
        assert result.verdict_tier == "MALICIOUS / HIGH CONFIDENCE SPOOF"
        assert result.protocol_subtotal + result.origin_subtotal > 100
