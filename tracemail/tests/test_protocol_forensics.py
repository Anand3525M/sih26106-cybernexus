"""
Comprehensive Test Suite for Module 1 (Protocol Forensics & Ingestion)
Tests RFC 5322 unfolding, RFC 7208 SPF (pyspf), RFC 6376 DKIM (dkimpy),
RFC 7489 DMARC (checkdmarc), and chronological hop anomaly analysis.
"""
import pytest
from pathlib import Path
from email.message import EmailMessage

from backend.config import settings
from backend.ingestion.parser import parse_eml_file, parse_eml_bytes, unfold_header
from backend.forensics.protocols import (
    evaluate_email_protocols,
    parse_relay_hops,
    verify_spf,
    verify_dkim,
    evaluate_dmarc,
    get_organizational_domain,
    is_private_or_local_ip,
)
from backend.contracts.protocol_forensics import SpfContract, DkimContract

class TestProtocolForensics:
    def test_rfc5322_multiline_header_unfolding(self):
        """Verify multiline folded headers with CRLF + spaces/tabs are unfolded per RFC 5322 Section 2.2.3."""
        folded_header = "Subject: Urgent Notification:\r\n  Action Required On\r\n\tYour Account"
        unfolded = unfold_header(folded_header)
        assert unfolded == "Subject: Urgent Notification: Action Required On Your Account"

        folded_with_lf = "From: Security Team\n   <security@alerts.google.com>"
        unfolded_lf = unfold_header(folded_with_lf)
        assert unfolded_lf == "From: Security Team <security@alerts.google.com>"

    def test_parse_legit_google_eml_headers_and_protocols(self):
        """Test legitimate Google EML parsing and protocol validation."""
        sample_path = settings.SAMPLES_DIR / "legit_google.eml"
        assert isinstance(sample_path, Path)
        assert sample_path.exists(), f"Sample file missing: {sample_path}"

        ingested = parse_eml_file(sample_path)
        assert "google.com" in ingested.headers.from_domain
        assert len(ingested.email_id) == 64
        assert len(ingested.raw_received_headers) > 0
        assert ingested.headers.subject != ""

        res = evaluate_email_protocols(ingested)
        assert "google.com" in res.headers.from_domain
        assert res.protocol_risk_subtotal >= 0
        assert len(res.relay_hops) > 0
        assert res.email_id == ingested.email_id

    def test_parse_spoofed_paypal_eml_alignment_failure(self):
        """Test spoofed PayPal email correctly detects DMARC alignment failure."""
        sample_path = settings.SAMPLES_DIR / "spoof_paypal.eml"
        assert sample_path.exists(), f"Sample file missing: {sample_path}"

        ingested = parse_eml_file(sample_path)
        res = evaluate_email_protocols(ingested)

        # In spoofed PayPal email, DKIM alignment MUST fail
        assert res.dmarc.alignment.dkim_aligned is False
        assert res.dmarc.verdict == "fail"
        assert res.protocol_risk_subtotal >= 35
        assert "dmarc_penalty" in res.subscore_deductions

    def test_relay_hops_chronology_and_latency_computation(self):
        """Verify Received headers are sorted chronologically and latencies are calculated."""
        sample_path = settings.SAMPLES_DIR / "legit_google.eml"
        ingested = parse_eml_file(sample_path)
        
        hops, origin_ip = parse_relay_hops(ingested.raw_received_headers)
        assert len(hops) > 0
        assert hops[0].hop_number == 1
        
        for h in hops:
            assert isinstance(h.transit_delay_seconds, int)
            assert h.transit_delay_seconds >= 0

    def test_relay_hop_timestamp_inversion_anomaly(self):
        """Detect clock skew / timestamp inversion when hop timestamps move backward."""
        # Simulated chronological Received headers where Hop 2 timestamp is earlier than Hop 1
        synthetic_received = [
            "from mta1.origin.com (mta1.origin.com [198.51.100.10]) by relay1.isp.com; Sat, 12 Sep 2026 12:00:00 +0000",
            "from relay1.isp.com (relay1.isp.com [198.51.100.11]) by relay2.isp.com; Sat, 12 Sep 2026 11:55:00 +0000",  # 5 minutes earlier!
        ]
        hops, origin = parse_relay_hops(synthetic_received)
        assert len(hops) == 2
        assert hops[0].hop_number == 1
        assert hops[1].hop_number == 2
        
        # Hop 2 MUST flag timestamp inversion anomaly
        assert any("Timestamp inversion anomaly" in a for a in hops[1].anomalies)

    def test_relay_hop_internal_rfc1918_bypass_anomaly(self):
        """Detect internal non-routable IP leakage after external public transmission."""
        synthetic_received = [
            "from origin.org (origin.org [198.51.100.25]) by public-mta.com; Sat, 12 Sep 2026 12:00:00 +0000",
            "from public-mta.com (internal [10.0.5.15]) by secure-gateway.com; Sat, 12 Sep 2026 12:00:05 +0000",  # 10.0.5.15 is private!
        ]
        hops, origin = parse_relay_hops(synthetic_received)
        assert len(hops) == 2
        assert any("Internal RFC1918 bypass anomaly" in a for a in hops[1].anomalies)

    def test_pyspf_private_ip_handling(self):
        """Verify SPF check correctly flags private non-routable IPs."""
        spf_res = verify_spf(
            client_ip="192.168.1.50",
            envelope_sender="admin@example.com",
            helo_host="mail.internal"
        )
        assert spf_res.verdict == "none"
        assert spf_res.score_penalty == 0
        assert "private" in spf_res.details.lower()

    def test_dkimpy_missing_signature(self):
        """Verify DKIM check handles missing DKIM-Signature header gracefully."""
        plain_email_bytes = b"From: user@test.org\r\nTo: dest@test.org\r\nSubject: Test\r\n\r\nHello World"
        dkim_res = verify_dkim(plain_email_bytes)
        assert dkim_res.verdict == "none"
        assert dkim_res.score_penalty > 0
        assert dkim_res.selector is None

    def test_dmarc_alignment_with_checkdmarc(self):
        """Verify DMARC alignment logic and organizational domain normalization."""
        spf_pass = SpfContract(
            verdict="pass",
            domain="mail.google.com",
            sender="service@mail.google.com",
            details="SPF pass",
            score_penalty=0
        )
        dkim_pass = DkimContract(
            verdict="pass",
            selector="2026",
            domain="google.com",
            details="DKIM pass",
            score_penalty=0
        )
        
        # Test relaxed alignment with From domain google.com
        dmarc_res = evaluate_dmarc("google.com", spf_pass, dkim_pass)
        assert dmarc_res.verdict == "pass"
        assert dmarc_res.alignment.spf_aligned is True
        assert dmarc_res.alignment.dkim_aligned is True
        assert dmarc_res.score_penalty == 0

        # Test unaligned sender
        spf_unaligned = SpfContract(
            verdict="pass",
            domain="attacker-server.com",
            sender="phish@attacker-server.com",
            details="SPF pass for attacker",
            score_penalty=0
        )
        dkim_unaligned = DkimContract(
            verdict="none",
            details="No DKIM",
            score_penalty=20
        )
        dmarc_fail = evaluate_dmarc("paypal.com", spf_unaligned, dkim_unaligned)
        assert dmarc_fail.verdict == "fail"
        assert dmarc_fail.alignment.spf_aligned is False
        assert dmarc_fail.alignment.dkim_aligned is False
        assert dmarc_fail.score_penalty >= 25
