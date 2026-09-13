import pytest
from pathlib import Path
from backend.config import settings
from backend.ingestion.parser import parse_eml_file, parse_eml_bytes
from backend.forensics.protocols import evaluate_email_protocols, parse_relay_hops

class TestProtocolForensics:
    def test_parse_legit_google_eml(self):
        sample_path = settings.SAMPLES_DIR / "legit_google.eml"
        assert sample_path.exists(), f"Sample file missing: {sample_path}"

        ingested = parse_eml_file(sample_path)
        assert "google.com" in ingested.headers.from_domain
        assert len(ingested.email_id) == 64
        assert len(ingested.raw_received_headers) > 0

        res = evaluate_email_protocols(ingested)
        assert "google.com" in res.headers.from_domain
        assert res.protocol_risk_subtotal >= 0
        assert len(res.relay_hops) > 0

    def test_parse_spoofed_paypal_eml(self):
        sample_path = settings.SAMPLES_DIR / "spoof_paypal.eml"
        assert sample_path.exists(), f"Sample file missing: {sample_path}"

        ingested = parse_eml_file(sample_path)
        res = evaluate_email_protocols(ingested)

        # In spoofed PayPal email, DMARC alignment should fail
        assert res.dmarc.alignment.dkim_aligned is False
        assert res.protocol_risk_subtotal > 20
        assert "dmarc_penalty" in res.subscore_deductions

    def test_relay_hop_chronological_ordering_and_anomalies(self):
        sample_path = settings.SAMPLES_DIR / "legit_google.eml"
        ingested = parse_eml_file(sample_path)
        
        hops, origin_ip = parse_relay_hops(ingested.raw_received_headers)
        assert len(hops) > 0
        assert hops[0].hop_number == 1
        # Check all hops have valid attributes
        for h in hops:
            assert isinstance(h.transit_delay_seconds, int)
            assert h.transit_delay_seconds >= 0
