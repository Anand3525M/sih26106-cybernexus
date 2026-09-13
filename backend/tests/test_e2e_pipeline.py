import pytest
from pathlib import Path
from backend.config import settings
from backend.ingestion.parser import parse_eml_file
from backend.forensics.protocols import evaluate_email_protocols
from backend.intelligence.geoip import analyze_origin_intelligence
from backend.cases.manager import create_case
from backend.contracts.case_management import CaseCreateInput
from backend.cases.ledger import verify_chain_integrity
from backend.reports.generator import generate_court_report

class TestE2EPipeline:
    def test_full_forensic_pipeline_and_pdf_generation(self):
        """End-to-end test: EML Ingestion -> Protocols -> Origin -> Case -> ReportLab PDF -> Audit Ledger."""
        # 1. Ingest Sample Email
        sample_path = settings.SAMPLES_DIR / "spoof_paypal.eml"
        assert sample_path.exists(), f"Sample missing: {sample_path}"
        ingested = parse_eml_file(sample_path)
        assert len(ingested.email_id) == 64

        # 2. Protocol Forensics (Module 1)
        proto_res = evaluate_email_protocols(ingested)
        assert proto_res.email_id == ingested.email_id
        assert proto_res.dmarc.verdict in ["pass", "fail"]

        # 3. Origin Intelligence (Module 2)
        origin_res = analyze_origin_intelligence(
            ip=proto_res.origin_ip or "185.220.101.42",
            domain=ingested.headers.from_domain,
            hops=proto_res.relay_hops
        )
        assert origin_res.geolocation.country_code is not None

        # 4. Case Management (Module 3)
        case = create_case(CaseCreateInput(
            title="Investigation: Spoofed PayPal Notification",
            description="Phishing email targeting credentials via lookalike domain",
            investigator="Agent Smith",
            priority="HIGH",
            initial_email_ids=[ingested.email_id],
            tags=["Phishing", "CredentialHarvesting"]
        ))
        assert case.case_id.startswith("CASE-")

        # 5. Court-Admissible Forensic PDF Dossier Generation
        pdf_path = generate_court_report(
            protocol_res=proto_res,
            origin_res=origin_res,
            investigator="Agent Smith"
        )
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 1000  # Generated PDF has substantive content

        # 6. Cryptographic Chain of Custody Verification
        audit_check = verify_chain_integrity()
        assert audit_check.chain_valid is True
        assert audit_check.total_blocks >= 2
        assert audit_check.tampered_block_index is None
