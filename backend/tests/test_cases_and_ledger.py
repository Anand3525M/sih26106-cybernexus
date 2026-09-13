import pytest
from backend.cases.ledger import (
    init_ledger_if_empty,
    append_audit_block,
    verify_chain_integrity,
    simulate_tamper,
)
from backend.cases.manager import create_case, get_case, update_case
from backend.contracts.case_management import CaseCreateInput, CaseUpdateInput

class TestCasesAndAuditLedger:
    def test_audit_chain_genesis_and_append(self):
        """Verify genesis block initialization and sequential block appending."""
        init_ledger_if_empty()
        integrity = verify_chain_integrity()
        assert integrity.chain_valid is True
        assert integrity.total_blocks >= 1
        assert integrity.genesis_hash is not None

        # Append two blocks
        b1 = append_audit_block(
            event_type="EMAIL_INGESTED",
            actor="analyst_alice",
            entity_id="email-sha-001",
            entity_type="email",
            payload={"filename": "phish.eml", "risk": 85}
        )
        assert b1.index == 1
        assert len(b1.block_hash) == 64

        b2 = append_audit_block(
            event_type="PROTOCOL_EVALUATED",
            actor="forensic_daemon",
            entity_id="email-sha-001",
            entity_type="email",
            payload={"spf": "fail", "dkim": "fail"}
        )
        assert b2.index == 2
        assert b2.prev_hash == b1.block_hash

        # Verify chain integrity
        verif = verify_chain_integrity()
        assert verif.chain_valid is True
        assert verif.total_blocks == 3
        assert verif.tampered_block_index is None

    def test_tamper_detection_pinpoints_corrupted_block(self):
        """Simulate tampering in historical block and verify immediate rejection."""
        # Append blocks
        append_audit_block("EMAIL_INGESTED", "investigator", "E1", "email", {"val": 1})
        append_audit_block("CASE_CREATED", "investigator", "C1", "case", {"val": 2})
        append_audit_block("REPORT_GENERATED", "investigator", "R1", "report", {"val": 3})

        pre_tamper = verify_chain_integrity()
        assert pre_tamper.chain_valid is True

        # Maliciously modify Block #1
        tamper_success = simulate_tamper(block_index=1, forged_actor="malicious_insider")
        assert tamper_success is True

        # Verification MUST fail and report block_index 1
        post_tamper = verify_chain_integrity()
        assert post_tamper.chain_valid is False
        assert post_tamper.tampered_block_index == 1
        assert "tamper" in post_tamper.tamper_reason.lower() or "invalid" in post_tamper.tamper_reason.lower()

    def test_case_lifecycle_and_audit_head(self):
        """Verify case creation, update, and cryptographic anchor linking."""
        case_in = CaseCreateInput(
            title="Operation Silver Wire",
            description="Phishing campaign targeting treasury wire authorizations",
            investigator="detective_bob",
            priority="HIGH",
            initial_email_ids=["email-sha-123"],
            tags=["BEC", "WireFraud"]
        )
        case = create_case(case_in)
        assert case.case_id.startswith("CASE-")
        assert case.status == "OPEN"
        assert case.audit_chain_head is not None

        # Update case with a note
        update_in = CaseUpdateInput(
            status="INVESTIGATING",
            new_note="Confirmed spoofed domain hosted on bulletproof provider",
            investigator="detective_bob"
        )
        updated = update_case(case.case_id, update_in)
        assert updated is not None
        assert updated.status == "INVESTIGATING"
        assert len(updated.notes) == 1
        assert updated.notes[0].author == "detective_bob"
        assert updated.audit_chain_head != case.audit_chain_head
