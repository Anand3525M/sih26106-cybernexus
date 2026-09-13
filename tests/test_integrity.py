import pytest
import json
from pathlib import Path
from cases.integrity import IntegrityLedger

def test_ledger_integrity_and_tamper_detection(tmp_path):
    ledger_path = tmp_path / "test_ledger.json"
    ledger = IntegrityLedger(ledger_path)

    # Add two records
    b1 = ledger.add_verdict("EMAIL_001", "SPOOFED", 85)
    b2 = ledger.add_verdict("EMAIL_002", "LEGITIMATE", 12)

    # 1. Verify clean ledger
    is_intact, msg = ledger.verify_chain()
    assert is_intact is True
    assert "Verified" in msg

    # 2. Simulate malicious record modification in storage
    with open(ledger_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data[0]["threat_score"] = 0  # Hacker changes 85 -> 0
    with open(ledger_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    # 3. Verify tamper detection triggers
    is_intact, msg = ledger.verify_chain()
    assert is_intact is False
    assert "Tampering detected at block #1" in msg
