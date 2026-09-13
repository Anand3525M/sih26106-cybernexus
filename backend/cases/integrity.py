import hashlib
import json
from pathlib import Path
from typing import List, Dict, Tuple

GENESIS_HASH = "0" * 64

class IntegrityLedger:
    def __init__(self, storage_file: Path):
        self.storage_file = Path(storage_file)
        if not self.storage_file.exists():
            self.storage_file.parent.mkdir(parents=True, exist_ok=True)
            self._save_chain([])

    def _save_chain(self, chain: List[Dict]):
        with open(self.storage_file, "w", encoding="utf-8") as f:
            json.dump(chain, f, indent=2)

    def load_chain(self) -> List[Dict]:
        if not self.storage_file.exists():
            return []
        with open(self.storage_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def compute_record_hash(self, record_id: str, verdict: str, threat_score: int, prev_hash: str) -> str:
        payload = f"{record_id}|{verdict}|{threat_score}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def add_verdict(self, record_id: str, verdict: str, threat_score: int) -> Dict:
        chain = self.load_chain()
        prev_hash = chain[-1]["current_hash"] if chain else GENESIS_HASH
        current_hash = self.compute_record_hash(record_id, verdict, threat_score, prev_hash)
        
        block = {
            "index": len(chain) + 1,
            "record_id": record_id,
            "verdict": verdict,
            "threat_score": threat_score,
            "prev_hash": prev_hash,
            "current_hash": current_hash
        }
        chain.append(block)
        self._save_chain(chain)
        return block

    def verify_chain(self) -> Tuple[bool, str]:
        chain = self.load_chain()
        if not chain:
            return True, "Ledger empty — intact."

        expected_prev = GENESIS_HASH
        for idx, block in enumerate(chain):
            if block["prev_hash"] != expected_prev:
                return False, f"Broken link at block #{block['index']}: prev_hash mismatch."
            recalculated = self.compute_record_hash(
                block["record_id"], block["verdict"], block["threat_score"], block["prev_hash"]
            )
            if recalculated != block["current_hash"]:
                return False, f"Tampering detected at block #{block['index']}: invalid payload hash."
            expected_prev = block["current_hash"]

        return True, f"Verified: All {len(chain)} records intact and cryptographically chained."
