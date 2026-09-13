import sqlite3
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from backend.config import settings
from backend.contracts.case_management import (
    AuditEventInput,
    AuditBlockContract,
    AuditIntegrityContract,
)

GENESIS_PREV_HASH = "0" * 64

def get_ledger_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(settings.DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_blocks (
            block_index INTEGER PRIMARY KEY,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def compute_payload_hash(payload: Dict[str, Any]) -> str:
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

def compute_block_hash(
    index: int,
    timestamp_utc: str,
    event_type: str,
    actor: str,
    entity_id: str,
    payload_hash: str,
    prev_hash: str
) -> str:
    seed = f"{index}:{timestamp_utc}:{event_type}:{actor}:{entity_id}:{payload_hash}:{prev_hash}:{settings.AUDIT_SALT}"
    return hashlib.sha256(seed.encode('utf-8')).hexdigest()

def init_ledger_if_empty() -> None:
    conn = get_ledger_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_blocks")
    count = cur.fetchone()[0]
    
    if count == 0:
        # Create Genesis Block
        ts = "2026-01-01T00:00:00Z"
        payload = {"genesis": "TraceMail Root Anchor", "track": settings.TRACK}
        p_hash = compute_payload_hash(payload)
        b_hash = compute_block_hash(0, ts, "GENESIS", "SYSTEM_ROOT", "0", p_hash, GENESIS_PREV_HASH)
        
        cur.execute("""
            INSERT INTO audit_blocks (
                block_index, timestamp_utc, event_type, actor, entity_id, entity_type,
                payload_json, payload_hash, prev_hash, block_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (0, ts, "GENESIS", "SYSTEM_ROOT", "0", "ROOT", json.dumps(payload), p_hash, GENESIS_PREV_HASH, b_hash))
        conn.commit()
    conn.close()

def append_audit_block(
    event_type: str,
    actor: str,
    entity_id: str,
    entity_type: str,
    payload: Dict[str, Any]
) -> AuditBlockContract:
    """Append an immutable, cryptographic audit entry to the forward hash chain."""
    init_ledger_if_empty()
    conn = get_ledger_db()
    cur = conn.cursor()

    cur.execute("SELECT block_index, block_hash FROM audit_blocks ORDER BY block_index DESC LIMIT 1")
    last_row = cur.fetchone()
    last_index = last_row["block_index"]
    prev_hash = last_row["block_hash"]

    new_index = last_index + 1
    now_utc = datetime.now(timezone.utc).isoformat()
    p_hash = compute_payload_hash(payload)
    b_hash = compute_block_hash(new_index, now_utc, event_type, actor, entity_id, p_hash, prev_hash)

    cur.execute("""
        INSERT INTO audit_blocks (
            block_index, timestamp_utc, event_type, actor, entity_id, entity_type,
            payload_json, payload_hash, prev_hash, block_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (new_index, now_utc, event_type, actor, entity_id, entity_type, json.dumps(payload), p_hash, prev_hash, b_hash))
    conn.commit()
    conn.close()

    return AuditBlockContract(
        index=new_index,
        timestamp_utc=now_utc,
        event_type=event_type,
        actor=actor,
        entity_id=entity_id,
        entity_type=entity_type,
        payload_hash=p_hash,
        prev_hash=prev_hash,
        block_hash=b_hash
    )

def verify_chain_integrity() -> AuditIntegrityContract:
    """Walk every block in the ledger and verify cryptographic hashes and linkage."""
    init_ledger_if_empty()
    conn = get_ledger_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC")
    rows = cur.fetchall()
    conn.close()

    total_blocks = len(rows)
    now_utc = datetime.now(timezone.utc).isoformat()

    if total_blocks == 0:
        return AuditIntegrityContract(
            chain_valid=True,
            total_blocks=0,
            verified_blocks=0,
            genesis_hash=GENESIS_PREV_HASH,
            latest_block_hash=GENESIS_PREV_HASH,
            tampered_block_index=None,
            tamper_reason=None,
            verification_timestamp_utc=now_utc
        )

    genesis_hash = rows[0]["block_hash"]
    latest_hash = rows[-1]["block_hash"]
    expected_prev = GENESIS_PREV_HASH

    for i, r in enumerate(rows):
        idx = r["block_index"]
        ts = r["timestamp_utc"]
        event = r["event_type"]
        actor = r["actor"]
        entity_id = r["entity_id"]
        p_json = r["payload_json"]
        stored_p_hash = r["payload_hash"]
        stored_prev = r["prev_hash"]
        stored_b_hash = r["block_hash"]

        # 1. Verify prev_hash linkage
        if stored_prev != expected_prev:
            return AuditIntegrityContract(
                chain_valid=False,
                total_blocks=total_blocks,
                verified_blocks=i,
                genesis_hash=genesis_hash,
                latest_block_hash=latest_hash,
                tampered_block_index=idx,
                tamper_reason=f"Broken prev_hash linkage at block #{idx}. Expected {expected_prev[:16]}..., found {stored_prev[:16]}...",
                verification_timestamp_utc=now_utc
            )

        # 2. Verify payload hash
        payload_dict = json.loads(p_json)
        recalculated_p_hash = compute_payload_hash(payload_dict)
        if recalculated_p_hash != stored_p_hash:
            return AuditIntegrityContract(
                chain_valid=False,
                total_blocks=total_blocks,
                verified_blocks=i,
                genesis_hash=genesis_hash,
                latest_block_hash=latest_hash,
                tampered_block_index=idx,
                tamper_reason=f"Payload tampering detected at block #{idx}. Payload hash mismatch.",
                verification_timestamp_utc=now_utc
            )

        # 3. Verify block hash calculation
        recalculated_b_hash = compute_block_hash(idx, ts, event, actor, entity_id, stored_p_hash, stored_prev)
        if recalculated_b_hash != stored_b_hash:
            return AuditIntegrityContract(
                chain_valid=False,
                total_blocks=total_blocks,
                verified_blocks=i,
                genesis_hash=genesis_hash,
                latest_block_hash=latest_hash,
                tampered_block_index=idx,
                tamper_reason=f"Cryptographic hash invalid at block #{idx}. Content or timestamp altered.",
                verification_timestamp_utc=now_utc
            )

        expected_prev = stored_b_hash

    return AuditIntegrityContract(
        chain_valid=True,
        total_blocks=total_blocks,
        verified_blocks=total_blocks,
        genesis_hash=genesis_hash,
        latest_block_hash=latest_hash,
        tampered_block_index=None,
        tamper_reason=None,
        verification_timestamp_utc=now_utc
    )

def simulate_tamper(block_index: int, forged_actor: str = "malicious_insider") -> bool:
    """Artificially alter an immutable block to demonstrate court tamper detection."""
    conn = get_ledger_db()
    cur = conn.cursor()
    cur.execute("SELECT block_index FROM audit_blocks WHERE block_index = ?", (block_index,))
    if not cur.fetchone():
        conn.close()
        return False
    
    cur.execute("UPDATE audit_blocks SET actor = ? WHERE block_index = ?", (forged_actor, block_index))
    conn.commit()
    conn.close()
    return True
