import sqlite3
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any

from backend.config import settings
from backend.cases.ledger import append_audit_block
from backend.contracts.case_management import (
    CaseCreateInput,
    CaseUpdateInput,
    CaseDetailContract,
    CaseNoteContract,
)

def get_cases_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(settings.DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL,
            priority TEXT NOT NULL,
            investigator TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            linked_emails_json TEXT NOT NULL,
            ioc_watchlist_json TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            notes_json TEXT NOT NULL,
            audit_head TEXT
        )
    """)
    conn.commit()
    return conn

def create_case(input_data: CaseCreateInput) -> CaseDetailContract:
    case_id = f"CASE-{datetime.now().year}-{str(uuid.uuid4())[:8].upper()}"
    now_utc = datetime.now(timezone.utc).isoformat()
    
    # Audit log entry for case creation
    audit_block = append_audit_block(
        event_type="CASE_CREATED",
        actor=input_data.investigator,
        entity_id=case_id,
        entity_type="case",
        payload={
            "case_id": case_id,
            "title": input_data.title,
            "priority": input_data.priority,
            "initial_emails": input_data.initial_email_ids
        }
    )

    conn = get_cases_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO cases (
            case_id, title, description, status, priority, investigator,
            created_at_utc, updated_at_utc, linked_emails_json,
            ioc_watchlist_json, tags_json, notes_json, audit_head
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_id,
        input_data.title,
        input_data.description,
        "OPEN",
        input_data.priority,
        input_data.investigator,
        now_utc,
        now_utc,
        json.dumps(input_data.initial_email_ids),
        json.dumps([]),
        json.dumps(input_data.tags),
        json.dumps([]),
        audit_block.block_hash
    ))
    conn.commit()
    conn.close()

    return CaseDetailContract(
        case_id=case_id,
        title=input_data.title,
        description=input_data.description,
        status="OPEN",
        priority=input_data.priority,
        investigator=input_data.investigator,
        created_at_utc=now_utc,
        updated_at_utc=now_utc,
        linked_email_ids=input_data.initial_email_ids,
        ioc_watchlist=[],
        tags=input_data.tags,
        notes=[],
        audit_chain_head=audit_block.block_hash
    )

def get_case(case_id: str) -> Optional[CaseDetailContract]:
    conn = get_cases_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None

    raw_notes = json.loads(row["notes_json"])
    notes = [CaseNoteContract.model_validate(n) for n in raw_notes]

    return CaseDetailContract(
        case_id=row["case_id"],
        title=row["title"],
        description=row["description"] or "",
        status=row["status"],
        priority=row["priority"],
        investigator=row["investigator"],
        created_at_utc=row["created_at_utc"],
        updated_at_utc=row["updated_at_utc"],
        linked_email_ids=json.loads(row["linked_emails_json"]),
        ioc_watchlist=json.loads(row["ioc_watchlist_json"]),
        tags=json.loads(row["tags_json"]),
        notes=notes,
        audit_chain_head=row["audit_head"]
    )

def update_case(case_id: str, updates: CaseUpdateInput) -> Optional[CaseDetailContract]:
    current = get_case(case_id)
    if not current:
        return None

    now_utc = datetime.now(timezone.utc).isoformat()
    new_status = updates.status or current.status
    new_priority = updates.priority or current.priority
    
    # Merge emails and IOCs
    emails = list(set(current.linked_email_ids + updates.added_email_ids))
    iocs = list(set(current.ioc_watchlist + updates.added_iocs))
    
    notes_list = [n.model_dump() for n in current.notes]
    if updates.new_note:
        notes_list.append({
            "note_id": str(uuid.uuid4())[:8],
            "author": updates.investigator,
            "timestamp_utc": now_utc,
            "content": updates.new_note
        })

    # Log to audit chain
    audit_block = append_audit_block(
        event_type="CASE_MODIFIED",
        actor=updates.investigator,
        entity_id=case_id,
        entity_type="case",
        payload={
            "case_id": case_id,
            "status": new_status,
            "priority": new_priority,
            "added_emails": updates.added_email_ids,
            "added_iocs": updates.added_iocs,
            "has_new_note": bool(updates.new_note)
        }
    )

    conn = get_cases_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE cases SET
            status = ?,
            priority = ?,
            updated_at_utc = ?,
            linked_emails_json = ?,
            ioc_watchlist_json = ?,
            notes_json = ?,
            audit_head = ?
        WHERE case_id = ?
    """, (
        new_status,
        new_priority,
        now_utc,
        json.dumps(emails),
        json.dumps(iocs),
        json.dumps(notes_list),
        audit_block.block_hash,
        case_id
    ))
    conn.commit()
    conn.close()

    return get_case(case_id)
