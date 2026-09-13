import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from backend.config import settings
from backend.ingestion.parser import IngestedEmail
from backend.contracts.protocol_forensics import ProtocolForensicsResult
from backend.contracts.origin_intelligence import OriginIntelligenceResult

def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target_path = db_path or settings.DB_PATH
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(db_path: Optional[Path] = None) -> None:
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
    -- 1. Ingested Emails Table
    CREATE TABLE IF NOT EXISTS emails (
        email_id TEXT PRIMARY KEY,
        sha256 TEXT NOT NULL UNIQUE,
        source_filename TEXT NOT NULL,
        received_timestamp_utc TEXT NOT NULL,
        from_address TEXT NOT NULL,
        from_domain TEXT NOT NULL,
        reply_to TEXT,
        return_path TEXT,
        to_addresses_json TEXT,
        subject TEXT,
        body_plain TEXT,
        body_html TEXT,
        extracted_urls_json TEXT,
        attachments_json TEXT,
        created_at_utc TEXT NOT NULL
    );

    -- 2. Protocol Forensics Table
    CREATE TABLE IF NOT EXISTS protocol_forensics (
        email_id TEXT PRIMARY KEY,
        spf_verdict TEXT NOT NULL,
        spf_domain TEXT,
        spf_details TEXT,
        dkim_verdict TEXT NOT NULL,
        dkim_domain TEXT,
        dkim_details TEXT,
        dmarc_verdict TEXT NOT NULL,
        dmarc_policy TEXT,
        dmarc_spf_aligned INTEGER NOT NULL,
        dmarc_dkim_aligned INTEGER NOT NULL,
        dmarc_details TEXT,
        arc_verdict TEXT,
        origin_ip TEXT,
        relay_hops_json TEXT,
        protocol_risk_subtotal INTEGER NOT NULL,
        subscore_deductions_json TEXT,
        created_at_utc TEXT NOT NULL,
        FOREIGN KEY(email_id) REFERENCES emails(email_id) ON DELETE CASCADE
    );

    -- 3. Origin Intelligence Table
    CREATE TABLE IF NOT EXISTS origin_intelligence (
        email_id TEXT PRIMARY KEY,
        target_ip TEXT,
        target_domain TEXT NOT NULL,
        country_code TEXT,
        country_name TEXT,
        city TEXT,
        latitude REAL,
        longitude REAL,
        asn INTEGER,
        as_org TEXT,
        total_transit_seconds INTEGER,
        timing_anomalies_json TEXT,
        homoglyph_detected INTEGER,
        typosquat_suspect INTEGER,
        is_tor_exit INTEGER,
        threat_reputation_score INTEGER,
        origin_risk_subtotal INTEGER NOT NULL,
        from_cache INTEGER NOT NULL,
        created_at_utc TEXT NOT NULL,
        FOREIGN KEY(email_id) REFERENCES emails(email_id) ON DELETE CASCADE
    );

    -- 4. Investigation Cases Table
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'OPEN',
        priority TEXT NOT NULL DEFAULT 'MEDIUM',
        investigator TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL,
        linked_emails_json TEXT NOT NULL,
        ioc_watchlist_json TEXT NOT NULL,
        tags_json TEXT NOT NULL,
        notes_json TEXT NOT NULL,
        audit_head TEXT
    );
    """)

    conn.commit()
    conn.close()

def store_email_analysis(
    ingested: IngestedEmail,
    protocol_res: ProtocolForensicsResult,
    origin_res: OriginIntelligenceResult,
    db_path: Optional[Path] = None
) -> None:
    """Persist ingested email, protocol forensics, and origin intelligence in SQLite."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now_utc = datetime.now(timezone.utc).isoformat()

    # 1. Store Email Record
    cursor.execute("""
        INSERT INTO emails (
            email_id, sha256, source_filename, received_timestamp_utc,
            from_address, from_domain, reply_to, return_path, to_addresses_json,
            subject, body_plain, body_html, extracted_urls_json, attachments_json,
            created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(email_id) DO UPDATE SET
            subject = excluded.subject,
            from_address = excluded.from_address
    """, (
        ingested.email_id,
        ingested.email_id,
        ingested.source_filename,
        ingested.headers.timestamp_utc or now_utc,
        ingested.headers.from_address,
        ingested.headers.from_domain,
        ingested.headers.reply_to,
        ingested.headers.return_path,
        json.dumps(ingested.headers.to_addresses),
        ingested.headers.subject,
        ingested.body_plain,
        ingested.body_html,
        json.dumps(ingested.extracted_urls),
        json.dumps(ingested.attachments),
        now_utc
    ))

    # 2. Store Protocol Forensics
    cursor.execute("""
        INSERT INTO protocol_forensics (
            email_id, spf_verdict, spf_domain, spf_details,
            dkim_verdict, dkim_domain, dkim_details,
            dmarc_verdict, dmarc_policy, dmarc_spf_aligned, dmarc_dkim_aligned, dmarc_details,
            arc_verdict, origin_ip, relay_hops_json, protocol_risk_subtotal,
            subscore_deductions_json, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(email_id) DO UPDATE SET
            protocol_risk_subtotal = excluded.protocol_risk_subtotal
    """, (
        protocol_res.email_id,
        protocol_res.spf.verdict,
        protocol_res.spf.domain,
        protocol_res.spf.details,
        protocol_res.dkim.verdict,
        protocol_res.dkim.domain,
        protocol_res.dkim.details,
        protocol_res.dmarc.verdict,
        protocol_res.dmarc.policy,
        1 if protocol_res.dmarc.alignment.spf_aligned else 0,
        1 if protocol_res.dmarc.alignment.dkim_aligned else 0,
        protocol_res.dmarc.details,
        protocol_res.arc.verdict,
        protocol_res.origin_ip,
        json.dumps([h.model_dump() for h in protocol_res.relay_hops]),
        protocol_res.protocol_risk_subtotal,
        json.dumps(protocol_res.subscore_deductions),
        now_utc
    ))

    # 3. Store Origin Intelligence
    cursor.execute("""
        INSERT INTO origin_intelligence (
            email_id, target_ip, target_domain, country_code, country_name, city,
            latitude, longitude, asn, as_org, total_transit_seconds, timing_anomalies_json,
            homoglyph_detected, typosquat_suspect, is_tor_exit, threat_reputation_score,
            origin_risk_subtotal, from_cache, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(email_id) DO UPDATE SET
            origin_risk_subtotal = excluded.origin_risk_subtotal
    """, (
        protocol_res.email_id,
        origin_res.target_ip,
        origin_res.target_domain,
        origin_res.geolocation.country_code,
        origin_res.geolocation.country_name,
        origin_res.geolocation.city,
        origin_res.geolocation.latitude,
        origin_res.geolocation.longitude,
        origin_res.asn.asn,
        origin_res.asn.as_org,
        origin_res.hop_timing.total_transit_seconds,
        json.dumps(origin_res.hop_timing.timing_anomalies),
        1 if origin_res.domain_intel.homoglyph_detected else 0,
        1 if origin_res.domain_intel.typosquat_suspect else 0,
        1 if origin_res.threat_assessment.is_tor_exit_node else 0,
        origin_res.threat_assessment.threat_reputation_score,
        origin_res.origin_risk_subtotal,
        1 if origin_res.cache_status.from_cache else 0,
        now_utc
    ))

    conn.commit()
    conn.close()

def list_cases(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve all investigation cases with associated email details and verdicts."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM cases ORDER BY created_at_utc DESC")
    rows = cursor.fetchall()
    
    cases_result = []
    for r in rows:
        case_data = dict(r)
        linked_ids = json.loads(case_data.get("linked_emails_json", "[]"))
        
        # Retrieve associated email verdicts for each linked email
        associated_verdicts = []
        for eid in linked_ids:
            cursor.execute("""
                SELECT e.email_id, e.subject, e.from_address, p.dmarc_verdict, p.protocol_risk_subtotal
                FROM emails e
                LEFT JOIN protocol_forensics p ON e.email_id = p.email_id
                WHERE e.email_id = ?
            """, (eid,))
            email_row = cursor.fetchone()
            if email_row:
                associated_verdicts.append(dict(email_row))

        case_data["associated_email_verdicts"] = associated_verdicts
        case_data["linked_emails"] = linked_ids
        case_data["ioc_watchlist"] = json.loads(case_data.get("ioc_watchlist_json", "[]"))
        case_data["tags"] = json.loads(case_data.get("tags_json", "[]"))
        case_data["notes"] = json.loads(case_data.get("notes_json", "[]"))
        cases_result.append(case_data)

    conn.close()
    return cases_result
