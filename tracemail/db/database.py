import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from backend.config import settings
from backend.ingestion.parser import IngestedEmail
from backend.contracts.protocol_forensics import (
    ProtocolForensicsResult,
    MessageHeaders,
    SpfContract,
    DkimContract,
    DmarcContract,
    DmarcAlignmentContract,
    ArcContract,
    RelayHopContract,
)
from backend.contracts.origin_intelligence import (
    OriginIntelligenceResult,
    GeoLocationContract,
    AsnContract,
    HopTimingContract,
    DomainIntelContract,
    OriginThreatContract,
    CacheStatusContract,
)

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

def get_email_analysis(email_id: str, db_path: Optional[Path] = None) -> Optional[Tuple[ProtocolForensicsResult, OriginIntelligenceResult]]:
    """Retrieve stored email protocol forensics and origin intelligence from SQLite."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Query matching email (exact or prefix)
    cursor.execute("""
        SELECT * FROM emails WHERE email_id = ? OR email_id LIKE ? LIMIT 1
    """, (email_id, f"{email_id}%"))
    email_row = cursor.fetchone()
    if not email_row:
        conn.close()
        return None

    full_email_id = email_row["email_id"]

    cursor.execute("SELECT * FROM protocol_forensics WHERE email_id = ?", (full_email_id,))
    proto_row = cursor.fetchone()

    cursor.execute("SELECT * FROM origin_intelligence WHERE email_id = ?", (full_email_id,))
    origin_row = cursor.fetchone()

    conn.close()

    if not proto_row or not origin_row:
        return None

    # Reconstruct MessageHeaders
    to_addrs = json.loads(email_row["to_addresses_json"] or "[]")
    headers = MessageHeaders(
        message_id=None,
        from_address=email_row["from_address"],
        from_domain=email_row["from_domain"],
        from_display_name=None,
        reply_to=email_row["reply_to"],
        return_path=email_row["return_path"],
        to_addresses=to_addrs,
        subject=email_row["subject"] or "",
        date_header=None,
        timestamp_utc=email_row["received_timestamp_utc"],
        all_headers={
            "From": email_row["from_address"],
            "Subject": email_row["subject"] or "",
            "To": ", ".join(to_addrs) if to_addrs else ""
        }
    )

    # Reconstruct ProtocolForensicsResult
    spf = SpfContract(
        verdict=proto_row["spf_verdict"],
        domain=proto_row["spf_domain"] or email_row["from_domain"],
        client_ip=proto_row["origin_ip"],
        sender=email_row["from_address"],
        raw_record=None,
        details=proto_row["spf_details"] or "",
        score_penalty=0
    )
    dkim = DkimContract(
        verdict=proto_row["dkim_verdict"],
        selector="default",
        domain=proto_row["dkim_domain"],
        identity=None,
        algorithm=None,
        canonicalization=None,
        headers_signed=[],
        public_key_dns=None,
        details=proto_row["dkim_details"] or "",
        score_penalty=0
    )
    dmarc = DmarcContract(
        verdict=proto_row["dmarc_verdict"],
        policy=proto_row["dmarc_policy"],
        subdomain_policy=None,
        percentage=100,
        domain=email_row["from_domain"],
        alignment=DmarcAlignmentContract(
            spf_aligned=bool(proto_row["dmarc_spf_aligned"]),
            dkim_aligned=bool(proto_row["dmarc_dkim_aligned"])
        ),
        raw_record=None,
        details=proto_row["dmarc_details"] or "",
        score_penalty=0
    )
    arc = ArcContract(
        verdict=proto_row["arc_verdict"] or "none",
        instance_count=0,
        details="Retrieved from forensic database archive"
    )
    raw_hops = json.loads(proto_row["relay_hops_json"] or "[]")
    relay_hops = [RelayHopContract(**h) for h in raw_hops]

    protocol_res = ProtocolForensicsResult(
        email_id=full_email_id,
        source_filename=email_row["source_filename"],
        headers=headers,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        arc=arc,
        relay_hops=relay_hops,
        origin_ip=proto_row["origin_ip"],
        protocol_risk_subtotal=proto_row["protocol_risk_subtotal"],
        subscore_deductions=json.loads(proto_row["subscore_deductions_json"] or "{}")
    )

    # Reconstruct OriginIntelligenceResult
    geo = GeoLocationContract(
        country_code=origin_row["country_code"],
        country_name=origin_row["country_name"],
        city=origin_row["city"],
        latitude=origin_row["latitude"],
        longitude=origin_row["longitude"],
        postal_code=None,
        accuracy_radius_km=None,
        source_database="GeoLite2-City-Offline"
    )
    asn = AsnContract(
        asn=origin_row["asn"],
        as_name=None,
        as_org=origin_row["as_org"],
        network_prefix=None,
        source="GeoLite2-ASN-Offline"
    )
    timing_anomalies = json.loads(origin_row["timing_anomalies_json"] or "[]")
    hop_timing = HopTimingContract(
        total_transit_seconds=origin_row["total_transit_seconds"] or 0,
        hop_count=len(relay_hops),
        average_hop_delay_seconds=float(origin_row["total_transit_seconds"] or 0) / max(1, len(relay_hops)),
        max_delay_hop_number=None,
        max_delay_seconds=0,
        timing_anomalies=timing_anomalies
    )
    domain_intel = DomainIntelContract(
        domain=origin_row["target_domain"],
        normalized_domain=origin_row["target_domain"].lower(),
        is_punycode=False,
        decoded_punycode=None,
        homoglyph_detected=bool(origin_row["homoglyph_detected"]),
        typosquat_suspect=bool(origin_row["typosquat_suspect"]),
        created_date_utc=None,
        domain_age_days=None,
        is_recently_registered=False
    )
    threat_assessment = OriginThreatContract(
        is_tor_exit_node=bool(origin_row["is_tor_exit"]),
        is_known_proxy_vpn=False,
        ioc_watchlist_hit=False,
        matched_ioc_id=None,
        threat_reputation_score=origin_row["threat_reputation_score"] or 0
    )
    cache_status = CacheStatusContract(
        from_cache=bool(origin_row["from_cache"]),
        cache_key=f"{origin_row['target_ip'] or ''}:{origin_row['target_domain']}",
        cached_at_utc=origin_row["created_at_utc"]
    )
    origin_res = OriginIntelligenceResult(
        target_ip=origin_row["target_ip"],
        target_domain=origin_row["target_domain"],
        geolocation=geo,
        asn=asn,
        hop_timing=hop_timing,
        domain_intel=domain_intel,
        threat_assessment=threat_assessment,
        cache_status=cache_status,
        origin_risk_subtotal=origin_row["origin_risk_subtotal"]
    )

    return (protocol_res, origin_res)

