import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.config import settings
from backend.contracts.protocol_forensics import ProtocolForensicsResult
from backend.contracts.origin_intelligence import OriginIntelligenceResult
from backend.cases.ledger import verify_chain_integrity, append_audit_block

def generate_court_report(
    protocol_res: ProtocolForensicsResult,
    origin_res: OriginIntelligenceResult,
    investigator: str = "Lead Forensic Analyst"
) -> Path:
    """Generate a court-admissible forensic PDF dossier backed by cryptographic chain."""
    pdf_filename = f"forensic_dossier_{protocol_res.email_id[:16]}.pdf"
    output_path = settings.REPORTS_DIR / pdf_filename
    
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    bold_body = ParagraphStyle(
        'BoldBody',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("TraceMail — Forensic Intelligence Dossier", title_style))
    story.append(Paragraph(f"<b>National Cyber Security Track | Smart India Hackathon</b>", body_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563eb'), spaceAfter=12))

    # Executive Summary Table
    meta_data = [
        [Paragraph("<b>Target Email ID (SHA-256)</b>", bold_body), Paragraph(protocol_res.email_id, body_style)],
        [Paragraph("<b>Source Filename</b>", bold_body), Paragraph(protocol_res.source_filename, body_style)],
        [Paragraph("<b>From Address</b>", bold_body), Paragraph(protocol_res.headers.from_address, body_style)],
        [Paragraph("<b>Subject Line</b>", bold_body), Paragraph(protocol_res.headers.subject or "(No Subject)", body_style)],
        [Paragraph("<b>Protocol Risk Score</b>", bold_body), Paragraph(f"<b>{protocol_res.protocol_risk_subtotal}/100</b>", bold_body)],
        [Paragraph("<b>Origin Risk Score</b>", bold_body), Paragraph(f"<b>{origin_res.origin_risk_subtotal}/100</b>", bold_body)],
        [Paragraph("<b>Originating IP / Country</b>", bold_body), Paragraph(f"{origin_res.target_ip or 'None'} — {origin_res.geolocation.country_name} ({origin_res.geolocation.country_code})", body_style)],
        [Paragraph("<b>Offline Geolocation Engine</b>", bold_body), Paragraph(origin_res.geolocation.source_database, body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[160, 380])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # Protocol Forensics Breakdown
    story.append(Paragraph("1. RFC Protocol Cryptographic Authentication", h2_style))
    proto_data = [
        ["Protocol", "Verdict", "Alignment / Domain", "Forensic Assessment"],
        ["SPF (RFC 7208)", protocol_res.spf.verdict.upper(), protocol_res.spf.domain, protocol_res.spf.details[:60]],
        ["DKIM (RFC 6376)", protocol_res.dkim.verdict.upper(), protocol_res.dkim.domain or "N/A", protocol_res.dkim.details[:60]],
        ["DMARC (RFC 7489)", protocol_res.dmarc.verdict.upper(), f"SPF: {protocol_res.dmarc.alignment.spf_aligned}, DKIM: {protocol_res.dmarc.alignment.dkim_aligned}", protocol_res.dmarc.details[:60]],
        ["ARC (RFC 8617)", protocol_res.arc.verdict.upper(), f"Hops: {protocol_res.arc.instance_count}", protocol_res.arc.details[:60]],
    ]
    proto_table = Table(proto_data, colWidths=[90, 70, 150, 230])
    proto_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(proto_table)
    story.append(Spacer(1, 14))

    # Transmission Hop Timing
    story.append(Paragraph("2. MTA Hop Transmission & Transit Delays", h2_style))
    hop_rows = [["Hop #", "From Host", "By Host", "IP", "Delay (sec)", "Anomalies"]]
    for h in protocol_res.relay_hops:
        hop_rows.append([
            str(h.hop_number),
            (h.from_host or "-")[:18],
            (h.by_host or "-")[:18],
            h.ip or "-",
            str(h.transit_delay_seconds),
            "; ".join(h.anomalies)[:25] if h.anomalies else "Clean"
        ])
    if len(hop_rows) == 1:
        hop_rows.append(["1", "Direct Connection", "Recipient MX", origin_res.target_ip or "-", "0", "None"])

    hop_table = Table(hop_rows, colWidths=[40, 110, 110, 90, 60, 130])
    hop_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(hop_table)
    story.append(Spacer(1, 14))

    # Cryptographic Chain of Custody & Audit Verification
    story.append(Paragraph("3. Immutable Cryptographic Chain of Custody", h2_style))
    audit_integrity = verify_chain_integrity()
    audit_data = [
        [Paragraph("<b>Audit Ledger Status</b>", bold_body), Paragraph("VERIFIED — TAMPER-FREE" if audit_integrity.chain_valid else "CORRUPTED / TAMPERED", bold_body)],
        [Paragraph("<b>Total Immutable Blocks</b>", bold_body), Paragraph(str(audit_integrity.total_blocks), body_style)],
        [Paragraph("<b>Genesis Anchor Hash</b>", bold_body), Paragraph(audit_integrity.genesis_hash, body_style)],
        [Paragraph("<b>Ledger Head Hash</b>", bold_body), Paragraph(audit_integrity.latest_block_hash, body_style)],
        [Paragraph("<b>Audit Timestamp (UTC)</b>", bold_body), Paragraph(audit_integrity.verification_timestamp_utc, body_style)],
    ]
    audit_table = Table(audit_data, colWidths=[160, 380])
    audit_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(audit_table)

    # Build PDF
    doc.build(story)

    # Log report generation in audit ledger
    append_audit_block(
        event_type="REPORT_GENERATED",
        actor=investigator,
        entity_id=protocol_res.email_id,
        entity_type="report",
        payload={
            "email_id": protocol_res.email_id,
            "report_file": pdf_filename,
            "chain_head": audit_integrity.latest_block_hash
        }
    )

    return output_path
