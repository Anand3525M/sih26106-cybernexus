"""
TraceMail Tactical Dashboard Compatibility & Threat Scenarios
Provides preset defense scenarios, STIX 2.1 IOC bundle generation,
and Gotham graph correlation for the Palantir-style web interface.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from backend.contracts.protocol_forensics import ProtocolForensicsResult
from backend.contracts.origin_intelligence import OriginIntelligenceResult
from backend.contracts.risk_scoring import RiskFusionResult
from backend.intelligence.geoip import resolve_offline_ip

# Preset Tactical Threat Scenarios for SIH Defense Demo
PRESET_SCENARIOS = {
    "alpha": {
        "id": "alpha",
        "title": "Scenario Alpha: PayPal Account Takeover",
        "threat_type": "Credential Harvest / Tor Exit Origin",
        "target": "victim@enterprise.corp",
        "attacker": "security@paypaI-support.com",
        "raw_email": """Return-Path: <security@paypaI-support.com>
Delivered-To: victim@enterprise.corp
Received: from mail.bulletproof-relay.ru (mail.bulletproof-relay.ru [185.220.101.42])
\tby mx.targetorg.in (Postfix) with ESMTP id 4X9L10z
\tfor <victim@enterprise.corp>; Fri, 11 Sep 2026 18:24:05 +0000
Authentication-Results: mx.targetorg.in;
\tspf=fail (sender IP 185.220.101.42 is not authorized) smtp.mailfrom=security@paypaI-support.com;
\tdkim=fail (bad signature or missing key) header.d=paypaI-support.com;
\tdmarc=fail (action=reject) header.from=paypaI-support.com
From: "PayPal Security Support" <security@paypaI-support.com>
Reply-To: harvest-ops@bulletproof-relay.ru
To: victim@corporation.org
Subject: [CRITICAL] Your PayPal Account Has Been Restricted
Date: Fri, 11 Sep 2026 18:24:00 +0000
Message-ID: <20260911182400.102938@paypaI-support.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<p>Your PayPal account has been restricted due to unauthorized login attempts from a Tor node.</p>
<p>Verify immediately: <a href="http://185.220.101.42/paypal/verify.php">Verify PayPal Account</a></p>
"""
    },
    "bravo": {
        "id": "bravo",
        "title": "Scenario Bravo: CEO BEC Wire Transfer Fraud",
        "threat_type": "Business Email Compromise (BEC)",
        "target": "controller@finance-division.corp",
        "attacker": "ceo-office@corp-executive-portal.com",
        "raw_email": """Return-Path: <ceo-office@corp-executive-portal.com>
Delivered-To: controller@finance-division.corp
Received: from relay01.external-cloud.net (relay01.external-cloud.net [104.244.42.1])
\tby mx.finance-division.corp with ESMTP id F839A20
\tfor <controller@finance-division.corp>; Tue, 16 Jul 2026 14:10:05 +0000
Authentication-Results: mx.finance-division.corp;
\tspf=fail (domain of corp-executive-portal.com does not match sender);
\tdkim=none;
\tdmarc=fail
From: "David Henderson, CEO" <ceo-office@corp-executive-portal.com>
Reply-To: offshore-settlement@secure-wire-desk.net
To: "Sarah Jenkins, Controller" <controller@finance-division.corp>
Subject: CONFIDENTIAL: Time-Sensitive Acquisition Wire Transfer ($248,500)
Date: Tue, 16 Jul 2026 14:09:50 +0000
Message-ID: <bec-992384-ceo@corp-executive-portal.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Sarah,

I am currently in closed-door M&A negotiations regarding the project we discussed yesterday.
We need an immediate wire transfer of $248,500 to our escrow account today.
Reply directly to this email to receive wiring coordinates.

David Henderson
Chief Executive Officer
"""
    },
    "charlie": {
        "id": "charlie",
        "title": "Scenario Charlie: Weaponized Invoice Dropper",
        "threat_type": "Trojan Dropper (Double Extension)",
        "target": "accounts@enterprise.corp",
        "attacker": "billing@fast-invoicing-system.xyz",
        "raw_email": """Return-Path: <billing@fast-invoicing-system.xyz>
Delivered-To: accounts@enterprise.corp
Received: from relay.fast-invoicing-system.xyz (unknown [45.33.32.156])
\tby mx.enterprise.corp with ESMTP id 99DFA01
\tfor <accounts@enterprise.corp>; Wed, 17 Jul 2026 11:05:00 -0400
Authentication-Results: mx.enterprise.corp;
\tspf=fail;
\tdkim=none;
\tdmarc=fail
From: "Global Invoicing Dept" <billing@fast-invoicing-system.xyz>
Reply-To: accounts-audit@fast-invoicing-system.xyz
To: "Enterprise Accounts" <accounts@enterprise.corp>
Subject: OVERDUE INVOICE #INV-892104 - FINAL NOTICE BEFORE LEGAL ACTION
Date: Wed, 17 Jul 2026 11:04:45 -0400
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====_BOUNDARY_7781_===="

--====_BOUNDARY_7781_====
Content-Type: text/plain; charset=utf-8

Accounts Payable,

Your payment of $14,920.00 for Invoice #INV-892104 is 30 days overdue.
Review the attached payment slip immediately to avoid litigation.

Link: http://45.33.32.156:8080/portal/download_receipt.php

--====_BOUNDARY_7781_====
Content-Type: application/octet-stream; name="INVOICE_SCAN_892104.pdf.exe"
Content-Disposition: attachment; filename="INVOICE_SCAN_892104.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAmAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
RE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
--====_BOUNDARY_7781_====--
"""
    },
    "delta": {
        "id": "delta",
        "title": "Scenario Delta: Authorized Corporate Bulletin",
        "threat_type": "Benign / Authenticated Enterprise Memo",
        "target": "all-staff@enterprise.corp",
        "attacker": "it-security@enterprise.corp",
        "raw_email": """Return-Path: <it-security@enterprise.corp>
Delivered-To: all-staff@enterprise.corp
Received: from mail.enterprise.corp (mail.enterprise.corp [192.168.1.5])
\tby mx.enterprise.corp with ESMTPS id 334188
\tfor <all-staff@enterprise.corp>; Thu, 18 Jul 2026 08:00:00 +0000
Authentication-Results: mx.enterprise.corp;
\tspf=pass (enterprise.corp designates 192.168.1.5 as permitted sender);
\tdkim=pass (signature verified);
\tdmarc=pass (p=REJECT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=enterprise.corp;
\ts=selector1; t=1721289600;
\th=From:To:Subject:Date:Message-ID;
\tbh=ABCDEF123456789=; b=FEDCBA987654321=
From: "Enterprise IT Security" <it-security@enterprise.corp>
Reply-To: it-security@enterprise.corp
To: "All Staff" <all-staff@enterprise.corp>
Subject: Monthly Cyber Hygiene & Scheduled Maintenance Notice
Date: Thu, 18 Jul 2026 08:00:00 +0000
Message-ID: <bulletin-20260718@enterprise.corp>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Team,

This is our routine scheduled maintenance bulletin for Saturday, July 20th.
Internal network resources will undergo planned security updates between 02:00 and 04:00 UTC.
No password resets or credential confirmations are required for this update.

Best regards,
Enterprise Information Security Team
"""
    }
}

# In-memory tactical campaign incident registry for link-analysis graph & STIX export
TACTICAL_CAMPAIGN_REGISTRY: List[Dict[str, Any]] = []

def format_tactical_dashboard_payload(
    ingested_email: Any,
    protocol_res: ProtocolForensicsResult,
    origin_res: OriginIntelligenceResult,
    fusion_res: RiskFusionResult,
    audit_block: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Format analysis results to match the tactical HUD requirements of static/index.html.
    """
    score = fusion_res.composite_threat_score
    if score >= 61:
        verdict = "MALICIOUS"
        defcon = 1 if score >= 80 else 2
        defcon_title = "DEFCON 1 // IMMINENT ATTACK" if score >= 80 else "DEFCON 2 // ARMED HOSTILE"
    elif score >= 26:
        verdict = "SUSPICIOUS"
        defcon = 3
        defcon_title = "DEFCON 3 // ELEVATED THREAT"
    else:
        verdict = "BENIGN"
        defcon = 4 if score >= 15 else 5
        defcon_title = "DEFCON 4 // ADVISORY GUARDED" if score >= 15 else "DEFCON 5 // NORMAL OPERATIONS"

    score_breakdown = [
        {"factor": s.description, "points": s.penalty_points}
        for s in fusion_res.triggered_signals
    ]

    # Format relay hops for Leaflet interactive map with full cartographic signatures
    hops = []
    for h in protocol_res.relay_hops:
        hop_lat = None
        hop_lon = None
        hop_city = "MTA Transit"
        hop_country = "Global Network"
        hop_isp = "Internet Routing System"
        hop_status = "public"

        if h.is_private_ip:
            hop_status = "private"
            hop_city = "Enterprise Ingress Gateway"
            hop_country = "Secured Internal LAN"
            hop_isp = "RFC 1918 Perimeter"
            # Designated corporate perimeter coordinates (Enterprise SOC)
            hop_lat = 28.6139
            hop_lon = 77.2090
        elif h.ip and h.ip != "Unknown":
            h_geo, h_asn = resolve_offline_ip(h.ip)
            if h_geo.latitude != 0.0 or h_geo.longitude != 0.0:
                hop_lat = h_geo.latitude
                hop_lon = h_geo.longitude
            hop_city = h_geo.city or ("Tor Exit Gateway" if h.ip == "185.220.101.42" else "Transit Relay")
            hop_country = h_geo.country_name or "Transit Network"
            hop_isp = h_asn.as_org or (h_asn.as_name or "Autonomous System")
            if h.ip == "185.220.101.42" or (origin_res.threat_assessment.is_tor_exit_node and h.ip == protocol_res.origin_ip):
                hop_status = "tor"
            elif origin_res.threat_assessment.is_known_proxy_vpn and h.ip == protocol_res.origin_ip:
                hop_status = "bulletproof"
            elif h.ip == protocol_res.origin_ip:
                hop_status = "origin"

        # If this hop matches the verified origin IP, ensure origin coordinates are used
        if (h.ip == protocol_res.origin_ip) and origin_res.geolocation.latitude:
            hop_lat = origin_res.geolocation.latitude
            hop_lon = origin_res.geolocation.longitude
            hop_city = origin_res.geolocation.city or hop_city
            hop_country = origin_res.geolocation.country_name or hop_country
            hop_isp = origin_res.asn.as_org or hop_isp

        hops.append({
            "hop_index": h.hop_number,
            "raw_header_snippet": f"from {h.from_host or 'unknown'} by {h.by_host or 'unknown'}",
            "ip": h.ip or "Unknown",
            "from_host": h.from_host,
            "by_host": h.by_host,
            "transit_delay_seconds": h.transit_delay_seconds,
            "is_private": h.is_private_ip,
            "geo": {
                "city": hop_city,
                "country": hop_country,
                "isp": hop_isp,
                "lat": hop_lat,
                "lon": hop_lon,
                "status": hop_status
            }
        })

    # Extract hyperlinks from text/html
    urls = []
    if ingested_email.body_html:
        urls = re.findall(r'href=[\'"](https?://[^\'">\s]+)', ingested_email.body_html, re.IGNORECASE)
    if not urls and ingested_email.body_text:
        urls = re.findall(r'https?://[^\s<>"\']+', ingested_email.body_text)

    # Extract attachments
    attachments = []
    for att in ingested_email.attachments:
        ext = att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
        dangerous = ext in ("exe", "scr", "bat", "vbs", "ps1", "hta", "dll") or ".pdf.exe" in att.filename.lower()
        attachments.append({
            "filename": att.filename,
            "size_bytes": att.size_bytes,
            "dangerous": dangerous,
            "has_double_extension": ".pdf.exe" in att.filename.lower() or ".doc.exe" in att.filename.lower(),
            "sha256": att.sha256
        })

    is_spoofed = (
        origin_res.domain_intel.homoglyph_detected
        or origin_res.domain_intel.typosquat_suspect
        or protocol_res.dmarc.verdict == "fail"
    )
    spoof_detail = (
        f"Unaligned/Deceptive domain {ingested_email.headers.from_domain} impersonates legitimate identity."
        if is_spoofed else "Sender domain aligned and authenticated."
    )

    has_reply_to_mismatch = bool(
        ingested_email.headers.reply_to
        and ingested_email.headers.reply_to.lower() != ingested_email.headers.from_address.lower()
    )

    record = {
        "id": f"incident_{len(TACTICAL_CAMPAIGN_REGISTRY) + 1}",
        "email_id": protocol_res.email_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "subject": ingested_email.headers.subject,
        "sender": ingested_email.headers.from_address,
        "recipient": ", ".join(ingested_email.headers.to_addresses) if ingested_email.headers.to_addresses else "Unknown",
        "return_path": ingested_email.headers.return_path or "Unknown",
        "reply_to": ingested_email.headers.reply_to or "Unknown",
        "origin_ip": protocol_res.origin_ip or "Unknown",
        "origin_geo": {
            "city": origin_res.geolocation.city,
            "country": origin_res.geolocation.country_name,
            "isp": origin_res.asn.as_org,
            "lat": origin_res.geolocation.latitude,
            "lon": origin_res.geolocation.longitude
        },
        "verdict": verdict,
        "verdict_tier": fusion_res.verdict_tier,
        "defcon": defcon,
        "defcon_title": defcon_title,
        "score": score,
        "score_breakdown": score_breakdown,
        "hops": hops,
        "auth": {
            "spf": protocol_res.spf.verdict,
            "dkim": protocol_res.dkim.verdict,
            "dmarc": protocol_res.dmarc.verdict
        },
        "nlp_analysis": {
            "threat_score": min(40, len(urls) * 10),
            "urls_found": urls
        },
        "spoofing": {
            "spoofed": is_spoofed,
            "detail": spoof_detail,
            "brand": ingested_email.headers.from_domain
        },
        "reply_to_mismatch": {
            "mismatch": has_reply_to_mismatch,
            "detail": f"Reply-To ({ingested_email.headers.reply_to}) diverts replies away from From sender." if has_reply_to_mismatch else "Reply-To matches sender"
        },
        "attachments": {"attachments": attachments},
        "headers": ingested_email.headers.all_headers,
        "mitre_attack": [
            {"technique": "T1566.002", "name": "Phishing: Spearphishing Link", "detected": len(urls) > 0},
            {"technique": "T1036.007", "name": "Masquerading: Double File Extension", "detected": any(a["has_double_extension"] for a in attachments)},
            {"technique": "T1584.004", "name": "Compromise Infrastructure: Tor Exit Node", "detected": origin_res.threat_assessment.is_tor_exit_node}
        ],
        "audit_block": audit_block
    }

    TACTICAL_CAMPAIGN_REGISTRY.append(record)
    if len(TACTICAL_CAMPAIGN_REGISTRY) > 50:
        TACTICAL_CAMPAIGN_REGISTRY.pop(0)

    return record

def generate_stix_bundle(record: Dict[str, Any]) -> Dict[str, Any]:
    """Export incident IOCs in OASIS STIX 2.1 standard format."""
    now_iso = datetime.now(timezone.utc).isoformat()
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects = []

    # Threat Actor / Sighting
    objects.append({
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{uuid.uuid4()}",
        "created": now_iso,
        "modified": now_iso,
        "first_observed": now_iso,
        "last_observed": now_iso,
        "number_observed": 1
    })

    # Indicator for sender domain
    sender = record.get("sender") or ""
    domain = sender.split("@")[-1] if "@" in sender else ""
    if domain:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"Adversary Domain: {domain}",
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "labels": ["malicious-domain", "phishing"]
        })

    # Indicator for origin IP
    ip = record.get("origin_ip")
    if ip and ip != "Unknown":
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"Malicious Origin IP: {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "labels": ["malicious-ip", "tor-exit-node"]
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }

def get_tactical_campaigns_summary() -> List[Dict[str, Any]]:
    """Group analyzed incidents into correlated high-fidelity Threat Campaigns (Palantir style)."""
    campaigns: Dict[str, Dict[str, Any]] = {}

    for item in TACTICAL_CAMPAIGN_REGISTRY:
        sender = item.get("sender") or ""
        domain = sender.split("@")[-1].lower() if "@" in sender else "unknown"
        ip = item.get("origin_ip") or "unknown"
        verdict = item.get("verdict") or "BENIGN"
        att_wrapper = item.get("attachments")
        attachments = (att_wrapper.get("attachments") if isinstance(att_wrapper, dict) else []) or []
        has_exe = any(isinstance(a, dict) and (a.get("dangerous") or a.get("has_double_extension")) for a in attachments)
        origin_geo = item.get("origin_geo") or {}
        mitre_list = item.get("mitre_attack") or []
        is_tor = (
            origin_geo.get("city") == "Tor Relay Node" 
            or ip == "185.220.101.42" 
            or any(isinstance(m, dict) and m.get("detected") and m.get("technique") == "T1584.004" for m in mitre_list)
        )
        subj = (item.get("subject") or "").lower()
        reply_to_data = item.get("reply_to_mismatch") or {}
        is_bec = ("wire" in subj or "acquisition" in subj or reply_to_data.get("mismatch"))

        if is_tor or "paypal" in domain or "paypai" in domain:
            c_key = "CAMP-TOR-CREDENTIAL-HARVEST"
            c_name = "OPERATION COLD-PHISH // TOR CREDENTIAL HARVEST"
            actor = "UNC-2814 (Fin-Targeting Syndicate)"
        elif has_exe or "invoice" in (item.get("subject") or "").lower():
            c_key = "CAMP-TROJAN-INVOICE-DROPPER"
            c_name = "OPERATION VIPER-INVOICE // WEAPONIZED EXECUTABLES"
            actor = "TA-505 / CLOP Affiliate Variant"
        elif is_bec or "ceo" in (item.get("sender") or "").lower():
            c_key = "CAMP-EXECUTIVE-BEC-WIRE"
            c_name = "OPERATION APEX-FRAUD // EXECUTIVE IMPERSONATION"
            actor = "SILVERTERRIER (BEC Syndicate)"
        elif verdict == "BENIGN":
            c_key = "CAMP-CORPORATE-AUTHORIZED"
            c_name = "AUTHORIZED INTERNAL // ENTERPRISE COMMS"
            actor = "LEGITIMATE CORPORATE INFRASTRUCTURE"
        else:
            c_key = f"CAMP-{domain.upper()}"
            c_name = f"UNCLASSIFIED CLUSTER // {domain.upper()}"
            actor = "UNKNOWN ADVERSARY CELL"

        if c_key not in campaigns:
            campaigns[c_key] = {
                "campaign_id": c_key,
                "name": c_name,
                "threat_actor": actor,
                "verdict": verdict,
                "defcon": item.get("defcon", 5),
                "defcon_title": item.get("defcon_title", "DEFCON 5"),
                "max_score": item.get("score") or 0,
                "incident_count": 0,
                "incident_ids": [],
                "incidents": [],
                "targets": set(),
                "infrastructure_ips": set(),
                "domains": set(),
                "mitre_techniques": set(),
                "earliest_seen": item.get("timestamp"),
                "latest_seen": item.get("timestamp")
            }

        c = campaigns[c_key]
        c["incident_count"] += 1
        c["incident_ids"].append(item.get("id"))
        c["incidents"].append({
            "id": item.get("id"),
            "subject": item.get("subject"),
            "sender": item.get("sender"),
            "score": item.get("score"),
            "verdict": item.get("verdict"),
            "timestamp": item.get("timestamp")
        })
        item_score = item.get("score") or 0
        if item_score > (c.get("max_score") or 0):
            c["max_score"] = item_score
            c["verdict"] = item.get("verdict") or c["verdict"]
            c["defcon"] = item.get("defcon") or c["defcon"]
            c["defcon_title"] = item.get("defcon_title") or c["defcon_title"]
        c["targets"].add(item.get("recipient") or "unknown")
        if ip and ip != "Unknown":
            c["infrastructure_ips"].add(ip)
        if domain:
            c["domains"].add(domain)
        for m in (item.get("mitre_attack") or []):
            if isinstance(m, dict) and m.get("detected"):
                c["mitre_techniques"].add(f"{m.get('technique')}: {m.get('name')}")
        c["latest_seen"] = item.get("timestamp")

    result = []
    for c in campaigns.values():
        result.append({
            "campaign_id": c["campaign_id"],
            "name": c["name"],
            "threat_actor": c["threat_actor"],
            "verdict": c["verdict"],
            "defcon": c["defcon"],
            "defcon_title": c["defcon_title"],
            "max_score": c["max_score"],
            "incident_count": c["incident_count"],
            "incident_ids": c["incident_ids"],
            "incidents": c["incidents"],
            "targets": sorted(list(c["targets"])),
            "infrastructure_ips": sorted(list(c["infrastructure_ips"])),
            "domains": sorted(list(c["domains"])),
            "mitre_techniques": sorted(list(c["mitre_techniques"])),
            "earliest_seen": c["earliest_seen"],
            "latest_seen": c["latest_seen"]
        })
    return sorted(result, key=lambda x: x.get("max_score") or 0, reverse=True)

def get_campaign_graph_nodes_and_edges() -> Dict[str, Any]:
    """Generate Palantir Gotham Link-Analysis Correlation Graph across all analyzed attacks."""
    nodes = []
    edges = []
    seen = set()

    campaign_clusters = get_tactical_campaigns_summary()
    
    # 1. Add Campaign and Threat Actor Nodes
    for camp in campaign_clusters:
        camp_id = f"camp_{camp['campaign_id']}"
        if camp_id not in seen:
            seen.add(camp_id)
            nodes.append({
                "id": camp_id,
                "label": camp["name"],
                "type": "campaign",
                "verdict": camp["verdict"],
                "score": camp["max_score"],
                "defcon": camp["defcon"],
                "metadata": {
                    "actor": camp["threat_actor"],
                    "incidents": camp["incident_count"],
                    "targets": len(camp["targets"])
                }
            })

        actor_raw = camp.get("threat_actor") or "Unknown-Actor"
        actor_slug = re.sub(r'[^a-zA-Z0-9_-]', '_', actor_raw.split()[0] if actor_raw.split() else "Actor")
        actor_id = f"actor_{actor_slug}"
        if actor_id not in seen:
            seen.add(actor_id)
            nodes.append({
                "id": actor_id,
                "label": actor_raw,
                "type": "actor",
                "verdict": camp.get("verdict", "UNKNOWN"),
                "score": camp.get("max_score", 0),
                "metadata": {"attributed_campaigns": [camp.get("name", "Unknown Campaign")]}
            })
        edges.append({"source": actor_id, "target": camp_id, "relation": "ATTRIBUTED_TO"})

    # 2. Add Incident Nodes & Link to Campaign
    for idx, item in enumerate(TACTICAL_CAMPAIGN_REGISTRY):
        e_id = item.get("id", f"incident_{idx}")
        if e_id not in seen:
            seen.add(e_id)
            nodes.append({
                "id": e_id,
                "label": (item.get("subject") or "Untitled")[:34],
                "type": "email",
                "verdict": item.get("verdict") or "UNKNOWN",
                "score": item.get("score", 0),
                "metadata": {
                    "sender": item.get("sender"),
                    "recipient": item.get("recipient"),
                    "origin_ip": item.get("origin_ip")
                }
            })

        # Link to matching campaign
        for camp in campaign_clusters:
            if item.get("id") in camp.get("incident_ids", []):
                edges.append({"source": f"camp_{camp['campaign_id']}", "target": e_id, "relation": "CONTAINS_INCIDENT"})
                break

        # 3. Add Domain Node
        sender = item.get("sender") or ""
        domain = sender.split("@")[-1] if "@" in sender else "unknown-domain"
        d_id = f"domain_{domain}"
        if d_id not in seen:
            seen.add(d_id)
            nodes.append({
                "id": d_id,
                "label": domain,
                "type": "domain",
                "verdict": item.get("verdict"),
                "score": item.get("score", 0),
                "metadata": {"brand": domain, "sender": sender}
            })
        edges.append({"source": e_id, "target": d_id, "relation": "SENT_BY"})

        # 4. Add IP Node
        ip = item.get("origin_ip")
        if ip and ip != "Unknown":
            ip_id = f"ip_{ip}"
            if ip_id not in seen:
                seen.add(ip_id)
                nodes.append({
                    "id": ip_id,
                    "label": ip,
                    "type": "ip",
                    "verdict": item.get("verdict"),
                    "score": item.get("score", 0),
                    "metadata": item.get("origin_geo") or {}
                })
            edges.append({"source": e_id, "target": ip_id, "relation": "ROUTED_THROUGH"})

        # 5. Add Target Mailbox Node
        recipient = item.get("recipient")
        if recipient and recipient != "Unknown":
            t_id = f"target_{recipient}"
            if t_id not in seen:
                seen.add(t_id)
                nodes.append({
                    "id": t_id,
                    "label": recipient,
                    "type": "target",
                    "verdict": "TARGET",
                    "score": 0,
                    "metadata": {"mailbox": recipient}
                })
            edges.append({"source": e_id, "target": t_id, "relation": "TARGETS"})

        # 6. Add Payload / Attachment Node (if any)
        att_wrapper = item.get("attachments")
        attachments = (att_wrapper.get("attachments") if isinstance(att_wrapper, dict) else []) or []
        for att in attachments:
            if isinstance(att, dict) and (att.get("dangerous") or att.get("has_double_extension")):
                fname = att.get("filename") or "unknown_payload"
                att_id = f"att_{fname}"
                if att_id not in seen:
                    seen.add(att_id)
                    nodes.append({
                        "id": att_id,
                        "label": fname,
                        "type": "malware",
                        "verdict": "MALICIOUS",
                        "score": 95,
                        "metadata": {"sha256": att.get("sha256"), "size": att.get("size_bytes")}
                    })
                edges.append({"source": e_id, "target": att_id, "relation": "DROPS_PAYLOAD"})

    return {"nodes": nodes, "edges": edges, "campaigns": campaign_clusters}

