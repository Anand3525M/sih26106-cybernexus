import re
import html as html_module
import email
import ipaddress
import hashlib
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import requests

app = FastAPI(
    title="SIH26106 Sentinel — Palantir Cyber Defense & Threat Intelligence Platform",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# ── State ────────────────────────────────────────────────────────────────────
CAMPAIGN_REGISTRY: List[Dict[str, Any]] = []
MAX_CAMPAIGNS = 100

# ── IP Geo Cache & Session ───────────────────────────────────────────────────
_geo_cache: Dict[str, Dict[str, Any]] = {}
_http_session = requests.Session()

# ── Regex ────────────────────────────────────────────────────────────────────
IP_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
URL_REGEX = r'https?://[^\s<>"\'\])>}]+'

# ── Well-known brand domains for spoofing detection ──────────────────────────
BRAND_KEYWORDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "hotmail.com", "office365.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com"],
}

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".ru", ".tk", ".work", ".click", ".info",
    ".buzz", ".gq", ".ml", ".cf", ".ga", ".loan", ".win", ".icu",
    ".cam", ".fit", ".rest"
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".iso", ".zip", ".rar", ".7z", ".scr", ".html", ".htm",
    ".js", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".dll", ".pif",
    ".com", ".wsf", ".jar", ".lnk", ".hta", ".vbe"
]


# ── Scenario Presets (Palantir Defense Threat Lab) ───────────────────────────
PRESET_SCENARIOS = {
    "alpha": {
        "id": "alpha",
        "title": "Scenario Alpha: PayPal Account Takeover",
        "threat_type": "Credential Harvest / Tor Exit Origin",
        "target": "victim@enterprise.corp",
        "attacker": "security@paypal-update-verification.com",
        "raw_email": """Return-Path: <security@paypal-update-verification.com>
Delivered-To: victim@enterprise.corp
Received: from mx4.enterprise.corp (mx4.enterprise.corp [192.168.1.10])
\tby mail.enterprise.corp (Postfix) with ESMTP id ABC123
\tfor <victim@enterprise.corp>; Mon, 15 Jul 2024 09:23:45 -0400 (EDT)
Received: from paypal-update-verification.com (unknown [185.220.101.5])
\tby mx4.enterprise.corp (Postfix) with ESMTPS id 789DEF
\tfor <victim@enterprise.corp>; Mon, 15 Jul 2024 09:23:42 -0400 (EDT)
Authentication-Results: mx4.enterprise.corp;
\tspf=fail (domain of paypal-update-verification.com does not designate 185.220.101.5 as permitted sender)
\tsmtp.mailfrom=security@paypal-update-verification.com;
\tdkim=none (no signature);
\tdmarc=none (p=NONE sp=NONE dis=NONE)
X-Originating-IP: [185.220.101.5]
X-Sender-IP: 185.220.101.5
From: "PayPal Security Division" <security@paypal-update-verification.com>
Reply-To: support@paypal-help-center.info
To: "Valued Client" <victim@enterprise.corp>
Subject: URGENT: Your PayPal Account Has Been Limited - Immediate Action Required!
Date: Mon, 15 Jul 2024 09:23:40 -0400
Message-ID: <phish-789456-20240715@paypal-update-verification.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear Valued Customer,

URGENT: Your PayPal account has been limited due to suspicious unauthorized access.
We noticed multiple login attempts from an unknown Tor exit node.

IMMEDIATE ACTION REQUIRED:
Please verify your identity within 24 hours to prevent loss of all funds:
http://paypal-update-verification.com/login.php?email=victim@enterprise.corp&token=aHR0cDovL3BoaXNoLmNvbQ==

WARNING: Failure to verify within 24 hours will result in permanent account termination.

Sincerely,
PayPal Security Operations
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
\tfor <controller@finance-division.corp>; Tue, 16 Jul 2024 14:10:05 +0000
Authentication-Results: mx.finance-division.corp;
\tspf=fail (domain of corp-executive-portal.com does not match sender);
\tdkim=fail;
\tdmarc=fail
From: "David Henderson, CEO" <ceo-office@corp-executive-portal.com>
Reply-To: offshore-settlement@secure-wire-desk.net
To: "Sarah Jenkins, Controller" <controller@finance-division.corp>
Subject: CONFIDENTIAL: Time-Sensitive Acquisition Wire Transfer ($248,500)
Date: Tue, 16 Jul 2024 14:09:50 +0000
Message-ID: <bec-992384-ceo@corp-executive-portal.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Sarah,

I am currently in closed-door M&A negotiations regarding the project we discussed yesterday.
Due to strict regulatory confidentiality, please do not call me or discuss this with staff.

We need to execute an immediate SWIFT wire transfer of $248,500 to our escrow attorney before end of business today.
Please reply directly to this email so I can forward the bank wiring coordinates.

Treat this with utmost urgency and discretion.

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
\tfor <accounts@enterprise.corp>; Wed, 17 Jul 2024 11:05:00 -0400
Authentication-Results: mx.enterprise.corp;
\tspf=fail;
\tdkim=none;
\tdmarc=fail
From: "Global Invoicing Dept" <billing@fast-invoicing-system.xyz>
Reply-To: accounts-audit@fast-invoicing-system.xyz
To: "Enterprise Accounts" <accounts@enterprise.corp>
Subject: OVERDUE INVOICE #INV-892104 - FINAL NOTICE BEFORE LEGAL ACTION
Date: Wed, 17 Jul 2024 11:04:45 -0400
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====_BOUNDARY_7781_===="

--====_BOUNDARY_7781_====
Content-Type: text/plain; charset=utf-8

Accounts Payable,

Your payment of $14,920.00 for Invoice #INV-892104 is 30 days overdue.
Review the attached payment slip immediately to avoid litigation.

Link: http://45.33.32.156:8080/portal/download_receipt.php

Accounting Services Inc.

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
\tfor <all-staff@enterprise.corp>; Thu, 18 Jul 2024 08:00:00 +0000
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
Date: Thu, 18 Jul 2024 08:00:00 +0000
Message-ID: <bulletin-20240718@enterprise.corp>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Team,

This is our routine scheduled maintenance bulletin for Saturday, July 20th.
Internal network resources will undergo planned security updates between 02:00 and 04:00 UTC.

No password resets or credential confirmations are required for this update.
If you have questions, please reach out via our internal helpdesk ticket system.

Best regards,
Enterprise Information Security Team
"""
    }
}


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate that string is a real IPv4 address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 4 and not addr.is_multicast and not addr.is_unspecified
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved using the ipaddress module."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        return False


def resolve_ip(ip: str) -> Dict[str, Any]:
    """Resolve IP geolocation with caching. Returns null coords for private IPs."""
    if ip in _geo_cache:
        return _geo_cache[ip]

    if is_private_ip(ip):
        result = {
            "ip": ip,
            "status": "private",
            "country": "Private / RFC1918",
            "city": "Internal Relay",
            "lat": None,
            "lon": None,
            "isp": "Private Network"
        }
        _geo_cache[ip] = result
        return result

    try:
        resp = _http_session.get(
            f"https://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp",
            timeout=2.0
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "ip": ip,
                    "status": "success",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "isp": data.get("isp", "Unknown")
                }
                _geo_cache[ip] = result
                return result
    except Exception:
        pass

    result = {
        "ip": ip,
        "status": "unknown",
        "country": "Unknown",
        "city": "Unknown",
        "lat": None,
        "lon": None,
        "isp": "Unknown"
    }
    _geo_cache[ip] = result
    return result


def strip_html_tags(html_text: str) -> str:
    """Strip HTML tags and decode entities to extract readable text."""
    text = re.sub(r'<(style|script)[^>]*>.*?</\1>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<(br|/p|/div|/tr|/li)[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html_module.unescape(text)
    text = re.sub(r'\n\s*\n', '\n', text).strip()
    return text


def extract_urls_from_html(html_text: str) -> List[str]:
    """Extract href and src URLs from HTML markup."""
    hrefs = re.findall(r'href\s*=\s*["\']?(https?://[^\s"\'<>]+)', html_text, re.IGNORECASE)
    srcs = re.findall(r'src\s*=\s*["\']?(https?://[^\s"\'<>]+)', html_text, re.IGNORECASE)
    combined = []
    for u in hrefs + srcs:
        u_clean = u.rstrip('"\'>')
        if u_clean not in combined:
            combined.append(u_clean)
    return combined


def extract_domain_from_email_addr(addr: str) -> str:
    """Extract domain from an email address string like 'Name <user@domain.com>'."""
    match = re.search(r'@([\w.-]+)', addr)
    return match.group(1).lower().rstrip(".") if match else ""


def extract_display_name(addr: str) -> str:
    """Extract display name from 'Display Name <email@domain.com>'."""
    match = re.match(r'^"?([^"<]+)"?\s*<', addr)
    return match.group(1).strip() if match else ""


def detect_sender_spoofing(from_header: str) -> Dict[str, Any]:
    """Detect if display name or sender domain impersonates a well-known brand while using an unauthorized domain."""
    display_name = extract_display_name(from_header).lower()
    sender_domain = extract_domain_from_email_addr(from_header).rstrip(".")

    for brand, legit_domains in BRAND_KEYWORDS.items():
        if not legit_domains:
            continue
        is_legit = any(
            sender_domain == legit or sender_domain.endswith("." + legit)
            for legit in legit_domains
        )

        # Check display name for brand as a whole word to avoid false positives
        if re.search(rf'\b{re.escape(brand)}\b', display_name) and not is_legit:
            return {
                "spoofed": True,
                "brand": brand.title(),
                "claimed_domain": sender_domain,
                "legit_domains": legit_domains,
                "detail": f"Display name contains '{brand.title()}' but sender domain '{sender_domain}' is not an authorized {brand.title()} domain"
            }

        # Check sender domain (lookalike/typosquatting/cousin domain)
        clean_brand = brand.replace(" ", "")
        if (brand in sender_domain or clean_brand in sender_domain) and not is_legit:
            return {
                "spoofed": True,
                "brand": brand.title(),
                "claimed_domain": sender_domain,
                "legit_domains": legit_domains,
                "detail": f"Sender domain '{sender_domain}' contains brand name '{brand.title()}' (cousin domain / typosquatting) but is not an authorized {brand.title()} domain"
            }

    return {"spoofed": False}


def detect_reply_to_mismatch(from_header: str, reply_to: Optional[str]) -> Dict[str, Any]:
    """Detect if Reply-To domain differs from From domain — classic phishing indicator."""
    if not reply_to or reply_to in ["Unknown", "None", ""]:
        return {"mismatch": False}

    from_domain = extract_domain_from_email_addr(from_header)
    reply_domain = extract_domain_from_email_addr(reply_to)

    if from_domain and reply_domain and from_domain != reply_domain:
        return {
            "mismatch": True,
            "from_domain": from_domain,
            "reply_to_domain": reply_domain,
            "detail": f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'"
        }
    return {"mismatch": False}


def analyze_attachments(msg: email.message.EmailMessage) -> Dict[str, Any]:
    """Analyze email attachments for dangerous file types and double extensions."""
    attachments = []
    dangerous = []
    suspicious_naming = []

    if msg.is_multipart():
        for part in msg.walk():
            cdispo = str(part.get('Content-Disposition', ''))
            filename = part.get_filename()
            if 'attachment' in cdispo or (filename and 'inline' not in cdispo):
                filename = filename or "unknown"
                payload = part.get_payload(decode=True) or b""
                size = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest() if payload else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

                parts = filename.split(".")
                has_double_ext = (
                    len(parts) > 2 and (
                        "." + parts[-1].lower() in DANGEROUS_EXTENSIONS or
                        "." + parts[-2].lower() in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"]
                    )
                )

                is_dangerous = ext in DANGEROUS_EXTENSIONS or has_double_ext

                entry = {
                    "filename": filename,
                    "size_bytes": size,
                    "sha256": sha256,
                    "extension": ext,
                    "dangerous": is_dangerous,
                    "has_double_extension": has_double_ext
                }
                attachments.append(entry)
                if is_dangerous:
                    dangerous.append(filename)
                if has_double_ext:
                    suspicious_naming.append(filename)

    return {
        "count": len(attachments),
        "attachments": attachments,
        "dangerous_files": dangerous,
        "suspicious_naming": suspicious_naming,
        "has_dangerous": len(dangerous) > 0
    }


def analyze_body_threats(content: str, html_urls: List[str] = None) -> Dict[str, Any]:
    """Analyze email body for phishing indicators, urgency, and suspicious URLs."""
    urgency_terms = [
        "urgent", "immediately", "wire transfer", "suspended", "action required",
        "password expired", "verify your account", "payroll", "swift", "gift card",
        "confirm your identity", "unusual activity", "account has been limited",
        "unauthorized access", "click below", "within 24 hours", "permanently",
        "loss of all funds", "security alert", "suspicious login", "immediate action",
        "acquisition", "escrow", "confidential", "litigation", "overdue invoice"
    ]
    detected_phrases = [term for term in urgency_terms if term in content.lower()]

    urls = re.findall(URL_REGEX, content)
    if html_urls:
        for u in html_urls:
            if u not in urls:
                urls.append(u)

    urls = [re.sub(r'[.,;:!?)}\]]+$', '', u) for u in urls]

    score = 0
    reasons = []

    if detected_phrases:
        score += min(len(detected_phrases) * 10, 45)
        reasons.append(f"Social engineering trigger phrases detected: {', '.join(detected_phrases)}")

    # Detect direct IP in URL
    raw_ip_urls = [u for u in urls if re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?', u)]
    if raw_ip_urls:
        score += 35
        reasons.append(f"Direct IP-based URL detected (high phishing risk): {', '.join(raw_ip_urls)}")

    suspicious_links = [u for u in urls if any(tld in u.lower() for tld in SUSPICIOUS_TLDS)]
    if suspicious_links:
        score += 35
        reasons.append(f"High-risk domain extensions in URLs: {', '.join(suspicious_links)}")
    elif len(urls) > 3:
        score += 15
        reasons.append(f"High density of external links ({len(urls)} found)")

    return {
        "threat_score": min(score, 100),
        "triggers": reasons,
        "urls_found": urls
    }


def map_mitre_attack(
    threat_score: int,
    spoofing: Dict[str, Any],
    reply_to_check: Dict[str, Any],
    attachments: Dict[str, Any],
    urls_found: List[str],
    auth_status: Dict[str, str]
) -> List[Dict[str, str]]:
    """Map observed forensic artifacts to the MITRE ATT&CK Enterprise Matrix."""
    techniques = []

    if urls_found:
        techniques.append({
            "id": "T1566.002",
            "tactic": "Initial Access",
            "technique": "Phishing: Spearphishing Link",
            "description": f"Payload relies on malicious web hyperlinks ({len(urls_found)} URL(s) detected) to drive victim interaction."
        })

    if attachments.get("count", 0) > 0:
        techniques.append({
            "id": "T1566.001",
            "tactic": "Initial Access",
            "technique": "Phishing: Spearphishing Attachment",
            "description": f"Delivers malicious payload as email attachment ({attachments['count']} file(s))."
        })

    if attachments.get("has_dangerous"):
        techniques.append({
            "id": "T1204.002",
            "tactic": "Execution",
            "technique": "User Execution: Malicious File",
            "description": "Attachment utilizes dangerous or double extension executable designed for client execution."
        })

    if spoofing.get("spoofed"):
        techniques.append({
            "id": "T1036.005",
            "tactic": "Defense Evasion",
            "technique": "Masquerading: Match Legitimate Name",
            "description": f"Impersonates legitimate brand '{spoofing.get('brand')}' in display name or domain typosquatting."
        })

    if reply_to_check.get("mismatch"):
        techniques.append({
            "id": "T1534",
            "tactic": "Lateral Movement / Deception",
            "technique": "Internal Spearphishing & Disparate Routing",
            "description": f"Reply-To desynchronized to disparate domain '{reply_to_check.get('reply_to_domain')}' to hijack victim response thread."
        })

    if auth_status.get("spf") == "fail" or auth_status.get("dmarc") == "fail":
        techniques.append({
            "id": "T1586.002",
            "tactic": "Resource Development",
            "technique": "Compromise Accounts: Email Accounts",
            "description": "Sender infrastructure failed cryptographic authentication (SPF/DMARC), indicating forged sender envelope."
        })

    return techniques


def generate_containment_playbook(verdict: str, record: Dict[str, Any]) -> List[Dict[str, str]]:
    """Generate Palantir-style automated SOC incident containment recommendations."""
    actions = []
    origin_ip = record.get("origin_ip")
    sender_domain = extract_domain_from_email_addr(record.get("sender", ""))
    urls = record.get("nlp_analysis", {}).get("urls_found", [])

    if verdict in ["MALICIOUS", "SUSPICIOUS"]:
        if origin_ip and origin_ip != "Unknown" and not is_private_ip(origin_ip):
            actions.append({
                "action": "NETWORK CONTAINMENT",
                "severity": "CRITICAL",
                "command": f"iptables -A INPUT -s {origin_ip} -j DROP # Block relay IP across edge firewalls",
                "detail": f"Null-route traffic from adversary relay IP {origin_ip}"
            })

        if sender_domain:
            actions.append({
                "action": "MAIL GATEWAY PURGE",
                "severity": "HIGH",
                "command": f"postsuper -d ALL -s '@{sender_domain}' # Quarantine pending mail from sender domain",
                "detail": f"Quarantine and purge all active inbound messages originating from *@{sender_domain}"
            })

        if urls:
            actions.append({
                "action": "DNS SINKHOLE",
                "severity": "HIGH",
                "command": f"pihole -b {urls[0].split('/')[2]} # Sinkhole malicious URL host",
                "detail": f"Add extracted domain hosts ({len(urls)} target(s)) to perimeter DNS sinkhole"
            })

        actions.append({
            "action": "IDENTITY SAFEGUARD",
            "severity": "MEDIUM",
            "command": f"az ad user session revoke --id victim@enterprise.corp # Invalidate active OAuth refresh tokens",
            "detail": "Force-terminate user active browser sessions and trigger mandatory FIDO2 re-authentication"
        })
    else:
        actions.append({
            "action": "TELEMETRY LOGGING",
            "severity": "INFO",
            "command": "logger -p auth.info 'Email verification passed — SPF/DKIM confirmed'",
            "detail": "Log benign event to SIEM pipeline; no hostile perimeter containment actions required"
        })

    return actions


def generate_stix_bundle(record: Dict[str, Any]) -> Dict[str, Any]:
    """Generate an official OASIS STIX 2.1 JSON Cyber Threat Intelligence bundle."""
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects = []

    # 1. Identity (SOC Reporter)
    reporter_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": reporter_id,
        "name": "SIH 26106 Sentinel Cyber Defense Apparatus",
        "identity_class": "system",
        "created": now_iso,
        "modified": now_iso
    })

    # 2. Indicator for Origin IP
    if record.get("origin_ip") and record["origin_ip"] != "Unknown":
        ip_ind_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ip_ind_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Adversary Relay IP: {record['origin_ip']}",
            "pattern": f"[ipv4-addr:value = '{record['origin_ip']}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "labels": ["malicious-activity", "phishing-infrastructure"]
        })

    # 3. Indicators for URLs
    for u in record.get("nlp_analysis", {}).get("urls_found", []):
        url_ind_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": url_ind_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Phishing Credential Target: {u}",
            "pattern": f"[url:value = '{u}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "labels": ["malicious-url", "credential-harvesting"]
        })

    # 4. Indicators for Attachments
    for att in record.get("attachments", {}).get("attachments", []):
        file_ind_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": file_ind_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Weaponized File: {att['filename']}",
            "pattern": f"[file:hashes.'SHA-256' = '{att.get('sha256', '')}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "labels": ["malicious-file", "weaponized-attachment"]
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }


def process_email_forensics(raw_bytes: bytes) -> Dict[str, Any]:
    """Full forensic analysis pipeline for a raw email."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    headers_summary = {
        "from": msg.get("From", "Unknown"),
        "to": msg.get("To", "Unknown"),
        "subject": msg.get("Subject", "No Subject"),
        "date": msg.get("Date", "Unknown"),
        "return_path": msg.get("Return-Path", "Unknown"),
        "reply_to": msg.get("Reply-To", "Unknown"),
        "message_id": msg.get("Message-ID", "Unknown"),
        "x_mailer": msg.get("X-Mailer", "Unknown"),
        "x_originating_ip": msg.get("X-Originating-IP", "Unknown"),
        "authentication_results": msg.get("Authentication-Results", "None"),
    }

    # ── Received header hop reconstruction (RFC 5322: reverse order) ─────
    received_headers = msg.get_all("Received", [])
    extracted_hops = []
    hop_ips = []

    for header_val in reversed(received_headers):
        ips = re.findall(IP_REGEX, header_val)
        valid_ips = [ip for ip in ips if is_valid_ipv4(ip)]
        for ip in valid_ips:
            if ip not in hop_ips:
                hop_ips.append(ip)
                geo = resolve_ip(ip)
                extracted_hops.append({
                    "hop_index": len(extracted_hops) + 1,
                    "raw_header_snippet": header_val[:200],
                    "ip": ip,
                    "geo": geo
                })

    extra_ip_headers = [
        ("X-Originating-IP", headers_summary.get("x_originating_ip")),
        ("X-Sender-IP", msg.get("X-Sender-IP")),
        ("X-Real-IP", msg.get("X-Real-IP"))
    ]
    for hname, hval in extra_ip_headers:
        if hval and hval != "Unknown":
            clean_ips = [ip for ip in re.findall(IP_REGEX, str(hval)) if is_valid_ipv4(ip)]
            for ip in clean_ips:
                if ip not in hop_ips:
                    hop_ips.append(ip)
                    geo = resolve_ip(ip)
                    extracted_hops.insert(0, {
                        "hop_index": 0,
                        "raw_header_snippet": f"{hname}: {hval}",
                        "ip": ip,
                        "geo": geo
                    })
                    for i, h in enumerate(extracted_hops):
                        h["hop_index"] = i + 1

    origin_hop = None
    for hop in extracted_hops:
        if hop["geo"]["status"] != "private":
            origin_hop = hop
            break
    if not origin_hop and extracted_hops:
        origin_hop = extracted_hops[0]

    # ── Authentication parsing ───────────────────────────────────────────
    auth_header = headers_summary["authentication_results"] or ""
    rec_spf = msg.get("Received-SPF", "")
    arc_auth = msg.get("ARC-Authentication-Results", "")
    dkim_sig = msg.get("DKIM-Signature", "")

    auth_combined = f"{auth_header} {rec_spf} {arc_auth}".lower()
    has_auth_header = any(
        h not in ["none", "", "unknown", None]
        for h in [auth_header, rec_spf, arc_auth]
    )

    auth_status = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
    }
    if has_auth_header:
        if "spf=pass" in auth_combined or "pass " in rec_spf.lower():
            auth_status["spf"] = "pass"
        elif "spf=fail" in auth_combined or "spf=softfail" in auth_combined or "fail" in rec_spf.lower():
            auth_status["spf"] = "fail"

        if "dkim=pass" in auth_combined:
            auth_status["dkim"] = "pass"
        elif "dkim=fail" in auth_combined:
            auth_status["dkim"] = "fail"
        elif dkim_sig and auth_status["dkim"] == "none":
            auth_status["dkim"] = "pass"

        if "dmarc=pass" in auth_combined:
            auth_status["dmarc"] = "pass"
        elif "dmarc=fail" in auth_combined:
            auth_status["dmarc"] = "fail"

    # ── Body extraction ──────────────────────────────────────────────────
    body_text = ""
    body_html = ""
    html_urls = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition', ''))
            if 'attachment' in cdispo:
                continue
            if ctype == 'text/plain' and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    pass
            elif ctype == 'text/html' and not body_html:
                try:
                    body_html = part.get_content()
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
            if ctype == 'text/html':
                body_html = content
            else:
                body_text = content
        except Exception:
            pass

    if not body_text and body_html:
        body_text = strip_html_tags(body_html)

    if body_html:
        html_urls = extract_urls_from_html(body_html)

    # ── Threat analysis ──────────────────────────────────────────────────
    nlp_threats = analyze_body_threats(body_text, html_urls)
    attachment_analysis = analyze_attachments(msg)
    spoofing = detect_sender_spoofing(headers_summary["from"])
    reply_to_check = detect_reply_to_mismatch(
        headers_summary["from"], headers_summary.get("reply_to")
    )

    # ── Composite threat score ───────────────────────────────────────────
    total_score = nlp_threats["threat_score"]
    score_breakdown = [
        {"factor": "NLP linguistic heuristic & trigger scoring", "points": nlp_threats["threat_score"]}
    ]

    if has_auth_header and auth_status["spf"] == "fail":
        total_score += 20
        score_breakdown.append({"factor": "SPF authentication failed", "points": 20})

    if has_auth_header and auth_status["dkim"] == "fail":
        total_score += 15
        score_breakdown.append({"factor": "DKIM signature failed", "points": 15})

    if has_auth_header and auth_status["dmarc"] in ["fail", "none"]:
        pts = 25 if auth_status["dmarc"] == "fail" else 10
        total_score += pts
        score_breakdown.append({"factor": f"DMARC enforcement {auth_status['dmarc'].upper()}", "points": pts})

    if spoofing["spoofed"]:
        total_score += 25
        score_breakdown.append({"factor": f"Brand impersonation: {spoofing['brand']}", "points": 25})

    if reply_to_check["mismatch"]:
        total_score += 20
        score_breakdown.append({"factor": "Reply-To routing desynchronization", "points": 20})

    if attachment_analysis["has_dangerous"]:
        total_score += 25
        score_breakdown.append({
            "factor": f"Hostile attachment: {', '.join(attachment_analysis['dangerous_files'])}",
            "points": 25
        })

    sender_domain = extract_domain_from_email_addr(headers_summary["from"])
    if any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        total_score += 15
        score_breakdown.append({"factor": f"High-risk sender domain TLD: {sender_domain}", "points": 15})

    total_score = min(total_score, 100)
    verdict = "MALICIOUS" if total_score >= 65 else ("SUSPICIOUS" if total_score >= 40 else "BENIGN")

    # Map DEFCON Level (Military / Defense classification)
    if total_score >= 80:
        defcon = 1
        defcon_title = "DEFCON 1 // IMMINENT ATTACK"
    elif total_score >= 65:
        defcon = 2
        defcon_title = "DEFCON 2 // ARMED HOSTILE"
    elif total_score >= 40:
        defcon = 3
        defcon_title = "DEFCON 3 // ELEVATED THREAT"
    elif total_score >= 20:
        defcon = 4
        defcon_title = "DEFCON 4 // ADVISORY GUARDED"
    else:
        defcon = 5
        defcon_title = "DEFCON 5 // NORMAL OPERATIONS"

    # Map MITRE ATT&CK techniques
    mitre_tactics = map_mitre_attack(
        total_score,
        spoofing,
        reply_to_check,
        attachment_analysis,
        nlp_threats.get("urls_found", []),
        auth_status
    )

    record = {
        "id": f"incident_{len(CAMPAIGN_REGISTRY)}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "subject": headers_summary["subject"],
        "sender": headers_summary["from"],
        "recipient": headers_summary.get("to", "Unknown"),
        "return_path": headers_summary["return_path"],
        "reply_to": headers_summary.get("reply_to", "Unknown"),
        "origin_ip": origin_hop["ip"] if origin_hop else "Unknown",
        "origin_geo": origin_hop["geo"] if origin_hop else None,
        "verdict": verdict,
        "defcon": defcon,
        "defcon_title": defcon_title,
        "score": total_score,
        "score_breakdown": score_breakdown,
        "hops": extracted_hops,
        "auth": auth_status,
        "nlp_analysis": nlp_threats,
        "spoofing": spoofing,
        "reply_to_mismatch": reply_to_check,
        "attachments": attachment_analysis,
        "headers": headers_summary,
        "mitre_attack": mitre_tactics,
    }

    # Generate containment playbook
    record["containment_playbook"] = generate_containment_playbook(verdict, record)

    CAMPAIGN_REGISTRY.append(record)
    if len(CAMPAIGN_REGISTRY) > MAX_CAMPAIGNS:
        CAMPAIGN_REGISTRY.pop(0)

    return record


@app.get("/scenarios")
async def get_scenarios():
    """Return available pre-configured military threat scenarios."""
    return {
        "count": len(PRESET_SCENARIOS),
        "scenarios": [
            {
                "id": k,
                "title": v["title"],
                "threat_type": v["threat_type"],
                "target": v["target"],
                "attacker": v["attacker"],
                "raw_email": v["raw_email"]
            }
            for k, v in PRESET_SCENARIOS.items()
        ]
    }


@app.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    """Analyze an uploaded .eml email file."""
    raw_content = await file.read()
    if not raw_content or not raw_content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(raw_content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Maximum 10MB.")
    return process_email_forensics(raw_content)


@app.post("/analyze/text")
async def analyze_text(
    request: Request,
    raw_email: Optional[str] = Form(None)
):
    """Analyze raw email text pasted by the user (supports Form, JSON, and raw text)."""
    text_to_process = raw_email
    content_type = request.headers.get("content-type", "").lower()
    is_json = "application/json" in content_type

    if is_json:
        try:
            body = await request.json()
            if isinstance(body, dict):
                for key in ["raw_email", "email", "text", "payload", "content"]:
                    if key in body:
                        text_to_process = body[key]
                        break
            elif isinstance(body, str):
                text_to_process = body
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload.")
    elif not text_to_process:
        body_bytes = await request.body()
        if body_bytes:
            text_to_process = body_bytes.decode("utf-8", errors="ignore")

    if not text_to_process or not str(text_to_process).strip():
        raise HTTPException(
            status_code=422,
            detail="Email content is required (via 'raw_email' form field, JSON payload, or raw text body)."
        )

    if len(str(text_to_process)) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Input too large. Maximum 5MB.")

    return process_email_forensics(str(text_to_process).encode("utf-8"))


@app.get("/export/stix/{campaign_idx}")
async def export_stix_by_index(campaign_idx: int):
    """Export incident IOCs in OASIS STIX 2.1 JSON standard."""
    if 0 <= campaign_idx < len(CAMPAIGN_REGISTRY):
        bundle = generate_stix_bundle(CAMPAIGN_REGISTRY[campaign_idx])
        return JSONResponse(content=bundle)
    raise HTTPException(status_code=404, detail="Incident not found in active registry.")


@app.get("/campaign/graph")
async def get_campaign_graph():
    """Generate Palantir Gotham Link-Analysis Correlation Graph across all analyzed attacks."""
    nodes = []
    edges = []
    seen_nodes = set()

    for idx, item in enumerate(CAMPAIGN_REGISTRY):
        email_id = f"email_{idx}"
        sender_domain = extract_domain_from_email_addr(item.get('sender', '')) or "unknown-domain"
        sender_id = f"domain_{sender_domain}"
        ip_val = item.get('origin_ip')
        has_real_ip = ip_val and ip_val != "Unknown"
        ip_id = f"ip_{ip_val}" if has_real_ip else None

        # Email node
        if email_id not in seen_nodes:
            seen_nodes.add(email_id)
            nodes.append({
                "id": email_id,
                "label": item.get('subject', 'Untitled')[:38],
                "type": "email",
                "verdict": item.get("verdict", "UNKNOWN"),
                "score": item.get("score", 0),
                "metadata": {
                    "sender": item.get("sender"),
                    "recipient": item.get("recipient"),
                    "date": item.get("headers", {}).get("date")
                }
            })

        # Domain node
        if sender_id not in seen_nodes:
            seen_nodes.add(sender_id)
            nodes.append({
                "id": sender_id,
                "label": sender_domain,
                "type": "domain",
                "verdict": None,
                "metadata": {
                    "is_spoofed": item.get("spoofing", {}).get("spoofed", False),
                    "brand": item.get("spoofing", {}).get("brand")
                }
            })
        edges.append({"source": email_id, "target": sender_id, "relation": "SENT_BY"})

        # IP node
        if ip_id and has_real_ip:
            if ip_id not in seen_nodes:
                seen_nodes.add(ip_id)
                geo = item.get("origin_geo") or {}
                nodes.append({
                    "id": ip_id,
                    "label": ip_val,
                    "type": "ip",
                    "verdict": None,
                    "metadata": {
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "isp": geo.get("isp")
                    }
                })
            edges.append({"source": email_id, "target": ip_id, "relation": "ROUTED_THROUGH"})

        # Reply-To node
        if item.get("reply_to_mismatch", {}).get("mismatch"):
            reply_domain = item["reply_to_mismatch"].get("reply_to_domain") or "unknown-reply"
            reply_id = f"domain_{reply_domain}"
            if reply_id not in seen_nodes:
                seen_nodes.add(reply_id)
                nodes.append({
                    "id": reply_id,
                    "label": reply_domain,
                    "type": "domain",
                    "verdict": None,
                    "metadata": {"role": "Disparate Reply-To Target"}
                })
            edges.append({"source": email_id, "target": reply_id, "relation": "REPLY_DESYNC"})

        # Weaponized Attachment nodes
        for att in item.get("attachments", {}).get("attachments", []):
            if att.get("dangerous"):
                att_id = f"payload_{att['filename']}"
                if att_id not in seen_nodes:
                    seen_nodes.add(att_id)
                    nodes.append({
                        "id": att_id,
                        "label": att['filename'][:30],
                        "type": "payload",
                        "verdict": "MALICIOUS",
                        "metadata": {
                            "size_bytes": att.get("size_bytes"),
                            "sha256": att.get("sha256")
                        }
                    })
                edges.append({"source": email_id, "target": att_id, "relation": "CARRIES_PAYLOAD"})

        # Phishing URL target nodes
        for u in item.get("nlp_analysis", {}).get("urls_found", [])[:2]:
            clean_u = u.replace("http://", "").replace("https://", "").split("/")[0]
            url_id = f"url_{clean_u}"
            if url_id not in seen_nodes:
                seen_nodes.add(url_id)
                nodes.append({
                    "id": url_id,
                    "label": clean_u[:28],
                    "type": "url",
                    "verdict": "SUSPICIOUS",
                    "metadata": {"full_url": u}
                })
            edges.append({"source": email_id, "target": url_id, "relation": "HARVESTS_VIA"})

    return {"nodes": nodes, "edges": edges, "total_campaigns": len(CAMPAIGN_REGISTRY)}


@app.get("/health")
async def health():
    return {
        "status": "operational",
        "apparatus": "SIH 26106 Sentinel",
        "campaigns_in_registry": len(CAMPAIGN_REGISTRY),
        "geo_cache_entries": len(_geo_cache),
        "engine": "Palantir Cyber Intelligence Engine v3.0"
    }


app.mount("/", StaticFiles(directory="static", html=True), name="static")
