"""
Module 1: Ingestion & RFC 5322 MIME Parser
Unfolds multiline headers, extracts envelope metadata, bodies, attachments, and transmission hops.
"""
import re
import hashlib
import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union

from backend.contracts.protocol_forensics import MessageHeaders

# RFC 5321/5322 Token and IP Regular Expressions
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IPV6_REGEX = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"\')]+')

def unfold_header(raw_value: str) -> str:
    """
    Unfold multiline RFC 5322 header field per Section 2.2.3.
    Replaces CRLF or LF immediately followed by whitespace (WSP) with a single space.
    """
    if not raw_value:
        return ""
    # Replace CRLF or LF followed by spaces or tabs with a single space
    unfolded = re.sub(r'\r?\n[ \t]+', ' ', str(raw_value))
    # Normalize excessive interior whitespace while preserving content
    return " ".join(unfolded.split())

def extract_ip_from_hop(header_val: str) -> Optional[str]:
    """Extract first non-private or valid public IPv4/IPv6 address from a Received header string."""
    if not header_val:
        return None
        
    # Check IPv4
    ipv4_matches = IP_REGEX.findall(header_val)
    for ip in ipv4_matches:
        parts = [int(p) for p in ip.split('.')]
        if all(0 <= p <= 255 for p in parts) and ip not in ("255.255.255.255", "0.0.0.0"):
            return ip

    # Check IPv6
    ipv6_matches = IPV6_REGEX.findall(header_val)
    if ipv6_matches:
        return ipv6_matches[0]

    return None

class IngestedEmail:
    """Internal domain model representing a parsed RFC 5322 message."""
    def __init__(
        self,
        email_id: str,
        source_filename: str,
        headers: MessageHeaders,
        raw_received_headers: List[str],
        body_plain: str,
        body_html: str,
        extracted_urls: List[str],
        attachments: List[Dict[str, Any]],
        raw_bytes: bytes
    ):
        self.email_id = email_id
        self.source_filename = source_filename
        self.headers = headers
        self.raw_received_headers = raw_received_headers
        self.body_plain = body_plain
        self.body_html = body_html
        self.extracted_urls = extracted_urls
        self.attachments = attachments
        self.raw_bytes = raw_bytes

def parse_eml_bytes(raw_bytes: bytes, filename: str = "upload.eml") -> IngestedEmail:
    """
    Parse raw RFC 5322 EML bytes into IngestedEmail data structure.
    Strictly complies with RFC 5322 header unfolding and MIME decoding.
    """
    email_id = hashlib.sha256(raw_bytes).hexdigest()
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    
    # 1. Parse and Unfold From Address & Domain
    raw_from = unfold_header(msg.get("From", ""))
    display_name, from_addr = parseaddr(raw_from)
    from_domain = from_addr.split("@")[-1].lower().strip() if "@" in from_addr else "unknown.local"
    
    # 2. Return-Path and Reply-To
    raw_return_path = unfold_header(msg.get("Return-Path", ""))
    _, return_path = parseaddr(raw_return_path)
    if not return_path:
        return_path = from_addr
        
    raw_reply_to = unfold_header(msg.get("Reply-To", ""))
    _, reply_to = parseaddr(raw_reply_to)
    if not reply_to:
        reply_to = from_addr

    # 3. Recipients (To, Cc)
    to_list = []
    for raw_to in msg.get_all("To", []):
        unfolded_to = unfold_header(str(raw_to))
        for part in unfolded_to.split(","):
            _, addr = parseaddr(part)
            if addr and addr not in to_list:
                to_list.append(addr)

    # 4. Timestamps
    date_header_raw = msg.get("Date", "")
    date_header = unfold_header(date_header_raw) if date_header_raw else None
    timestamp_utc = None
    if date_header:
        try:
            dt = parsedate_to_datetime(date_header)
            timestamp_utc = dt.astimezone(timezone.utc).isoformat()
        except Exception:
            timestamp_utc = datetime.now(timezone.utc).isoformat()
    else:
        timestamp_utc = datetime.now(timezone.utc).isoformat()

    # 5. Extract all headers with clean unfolding
    all_headers = {}
    for k, v in msg.items():
        key_lower = str(k).lower().strip()
        val_unfolded = unfold_header(str(v))
        # Preserve header value
        if key_lower in all_headers:
            all_headers[key_lower] = f"{all_headers[key_lower]}; {val_unfolded}"
        else:
            all_headers[key_lower] = val_unfolded

    # 6. Received headers in raw chronological transmission order (oldest to newest)
    raw_received = msg.get_all("Received", [])
    # Unfold each individual Received header
    unfolded_received = [unfold_header(str(r)) for r in raw_received]
    # In RFC 5322, topmost Received header is the latest destination hop.
    # Reversing gives chronological order: [Originating MTA -> Intermediate -> Destination MX]
    chronological_received = list(reversed(unfolded_received))

    subject_raw = msg.get("Subject", "")
    subject_unfolded = unfold_header(str(subject_raw)) if subject_raw else ""

    message_id_raw = msg.get("Message-ID")
    message_id_unfolded = unfold_header(str(message_id_raw)) if message_id_raw else None

    message_headers = MessageHeaders(
        message_id=message_id_unfolded,
        from_address=from_addr,
        from_domain=from_domain,
        from_display_name=display_name or None,
        reply_to=reply_to,
        return_path=return_path,
        to_addresses=to_list,
        subject=subject_unfolded,
        date_header=date_header,
        timestamp_utc=timestamp_utc,
        all_headers=all_headers
    )

    # 7. Extract Body (Plain & HTML) and Attachments
    body_plain = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            payload = part.get_payload(decode=True)

            if "attachment" in content_disposition or part.get_filename():
                filename_att = part.get_filename() or "unnamed_attachment"
                payload_bytes = payload or b""
                attachments.append({
                    "filename": filename_att,
                    "content_type": content_type,
                    "size_bytes": len(payload_bytes),
                    "sha256": hashlib.sha256(payload_bytes).hexdigest()
                })
            elif content_type == "text/plain" and not body_plain:
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body_plain = payload.decode(charset, errors="replace") if payload else ""
                except Exception:
                    body_plain = str(payload)
            elif content_type == "text/html" and not body_html:
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body_html = payload.decode(charset, errors="replace") if payload else ""
                except Exception:
                    body_html = str(payload)
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        charset = msg.get_content_charset() or "utf-8"
        if content_type == "text/html":
            body_html = payload.decode(charset, errors="replace") if payload else ""
        else:
            body_plain = payload.decode(charset, errors="replace") if payload else ""

    # 8. Extract URLs from body
    extracted_urls = list(set(URL_REGEX.findall(f"{body_plain} {body_html}")))

    return IngestedEmail(
        email_id=email_id,
        source_filename=filename,
        headers=message_headers,
        raw_received_headers=chronological_received,
        body_plain=body_plain,
        body_html=body_html,
        extracted_urls=extracted_urls,
        attachments=attachments,
        raw_bytes=raw_bytes
    )

def parse_eml_file(file_path: Union[str, Path]) -> IngestedEmail:
    """
    Read and parse an RFC 5322 EML file from disk with strict pathlib.Path handling.
    """
    path_obj = Path(file_path).resolve()
    with open(path_obj, "rb") as f:
        raw_bytes = f.read()
    return parse_eml_bytes(raw_bytes, filename=path_obj.name)
