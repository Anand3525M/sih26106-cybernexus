import re
import hashlib
import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from backend.contracts.protocol_forensics import MessageHeaders

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"\')]+')

class IngestedEmail:
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

def extract_ip_from_hop(header_val: str) -> Optional[str]:
    """Extract first non-private or public IP from a Received header string."""
    matches = IP_REGEX.findall(header_val)
    if not matches:
        return None
    # Filter out obvious subnet masks or dates
    for ip in matches:
        parts = [int(p) for p in ip.split('.')]
        if all(0 <= p <= 255 for p in parts) and ip != "255.255.255.255" and ip != "0.0.0.0":
            return ip
    return matches[0] if matches else None

def parse_eml_bytes(raw_bytes: bytes, filename: str = "upload.eml") -> IngestedEmail:
    """Parse raw RFC 5322 EML bytes into IngestedEmail data structure."""
    email_id = hashlib.sha256(raw_bytes).hexdigest()
    
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    
    # 1. Parse From Address & Domain
    raw_from = msg.get("From", "")
    display_name, from_addr = parseaddr(raw_from)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else "unknown.local"
    
    # 2. Return-Path and Reply-To
    raw_return_path = msg.get("Return-Path", "")
    _, return_path = parseaddr(raw_return_path)
    if not return_path:
        return_path = from_addr
        
    raw_reply_to = msg.get("Reply-To", "")
    _, reply_to = parseaddr(raw_reply_to)
    if not reply_to:
        reply_to = from_addr

    # 3. Recipients
    to_list = []
    for raw_to in msg.get_all("To", []):
        for part in str(raw_to).split(","):
            _, addr = parseaddr(part)
            if addr:
                to_list.append(addr)

    # 4. Timestamps
    date_header = msg.get("Date", "")
    timestamp_utc = None
    if date_header:
        try:
            dt = parsedate_to_datetime(date_header)
            timestamp_utc = dt.astimezone(timezone.utc).isoformat()
        except Exception:
            timestamp_utc = datetime.now(timezone.utc).isoformat()
    else:
        timestamp_utc = datetime.now(timezone.utc).isoformat()

    # 5. Extract headers dictionary
    all_headers = {}
    for k, v in msg.items():
        all_headers[str(k).lower()] = str(v)

    # 6. Received headers in raw chronological order (oldest to newest)
    received_headers = [str(r) for r in msg.get_all("Received", [])]
    # In RFC 5322, topmost Received header is the latest hop.
    # Reversing gives chronological order: [Originating MTA -> Intermediate -> Destination MX]
    chronological_received = list(reversed(received_headers))

    message_headers = MessageHeaders(
        message_id=msg.get("Message-ID"),
        from_address=from_addr,
        from_domain=from_domain,
        from_display_name=display_name or None,
        reply_to=reply_to,
        return_path=return_path,
        to_addresses=to_list,
        subject=str(msg.get("Subject", "")),
        date_header=date_header or None,
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
                    body_plain = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    body_plain = str(payload)
            elif content_type == "text/html" and not body_html:
                try:
                    body_html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    body_html = str(payload)
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if content_type == "text/html":
            body_html = payload.decode(msg.get_content_charset() or "utf-8", errors="replace") if payload else ""
        else:
            body_plain = payload.decode(msg.get_content_charset() or "utf-8", errors="replace") if payload else ""

    # 8. Extract URLs from body
    extracted_urls = list(set(URL_REGEX.findall(body_plain + " " + body_html)))

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

def parse_eml_file(file_path: Path) -> IngestedEmail:
    """Convenience helper to read and parse an EML file from Path."""
    path_obj = Path(file_path).resolve()
    with open(path_obj, "rb") as f:
        raw_bytes = f.read()
    return parse_eml_bytes(raw_bytes, filename=path_obj.name)
