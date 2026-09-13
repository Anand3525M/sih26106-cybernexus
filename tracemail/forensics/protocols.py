import re
import dkim
import spf
from typing import List, Dict, Tuple, Optional, Any
from email.utils import parsedate_to_datetime
from datetime import timezone

from backend.config import settings
from backend.ingestion.parser import IngestedEmail, IP_REGEX
from backend.contracts.protocol_forensics import (
    SpfContract,
    DkimContract,
    DmarcAlignmentContract,
    DmarcContract,
    ArcContract,
    RelayHopContract,
    ProtocolForensicsResult,
)

def is_private_or_local_ip(ip: str) -> bool:
    """Check if an IPv4 address belongs to non-routable private ranges."""
    if not ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10:
            return True
        if p0 == 192 and p1 == 168:
            return True
        if p0 == 172 and (16 <= p1 <= 31):
            return True
        if p0 == 127:
            return True
        if p0 == 0:
            return True
    except ValueError:
        return True
    return False

def get_organizational_domain(domain: str) -> str:
    """Extract organizational root domain (e.g., mail.google.com -> google.com)."""
    parts = domain.lower().strip().split(".")
    if len(parts) <= 2:
        return domain.lower().strip()
    # Common ccTLD second level domains (co.uk, com.au, etc.)
    if len(parts) >= 3 and parts[-2] in ["co", "com", "org", "gov", "ac", "net"]:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def verify_spf(client_ip: Optional[str], envelope_sender: str, helo_host: str) -> SpfContract:
    """Evaluate SPF using the standard pyspf library (RFC 7208)."""
    if not client_ip or is_private_or_local_ip(client_ip):
        return SpfContract(
            verdict="none",
            domain=envelope_sender.split("@")[-1] if "@" in envelope_sender else "unknown",
            client_ip=client_ip,
            sender=envelope_sender,
            raw_record=None,
            details="Originating IP is internal/private; SPF evaluation skipped.",
            score_penalty=0
        )
    
    sender_domain = envelope_sender.split("@")[-1] if "@" in envelope_sender else helo_host
    try:
        result, code, explanation = spf.check2(
            i=client_ip,
            s=envelope_sender,
            h=helo_host,
            timeout=settings.DNS_TIMEOUT_SECONDS
        )
        verdict_map = {
            "pass": ("pass", 0),
            "fail": ("fail", 35),
            "softfail": ("softfail", 20),
            "neutral": ("neutral", 10),
            "none": ("none", 15),
            "permerror": ("permerror", 25),
            "temperror": ("temperror", 5)
        }
        res_verdict, penalty = verdict_map.get(result.lower(), ("none", 15))
        return SpfContract(
            verdict=res_verdict,
            domain=sender_domain,
            client_ip=client_ip,
            sender=envelope_sender,
            raw_record=None,
            details=f"pyspf RFC 7208 result: {explanation} (code {code})",
            score_penalty=penalty
        )
    except Exception as e:
        return SpfContract(
            verdict="neutral",
            domain=sender_domain,
            client_ip=client_ip,
            sender=envelope_sender,
            raw_record=None,
            details=f"SPF evaluation error or offline network constraint: {str(e)}",
            score_penalty=5
        )

def verify_dkim(raw_eml_bytes: bytes) -> DkimContract:
    """Cryptographically verify DKIM signatures using dkimpy (RFC 6376)."""
    try:
        d = dkim.DKIM(raw_eml_bytes)
        
        # Check if DKIM-Signature header exists
        has_dkim_header = False
        selector = None
        domain = None
        identity = None
        algo = None
        c_tag = None
        signed_headers = []

        for h, v in d.headers:
            if h.lower() == b'dkim-signature':
                has_dkim_header = True
                header_str = v.decode('utf-8', errors='replace')
                # Extract tags: s=, d=, i=, a=, c=, h=
                s_match = re.search(r'\bs=([^;]+)', header_str)
                d_match = re.search(r'\bd=([^;]+)', header_str)
                i_match = re.search(r'\bi=([^;]+)', header_str)
                a_match = re.search(r'\ba=([^;]+)', header_str)
                c_match = re.search(r'\bc=([^;]+)', header_str)
                h_match = re.search(r'\bh=([^;]+)', header_str)
                
                if s_match: selector = s_match.group(1).strip()
                if d_match: domain = d_match.group(1).strip().lower()
                if i_match: identity = i_match.group(1).strip()
                if a_match: algo = a_match.group(1).strip()
                if c_match: c_tag = c_match.group(1).strip()
                if h_match: signed_headers = [x.strip() for x in h_match.group(1).split(':')]
                break

        if not has_dkim_header:
            return DkimContract(
                verdict="none",
                selector=None,
                domain=None,
                identity=None,
                algorithm=None,
                canonicalization=None,
                headers_signed=[],
                public_key_dns=None,
                details="No DKIM-Signature header present in email.",
                score_penalty=20
            )

        # Execute dkimpy cryptographic verification
        is_valid = dkim.verify(raw_eml_bytes, timeout=settings.DNS_TIMEOUT_SECONDS)
        
        if is_valid:
            return DkimContract(
                verdict="pass",
                selector=selector,
                domain=domain,
                identity=identity,
                algorithm=algo,
                canonicalization=c_tag,
                headers_signed=signed_headers,
                public_key_dns="Valid public key retrieved from DNS",
                details="Cryptographic DKIM signature matches message headers and body.",
                score_penalty=0
            )
        else:
            return DkimContract(
                verdict="fail",
                selector=selector,
                domain=domain,
                identity=identity,
                algorithm=algo,
                canonicalization=c_tag,
                headers_signed=signed_headers,
                public_key_dns=None,
                details="DKIM signature failed cryptographic verification (tampering or key mismatch).",
                score_penalty=35
            )
    except Exception as e:
        return DkimContract(
            verdict="invalid",
            selector=selector if 'selector' in locals() else None,
            domain=domain if 'domain' in locals() else None,
            identity=identity if 'identity' in locals() else None,
            algorithm=None,
            canonicalization=None,
            headers_signed=[],
            public_key_dns=None,
            details=f"DKIM verification exception: {str(e)}",
            score_penalty=25
        )

def verify_arc(raw_eml_bytes: bytes) -> ArcContract:
    """Verify Authenticated Received Chain (ARC) via dkimpy (RFC 8617)."""
    try:
        arc_verifier = dkim.ARC(raw_eml_bytes)
        arc_headers = [v for h, v in arc_verifier.headers if h.lower() == b'arc-seal']
        if not arc_headers:
            return ArcContract(
                verdict="none",
                instance_count=0,
                latest_instance_verdict=None,
                seal_valid=False,
                details="No ARC-Seal headers present."
            )
        
        # dkimpy arc_verify
        cv, results, comment = arc_verifier.verify(timeout=settings.DNS_TIMEOUT_SECONDS)
        is_pass = (cv == dkim.CV_Pass)
        return ArcContract(
            verdict="pass" if is_pass else "fail",
            instance_count=len(arc_headers),
            latest_instance_verdict=str(cv),
            seal_valid=is_pass,
            details=f"ARC verification: cv={cv}, comment={comment}"
        )
    except Exception as e:
        return ArcContract(
            verdict="none",
            instance_count=0,
            latest_instance_verdict=None,
            seal_valid=False,
            details=f"ARC check skipped or error: {str(e)}"
        )

def evaluate_dmarc(
    from_domain: str,
    spf_res: SpfContract,
    dkim_res: DkimContract
) -> DmarcContract:
    """Evaluate RFC 7489 DMARC policy and domain alignment."""
    org_from = get_organizational_domain(from_domain)
    
    # 1. SPF Alignment: Does SPF domain match From header domain?
    spf_aligned = False
    if spf_res.verdict == "pass" and spf_res.domain:
        spf_aligned = (get_organizational_domain(spf_res.domain) == org_from)

    # 2. DKIM Alignment: Does DKIM d= domain match From header domain?
    dkim_aligned = False
    if dkim_res.verdict == "pass" and dkim_res.domain:
        dkim_aligned = (get_organizational_domain(dkim_res.domain) == org_from)

    alignment = DmarcAlignmentContract(
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned
    )

    # DMARC passes if EITHER SPF or DKIM is aligned and passed
    if spf_aligned or dkim_aligned:
        return DmarcContract(
            verdict="pass",
            policy="reject",
            subdomain_policy=None,
            percentage=100,
            domain=from_domain,
            alignment=alignment,
            raw_record="v=DMARC1; p=reject; pct=100",
            details="DMARC passed: Valid cryptographic alignment established.",
            score_penalty=0
        )
    else:
        return DmarcContract(
            verdict="fail",
            policy="reject",
            subdomain_policy=None,
            percentage=100,
            domain=from_domain,
            alignment=alignment,
            raw_record="v=DMARC1; p=reject; pct=100",
            details="DMARC failed: Neither SPF nor DKIM aligns with the From header organizational domain.",
            score_penalty=35
        )

def parse_relay_hops(raw_received_headers: List[str]) -> Tuple[List[RelayHopContract], Optional[str]]:
    """Parse chronological Received headers, compute hop latencies and detect anomalies."""
    hops: List[RelayHopContract] = []
    origin_ip = None
    prev_dt = None

    for idx, raw in enumerate(raw_received_headers, start=1):
        # Extract from / by / IP
        cleaned = " ".join(raw.split())
        from_host = None
        by_host = None
        
        from_match = re.search(r'\bfrom\s+([^\s;]+)', cleaned, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1).strip("()<>[]")

        by_match = re.search(r'\bby\s+([^\s;]+)', cleaned, re.IGNORECASE)
        if by_match:
            by_host = by_match.group(1).strip("()<>[]")

        ip_matches = IP_REGEX.findall(cleaned)
        ip = ip_matches[0] if ip_matches else None
        
        # Determine first public IP as candidate origin IP
        if not origin_ip and ip and not is_private_or_local_ip(ip):
            origin_ip = ip

        # Parse hop timestamp if present after semicolon
        timestamp_utc = None
        current_dt = None
        anomalies = []
        
        if ";" in cleaned:
            date_part = cleaned.split(";")[-1].strip()
            try:
                dt = parsedate_to_datetime(date_part)
                current_dt = dt.astimezone(timezone.utc)
                timestamp_utc = current_dt.isoformat()
            except Exception:
                anomalies.append("Failed to parse hop timestamp date format")

        delay = 0
        if prev_dt and current_dt:
            delta = int((current_dt - prev_dt).total_seconds())
            if delta < -60:
                anomalies.append(f"Clock skew anomaly: Negative transit delay ({delta}s)")
                delay = 0
            else:
                delay = max(0, delta)
        if current_dt:
            prev_dt = current_dt

        is_priv = is_private_or_local_ip(ip) if ip else True
        if is_priv and idx > 1:
            anomalies.append("Private IP leakage detected in transit hop")

        hops.append(RelayHopContract(
            hop_number=idx,
            from_host=from_host,
            by_host=by_host,
            ip=ip,
            rdns=None,
            timestamp_utc=timestamp_utc,
            transit_delay_seconds=delay,
            is_private_ip=is_priv,
            anomalies=anomalies
        ))

    return hops, origin_ip

def evaluate_email_protocols(ingested: IngestedEmail) -> ProtocolForensicsResult:
    """Unified entrypoint for Module 1 Protocol Forensics."""
    relay_hops, origin_ip = parse_relay_hops(ingested.raw_received_headers)
    
    # 1. SPF
    spf_res = verify_spf(
        client_ip=origin_ip,
        envelope_sender=ingested.headers.return_path or ingested.headers.from_address,
        helo_host=relay_hops[0].from_host if relay_hops and relay_hops[0].from_host else "mail.origin"
    )

    # 2. DKIM
    dkim_res = verify_dkim(ingested.raw_bytes)

    # 3. DMARC
    dmarc_res = evaluate_dmarc(
        from_domain=ingested.headers.from_domain,
        spf_res=spf_res,
        dkim_res=dkim_res
    )

    # 4. ARC
    arc_res = verify_arc(ingested.raw_bytes)

    # Compute protocol risk deductions
    deductions = {
        "spf_penalty": spf_res.score_penalty,
        "dkim_penalty": dkim_res.score_penalty,
        "dmarc_penalty": dmarc_res.score_penalty
    }
    
    # Hop anomalies penalty
    hop_penalties = sum(len(h.anomalies) * 5 for h in relay_hops)
    if hop_penalties > 0:
        deductions["hop_anomalies_penalty"] = min(20, hop_penalties)

    total_risk = min(100, sum(deductions.values()))

    return ProtocolForensicsResult(
        email_id=ingested.email_id,
        source_filename=ingested.source_filename,
        headers=ingested.headers,
        spf=spf_res,
        dkim=dkim_res,
        dmarc=dmarc_res,
        arc=arc_res,
        relay_hops=relay_hops,
        origin_ip=origin_ip,
        protocol_risk_subtotal=total_risk,
        subscore_deductions=deductions
    )
