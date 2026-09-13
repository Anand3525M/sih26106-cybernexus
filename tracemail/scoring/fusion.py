"""
TraceMail Module 4: Multi-Signal Risk Fusion Engine
backend/scoring/fusion.py

Synthesizes outputs from Module 1 (Protocol Forensics) and Module 2 (Origin Intelligence)
into a deterministic 0 to 100 Composite Threat Score and assigns strict verdict tiers:
- 0 - 25: "BENIGN / LEGITIMATE"
- 26 - 60: "SUSPICIOUS / ELEVATED"
- 61 - 100: "MALICIOUS / HIGH CONFIDENCE SPOOF"
"""
from typing import List, Dict, Any, Optional
from backend.contracts.protocol_forensics import ProtocolForensicsResult
from backend.contracts.origin_intelligence import OriginIntelligenceResult
from backend.contracts.risk_scoring import RiskSignalContract, RiskFusionResult, VerdictTier

def evaluate_risk_fusion(
    protocol_res: ProtocolForensicsResult,
    origin_res: OriginIntelligenceResult
) -> RiskFusionResult:
    """
    Evaluates multi-signal risk rules deterministically across protocol authentication,
    origin infrastructure reputation, and relay hop timing anomalies.
    """
    triggered_signals: List[RiskSignalContract] = []

    # =========================================================================
    # 1. PROTOCOL PENALTIES
    # =========================================================================
    # DMARC policy reject / fail: +35
    dmarc_fail = (
        protocol_res.dmarc.verdict == "fail"
        or (
            protocol_res.dmarc.verdict != "pass"
            and (
                protocol_res.dmarc.policy == "reject"
                or (not protocol_res.dmarc.alignment.spf_aligned and not protocol_res.dmarc.alignment.dkim_aligned)
            )
        )
    )
    if dmarc_fail:
        triggered_signals.append(RiskSignalContract(
            signal_id="PROTO_DMARC_FAIL",
            category="protocol",
            penalty_points=35,
            description="DMARC policy failed or reject policy enforced due to missing/unaligned SPF and DKIM.",
            evidence={
                "dmarc_verdict": protocol_res.dmarc.verdict,
                "dmarc_policy": str(protocol_res.dmarc.policy),
                "spf_aligned": str(protocol_res.dmarc.alignment.spf_aligned),
                "dkim_aligned": str(protocol_res.dmarc.alignment.dkim_aligned)
            }
        ))

    # SPF hardfail / unaligned: +25
    spf_fail = (
        protocol_res.spf.verdict in ["fail", "softfail", "permerror"]
        or not protocol_res.dmarc.alignment.spf_aligned
    )
    if spf_fail:
        triggered_signals.append(RiskSignalContract(
            signal_id="PROTO_SPF_UNALIGNED",
            category="protocol",
            penalty_points=25,
            description="SPF authorization failed or sender envelope domain is unaligned with From header.",
            evidence={
                "spf_verdict": protocol_res.spf.verdict,
                "spf_domain": protocol_res.spf.domain,
                "spf_aligned": str(protocol_res.dmarc.alignment.spf_aligned)
            }
        ))

    # DKIM signature mismatch / missing: +25
    dkim_fail = (
        protocol_res.dkim.verdict in ["fail", "invalid", "none"]
        or not protocol_res.dmarc.alignment.dkim_aligned
    )
    if dkim_fail:
        triggered_signals.append(RiskSignalContract(
            signal_id="PROTO_DKIM_MISMATCH",
            category="protocol",
            penalty_points=25,
            description="DKIM cryptographic signature is missing, invalid, or unaligned with From domain.",
            evidence={
                "dkim_verdict": protocol_res.dkim.verdict,
                "dkim_domain": str(protocol_res.dkim.domain),
                "dkim_aligned": str(protocol_res.dmarc.alignment.dkim_aligned)
            }
        ))

    # =========================================================================
    # 2. ORIGIN INTELLIGENCE PENALTIES
    # =========================================================================
    # Tor exit node or bulletproof ASN: +25
    is_tor = origin_res.threat_assessment.is_tor_exit_node
    as_org = (origin_res.asn.as_org or "").lower()
    as_name = (origin_res.asn.as_name or "").lower()
    is_bulletproof = ("bulletproof" in as_org or "bulletproof" in as_name or "darknet" in as_org)
    if is_tor or is_bulletproof:
        triggered_signals.append(RiskSignalContract(
            signal_id="ORIGIN_TOR_OR_BULLETPROOF",
            category="origin",
            penalty_points=25,
            description="Originating host attributed to known Tor exit router or high-risk bulletproof hosting network.",
            evidence={
                "is_tor_exit_node": str(is_tor),
                "as_org": str(origin_res.asn.as_org),
                "as_name": str(origin_res.asn.as_name)
            }
        ))

    # Domain homoglyph / typosquat / punycode: +20
    homoglyph = origin_res.domain_intel.homoglyph_detected
    typosquat = origin_res.domain_intel.typosquat_suspect
    punycode = origin_res.domain_intel.is_punycode
    if homoglyph or typosquat or punycode:
        triggered_signals.append(RiskSignalContract(
            signal_id="ORIGIN_DECEPTIVE_DOMAIN",
            category="origin",
            penalty_points=20,
            description="Sender domain employs homoglyphs, typosquatting characters, or IDN punycode obfuscation.",
            evidence={
                "homoglyph_detected": str(homoglyph),
                "typosquat_suspect": str(typosquat),
                "is_punycode": str(punycode),
                "domain": origin_res.domain_intel.domain
            }
        ))

    # Private RFC1918 bypass or internal IP anomaly: +15
    rfc1918_bypass = False
    rfc1918_evidence = []
    for h in protocol_res.relay_hops:
        for a in h.anomalies:
            if "rfc1918" in a.lower() or "bypass" in a.lower():
                rfc1918_bypass = True
                rfc1918_evidence.append(f"Hop #{h.hop_number}: {a}")
    for a in origin_res.hop_timing.timing_anomalies:
        if "rfc1918" in a.lower() or "bypass" in a.lower():
            rfc1918_bypass = True
            rfc1918_evidence.append(a)
    
    if rfc1918_bypass:
        triggered_signals.append(RiskSignalContract(
            signal_id="ORIGIN_RFC1918_BYPASS",
            category="origin",
            penalty_points=15,
            description="MTA relay route exhibits internal RFC1918 address bypass after public transit hop.",
            evidence={"anomalies": "; ".join(rfc1918_evidence)}
        ))

    # =========================================================================
    # 3. HOP TIMING ANOMALIES
    # =========================================================================
    # Negative hop transit latency (clock tampering): +15
    negative_delay = False
    negative_evidence = []
    for h in protocol_res.relay_hops:
        if h.transit_delay_seconds < 0:
            negative_delay = True
            negative_evidence.append(f"Hop #{h.hop_number} delay is {h.transit_delay_seconds}s")
        for a in h.anomalies:
            if any(k in a.lower() for k in ("inversion", "clock skew", "negative", "earlier than")):
                negative_delay = True
                negative_evidence.append(f"Hop #{h.hop_number}: {a}")
    for a in origin_res.hop_timing.timing_anomalies:
        if any(k in a.lower() for k in ("inversion", "clock skew", "negative", "earlier than")):
            negative_delay = True
            negative_evidence.append(a)

    if negative_delay:
        triggered_signals.append(RiskSignalContract(
            signal_id="TIMING_CLOCK_INVERSION",
            category="timing",
            penalty_points=15,
            description="Negative transit latency or clock skew detected across transmission hops (falsified headers).",
            evidence={"details": "; ".join(negative_evidence)}
        ))

    # Relay hop latency > 120s: +10
    high_latency = (
        any(h.transit_delay_seconds > 120 for h in protocol_res.relay_hops)
        or origin_res.hop_timing.max_delay_seconds > 120
    )
    if high_latency:
        max_sec = max(
            [h.transit_delay_seconds for h in protocol_res.relay_hops]
            + [origin_res.hop_timing.max_delay_seconds]
        )
        triggered_signals.append(RiskSignalContract(
            signal_id="TIMING_HOLDING_DELAY",
            category="timing",
            penalty_points=10,
            description="Relay hop transit latency exceeds 120 seconds threshold, indicating holding or relay queueing.",
            evidence={"max_hop_delay_seconds": str(max_sec)}
        ))

    # =========================================================================
    # 4. AGGREGATION & STRICT VERDICT TIERS
    # =========================================================================
    proto_subtotal = sum(s.penalty_points for s in triggered_signals if s.category == "protocol")
    origin_subtotal = sum(s.penalty_points for s in triggered_signals if s.category == "origin")
    timing_subtotal = sum(s.penalty_points for s in triggered_signals if s.category == "timing")

    raw_score = proto_subtotal + origin_subtotal + timing_subtotal
    composite_threat_score = max(0, min(100, raw_score))

    # Strict Verdict Tiers:
    # 0 - 25: "BENIGN / LEGITIMATE"
    # 26 - 60: "SUSPICIOUS / ELEVATED"
    # 61 - 100: "MALICIOUS / HIGH CONFIDENCE SPOOF"
    if composite_threat_score <= 25:
        verdict_tier: VerdictTier = "BENIGN / LEGITIMATE"
        summary = (
            f"Verdict: BENIGN / LEGITIMATE (Score: {composite_threat_score}/100). "
            f"All critical cryptographic protocols and routing indicators are within safe thresholds."
        )
    elif composite_threat_score <= 60:
        verdict_tier = "SUSPICIOUS / ELEVATED"
        summary = (
            f"Verdict: SUSPICIOUS / ELEVATED (Score: {composite_threat_score}/100). "
            f"Anomalies detected across {len(triggered_signals)} signals requiring manual forensic scrutiny."
        )
    else:
        verdict_tier = "MALICIOUS / HIGH CONFIDENCE SPOOF"
        summary = (
            f"Verdict: MALICIOUS / HIGH CONFIDENCE SPOOF (Score: {composite_threat_score}/100). "
            f"Critical protocol alignment failures and/or malicious origin infrastructure identified."
        )

    return RiskFusionResult(
        composite_threat_score=composite_threat_score,
        verdict_tier=verdict_tier,
        triggered_signals=triggered_signals,
        protocol_subtotal=proto_subtotal,
        origin_subtotal=origin_subtotal,
        timing_subtotal=timing_subtotal,
        summary=summary
    )
