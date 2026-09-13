from typing import List, Dict, Any, Tuple
from backend.contracts.protocol_forensics import RelayHopContract
from backend.contracts.origin_intelligence import HopTimingContract

def analyze_hop_timing(hops: List[RelayHopContract]) -> HopTimingContract:
    """Analyze transmission latencies between successive relay hops."""
    if not hops:
        return HopTimingContract(
            total_transit_seconds=0,
            hop_count=0,
            average_hop_delay_seconds=0.0,
            max_delay_hop_number=None,
            max_delay_seconds=0,
            timing_anomalies=[]
        )

    hop_count = len(hops)
    delays = [h.transit_delay_seconds for h in hops]
    total_transit = sum(delays)
    avg_delay = round(total_transit / max(1, hop_count), 2)
    
    max_delay = 0
    max_hop_idx = None
    anomalies: List[str] = []

    for h in hops:
        if h.transit_delay_seconds > max_delay:
            max_delay = h.transit_delay_seconds
            max_hop_idx = h.hop_number
        if h.transit_delay_seconds > 3600:
            anomalies.append(f"Holding anomaly: MTA hop {h.hop_number} delayed transmission by {h.transit_delay_seconds // 60} minutes")
        for a in h.anomalies:
            if a not in anomalies:
                anomalies.append(a)

    return HopTimingContract(
        total_transit_seconds=total_transit,
        hop_count=hop_count,
        average_hop_delay_seconds=avg_delay,
        max_delay_hop_number=max_hop_idx,
        max_delay_seconds=max_delay,
        timing_anomalies=anomalies
    )
