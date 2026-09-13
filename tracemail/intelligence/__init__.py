"""
TraceMail Origin Intelligence Module
100% Offline Geolocation (MaxMind GeoLite2-City), Autonomous Local SQLite Cache, Hop Timing Analysis
"""
from backend.intelligence.geoip import resolve_offline_ip, evaluate_domain_authenticity, analyze_origin_intelligence
from backend.intelligence.hop_timer import analyze_hop_timing
from backend.intelligence.cache import get_cached_intel, store_cached_intel

__all__ = [
    "resolve_offline_ip",
    "evaluate_domain_authenticity",
    "analyze_origin_intelligence",
    "analyze_hop_timing",
    "get_cached_intel",
    "store_cached_intel",
]
