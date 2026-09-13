import socket
import pytest
from backend.intelligence.geoip import resolve_offline_ip, evaluate_domain_authenticity, analyze_origin_intelligence
from backend.intelligence.cache import get_cached_intel

class TestOriginIntelligence:
    def test_offline_geolite2_resolution(self):
        """Test offline IP resolution using local MaxMind GeoLite2 database."""
        # 8.8.8.8 (Google Public DNS)
        geo, asn = resolve_offline_ip("8.8.8.8")
        assert geo.country_code == "US"
        assert geo.source_database == "GeoLite2-City-Offline"
        assert geo.latitude is not None
        assert geo.longitude is not None

    def test_strictly_offline_with_network_sockets_blocked(self, monkeypatch):
        """Strictly prohibit socket connection to prove 100% offline air-gapped capability."""
        def blocked_socket(*args, **kwargs):
            raise OSError("Network access strictly disabled during offline forensic test")

        monkeypatch.setattr(socket, "socket", blocked_socket)
        monkeypatch.setattr(socket, "create_connection", blocked_socket)

        # Lookup MUST succeed purely from local .mmdb without raising OSError
        geo, asn = resolve_offline_ip("209.85.220.41")
        assert geo.country_code == "US"
        assert geo.source_database == "GeoLite2-City-Offline"

    def test_private_rfc1918_ip_handling(self):
        """Test private subnets return LOCAL attribution."""
        geo, asn = resolve_offline_ip("192.168.1.100")
        assert geo.country_code == "LOCAL"
        assert geo.city == "Private LAN"

    def test_homoglyph_and_punycode_detection(self):
        """Detect Cyrillic homoglyph spoofing in brand domains."""
        # 'paypаl.com' with Cyrillic 'а' (U+0430)
        spoofed_domain = "payp\u0430l.com"
        intel = evaluate_domain_authenticity(spoofed_domain)
        assert intel.homoglyph_detected is True
        assert intel.is_recently_registered is True

        # Clean domain
        clean_intel = evaluate_domain_authenticity("google.com")
        assert clean_intel.homoglyph_detected is False

    def test_autonomous_sqlite_caching(self):
        """Verify repeat queries are served instantly from local SQLite cache."""
        target_ip = "8.8.8.8"
        target_domain = "dns.google"

        # First call: populates cache
        res1 = analyze_origin_intelligence(target_ip, target_domain)
        assert res1.cache_status.from_cache is False

        # Second call: served from cache
        res2 = analyze_origin_intelligence(target_ip, target_domain)
        assert res2.cache_status.from_cache is True
        assert res2.geolocation.country_code == res1.geolocation.country_code
