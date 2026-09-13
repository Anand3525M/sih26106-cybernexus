import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from backend.intelligence.external_intel import ExternalThreatEnricher

@pytest.mark.asyncio
async def test_probe_shodan_internetdb_success():
    enricher = ExternalThreatEnricher(timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"ports": [80, 443], "cves": ["CVE-2023-1234"], "tags": ["vpn"]}
    
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await enricher.probe_shodan_internetdb("198.51.100.42")
        assert res["ports"] == [80, 443]
        assert "CVE-2023-1234" in res["cves"]

@pytest.mark.asyncio
async def test_probe_shodan_internetdb_offline_fallback():
    enricher = ExternalThreatEnricher(timeout=0.1)
    with patch("httpx.AsyncClient.get", side_effect=Exception("Network unreachable")):
        res = await enricher.probe_shodan_internetdb("198.51.100.42")
        assert res == {"ports": [], "cves": [], "tags": []}

@pytest.mark.asyncio
async def test_probe_urlhaus_success_and_fallback():
    enricher = ExternalThreatEnricher(timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "ok", "url_status": "online"}
    
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await enricher.probe_urlhaus("http://malicious-link.test")
        assert res["query_status"] == "ok"

    with patch("httpx.AsyncClient.post", side_effect=Exception("Timeout")):
        res = await enricher.probe_urlhaus("http://malicious-link.test")
        assert res == {"query_status": "offline"}

@pytest.mark.asyncio
async def test_probe_malware_bazaar_success_and_fallback():
    enricher = ExternalThreatEnricher(timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "ok", "data": [{"signature": "Trojan"}]}
    
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await enricher.probe_malware_bazaar("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert res["query_status"] == "ok"

    with patch("httpx.AsyncClient.post", side_effect=Exception("DNS failure")):
        res = await enricher.probe_malware_bazaar("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert res == {"query_status": "offline"}
