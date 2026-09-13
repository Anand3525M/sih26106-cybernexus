import httpx
import logging
from typing import Dict, Any, List

logger = logging.getLogger("TraceMail-Enrichment")

class ExternalThreatEnricher:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def probe_shodan_internetdb(self, ip: str) -> Dict[str, Any]:
        """Free, zero-key port and vulnerability scanner from Shodan."""
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            logger.debug(f"Shodan InternetDB offline/unreachable: {e}")
        return {"ports": [], "cves": [], "tags": []}

    async def probe_urlhaus(self, url_to_check: str) -> Dict[str, Any]:
        """Queries Abuse.ch URLhaus for known malicious URLs."""
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(endpoint, data={"url": url_to_check})
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            logger.debug(f"URLhaus offline/unreachable: {e}")
        return {"query_status": "offline"}

    async def probe_malware_bazaar(self, sha256_hash: str) -> Dict[str, Any]:
        """Queries Abuse.ch MalwareBazaar for payload signature matches."""
        endpoint = "https://mb-api.abuse.ch/api/v1/"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(endpoint, data={"query": "get_info", "hash": sha256_hash})
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            logger.debug(f"MalwareBazaar offline/unreachable: {e}")
        return {"query_status": "offline"}
