import asyncio
import httpx
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("TraceMail-Enrichment")

class ExternalThreatEnricher:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def probe_shodan_internetdb(self, ip: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Free, zero-key port and vulnerability scanner from Shodan."""
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            if client is not None:
                res = await client.get(url)
                if res.status_code == 200:
                    return res.json()
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as local_client:
                    res = await local_client.get(url)
                    if res.status_code == 200:
                        return res.json()
        except Exception as e:
            logger.debug(f"Shodan InternetDB offline/unreachable: {e}")
        return {"ports": [], "cves": [], "tags": []}

    async def probe_urlhaus(self, url_to_check: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Queries Abuse.ch URLhaus for known malicious URLs."""
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        try:
            if client is not None:
                res = await client.post(endpoint, data={"url": url_to_check})
                if res.status_code == 200:
                    return res.json()
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as local_client:
                    res = await local_client.post(endpoint, data={"url": url_to_check})
                    if res.status_code == 200:
                        return res.json()
        except Exception as e:
            logger.debug(f"URLhaus offline/unreachable: {e}")
        return {"query_status": "offline"}

    async def probe_malware_bazaar(self, sha256_hash: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Queries Abuse.ch MalwareBazaar for payload signature matches."""
        endpoint = "https://mb-api.abuse.ch/api/v1/"
        try:
            if client is not None:
                res = await client.post(endpoint, data={"query": "get_info", "hash": sha256_hash})
                if res.status_code == 200:
                    return res.json()
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as local_client:
                    res = await local_client.post(endpoint, data={"query": "get_info", "hash": sha256_hash})
                    if res.status_code == 200:
                        return res.json()
        except Exception as e:
            logger.debug(f"MalwareBazaar offline/unreachable: {e}")
        return {"query_status": "offline"}

    async def enrich_all(
        self,
        ip: Optional[str] = None,
        urls: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Runs Shodan, URLhaus, and MalwareBazaar probes concurrently with connection pooling."""
        enrichment: Dict[str, Any] = {"shodan": {}, "urlhaus_hits": [], "malware_bazaar_hits": []}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                tasks = []
                task_types = []

                if ip and ip != "Unknown":
                    tasks.append(self.probe_shodan_internetdb(ip, client=client))
                    task_types.append(("shodan", ip))

                for u in (urls or [])[:10]:
                    tasks.append(self.probe_urlhaus(u, client=client))
                    task_types.append(("urlhaus", u))

                for att in (attachments or [])[:5]:
                    if isinstance(att, dict) and att.get("sha256"):
                        tasks.append(self.probe_malware_bazaar(att["sha256"], client=client))
                        task_types.append(("malware_bazaar", att))

                if not tasks:
                    return enrichment

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for (ttype, meta), res in zip(task_types, results):
                    if isinstance(res, Exception):
                        continue
                    if ttype == "shodan":
                        enrichment["shodan"] = res
                    elif ttype == "urlhaus":
                        if isinstance(res, dict) and res.get("query_status") != "offline":
                            enrichment["urlhaus_hits"].append({"url": meta, "result": res})
                    elif ttype == "malware_bazaar":
                        if isinstance(res, dict) and res.get("query_status") != "offline":
                            enrichment["malware_bazaar_hits"].append({
                                "filename": meta.get("filename", "unknown"),
                                "sha256": meta.get("sha256", ""),
                                "result": res
                            })
        except Exception as e:
            logger.debug(f"External enrichment batch exception: {e}")
        return enrichment

