import imaplib
import email
import time
import os
import asyncio
import httpx
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TraceMail-Watcher")

# Configuration via environment variables or test defaults
IMAP_HOST = os.getenv("TRACEMAIL_IMAP_HOST", "imap.gmail.com")
IMAP_USER = os.getenv("TRACEMAIL_IMAP_USER", "")
IMAP_PASS = os.getenv("TRACEMAIL_IMAP_PASS", "")
IMAP_PORT = int(os.getenv("TRACEMAIL_IMAP_PORT", 993))
API_ENDPOINT = "http://127.0.0.1:8000/api/v1/analyze"

class LiveMailWatcher:
    def __init__(self):
        self.host = IMAP_HOST
        self.user = IMAP_USER
        self.password = IMAP_PASS
        self.port = IMAP_PORT

    def check_credentials(self) -> bool:
        if not self.user or not self.password:
            logger.warning("[!] IMAP credentials not set. Watcher running in mock simulation mode.")
            return False
        return True

    async def process_raw_eml(self, eml_bytes: bytes, filename: str = "incoming_mail.eml"):
        """Submits the captured email directly to the TraceMail engine."""
        async with httpx.AsyncClient() as client:
            files = {"file": (filename, eml_bytes, "message/rfc822")}
            try:
                res = await client.post(API_ENDPOINT, files=files)
                if res.status_code == 200:
                    data = res.json()
                    score = data.get("scoring", {}).get("composite_threat_score", 0)
                    tier = data.get("scoring", {}).get("verdict_tier", "UNKNOWN")
                    logger.info(f"[✓] INGESTED & PARSED: Threat Score: {score}/100 [{tier}]")
                else:
                    logger.error(f"[!] API ingestion returned HTTP {res.status_code}")
            except Exception as ex:
                logger.error(f"[!] Connection to TraceMail core failed: {ex}")

    def run_polling_loop(self):
        if not self.check_credentials():
            logger.info("[*] To activate live Gmail/Zoho ingestion, export TRACEMAIL_IMAP_USER and TRACEMAIL_IMAP_PASS.")
            return

        logger.info(f"[*] Starting live IMAP listener on {self.host} for user: {self.user}")
        while True:
            try:
                mail = imaplib.IMAP4_SSL(self.host, self.port)
                mail.login(self.user, self.password)
                mail.select("inbox")

                status, messages = mail.search(None, 'UNSEEN')
                if status == "OK" and messages[0]:
                    email_ids = messages[0].split()
                    logger.info(f"[!] New unread email detected: {len(email_ids)} item(s)")

                    for e_id in email_ids:
                        res, msg_data = mail.fetch(e_id, '(RFC822)')
                        for part in msg_data:
                            if isinstance(part, tuple):
                                eml_bytes = part[1]
                                asyncio.run(self.process_raw_eml(eml_bytes))

                mail.close()
                mail.logout()
            except Exception as e:
                logger.error(f"[!] Polling exception: {e}")

            time.sleep(8)

if __name__ == "__main__":
    watcher = LiveMailWatcher()
    watcher.run_polling_loop()
