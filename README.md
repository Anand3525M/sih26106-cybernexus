# TraceMail // CodeNexus (SIH 26106)
> **AI-Powered Email Threat Detection, GeoLocation, and Forensic Intelligence Platform**
> *Developed by Team CodeNexus (formerly CyberNexus)*
> *Sponsor: AICTE | Theme: Blockchain & Cybersecurity | Track: Software*

---

## 1. Executive Overview
TraceMail is an automated digital forensics and threat intelligence platform engineered to analyze Business Email Compromise (BEC), spear-phishing, and header-spoofing attacks. Rather than relying exclusively on probabilistic language models, TraceMail executes a deterministic RFC-822 multi-hop reconstruction, cryptographically verifies domain authentication parameters (SPF, DKIM, DMARC), resolves transit infrastructure to geographic coordinates and autonomous systems (ASNs), and correlates disparate incidents across an enterprise campaign graph.

---

## 2. Core Capabilities

* **Deterministic RFC-822 / MIME Header Parser:** Inspects transit Received: headers in reverse chronological order from the recipient Mail Transfer Agent (MTA) back to the originating ingress node.
* **Cryptographic Domain Authentication Matrix:**
  * **SPF (Sender Policy Framework):** Validates outbound server IP authorization against publisher DNS records.
  * **DKIM (DomainKeys Identified Mail):** Cryptographic digital signature validation.
  * **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** Evaluates organizational alignment and enforcement policies.
* **Relay Infrastructure & GeoIP Resolution:** Maps each intermediate hop IP to its Autonomous System Number (ASN), Internet Service Provider (ISP), country, city, and geographic coordinates.
* **Linguistic Threat Engine:** Pinpoints psychological urgency indicators, unauthorized wire transfer/payroll intervention terminology, and anomalous or typosquatted top-level domains (TLDs).
* **Multi-Target Campaign Correlation:** Discovers shared infrastructure (shared C2 IPs, subdomains, registration clusters) linking individual emails into a coordinated campaign.

---

## 3. Repository Layout

- `backend/`: FastAPI REST endpoints, routing, and schema validation
- `tracemail/`: Core forensics engine (hop tracing, SPF/DKIM/DMARC, GeoIP)
- `static/`: High-density defense analyst console (Leaflet.js + CartoDB)
- `test-data/`: Synthetic phishing corpora and RFC-822 email payloads
- `requirements.txt`: Frozen dependency specifications
- `RMADME.md`: System documentation

---

## 4. Quickstart

```bash
# 1. Activate venv
source venv/bin/activate

# 2. Run platform
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Open http://localhost:8000 in your browser.
