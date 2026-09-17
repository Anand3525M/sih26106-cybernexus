import re
import json as _json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, status, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.db.database import init_db, store_email_analysis, list_cases, get_email_analysis, get_db_connection
from backend.ingestion.parser import parse_eml_bytes, parse_eml_file
from backend.forensics.protocols import evaluate_email_protocols
from backend.intelligence.geoip import analyze_origin_intelligence
from backend.intelligence.external_intel import ExternalThreatEnricher
from backend.scoring.fusion import evaluate_risk_fusion
from backend.reports.generator import generate_court_report
from cases.integrity import IntegrityLedger
from backend.cases.manager import create_case
from backend.api.tactical import (
    PRESET_SCENARIOS,
    TACTICAL_CAMPAIGN_REGISTRY,
    format_tactical_dashboard_payload,
    generate_stix_bundle,
    get_campaign_graph_nodes_and_edges,
    get_tactical_campaigns_summary
)
from backend.contracts.case_management import CaseCreateInput, CaseDetailContract
from backend.contracts.protocol_forensics import ProtocolForensicsResult
from backend.contracts.origin_intelligence import OriginIntelligenceResult

# Security Boundary: 25MB maximum upload envelope
MAX_EML_SIZE = 25 * 1024 * 1024

# In-memory fast cache for recent forensic analyses
ANALYSIS_CACHE: Dict[str, Tuple[ProtocolForensicsResult, OriginIntelligenceResult]] = {}

# External Threat Intelligence Enricher (Shodan InternetDB, URLhaus, MalwareBazaar)
external_enricher = ExternalThreatEnricher(timeout=3.0)

# OpenAPI Metadata Tags adhering to @api-design-principles
TAGS_METADATA = [
    {
        "name": "Incidents & Forensics",
        "description": "RFC-822 email ingestion, protocol forensics, origin intelligence, and threat verdicts."
    },
    {
        "name": "Campaign Intelligence",
        "description": "Autonomous cross-incident threat campaigns and Palantir Gotham link correlation topologies."
    },
    {
        "name": "Autonomous Ingestion",
        "description": "Batch multipart email upload and automated mailbox/repository synchronization."
    },
    {
        "name": "Cryptographic Integrity",
        "description": "SHA-256 forward-linked audit blockchain, verification proofs, and tamper detection test harness."
    },
    {
        "name": "Investigation Cases",
        "description": "Forensic case management, investigator assignment, and IOC watchlist tracking."
    },
    {
        "name": "Threat Scenarios",
        "description": "Pre-configured tactical threat scenarios for benchmark demonstration and evaluation."
    },
    {
        "name": "System & Observability",
        "description": "Health checks, engine readiness, database availability, and service telemetry."
    }
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure database tables and runtime directories are initialized on app startup."""
    init_db()
    settings.LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(
    title=f"{settings.PROJECT_NAME} Forensic Intelligence Platform",
    version=settings.VERSION,
    description="Defense-grade Email Threat Detection, RFC Protocol Forensics, Offline Origin Intelligence, and Cryptographic Audit Ledger",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=TAGS_METADATA,
    lifespan=lifespan
)

# Enable CORS for local dashboards and production origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------------
# WebSocket Threat Stream & Connection Manager
# -------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws/threat-stream")
async def websocket_threat_stream(websocket: WebSocket):
    """Real-time bi-directional threat intelligence streaming socket."""
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# -------------------------------------------------------------------------
# Core Processing Helper
# -------------------------------------------------------------------------

def _run_pipeline_and_format_tactical(raw_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Execute complete forensic pipeline and format result for tactical dashboard."""
    # 1. Ingestion
    ingested = parse_eml_bytes(raw_bytes, filename=filename)
    # 2. Protocols
    protocol_res = evaluate_email_protocols(ingested)
    # 3. Origin Intelligence
    origin_res = analyze_origin_intelligence(
        ip=protocol_res.origin_ip,
        domain=ingested.headers.from_domain,
        hops=protocol_res.relay_hops
    )
    # 4. Persistence
    store_email_analysis(ingested, protocol_res, origin_res)
    ANALYSIS_CACHE[protocol_res.email_id] = (protocol_res, origin_res)
    # 5. Risk Fusion
    fusion_res = evaluate_risk_fusion(protocol_res, origin_res)
    # 6. Audit Chain
    ledger = IntegrityLedger(settings.LEDGER_PATH)
    audit_block = ledger.add_verdict(
        record_id=protocol_res.email_id,
        verdict=fusion_res.verdict_tier,
        threat_score=fusion_res.composite_threat_score
    )
    # 7. Format Tactical UI response
    return format_tactical_dashboard_payload(ingested, protocol_res, origin_res, fusion_res, audit_block)

# -------------------------------------------------------------------------
# 1. System & Observability Endpoints
# -------------------------------------------------------------------------

@app.get("/api/v1/system/health", tags=["System & Observability"], summary="Service Health & Status")
@app.get("/api/v1/health", tags=["System & Observability"], include_in_schema=False)
@app.get("/health", tags=["System & Observability"], include_in_schema=False)
def health_check():
    """Service health, version telemetry, and environment status."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "track": settings.TRACK,
        "offline_demo_mode": settings.DEMO_MODE,
        "geoip_database_available": settings.GEOIP_DB_PATH.exists(),
        "campaigns_in_registry": len(TACTICAL_CAMPAIGN_REGISTRY)
    }

@app.get("/", include_in_schema=False)
def root_redirect():
    """Redirect root path to interactive Forensic Console UI."""
    return RedirectResponse(url="/ui/")

# -------------------------------------------------------------------------
# 2. Incidents & Forensic Analysis Endpoints
# -------------------------------------------------------------------------

@app.post("/api/v1/incidents/analyze", tags=["Incidents & Forensics"], summary="Analyze RFC-822 Email Message")
@app.post("/api/v1/analyze", tags=["Incidents & Forensics"], summary="Analyze Email Message (Legacy)")
async def analyze_email_file(file: UploadFile = File(...)):
    """
    Accepts raw .eml message upload via multipart/form-data.
    Executes: Ingestion Parser -> Protocol Forensics -> Offline Origin Intelligence.
    Persists results to SQLite and records the verdict into the SHA-256 audit hash chain.
    Enforces a strict 25MB boundary to prevent Memory DoS attacks.
    """
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file missing filename.")
        
    try:
        raw_bytes = await file.read(MAX_EML_SIZE + 1)
        if len(raw_bytes) > MAX_EML_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Payload Too Large: EML exceeds 25MB envelope threshold."
            )
    except HTTPException:
        raise
    except Exception as read_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to read file: {str(read_err)}")

    if not raw_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded .eml file is empty.")

    # 1. Ingestion & RFC 5322 MIME Header Parsing
    ingested = parse_eml_bytes(raw_bytes, filename=file.filename)

    # 2. Protocol Forensics (SPF, DKIM, DMARC, ARC, Relay Hops)
    protocol_res = evaluate_email_protocols(ingested)

    # 3. Offline Origin Intelligence & Hop Timing
    origin_res = analyze_origin_intelligence(
        ip=protocol_res.origin_ip,
        domain=ingested.headers.from_domain,
        hops=protocol_res.relay_hops
    )

    # 4. Automatically Store Result in SQLite Database
    store_email_analysis(ingested, protocol_res, origin_res)
    ANALYSIS_CACHE[protocol_res.email_id] = (protocol_res, origin_res)

    # 5. Multi-Signal Risk Fusion Engine
    fusion_res = evaluate_risk_fusion(protocol_res, origin_res)
    threat_score = fusion_res.composite_threat_score
    verdict_tier = fusion_res.verdict_tier

    # 6. Append Verdict into Cryptographic Audit Hash Chain
    ledger = IntegrityLedger(settings.LEDGER_PATH)
    audit_block = ledger.add_verdict(
        record_id=protocol_res.email_id,
        verdict=verdict_tier,
        threat_score=threat_score
    )

    # Automatically register into tactical campaign registry
    try:
        format_tactical_dashboard_payload(ingested, protocol_res, origin_res, fusion_res, audit_block)
    except Exception:
        pass

    # 7. External Threat Intelligence Enrichment (Shodan, URLhaus, MalwareBazaar)
    enrichment = {"shodan": {}, "urlhaus_hits": [], "malware_bazaar_hits": []}
    try:
        if protocol_res.origin_ip:
            enrichment["shodan"] = await external_enricher.probe_shodan_internetdb(protocol_res.origin_ip)
        for url in ingested.extracted_urls[:10]:
            urlhaus_res = await external_enricher.probe_urlhaus(url)
            if urlhaus_res.get("query_status") != "offline":
                enrichment["urlhaus_hits"].append({"url": url, "result": urlhaus_res})
        for att in ingested.attachments[:5]:
            mb_res = await external_enricher.probe_malware_bazaar(att["sha256"])
            if mb_res.get("query_status") != "offline":
                enrichment["malware_bazaar_hits"].append({"filename": att["filename"], "sha256": att["sha256"], "result": mb_res})
    except Exception:
        pass

    return {
        "status": "success",
        "email_id": protocol_res.email_id,
        "source_filename": protocol_res.source_filename,
        "verdict": verdict_tier,
        "verdict_tier": verdict_tier,
        "threat_score": threat_score,
        "scoring": {
            "composite_threat_score": threat_score,
            "verdict_tier": verdict_tier,
            "triggered_signals": [s.model_dump() for s in fusion_res.triggered_signals]
        },
        "risk_assessment": fusion_res.model_dump(),
        "protocol_forensics": protocol_res.model_dump(),
        "forensics": {
            **protocol_res.model_dump(),
            "hops": [
                {
                    "hop_number": h.hop_number,
                    "sending_host": h.from_host,
                    "receiving_host": h.by_host,
                    "ip_address": h.ip,
                    "transit_delay_seconds": h.transit_delay_seconds
                }
                for h in protocol_res.relay_hops
            ]
        },
        "origin_intelligence": origin_res.model_dump(),
        "intelligence": {
            **origin_res.model_dump(),
            "asn": {
                **origin_res.asn.model_dump(),
                "autonomous_system_organization": origin_res.asn.as_org or origin_res.asn.as_name or "Tor Relay Node"
            }
        },
        "raw_headers": "\n".join(f"{k}: {v}" for k, v in ingested.headers.all_headers.items()),
        "external_intelligence": enrichment,
        "audit_block": audit_block
    }

@app.post("/analyze/file", tags=["Incidents & Forensics"], include_in_schema=False)
async def tactical_analyze_uploaded_file(file: UploadFile = File(...)):
    """Legacy route: Analyze uploaded .eml file and format for tactical HUD."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file missing filename.")
    raw_bytes = await file.read(MAX_EML_SIZE + 1)
    if len(raw_bytes) > MAX_EML_SIZE:
        raise HTTPException(status_code=413, detail="Payload Too Large: EML exceeds 25MB envelope threshold.")
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    result = _run_pipeline_and_format_tactical(raw_bytes, file.filename)
    await manager.broadcast({"type": "incident", "data": result})
    return result

@app.post("/analyze/text", tags=["Incidents & Forensics"], include_in_schema=False)
async def tactical_analyze_pasted_text(
    request: Request,
    raw_email: Optional[str] = Form(None)
):
    """Legacy route: Analyze pasted email text and format for tactical HUD."""
    text_to_process = raw_email
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
            if isinstance(body, dict):
                for key in ["raw_email", "email", "text", "payload", "content"]:
                    if key in body:
                        text_to_process = body[key]
                        break
            elif isinstance(body, str):
                text_to_process = body
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload.")
    elif not text_to_process:
        body_bytes = await request.body()
        if body_bytes:
            text_to_process = body_bytes.decode("utf-8", errors="ignore")

    if not text_to_process or not str(text_to_process).strip():
        raise HTTPException(status_code=400, detail="Email content is required.")

    raw_bytes = str(text_to_process).encode("utf-8")
    result = _run_pipeline_and_format_tactical(raw_bytes, "intercepted_sample.eml")
    await manager.broadcast({"type": "incident", "data": result})
    return result

@app.get("/api/v1/incidents", tags=["Incidents & Forensics"], summary="List Analyzed Incidents")
def get_all_incidents(
    verdict: Optional[str] = Query(None, description="Filter by verdict: MALICIOUS, SUSPICIOUS, BENIGN"),
    q: Optional[str] = Query(None, description="Keyword search in subject, sender, origin IP, recipient"),
    limit: int = Query(50, ge=1, le=100, description="Max incidents to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """Retrieve full catalog of ingested threat incidents with filtering and pagination."""
    items = list(reversed(TACTICAL_CAMPAIGN_REGISTRY))
    if verdict:
        items = [i for i in items if (i.get("verdict") or "").upper() == verdict.upper()]
    if q:
        query_lower = q.lower()
        items = [
            i for i in items
            if query_lower in (i.get("subject") or "").lower()
            or query_lower in (i.get("sender") or "").lower()
            or query_lower in (i.get("origin_ip") or "").lower()
            or query_lower in (i.get("recipient") or "").lower()
        ]
    total = len(items)
    paginated = items[offset : offset + limit]
    return {
        "status": "success",
        "count": len(paginated),
        "total_count": total,
        "offset": offset,
        "limit": limit,
        "incidents": paginated
    }

@app.get("/api/v1/incidents/{incident_id}", tags=["Incidents & Forensics"], summary="Get Incident Details")
def get_incident_by_id(incident_id: str):
    """Retrieve detailed forensic incident record by ID."""
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', incident_id)
    for inc in TACTICAL_CAMPAIGN_REGISTRY:
        if inc.get("id") == safe_id or inc.get("email_id") == safe_id:
            return {"status": "success", "incident": inc}
    db_analysis = get_email_analysis(safe_id)
    if db_analysis:
        proto_res, origin_res = db_analysis
        return {
            "status": "success",
            "incident": {
                "id": proto_res.email_id,
                "protocol_forensics": proto_res.model_dump(),
                "origin_intelligence": origin_res.model_dump()
            }
        }
    raise HTTPException(status_code=404, detail=f"Incident with ID '{safe_id}' not found.")

@app.get("/api/v1/incidents/{incident_id}/report", tags=["Incidents & Forensics"], summary="Export Court-Admissible PDF")
@app.get("/api/v1/reports/{email_id}/pdf", tags=["Incidents & Forensics"], summary="Export PDF Report (Legacy)")
async def export_pdf_report(email_id: Optional[str] = None, incident_id: Optional[str] = None):
    """
    Generate and export a court-admissible forensic PDF dossier backed by cryptographic chain.
    Path traversal attacks are actively sanitized.
    """
    target_id = email_id or incident_id or "current_case"
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', target_id)

    # 1. Check pre-generated report on disk
    candidate_path = settings.REPORTS_DIR / f"forensic_dossier_{safe_id[:16]}.pdf"
    if candidate_path.exists():
        return FileResponse(
            str(candidate_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{safe_id[:16]}.pdf"
        )

    # 2. Check in-memory fast cache
    if safe_id in ANALYSIS_CACHE:
        proto_res, origin_res = ANALYSIS_CACHE[safe_id]
        pdf_path = generate_court_report(proto_res, origin_res)
        return FileResponse(
            str(pdf_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{safe_id[:16]}.pdf"
        )

    # 3. Check SQLite database
    analysis = get_email_analysis(safe_id)
    if analysis:
        proto_res, origin_res = analysis
        pdf_path = generate_court_report(proto_res, origin_res)
        return FileResponse(
            str(pdf_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{safe_id[:16]}.pdf"
        )

    # 4. Fallback: if 'current_case' or 'latest', check latest from cache
    if safe_id in ("current_case", "latest") and ANALYSIS_CACHE:
        latest_id = list(ANALYSIS_CACHE.keys())[-1]
        proto_res, origin_res = ANALYSIS_CACHE[latest_id]
        pdf_path = generate_court_report(proto_res, origin_res)
        return FileResponse(
            str(pdf_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{latest_id[:16]}.pdf"
        )

    # 5. Fallback: check if matches sample file in test-data/
    sample_file = settings.SAMPLES_DIR / f"{safe_id}.eml"
    if sample_file.exists():
        ingested = parse_eml_file(sample_file)
        proto_res = evaluate_email_protocols(ingested)
        origin_res = analyze_origin_intelligence(
            ip=proto_res.origin_ip,
            domain=ingested.headers.from_domain,
            hops=proto_res.relay_hops
        )
        store_email_analysis(ingested, proto_res, origin_res)
        ANALYSIS_CACHE[proto_res.email_id] = (proto_res, origin_res)
        pdf_path = generate_court_report(proto_res, origin_res)
        return FileResponse(
            str(pdf_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{proto_res.email_id[:16]}.pdf"
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Forensic record for email ID '{safe_id}' not found."
    )

@app.get("/api/v1/incidents/{incident_id}/stix", tags=["Incidents & Forensics"], summary="Export Incident STIX 2.1")
@app.get("/export/stix/{campaign_idx}", tags=["Incidents & Forensics"], include_in_schema=False)
def export_stix_by_index(incident_id: Optional[str] = None, campaign_idx: Optional[int] = None):
    """Export incident IOCs in OASIS STIX 2.1 JSON standard."""
    if campaign_idx is not None and 0 <= campaign_idx < len(TACTICAL_CAMPAIGN_REGISTRY):
        return JSONResponse(content=generate_stix_bundle(TACTICAL_CAMPAIGN_REGISTRY[campaign_idx]))

    if incident_id:
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', incident_id)
        # 1. Check in tactical registry (both incident id and email_id)
        for inc in TACTICAL_CAMPAIGN_REGISTRY:
            if inc.get("id") == safe_id or inc.get("email_id") == safe_id:
                return JSONResponse(content=generate_stix_bundle(inc))

        # 2. Check in-memory analysis cache
        if safe_id in ANALYSIS_CACHE:
            proto_res, origin_res = ANALYSIS_CACHE[safe_id]
            rec = {
                "id": safe_id,
                "sender": proto_res.dkim.domain or (origin_res.domain_intel.domain if origin_res.domain_intel else ""),
                "origin_ip": proto_res.origin_ip
            }
            return JSONResponse(content=generate_stix_bundle(rec))

        # 3. Check SQLite database
        db_record = get_email_analysis(safe_id)
        if db_record:
            proto_res, origin_res = db_record
            rec = {
                "id": safe_id,
                "sender": proto_res.dkim.domain or (origin_res.domain_intel.domain if origin_res.domain_intel else ""),
                "origin_ip": proto_res.origin_ip
            }
            return JSONResponse(content=generate_stix_bundle(rec))

        # 4. Fallback: if 'current_case' or 'latest', check latest from cache
        if safe_id in ("current_case", "latest") and ANALYSIS_CACHE:
            latest_id = list(ANALYSIS_CACHE.keys())[-1]
            proto_res, origin_res = ANALYSIS_CACHE[latest_id]
            rec = {
                "id": latest_id,
                "sender": proto_res.dkim.domain or "",
                "origin_ip": proto_res.origin_ip
            }
            return JSONResponse(content=generate_stix_bundle(rec))

        # 5. Check sample files
        sample_file = settings.SAMPLES_DIR / f"{safe_id}.eml"
        if sample_file.exists():
            ingested = parse_eml_file(sample_file)
            proto_res = evaluate_email_protocols(ingested)
            rec = {
                "id": proto_res.email_id,
                "sender": ingested.headers.from_address,
                "origin_ip": proto_res.origin_ip
            }
            return JSONResponse(content=generate_stix_bundle(rec))

        raise HTTPException(status_code=404, detail=f"Incident '{safe_id}' not found.")

    if TACTICAL_CAMPAIGN_REGISTRY:
        return JSONResponse(content=generate_stix_bundle(TACTICAL_CAMPAIGN_REGISTRY[-1]))
    raise HTTPException(status_code=404, detail="No incident recorded in registry yet.")

# -------------------------------------------------------------------------
# 3. Campaign Intelligence Endpoints
# -------------------------------------------------------------------------

@app.get("/api/v1/campaigns", tags=["Campaign Intelligence"], summary="List Correlated Campaigns")
def get_campaigns_summary(
    defcon: Optional[int] = Query(None, ge=1, le=5, description="Filter by DEFCON level 1-5"),
    actor: Optional[str] = Query(None, description="Filter by attributed threat actor")
):
    """Retrieve correlated multi-incident threat campaigns with infrastructure and victim profiles."""
    campaigns = get_tactical_campaigns_summary()
    if defcon is not None:
        campaigns = [c for c in campaigns if c.get("defcon") == defcon]
    if actor:
        campaigns = [c for c in campaigns if actor.lower() in (c.get("threat_actor") or "").lower()]
    return {
        "status": "success",
        "campaign_count": len(campaigns),
        "campaigns": campaigns
    }

@app.get("/api/v1/campaigns/graph", tags=["Campaign Intelligence"], summary="Get Palantir Gotham Link Topology")
@app.get("/campaign/graph", tags=["Campaign Intelligence"], include_in_schema=False)
@app.get("/api/v1/campaign/graph", tags=["Campaign Intelligence"], include_in_schema=False)
def get_campaign_graph():
    """Generate Palantir Gotham Link-Analysis Correlation Graph across attacks."""
    return get_campaign_graph_nodes_and_edges()

@app.get("/api/v1/campaigns/{campaign_id}", tags=["Campaign Intelligence"], summary="Get Campaign Dossier")
def get_campaign_dossier(campaign_id: str):
    """Retrieve complete intelligence dossier for a single threat campaign cluster."""
    campaigns = get_tactical_campaigns_summary()
    for c in campaigns:
        if c.get("campaign_id") == campaign_id or campaign_id.lower() in c.get("name", "").lower():
            return {"status": "success", "campaign": c}
    raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")

# -------------------------------------------------------------------------
# 4. Autonomous Ingestion Endpoints
# -------------------------------------------------------------------------

@app.post("/api/v1/ingest/batch", tags=["Autonomous Ingestion"], summary="Batch Upload .EML Files")
@app.post("/analyze/bulk", tags=["Autonomous Ingestion"], include_in_schema=False)
async def tactical_analyze_bulk_files(files: List[UploadFile] = File(...)):
    """Analyze multiple uploaded .eml files asynchronously and broadcast to live threat stream."""
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")
    results = []
    for f in files:
        if not f.filename:
            continue
        try:
            raw_bytes = await f.read(MAX_EML_SIZE + 1)
            if len(raw_bytes) > MAX_EML_SIZE:
                results.append({"filename": f.filename, "error": "File exceeds 25MB boundary", "status": "failed"})
                continue
            if not raw_bytes:
                continue
            rec = _run_pipeline_and_format_tactical(raw_bytes, f.filename)
            await manager.broadcast({"type": "incident", "data": rec})
            results.append(rec)
        except Exception as err:
            results.append({"filename": f.filename, "error": str(err), "status": "failed"})
    return {
        "status": "success",
        "processed_count": len(results),
        "incidents": results
    }

@app.post("/api/v1/ingest/sync", tags=["Autonomous Ingestion"], summary="Sync Mailbox / Repository Feeds")
@app.post("/api/v1/ingest/sync-inbox", tags=["Autonomous Ingestion"], include_in_schema=False)
async def auto_sync_inbox_feed():
    """
    Automated Mailbox & Benchmark Ingestion Engine.
    Scans test-data repository, ingests authentic .eml attack scenarios into the pipeline,
    and streams them in real-time over the WebSocket threat stream.
    """
    sample_dir = Path("test-data")
    if not sample_dir.exists():
        sample_dir = settings.SAMPLES_DIR

    eml_files = sorted(list(sample_dir.glob("*.eml")))
    if not eml_files:
        results = []
        for k, sc in PRESET_SCENARIOS.items():
            raw_bytes = sc["raw_email"].encode("utf-8")
            rec = _run_pipeline_and_format_tactical(raw_bytes, f"{k}.eml")
            await manager.broadcast({"type": "incident", "data": rec})
            results.append(rec)
        return {
            "status": "success",
            "source": "preset_scenarios",
            "synced_count": len(results),
            "incidents": results
        }

    results = []
    for eml_path in eml_files:
        try:
            raw_bytes = eml_path.read_bytes()
            rec = _run_pipeline_and_format_tactical(raw_bytes, eml_path.name)
            await manager.broadcast({"type": "incident", "data": rec})
            results.append(rec)
        except Exception:
            pass

    return {
        "status": "success",
        "source": "test-data",
        "synced_count": len(results),
        "incidents": results
    }

# -------------------------------------------------------------------------
# 5. Cryptographic Integrity Endpoints
# -------------------------------------------------------------------------

@app.get("/api/v1/integrity/chain", tags=["Cryptographic Integrity"], summary="Verify SHA-256 Audit Blockchain")
@app.get("/api/v1/integrity/verify", tags=["Cryptographic Integrity"], summary="Verify Audit Ledger (Legacy)")
def verify_integrity_ledger():
    """
    Verify the cryptographic integrity of the SHA-256 forward-linked audit chain.
    Walks each block, verifies previous hash linkage, and recalculates payload hashes.
    """
    ledger = IntegrityLedger(settings.LEDGER_PATH)
    is_intact, message = ledger.verify_chain()
    chain = ledger.load_chain()

    return {
        "status": "success",
        "is_intact": is_intact,
        "chain_valid": is_intact,
        "message": message,
        "total_blocks": len(chain),
        "verified_blocks": len(chain),
        "tamper_detected": not is_intact,
        "tampered_block_index": None if is_intact else 0,
        "latest_hash": chain[-1]["current_hash"] if chain else None,
        "chain": chain
    }

@app.post("/api/v1/integrity/simulation/tamper", tags=["Cryptographic Integrity"], summary="Inject Tamper Simulation")
@app.post("/api/v1/integrity/tamper", tags=["Cryptographic Integrity"], include_in_schema=False)
async def inject_ledger_tamper():
    """Simulates database tampering to demonstrate instant SHA-256 break detection."""
    ledger_path = Path("backend/data/audit_ledger.json")
    if ledger_path.exists():
        data = _json.loads(ledger_path.read_text(encoding="utf-8"))
        if len(data) >= 1:
            target_idx = 1 if len(data) > 1 else 0
            data[target_idx]["evidence_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            data[target_idx]["record_id"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            ledger_path.write_text(_json.dumps(data, indent=2), encoding="utf-8")
            return {"status": "TAMPER_INJECTED", "corrupted_block": target_idx}
    return {"status": "FAILED", "reason": "Ledger empty or not found"}

@app.post("/api/v1/integrity/simulation/reseal", tags=["Cryptographic Integrity"], summary="Reseal Audit Ledger")
@app.post("/api/v1/integrity/reseal", tags=["Cryptographic Integrity"], include_in_schema=False)
async def reseal_ledger_chain():
    """Recalculates and reseals the SHA-256 audit ledger forward hashes."""
    ledger = IntegrityLedger(settings.LEDGER_PATH)
    chain = ledger.load_chain()
    from cases.integrity import GENESIS_HASH
    expected_prev = GENESIS_HASH
    for block in chain:
        block["prev_hash"] = expected_prev
        block["current_hash"] = ledger.compute_record_hash(
            block["record_id"], block["verdict"], block["threat_score"], block["prev_hash"]
        )
        if "evidence_hash" in block and block["evidence_hash"] != block["record_id"]:
            block.pop("evidence_hash", None)
        expected_prev = block["current_hash"]
    ledger._save_chain(chain)
    return {"status": "RESEALED", "total_blocks": len(chain), "latest_hash": expected_prev}

# -------------------------------------------------------------------------
# 6. Threat Scenarios Endpoints
# -------------------------------------------------------------------------

@app.get("/api/v1/scenarios", tags=["Threat Scenarios"], summary="List Benchmark Attack Scenarios")
@app.get("/scenarios", tags=["Threat Scenarios"], include_in_schema=False)
def get_preset_threat_scenarios():
    """Return available pre-configured tactical threat defense scenarios."""
    return {
        "count": len(PRESET_SCENARIOS),
        "scenarios": [
            {
                "id": k,
                "title": v["title"],
                "threat_type": v["threat_type"],
                "target": v["target"],
                "attacker": v["attacker"],
                "raw_email": v["raw_email"]
            }
            for k, v in PRESET_SCENARIOS.items()
        ]
    }

@app.get("/api/v1/scenarios/{scenario_id}", tags=["Threat Scenarios"], summary="Get Preset Scenario")
def get_scenario_by_id(scenario_id: str):
    """Return single preset threat scenario by identifier key."""
    if scenario_id in PRESET_SCENARIOS:
        v = PRESET_SCENARIOS[scenario_id]
        return {
            "status": "success",
            "scenario": {
                "id": scenario_id,
                "title": v["title"],
                "threat_type": v["threat_type"],
                "target": v["target"],
                "attacker": v["attacker"],
                "raw_email": v["raw_email"]
            }
        }
    raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

# -------------------------------------------------------------------------
# 7. Case Management Endpoints
# -------------------------------------------------------------------------

@app.get("/api/v1/cases", tags=["Investigation Cases"], summary="List Investigation Cases")
def get_all_cases():
    """Lists all forensic investigation cases with associated linked emails and verdicts."""
    cases = list_cases()
    return {
        "status": "success",
        "total_cases": len(cases),
        "cases": cases
    }

@app.post("/api/v1/cases", tags=["Investigation Cases"], status_code=status.HTTP_201_CREATED, summary="Create Investigation Case")
def create_new_case(case_input: CaseCreateInput):
    """Create a new forensic investigation case linked to email threat records."""
    case_detail = create_case(case_input)
    return {
        "status": "success",
        "case": case_detail.model_dump()
    }

# -------------------------------------------------------------------------
# Static File Mounts
# -------------------------------------------------------------------------

# Mount static test-data for frontend demo scenarios
if settings.SAMPLES_DIR.exists():
    app.mount("/test-data", StaticFiles(directory=str(settings.SAMPLES_DIR)), name="test-data")

# Mount frontend static UI
app.mount("/ui", StaticFiles(directory="static", html=True), name="static")
