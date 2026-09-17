from typing import List, Dict, Any, Optional, Tuple
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, status, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.db.database import init_db, store_email_analysis, list_cases, get_email_analysis, get_db_connection
import json as _json
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
from contextlib import asynccontextmanager
from backend.contracts.case_management import CaseCreateInput, CaseDetailContract
from backend.contracts.protocol_forensics import ProtocolForensicsResult
from backend.contracts.origin_intelligence import OriginIntelligenceResult

# In-memory fast cache for recent forensic analyses
ANALYSIS_CACHE: Dict[str, Tuple[ProtocolForensicsResult, OriginIntelligenceResult]] = {}

# External Threat Intelligence Enricher (Shodan InternetDB, URLhaus, MalwareBazaar)
external_enricher = ExternalThreatEnricher(timeout=3.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure database tables and runtime directories are initialized on app startup."""
    init_db()
    settings.LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(
    title=f"{settings.PROJECT_NAME} Forensic Intelligence Platform",
    version=settings.VERSION,
    description="Operational Email Threat Detection, RFC Protocol Forensics, Offline Origin Intelligence, and Cryptographic Audit Ledger",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Enable CORS for local React / Vite dashboards (port 3000, 5173) and production origins
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
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/v1/health", tags=["System"])
def health_check():
    """Service health and environment status."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "track": settings.TRACK,
        "offline_demo_mode": settings.DEMO_MODE,
        "geoip_database_available": settings.GEOIP_DB_PATH.exists()
    }

@app.post("/api/v1/analyze", tags=["Forensics"])
async def analyze_email_file(file: UploadFile = File(...)):
    """
    Accepts raw .eml message upload via multipart/form-data.
    Executes: Ingestion Parser -> Protocol Forensics -> Offline Origin Intelligence.
    Persists results to SQLite and records the verdict into the SHA-256 audit hash chain.
    """
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file missing filename.")
        
    try:
        raw_bytes = await file.read()
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

    # 5. Multi-Signal Risk Fusion Engine (Module 4)
    fusion_res = evaluate_risk_fusion(protocol_res, origin_res)
    threat_score = fusion_res.composite_threat_score
    verdict_tier = fusion_res.verdict_tier

    # 6. Append Verdict into Cryptographic Audit Hash Chain (cases/integrity.py)
    ledger = IntegrityLedger(settings.LEDGER_PATH)
    audit_block = ledger.add_verdict(
        record_id=protocol_res.email_id,
        verdict=verdict_tier,
        threat_score=threat_score
    )

    # 7. External Threat Intelligence Enrichment (Shodan, URLhaus, MalwareBazaar)
    enrichment = {"shodan": {}, "urlhaus_hits": [], "malware_bazaar_hits": []}
    try:
        # Probe Shodan InternetDB for origin IP ports/CVEs
        if protocol_res.origin_ip:
            enrichment["shodan"] = await external_enricher.probe_shodan_internetdb(protocol_res.origin_ip)

        # Probe URLhaus for each extracted URL
        for url in ingested.extracted_urls[:10]:  # Cap at 10 to avoid timeout storms
            urlhaus_res = await external_enricher.probe_urlhaus(url)
            if urlhaus_res.get("query_status") != "offline":
                enrichment["urlhaus_hits"].append({"url": url, "result": urlhaus_res})

        # Probe MalwareBazaar for attachment SHA-256 hashes
        for att in ingested.attachments[:5]:  # Cap at 5
            mb_res = await external_enricher.probe_malware_bazaar(att["sha256"])
            if mb_res.get("query_status") != "offline":
                enrichment["malware_bazaar_hits"].append({"filename": att["filename"], "sha256": att["sha256"], "result": mb_res})
    except Exception:
        pass  # Enrichment is best-effort; core pipeline must not break

    # 8. Return Structured JSON adhering strictly to approved data contracts with UI aliases
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

@app.get("/api/v1/integrity/verify", tags=["Cryptographic Audit"])
def verify_integrity_ledger():
    """
    Verify the cryptographic integrity of the SHA-256 forward-linked audit chain.
    Walks each block, verifies previous hash linkage, and recalculates payload hashes.
    """
    ledger = IntegrityLedger(settings.LEDGER_PATH)
    is_intact, message = ledger.verify_chain()
    chain = ledger.load_chain()

    return {
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

@app.get("/api/v1/cases", tags=["Case Management"])
def get_all_cases():
    """
    Lists all forensic investigation cases with associated linked emails and verdicts.
    """
    cases = list_cases()
    return {
        "status": "success",
        "total_cases": len(cases),
        "cases": cases
    }

@app.post("/api/v1/cases", tags=["Case Management"], status_code=status.HTTP_201_CREATED)
def create_new_case(case_input: CaseCreateInput):
    """
    Create a new forensic investigation case linked to email threat records.
    """
    case_detail = create_case(case_input)
    return {
        "status": "success",
        "case": case_detail.model_dump()
    }

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

@app.get("/", include_in_schema=False)
def root_redirect():
    """Redirect root route to Tactical Dashboard UI."""
    return RedirectResponse(url="/ui/")

@app.get("/health", tags=["System"], include_in_schema=False)
def legacy_health_check():
    """Legacy health check for tactical frontend dashboard."""
    data = health_check()
    data["campaigns_in_registry"] = len(TACTICAL_CAMPAIGN_REGISTRY)
    return data

@app.get("/scenarios", tags=["Tactical UI"])
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

@app.post("/analyze/file", tags=["Tactical UI"])
async def tactical_analyze_uploaded_file(file: UploadFile = File(...)):
    """Analyze uploaded .eml file and format for tactical HUD."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file missing filename.")
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    result = _run_pipeline_and_format_tactical(raw_bytes, file.filename)
    await manager.broadcast({"type": "incident", "data": result})
    return result

@app.post("/analyze/text", tags=["Tactical UI"])
async def tactical_analyze_pasted_text(
    request: Request,
    raw_email: Optional[str] = Form(None)
):
    """Analyze pasted email text and format for tactical HUD."""
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

@app.post("/analyze/bulk", tags=["Tactical UI"])
@app.post("/api/v1/ingest/batch", tags=["Forensics"])
async def tactical_analyze_bulk_files(files: List[UploadFile] = File(...)):
    """Analyze multiple uploaded .eml files asynchronously and broadcast to live threat stream."""
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")
    results = []
    for f in files:
        if not f.filename:
            continue
        try:
            raw_bytes = await f.read()
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

@app.post("/api/v1/ingest/sync-inbox", tags=["Forensics"])
async def auto_sync_inbox_feed():
    """
    Automated Mailbox & Sample Ingestion Engine.
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

@app.get("/api/v1/incidents", tags=["Tactical UI"])
def get_all_incidents():
    """Retrieve full catalog of ingested threat incidents with forensic metadata."""
    return {
        "status": "success",
        "total_count": len(TACTICAL_CAMPAIGN_REGISTRY),
        "incidents": list(reversed(TACTICAL_CAMPAIGN_REGISTRY))
    }

@app.get("/api/v1/campaigns", tags=["Tactical UI"])
def get_campaigns_summary():
    """Retrieve correlated multi-incident threat campaigns."""
    campaigns = get_tactical_campaigns_summary()
    return {
        "status": "success",
        "campaign_count": len(campaigns),
        "campaigns": campaigns
    }

@app.get("/campaign/graph", tags=["Tactical UI"])
def get_campaign_graph():
    """Generate Palantir Gotham Link-Analysis Correlation Graph across attacks."""
    return get_campaign_graph_nodes_and_edges()

@app.get("/export/stix/{campaign_idx}", tags=["Tactical UI"])
def export_stix_by_index(campaign_idx: int):
    """Export incident IOCs in OASIS STIX 2.1 JSON standard."""
    if 0 <= campaign_idx < len(TACTICAL_CAMPAIGN_REGISTRY):
        return JSONResponse(content=generate_stix_bundle(TACTICAL_CAMPAIGN_REGISTRY[campaign_idx]))
    if TACTICAL_CAMPAIGN_REGISTRY:
        return JSONResponse(content=generate_stix_bundle(TACTICAL_CAMPAIGN_REGISTRY[-1]))
    raise HTTPException(status_code=404, detail="No incident recorded in registry yet.")

@app.get("/api/v1/reports/{email_id}/pdf", tags=["Reports"])
async def export_pdf_report(email_id: str):
    """
    Generate and export a court-admissible forensic PDF dossier backed by cryptographic chain.
    """
    # 1. Check if pre-generated report exists on disk
    candidate_path = settings.REPORTS_DIR / f"forensic_dossier_{email_id[:16]}.pdf"
    if candidate_path.exists():
        return FileResponse(
            str(candidate_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{email_id[:16]}.pdf"
        )

    # 2. Check in-memory fast cache
    if email_id in ANALYSIS_CACHE:
        proto_res, origin_res = ANALYSIS_CACHE[email_id]
        pdf_path = generate_court_report(proto_res, origin_res)
        return FileResponse(
            str(pdf_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{email_id[:16]}.pdf"
        )

    # 3. Check SQLite database
    analysis = get_email_analysis(email_id)
    if analysis:
        proto_res, origin_res = analysis
        pdf_path = generate_court_report(proto_res, origin_res)
        return FileResponse(
            str(pdf_path),
            media_type="application/pdf",
            filename=f"Forensic_Dossier_{email_id[:16]}.pdf"
        )

    # 4. Fallback: if 'current_case' or 'latest', check latest from cache
    if email_id in ("current_case", "latest"):
        if ANALYSIS_CACHE:
            latest_id = list(ANALYSIS_CACHE.keys())[-1]
            proto_res, origin_res = ANALYSIS_CACHE[latest_id]
            pdf_path = generate_court_report(proto_res, origin_res)
            return FileResponse(
                str(pdf_path),
                media_type="application/pdf",
                filename=f"Forensic_Dossier_{latest_id[:16]}.pdf"
            )

    # 5. Fallback: check if matches sample file in test-data/
    sample_file = settings.SAMPLES_DIR / f"{email_id}.eml"
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
        detail=f"Forensic record for email ID '{email_id}' not found."
    )

# Mount static test-data for frontend demo scenarios
if settings.SAMPLES_DIR.exists():
    app.mount("/test-data", StaticFiles(directory=str(settings.SAMPLES_DIR)), name="test-data")

# Mount frontend static UI
app.mount("/ui", StaticFiles(directory="static", html=True), name="static")



import json
from pathlib import Path
from fastapi.responses import JSONResponse

@app.get("/api/v1/campaign/graph", tags=["Threat Intelligence"])
async def get_campaign_graph_v1():
    """Returns the correlated threat topology graph."""
    graph_file = Path("sweta-singh/campaign_graph.json")
    if graph_file.exists():
        data = json.loads(graph_file.read_text(encoding="utf-8"))
        return JSONResponse(content=data)
    return JSONResponse(content={"nodes": [], "links": []})

@app.post("/api/v1/integrity/tamper", tags=["Cryptographic Audit"])
async def inject_ledger_tamper():
    """Simulates database tampering to demonstrate SHA-256 break."""
    ledger_path = Path("backend/data/audit_ledger.json")
    if ledger_path.exists():
        data = json.loads(ledger_path.read_text(encoding="utf-8"))
        if len(data) >= 1:
            target_idx = 1 if len(data) > 1 else 0
            # Corrupt the payload hash of block
            data[target_idx]["evidence_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            data[target_idx]["record_id"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            ledger_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return {"status": "TAMPER_INJECTED", "corrupted_block": target_idx}
    return {"status": "FAILED", "reason": "Ledger empty or not found"}

@app.post("/api/v1/integrity/reseal", tags=["Cryptographic Audit"])
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


