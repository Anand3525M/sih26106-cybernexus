from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.db.database import init_db, store_email_analysis, list_cases
from backend.ingestion.parser import parse_eml_bytes
from backend.forensics.protocols import evaluate_email_protocols
from backend.intelligence.geoip import analyze_origin_intelligence
from backend.scoring.fusion import evaluate_risk_fusion
from cases.integrity import IntegrityLedger
from backend.cases.manager import create_case
from backend.api.tactical import (
    PRESET_SCENARIOS,
    TACTICAL_CAMPAIGN_REGISTRY,
    format_tactical_dashboard_payload,
    generate_stix_bundle,
    get_campaign_graph_nodes_and_edges
)
from contextlib import asynccontextmanager
from backend.contracts.case_management import CaseCreateInput, CaseDetailContract
from backend.contracts.protocol_forensics import ProtocolForensicsResult
from backend.contracts.origin_intelligence import OriginIntelligenceResult

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

    # 7. Return Structured JSON adhering strictly to approved data contracts
    return {
        "status": "success",
        "email_id": protocol_res.email_id,
        "source_filename": protocol_res.source_filename,
        "verdict": verdict_tier,
        "verdict_tier": verdict_tier,
        "threat_score": threat_score,
        "risk_assessment": fusion_res.model_dump(),
        "protocol_forensics": protocol_res.model_dump(),
        "origin_intelligence": origin_res.model_dump(),
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
        "message": message,
        "total_blocks": len(chain),
        "tamper_detected": not is_intact,
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
    return _run_pipeline_and_format_tactical(raw_bytes, file.filename)

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
    return _run_pipeline_and_format_tactical(raw_bytes, "intercepted_sample.eml")

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

# Mount frontend static UI
app.mount("/ui", StaticFiles(directory="static", html=True), name="static")
