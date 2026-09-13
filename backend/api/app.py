"""
TraceMail Production FastAPI Backend Application
FastAPI REST API orchestrating Ingestion, Protocol Forensics, Offline Origin Intelligence,
SQLite Persistence, SHA-256 Audit Integrity Ledger, and Investigation Cases.
"""
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.db.database import init_db, store_email_analysis, list_cases
from backend.ingestion.parser import parse_eml_bytes
from backend.forensics.protocols import evaluate_email_protocols
from backend.intelligence.geoip import analyze_origin_intelligence
from cases.integrity import IntegrityLedger
from backend.cases.manager import create_case
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

    # 5. Determine Forensic Threat Verdict and Score
    threat_score = max(protocol_res.protocol_risk_subtotal, origin_res.origin_risk_subtotal)
    if protocol_res.protocol_risk_subtotal >= 35 or origin_res.origin_risk_subtotal >= 35:
        verdict = "SPOOFED_OR_MALICIOUS"
    elif protocol_res.protocol_risk_subtotal >= 15 or origin_res.origin_risk_subtotal >= 15:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    # 6. Append Verdict into Cryptographic Audit Hash Chain (cases/integrity.py)
    ledger = IntegrityLedger(settings.LEDGER_PATH)
    audit_block = ledger.add_verdict(
        record_id=protocol_res.email_id,
        verdict=verdict,
        threat_score=threat_score
    )

    # 7. Return Structured JSON adhering strictly to approved data contracts
    return {
        "status": "success",
        "email_id": protocol_res.email_id,
        "source_filename": protocol_res.source_filename,
        "verdict": verdict,
        "threat_score": threat_score,
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
