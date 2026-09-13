"""
End-to-End Test Suite for Module 5 (FastAPI Application Endpoints)
Validates POST /api/v1/analyze, GET /api/v1/integrity/verify, GET /api/v1/cases,
GET /api/v1/health, and OpenAPI /docs endpoint.
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.config import settings
from backend.api.app import app
from backend.cases.manager import create_case
from backend.contracts.case_management import CaseCreateInput

client = TestClient(app)

class TestFastApiEndpoints:
    def test_health_endpoint_status_200(self):
        """GET /api/v1/health returns status 200 with service health info."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == settings.PROJECT_NAME

    def test_openapi_docs_status_200(self):
        """GET /docs returns status 200 with interactive Swagger UI."""
        response = client.get("/docs")
        assert response.status_code == 200
        assert "swagger" in response.text.lower() or "html" in response.headers.get("content-type", "").lower()

    def test_analyze_endpoint_status_200_with_eml_upload(self):
        """POST /api/v1/analyze accepts .eml, returns forensic data, and writes to audit chain."""
        sample_path = settings.SAMPLES_DIR / "spoof_paypal.eml"
        assert sample_path.exists(), f"Sample missing: {sample_path}"

        with open(sample_path, "rb") as f:
            files = {"file": ("spoof_paypal.eml", f, "message/rfc822")}
            response = client.post("/api/v1/analyze", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert len(data["email_id"]) == 64
        assert "protocol_forensics" in data
        assert "origin_intelligence" in data
        assert "audit_block" in data
        assert data["audit_block"]["record_id"] == data["email_id"]
        assert len(data["audit_block"]["current_hash"]) == 64

    def test_integrity_verify_endpoint_status_200(self):
        """GET /api/v1/integrity/verify returns 200 and validates the audit ledger."""
        response = client.get("/api/v1/integrity/verify")
        assert response.status_code == 200
        data = response.json()
        assert data["is_intact"] is True
        assert data["tamper_detected"] is False
        assert "total_blocks" in data
        assert "chain" in data

    def test_cases_endpoint_status_200(self):
        """GET /api/v1/cases returns 200 and lists investigation cases with email details."""
        # Create a test case first
        case_in = CaseCreateInput(
            title="Operation PhishGuard",
            description="Testing API case listing endpoint",
            investigator="Forensic Lead",
            priority="HIGH",
            initial_email_ids=["sample-hash-1234"],
            tags=["API_TEST"]
        )
        create_case(case_in)

        response = client.get("/api/v1/cases")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "cases" in data
        assert isinstance(data["cases"], list)
        assert len(data["cases"]) >= 1

    def test_analyze_empty_file_returns_400(self):
        """POST /api/v1/analyze with empty bytes returns HTTP 400 Bad Request."""
        files = {"file": ("empty.eml", b"", "message/rfc822")}
        response = client.post("/api/v1/analyze", files=files)
        assert response.status_code == 400
