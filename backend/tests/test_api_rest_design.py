import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from backend.api.app import app
from backend.config import settings

client = TestClient(app)

class TestRestApiDesignPrinciples:
    """
    Validates compliance with @api-design-principles:
    - Resource naming (nouns, plural, /api/v1)
    - Consistent envelopes and status codes
    - Query parameter filtering & pagination
    - Canonical routes and legacy backward compatibility
    - Path traversal sanitization and size boundary enforcement
    """

    def test_canonical_system_health(self):
        """GET /api/v1/system/health returns standard health telemetry."""
        res = client.get("/api/v1/system/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "geoip_database_available" in data

    def test_canonical_incidents_listing_and_pagination(self):
        """GET /api/v1/incidents supports pagination and filtering."""
        res = client.get("/api/v1/incidents?limit=5&offset=0")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "count" in data
        assert "total_count" in data
        assert isinstance(data["incidents"], list)
        assert data["limit"] == 5
        assert data["offset"] == 0

    def test_canonical_incident_analysis_and_subresources(self):
        """POST /api/v1/incidents/analyze executes deterministic pipeline."""
        sample_path = Path("test-data/spoof_paypal.eml")
        if not sample_path.exists():
            sample_path = settings.SAMPLES_DIR / "spoof_paypal.eml"

        with open(sample_path, "rb") as f:
            res = client.post("/api/v1/incidents/analyze", files={"file": ("spoof_paypal.eml", f, "message/rfc822")})
        
        assert res.status_code == 200
        payload = res.json()
        assert payload["status"] == "success"
        email_id = payload["email_id"]
        assert email_id is not None

        # Test sub-resource: GET /api/v1/incidents/{id}/report (PDF)
        pdf_res = client.get(f"/api/v1/incidents/{email_id}/report")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"

        # Test sub-resource: GET /api/v1/incidents/{id}/stix (STIX 2.1)
        stix_res = client.get(f"/api/v1/incidents/{email_id}/stix")
        assert stix_res.status_code == 200
        stix_data = stix_res.json()
        assert stix_data["type"] == "bundle"
        assert stix_data["spec_version"] == "2.1"

    def test_canonical_campaigns_and_graph(self):
        """GET /api/v1/campaigns and /api/v1/campaigns/graph provide correlated threat topology."""
        camp_res = client.get("/api/v1/campaigns")
        assert camp_res.status_code == 200
        c_data = camp_res.json()
        assert c_data["status"] == "success"
        assert "campaigns" in c_data

        graph_res = client.get("/api/v1/campaigns/graph")
        assert graph_res.status_code == 200
        g_data = graph_res.json()
        assert "nodes" in g_data
        assert "edges" in g_data

    def test_canonical_integrity_chain(self):
        """GET /api/v1/integrity/chain returns blockchain audit proofs."""
        res = client.get("/api/v1/integrity/chain")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "is_intact" in data
        assert "total_blocks" in data
        assert "chain" in data

    def test_canonical_scenarios(self):
        """GET /api/v1/scenarios returns preset scenarios with key lookup."""
        res = client.get("/api/v1/scenarios")
        assert res.status_code == 200
        data = res.json()
        assert "scenarios" in data

        single_res = client.get("/api/v1/scenarios/alpha")
        assert single_res.status_code == 200
        s_data = single_res.json()
        assert s_data["status"] == "success"
        assert s_data["scenario"]["id"] == "alpha"

    def test_path_traversal_sanitization(self):
        """Sanitizes malicious traversal attempts in report export."""
        res = client.get("/api/v1/incidents/..%2F..%2Fetc%2Fpasswd/report")
        assert res.status_code == 404

    def test_upload_boundary_guard_25mb(self):
        """Rejects files exceeding 25MB boundary with HTTP 413."""
        huge_bytes = b"X" * (25 * 1024 * 1024 + 10)
        res = client.post("/api/v1/incidents/analyze", files={"file": ("huge.eml", huge_bytes, "message/rfc822")})
        assert res.status_code == 413
