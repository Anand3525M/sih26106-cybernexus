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

    def test_case_crud_rest_endpoints(self):
        """Validates case creation, lookup by ID, update by PATCH, and 404 handling."""
        # 1. Create Case
        create_payload = {
            "title": "Operation REST Validation",
            "description": "Validating case CRUD endpoints",
            "investigator": "Forensic Agent 007",
            "priority": "MEDIUM",
            "initial_email_ids": ["email-test-001"],
            "tags": ["REST", "AutomatedTest"]
        }
        res_create = client.post("/api/v1/cases", json=create_payload)
        assert res_create.status_code == 201
        created_case = res_create.json()["case"]
        case_id = created_case["case_id"]

        # 2. Get Case by ID
        res_get = client.get(f"/api/v1/cases/{case_id}")
        assert res_get.status_code == 200
        assert res_get.json()["case"]["case_id"] == case_id
        assert res_get.json()["case"]["title"] == "Operation REST Validation"

        # 3. Patch Case
        patch_payload = {
            "investigator": "Forensic Agent 007",
            "status": "INVESTIGATING",
            "priority": "CRITICAL",
            "added_email_ids": ["email-test-002"],
            "new_note": "Identified additional secondary compromised MTA."
        }
        res_patch = client.patch(f"/api/v1/cases/{case_id}", json=patch_payload)
        assert res_patch.status_code == 200
        updated = res_patch.json()["case"]
        assert updated["status"] == "INVESTIGATING"
        assert updated["priority"] == "CRITICAL"
        assert len(updated["linked_email_ids"]) == 2
        assert len(updated["notes"]) == 1

        # 4. 404 for Non-existent Case
        res_404 = client.get("/api/v1/cases/CASE-NON-EXISTENT")
        assert res_404.status_code == 404

    def test_tactical_resilience_to_null_and_malformed_data(self):
        """Validates that graph, STIX, and clustering handle NoneType fields without raising exceptions."""
        from backend.api.tactical import (
            TACTICAL_CAMPAIGN_REGISTRY,
            get_campaign_graph_nodes_and_edges,
            generate_stix_bundle,
            get_tactical_campaigns_summary
        )

        # Inject malformed record with explicit None values across all fields
        malformed_record = {
            "id": "malformed_test_incident",
            "subject": None,
            "sender": None,
            "recipient": None,
            "origin_ip": None,
            "origin_geo": None,
            "verdict": None,
            "score": None,
            "attachments": None,
            "reply_to_mismatch": None,
            "mitre_attack": None
        }
        TACTICAL_CAMPAIGN_REGISTRY.append(malformed_record)

        try:
            # 1. Summary clustering must not raise
            summary = get_tactical_campaigns_summary()
            assert isinstance(summary, list)

            # 2. Graph generation must not raise
            graph = get_campaign_graph_nodes_and_edges()
            assert "nodes" in graph
            assert "edges" in graph
            assert any(n["id"] == "malformed_test_incident" for n in graph["nodes"])

            # 3. STIX generation must not raise
            stix = generate_stix_bundle(malformed_record)
            assert stix["type"] == "bundle"
        finally:
            TACTICAL_CAMPAIGN_REGISTRY.remove(malformed_record)

