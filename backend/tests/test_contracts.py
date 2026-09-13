import json
import pytest
from pydantic import ValidationError

from backend.contracts.protocol_forensics import (
    RawEmlInput,
    MessageHeaders,
    SpfContract,
    DkimContract,
    DmarcAlignmentContract,
    DmarcContract,
    ArcContract,
    RelayHopContract,
    ProtocolForensicsResult,
)
from backend.contracts.origin_intelligence import (
    OriginIntelInput,
    GeoLocationContract,
    AsnContract,
    HopTimingContract,
    DomainIntelContract,
    OriginThreatContract,
    CacheStatusContract,
    OriginIntelligenceResult,
)
from backend.contracts.case_management import (
    CaseCreateInput,
    CaseUpdateInput,
    AuditEventInput,
    AuditBlockContract,
    AuditIntegrityContract,
    CaseDetailContract,
)

class TestDataContracts:
    def test_module_1_protocol_contracts_json_schema(self):
        """Verify that Module 1 contracts export compliant JSON Schema definitions."""
        schemas = [
            RawEmlInput.model_json_schema(),
            MessageHeaders.model_json_schema(),
            SpfContract.model_json_schema(),
            DkimContract.model_json_schema(),
            DmarcContract.model_json_schema(),
            ArcContract.model_json_schema(),
            RelayHopContract.model_json_schema(),
            ProtocolForensicsResult.model_json_schema(),
        ]
        for s in schemas:
            assert "title" in s
            assert "properties" in s
            assert "type" in s
            assert s["type"] == "object"

    def test_module_2_origin_intel_contracts_json_schema(self):
        """Verify that Module 2 contracts export compliant JSON Schema definitions."""
        schemas = [
            OriginIntelInput.model_json_schema(),
            GeoLocationContract.model_json_schema(),
            AsnContract.model_json_schema(),
            HopTimingContract.model_json_schema(),
            DomainIntelContract.model_json_schema(),
            OriginThreatContract.model_json_schema(),
            CacheStatusContract.model_json_schema(),
            OriginIntelligenceResult.model_json_schema(),
        ]
        for s in schemas:
            assert "title" in s
            assert "properties" in s
            assert s["type"] == "object"

    def test_module_3_case_contracts_json_schema(self):
        """Verify that Module 3 contracts export compliant JSON Schema definitions."""
        schemas = [
            CaseCreateInput.model_json_schema(),
            CaseUpdateInput.model_json_schema(),
            AuditEventInput.model_json_schema(),
            AuditBlockContract.model_json_schema(),
            AuditIntegrityContract.model_json_schema(),
            CaseDetailContract.model_json_schema(),
        ]
        for s in schemas:
            assert "title" in s
            assert "properties" in s
            assert s["type"] == "object"

    def test_contract_rigid_validation_forbids_extra(self):
        """Verify that contracts strictly forbid undefined extra fields."""
        with pytest.raises(ValidationError):
            SpfContract(
                verdict="pass",
                domain="example.com",
                sender="test@example.com",
                details="test",
                score_penalty=0,
                unauthorized_extra_field="malicious_injection"
            )

    def test_contract_roundtrip_serialization(self):
        """Verify serialization to JSON string and roundtrip deserialization."""
        geo = GeoLocationContract(
            country_code="IN",
            country_name="India",
            city="New Delhi",
            latitude=28.6139,
            longitude=77.2090,
            postal_code="110001",
            accuracy_radius_km=10,
            source_database="GeoLite2-City-Offline"
        )
        json_str = geo.model_dump_json()
        deserialized = GeoLocationContract.model_validate_json(json_str)
        assert deserialized.country_code == "IN"
        assert deserialized.city == "New Delhi"
        assert deserialized.latitude == 28.6139
