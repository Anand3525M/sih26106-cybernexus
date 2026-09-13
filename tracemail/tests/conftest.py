import os
import tempfile
import pytest
from pathlib import Path
from backend.config import settings

@pytest.fixture(autouse=True)
def isolated_test_environment(monkeypatch):
    """Ensure tests run against an isolated temporary SQLite database and report directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_db = tmp_path / "test_tracemail.db"
        test_reports = tmp_path / "reports"
        test_reports.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(settings, "DB_PATH", test_db)
        monkeypatch.setattr(settings, "REPORTS_DIR", test_reports)
        monkeypatch.setattr(settings, "DEMO_MODE", True)

        yield
