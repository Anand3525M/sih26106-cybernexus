import os
from pathlib import Path
from pydantic import BaseModel

# Base directory using pathlib.Path (cross-platform, zero hardcoded slashes)
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DATA_DIR = BACKEND_DIR / "data"
GEOIP_DIR = DATA_DIR / "geoip"
SAMPLES_DIR = BASE_DIR / "test-data"
REPORTS_DIR = BACKEND_DIR / "data" / "reports"
DB_PATH = BASE_DIR / "tracemail.db"
GEOIP_DB_PATH = GEOIP_DIR / "GeoLite2-City.mmdb"
LEDGER_PATH = DATA_DIR / "audit_ledger.json"

class Settings(BaseModel):
    PROJECT_NAME: str = "TraceMail"
    VERSION: str = "1.0.0"
    TRACK: str = "Smart India Hackathon (SIH) - Cyber Security Track"
    BASE_DIR: Path = BASE_DIR
    BACKEND_DIR: Path = BACKEND_DIR
    DATA_DIR: Path = DATA_DIR
    GEOIP_DIR: Path = GEOIP_DIR
    GEOIP_DB_PATH: Path = GEOIP_DB_PATH
    REPORTS_DIR: Path = REPORTS_DIR
    SAMPLES_DIR: Path = SAMPLES_DIR
    DB_PATH: Path = DB_PATH
    LEDGER_PATH: Path = LEDGER_PATH
    
    # Offline Air-Gapped Enforcement & Timeouts
    DEMO_MODE: bool = True
    ALLOW_NETWORK_LOOKUPS: bool = False
    DNS_TIMEOUT_SECONDS: float = 2.0
    
    # Hash Chain Genesis Secret / Salt
    AUDIT_SALT: str = "TraceMail-SIH2026-Immutable-Root-Salt"

settings = Settings()

# Ensure required runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
GEOIP_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
