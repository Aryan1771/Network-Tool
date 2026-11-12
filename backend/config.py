import os
import secrets
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
REPORTS_DIR = DATA_DIR / "reports"
UPLOADS_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "forensic_db.sqlite"

# Ensure runtime directories exist
for folder in [DATA_DIR, EVIDENCE_DIR, REPORTS_DIR, UPLOADS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

class Config:
    # Use the deployment secret when configured; otherwise create an unpredictable
    # process-local key so local startup never relies on a hardcoded secret.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    DATABASE_PATH = str(DB_PATH)
    EVIDENCE_PATH = str(EVIDENCE_DIR)
    REPORTS_PATH = str(REPORTS_DIR)
    UPLOADS_PATH = str(UPLOADS_DIR)
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max PCAP upload
    
    # Detection Threshold Defaults
    PORT_SCAN_THRESHOLD_PORTS = 20      # >20 unique ports
    PORT_SCAN_WINDOW_SECONDS = 10       # within 10s
    
    SYN_FLOOD_THRESHOLD_PPS = 100       # >100 SYN packets/sec
    SYN_FLOOD_RATIO_THRESHOLD = 0.10    # <10% handshake completion
    
    BRUTE_FORCE_THRESHOLD_ATTEMPTS = 10 # >10 attempts
    BRUTE_FORCE_WINDOW_SECONDS = 60     # within 60s
    BRUTE_FORCE_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    
    DATA_EXFIL_MULTIPLIER = 5.0         # 5x normal baseline
    DATA_EXFIL_WINDOW_SECONDS = 300     # 5 minutes (300s)
    DATA_EXFIL_BASELINE_BYTES = 50000   # default baseline per window (50 KB)
    
    # Live capture settings
    DEFAULT_CAPTURE_PACKET_LIMIT = 5000
    DEFAULT_INTERFACE = None
