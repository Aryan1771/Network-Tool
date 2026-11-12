import sqlite3
import threading
import json
from pathlib import Path
from backend.config import Config

# Thread-local storage for database connections
_local = threading.local()

def get_db():
    """Return a thread-local SQLite connection with Row factory."""
    if not hasattr(_local, "connection") or _local.connection is None:
        _local.connection = sqlite3.connect(
            Config.DATABASE_PATH,
            check_same_thread=False,
            timeout=30.0
        )
        _local.connection.row_factory = sqlite3.Row
        # Enable WAL mode and foreign keys for high concurrency and referential integrity
        _local.connection.execute("PRAGMA journal_mode=WAL;")
        _local.connection.execute("PRAGMA foreign_keys=ON;")
    return _local.connection

def close_db(e=None):
    """Close the thread-local database connection."""
    conn = getattr(_local, "connection", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        _local.connection = None

def init_db():
    """Initialize the SQLite database with schema and default settings."""
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript(schema_sql)
    
    # Seed default detection settings if empty
    default_settings = [
        ("port_scan_threshold_ports", str(Config.PORT_SCAN_THRESHOLD_PORTS), "int", "Unique destination ports scanned within the time window to trigger PORT_SCAN alert"),
        ("port_scan_window_seconds", str(Config.PORT_SCAN_WINDOW_SECONDS), "int", "Time window in seconds for port scan detection"),
        ("syn_flood_threshold_pps", str(Config.SYN_FLOOD_THRESHOLD_PPS), "int", "SYN packets per second threshold to trigger SYN_FLOOD alert"),
        ("syn_flood_ratio_threshold", str(Config.SYN_FLOOD_RATIO_THRESHOLD), "float", "Maximum handshake completion ratio to classify SYN flood"),
        ("brute_force_threshold_attempts", str(Config.BRUTE_FORCE_THRESHOLD_ATTEMPTS), "int", "Repeated connection attempts to service port within window to trigger BRUTE_FORCE alert"),
        ("brute_force_window_seconds", str(Config.BRUTE_FORCE_WINDOW_SECONDS), "int", "Time window in seconds for brute force login detection"),
        ("brute_force_ports", json.dumps(Config.BRUTE_FORCE_PORTS), "json", "Monitored authentication and service ports"),
        ("data_exfil_multiplier", str(Config.DATA_EXFIL_MULTIPLIER), "float", "Multiplier over normal baseline to trigger DATA_EXFILTRATION alert"),
        ("data_exfil_window_seconds", str(Config.DATA_EXFIL_WINDOW_SECONDS), "int", "Time window in seconds for data exfiltration detection"),
        ("data_exfil_baseline_bytes", str(Config.DATA_EXFIL_BASELINE_BYTES), "int", "Baseline normal outbound bytes per window"),
    ]
    
    for key, val, dtype, desc in default_settings:
        cursor.execute("""
            INSERT OR IGNORE INTO detection_settings (setting_key, setting_value, data_type, description)
            VALUES (?, ?, ?, ?)
        """, (key, val, dtype, desc))
        
    conn.commit()

def query_db(query, args=(), one=False):
    """Execute a SELECT query and return rows as list of dicts or single dict."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    if one:
        return dict(rv[0]) if rv else None
    return [dict(r) for r in rv]

def execute_db(query, args=(), commit=True):
    """Execute INSERT/UPDATE/DELETE query and return lastrowid and affected rows."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    if commit:
        conn.commit()
    last_id = cur.lastrowid
    row_count = cur.rowcount
    cur.close()
    return last_id, row_count
