#!/usr/bin/env python3
"""
Network Incident Investigation and Automated Forensic System

Launcher Entry Point:
Initializes database, checks dependencies, seeds demo baseline if empty,
and runs the Flask HTTP service.
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.database.db import init_db, query_db
from backend.evaluation.evaluator import EvaluationFramework
from app import app

logger = logging.getLogger(__name__)

def initialize_database(seed_demo=True):
    """Initialize persistent storage and seed the demo dataset when empty."""
    # Initialize SQLite database
    init_db()

    # Check if database has packets, if completely empty, seed demo data for immediate exploration
    existing_packets = query_db("SELECT COUNT(*) as c FROM packets", one=True)
    if seed_demo and (not existing_packets or existing_packets["c"] == 0):
        try:
            EvaluationFramework.seed_demo_data()
        except Exception as e:
            logger.exception("Unable to seed demo data")
            raise RuntimeError("Unable to seed initial demo data") from e
    return existing_packets["c"] if existing_packets else 0


def main():
    print("=" * 75)
    print("  NETWORK INCIDENT INVESTIGATION & AUTOMATED FORENSIC SYSTEM")
    print("  Network Incident Investigation System")
    print("=" * 75)

    print("[*] Initializing SQLite forensic database schema...")
    packet_count = initialize_database()
    if packet_count:
        print(f"[+] Forensic database loaded with {packet_count} existing packet records.")
    else:
        print("[+] Fresh database initialized with demonstration data.")

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print(f"\n[+] Starting Forensic Dashboard Web Server on http://{host}:{port} ...")
    print("    Press Ctrl+C to terminate the server.\n")

    app.run(host=host, port=port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
