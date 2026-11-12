#!/usr/bin/env python3
"""
Network Incident Investigation and Automated Forensic System

Launcher Entry Point:
Initializes database, checks dependencies, seeds demo baseline if empty,
and runs the Flask HTTP service.
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.database.db import init_db, query_db
from backend.evaluation.evaluator import EvaluationFramework
from app import app

def main():
    print("=" * 75)
    print("  NETWORK INCIDENT INVESTIGATION & AUTOMATED FORENSIC SYSTEM")
    print("  Network Incident Investigation System")
    print("=" * 75)
    
    # Initialize SQLite database
    print("[*] Initializing SQLite forensic database schema...")
    init_db()

    # Check if database has packets, if completely empty, seed demo data for immediate exploration
    existing_packets = query_db("SELECT COUNT(*) as c FROM packets", one=True)
    if not existing_packets or existing_packets["c"] == 0:
        print("[*] Fresh database detected. Seeding comprehensive demo investigation scenario...")
        try:
            EvaluationFramework.seed_demo_data()
            print("[+] Demo scenario seeded successfully!")
        except Exception as e:
            print(f"[!] Warning while seeding demo data: {e}")
    else:
        print(f"[+] Forensic database loaded with {existing_packets['c']} existing packet records.")

    print("\n[+] Starting Forensic Dashboard Web Server on http://127.0.0.1:5000 ...")
    print("    Press Ctrl+C to terminate the server.\n")

    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)

if __name__ == "__main__":
    main()
