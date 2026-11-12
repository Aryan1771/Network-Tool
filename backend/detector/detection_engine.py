import logging
from backend.database.db import query_db, execute_db
from backend.detector.rules import DetectionRules
from backend.detector.correlator import IncidentCorrelator

logger = logging.getLogger(__name__)

class DetectionEngine:
    """
    Automated Incident Detection Engine.
    Executes rule evaluators, correlates alerts, logs timeline milestones, and flags packets.
    """

    @classmethod
    def analyze_packets(cls, packets, session_id=None, is_demo=0, ignore_dedup=False):
        """
        Executes all 4 incident detection algorithms over a collection of packets.
        Returns list of newly detected incident records.
        """
        if not packets:
            return []

        detected_alerts = []

        # 1. Port Scan Detection
        try:
            port_scans = DetectionRules.evaluate_port_scan(packets)
            detected_alerts.extend(port_scans)
        except Exception as e:
            logger.error(f"Error evaluating Port Scan rule: {e}")

        # 2. SYN Flood Detection
        try:
            syn_floods = DetectionRules.evaluate_syn_flood(packets)
            detected_alerts.extend(syn_floods)
        except Exception as e:
            logger.error(f"Error evaluating SYN Flood rule: {e}")

        # 3. Brute-Force Login Detection
        try:
            brute_forces = DetectionRules.evaluate_brute_force(packets)
            detected_alerts.extend(brute_forces)
        except Exception as e:
            logger.error(f"Error evaluating Brute Force rule: {e}")

        # 4. Data Exfiltration Detection
        try:
            exfils = DetectionRules.evaluate_data_exfiltration(packets)
            detected_alerts.extend(exfils)
        except Exception as e:
            logger.error(f"Error evaluating Data Exfiltration rule: {e}")

        newly_created_incidents = []

        for alert in detected_alerts:
            # Check deduplication to prevent alert storms unless explicitly ignored
            if not ignore_dedup and IncidentCorrelator.is_duplicate(alert["incident_type"], alert["src_ip"], alert["dst_ip"], session_id=session_id):
                continue

            # Ensure valid session_id for foreign key constraint if provided
            valid_session_id = None
            if session_id:
                sess_check = query_db("SELECT id FROM capture_sessions WHERE id = ?", (session_id,), one=True)
                if sess_check:
                    valid_session_id = session_id
                else:
                    # Register capture session to preserve relational integrity
                    execute_db("""
                        INSERT OR IGNORE INTO capture_sessions (id, session_name, source_type, status, is_demo)
                        VALUES (?, ?, 'automated', 'completed', ?)
                    """, (session_id, f"Session {session_id}", is_demo))
                    valid_session_id = session_id

            incident_id = IncidentCorrelator.generate_incident_id()

            # Insert into incidents table
            execute_db("""
                INSERT INTO incidents (
                    id, session_id, incident_type, severity, title, description,
                    src_ip, dst_ip, target_ports, protocol, rule_name, threshold_details,
                    status, analyst_assignee, is_demo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                valid_session_id,
                alert["incident_type"],
                alert["severity"],
                alert["title"],
                alert["description"],
                alert["src_ip"],
                alert["dst_ip"],
                alert.get("target_ports"),
                alert.get("protocol", "TCP"),
                alert["rule_name"],
                alert.get("threshold_details"),
                "New",
                "Forensic Analyst (Team JIIT)",
                is_demo
            ))

            # Flag triggering packets as suspicious in database
            triggering = alert.get("triggering_packets", [])
            for p in triggering:
                if p.get("id"):
                    execute_db("UPDATE packets SET is_suspicious = 1 WHERE id = ?", (p["id"],))

            # Construct timeline milestones
            IncidentCorrelator.create_timeline_milestones(incident_id, alert, triggering)

            newly_created_incidents.append(incident_id)

        return newly_created_incidents

    @classmethod
    def update_incident_status(cls, incident_id, new_status, analyst_name="Lead Analyst"):
        """
        Updates incident lifecycle status (New -> Investigating -> Resolved)
        and adds an event milestone to the incident timeline.
        """
        execute_db("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
        
        # Log to incident_events
        import time
        from datetime import datetime
        now_ts = time.time()
        now_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        execute_db("""
            INSERT INTO incident_events (incident_id, timestamp, datetime_str, event_type, summary, details, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, now_ts, now_dt,
            "STATUS_CHANGE",
            f"Investigation Status Updated: {new_status}",
            f"Analyst {analyst_name} transitioned incident {incident_id} to '{new_status}' status.",
            "LOW"
        ))

    @classmethod
    def add_investigation_note(cls, incident_id, author, note_text):
        """
        Appends an analyst forensic investigation note and logs a timeline event.
        """
        execute_db("""
            INSERT INTO investigation_notes (incident_id, author, note_text)
            VALUES (?, ?, ?)
        """, (incident_id, author, note_text))

        import time
        from datetime import datetime
        now_ts = time.time()
        now_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        execute_db("""
            INSERT INTO incident_events (incident_id, timestamp, datetime_str, event_type, summary, details, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, now_ts, now_dt,
            "NOTE_ADDED",
            f"Forensic Investigation Note Added by {author}",
            note_text,
            "LOW"
        ))
