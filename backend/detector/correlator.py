import json
from datetime import datetime
from backend.database.db import query_db, execute_db

class IncidentCorrelator:
    """
    Correlates raw network events and packet traces into forensic incident timelines.
    """

    @staticmethod
    def generate_incident_id():
        """Generates next sequential Incident ID: INC-2026-XXXX"""
        row = query_db("SELECT COUNT(*) as count FROM incidents", one=True)
        count = (row["count"] if row else 0) + 1
        year = datetime.now().year
        return f"INC-{year}-{count:04d}"

    @staticmethod
    def is_duplicate(incident_type, src_ip, dst_ip, session_id=None, cooldown_seconds=60):
        """
        Deduplication check: returns True if an active incident with matching
        attributes was recorded recently in the same session or within cooldown window.
        """
        if session_id:
            row = query_db("""
                SELECT id FROM incidents
                WHERE incident_type = ? AND src_ip = ? AND dst_ip = ? AND session_id = ?
                LIMIT 1
            """, (incident_type, src_ip, dst_ip, session_id), one=True)
            if row:
                return True

        row = query_db("""
            SELECT id, detected_at, 
                   strftime('%s', 'now') - strftime('%s', detected_at) as age_sec
            FROM incidents
            WHERE incident_type = ? AND src_ip = ? AND dst_ip = ?
            ORDER BY detected_at DESC LIMIT 1
        """, (incident_type, src_ip, dst_ip), one=True)
        
        if row and row["age_sec"] is not None and row["age_sec"] < cooldown_seconds:
            return True
        return False

    @staticmethod
    def create_timeline_milestones(incident_id, incident_data, triggering_packets):
        """
        Constructs correlated forensic timeline milestones for the incident.
        """
        src = incident_data["src_ip"]
        dst = incident_data["dst_ip"]
        inc_type = incident_data["incident_type"]
        sev = incident_data["severity"]

        # Milestone 1: Incident Initiation
        first_pkt = triggering_packets[0] if triggering_packets else None
        init_time = first_pkt["timestamp"] if first_pkt else datetime.now().timestamp()
        init_dt = first_pkt["datetime_str"] if first_pkt else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        execute_db("""
            INSERT INTO incident_events (incident_id, timestamp, datetime_str, event_type, summary, details, src_ip, dst_ip, port, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, init_time, init_dt,
            "INITIATION",
            f"Initial communication observed between {src} and {dst}",
            f"First suspicious interaction logged. Protocol: {incident_data.get('protocol', 'TCP')}, Target: {dst}",
            src, dst, first_pkt.get("dst_port") if first_pkt else None, "LOW"
        ))

        # Milestone 2: Suspicious Pattern Escalation
        mid_idx = len(triggering_packets) // 2
        mid_pkt = triggering_packets[mid_idx] if triggering_packets else first_pkt
        mid_time = mid_pkt["timestamp"] if mid_pkt else init_time + 1.0
        mid_dt = mid_pkt["datetime_str"] if mid_pkt else init_dt

        details_dict = json.loads(incident_data.get("threshold_details", "{}"))
        pattern_desc = f"Pattern intensity escalated: {inc_type} behavioral profile matched."
        
        execute_db("""
            INSERT INTO incident_events (incident_id, timestamp, datetime_str, event_type, summary, details, src_ip, dst_ip, port, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, mid_time, mid_dt,
            "SUSPICIOUS_PACKET",
            f"Anomalous packet sequence detected from {src}",
            pattern_desc,
            src, dst, mid_pkt.get("dst_port") if mid_pkt else None, "MEDIUM"
        ))

        # Milestone 3: Threshold Exceeded & SOC Alert Generated
        last_pkt = triggering_packets[-1] if triggering_packets else first_pkt
        alert_time = last_pkt["timestamp"] if last_pkt else datetime.now().timestamp()
        alert_dt = last_pkt["datetime_str"] if last_pkt else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        execute_db("""
            INSERT INTO incident_events (incident_id, timestamp, datetime_str, event_type, summary, details, src_ip, dst_ip, port, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, alert_time, alert_dt,
            "THRESHOLD_EXCEEDED",
            f"Detection rule {incident_data.get('rule_name')} threshold exceeded",
            f"Threshold metrics breached: {json.dumps(details_dict)}",
            src, dst, last_pkt.get("dst_port") if last_pkt else None, sev
        ))

        execute_db("""
            INSERT INTO incident_events (incident_id, timestamp, datetime_str, event_type, summary, details, src_ip, dst_ip, port, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, alert_time + 0.1, alert_dt,
            "ALERT_GENERATED",
            f"Security Incident Alert Created: {incident_data['title']}",
            f"Automated incident ticket {incident_id} registered with {sev} severity classification.",
            src, dst, last_pkt.get("dst_port") if last_pkt else None, sev
        ))
