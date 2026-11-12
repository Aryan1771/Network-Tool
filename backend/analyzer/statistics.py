from backend.database.db import query_db

class TrafficStatistics:
    """
    Traffic Statistics Engine:
    Computes analytical and forensic metrics across captured packet sessions.
    """

    @staticmethod
    def get_overview_statistics(session_id=None):
        """
        Calculates high-level forensic dashboard statistics.
        """
        where_clause = ""
        params = []
        if session_id:
            where_clause = "WHERE session_id = ?"
            params = [session_id]

        # Total packets and bytes
        pkt_stats = query_db(f"""
            SELECT COUNT(*) AS total_packets, 
                   COALESCE(SUM(packet_size), 0) AS total_bytes,
                   COALESCE(MIN(timestamp), 0) AS start_time,
                   COALESCE(MAX(timestamp), 0) AS end_time
            FROM packets {where_clause}
        """, params, one=True) or {"total_packets": 0, "total_bytes": 0, "start_time": 0, "end_time": 0}

        # Unique connections (unique src_ip, dst_ip, dst_port, protocol)
        conn_stats = query_db(f"""
            SELECT COUNT(DISTINCT src_ip || '-' || dst_ip || '-' || COALESCE(dst_port, 0) || '-' || protocol) AS total_connections
            FROM packets {where_clause}
        """, params, one=True) or {"total_connections": 0}

        # Incidents statistics
        inc_where = ""
        inc_params = []
        if session_id:
            inc_where = "WHERE session_id = ?"
            inc_params = [session_id]

        inc_stats = query_db(f"""
            SELECT 
                COUNT(*) AS total_incidents,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_incidents,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_incidents,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_incidents,
                SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low_incidents
            FROM incidents {inc_where}
        """, inc_params, one=True) or {
            "total_incidents": 0, "critical_incidents": 0, "high_incidents": 0, "medium_incidents": 0, "low_incidents": 0
        }

        # Evidence count
        evd_where = ""
        evd_params = []
        if session_id:
            evd_where = "WHERE session_id = ?"
            evd_params = [session_id]

        evd_stats = query_db(f"""
            SELECT COUNT(*) AS total_evidence,
                   SUM(CASE WHEN verification_status = 'VERIFIED' THEN 1 ELSE 0 END) AS verified_evidence,
                   SUM(CASE WHEN verification_status = 'TAMPERED' THEN 1 ELSE 0 END) AS tampered_evidence
            FROM evidence {evd_where}
        """, evd_params, one=True) or {"total_evidence": 0, "verified_evidence": 0, "tampered_evidence": 0}

        return {
            "total_packets": pkt_stats["total_packets"],
            "total_bytes": pkt_stats["total_bytes"],
            "total_connections": conn_stats["total_connections"],
            "total_incidents": inc_stats["total_incidents"] or 0,
            "critical_incidents": inc_stats["critical_incidents"] or 0,
            "high_incidents": inc_stats["high_incidents"] or 0,
            "medium_incidents": inc_stats["medium_incidents"] or 0,
            "low_incidents": inc_stats["low_incidents"] or 0,
            "evidence_files": evd_stats["total_evidence"] or 0,
            "verified_evidence": evd_stats["verified_evidence"] or 0,
            "tampered_evidence": evd_stats["tampered_evidence"] or 0,
            "start_time": pkt_stats["start_time"],
            "end_time": pkt_stats["end_time"]
        }

    @staticmethod
    def get_protocol_distribution(session_id=None):
        where = "WHERE session_id = ?" if session_id else ""
        params = [session_id] if session_id else []
        rows = query_db(f"""
            SELECT protocol, COUNT(*) as count, SUM(packet_size) as total_bytes
            FROM packets {where}
            GROUP BY protocol
            ORDER BY count DESC
        """, params)
        return rows

    @staticmethod
    def get_top_hosts(session_id=None, limit=5):
        where = "WHERE session_id = ?" if session_id else ""
        params = [session_id] if session_id else []
        # Union source and destination IPs
        rows = query_db(f"""
            SELECT host_ip, SUM(pkt_count) as total_packets, SUM(byte_vol) as total_bytes
            FROM (
                SELECT src_ip as host_ip, COUNT(*) as pkt_count, SUM(packet_size) as byte_vol
                FROM packets {where} GROUP BY src_ip
                UNION ALL
                SELECT dst_ip as host_ip, COUNT(*) as pkt_count, SUM(packet_size) as byte_vol
                FROM packets {where} GROUP BY dst_ip
            )
            WHERE host_ip != '0.0.0.0'
            GROUP BY host_ip
            ORDER BY total_packets DESC
            LIMIT ?
        """, params + [limit])
        return rows

    @staticmethod
    def get_top_ports(session_id=None, limit=8):
        where = "WHERE dst_port IS NOT NULL"
        params = []
        if session_id:
            where += " AND session_id = ?"
            params.append(session_id)
        params.append(limit)

        rows = query_db(f"""
            SELECT dst_port as port, protocol, COUNT(*) as count
            FROM packets {where}
            GROUP BY dst_port, protocol
            ORDER BY count DESC
            LIMIT ?
        """, params)
        return rows

    @staticmethod
    def get_traffic_activity_timeline(session_id=None, buckets=30):
        """
        Aggregates packet counts into time buckets for dynamic Chart.js graphing.
        """
        where = "WHERE session_id = ?" if session_id else ""
        params = [session_id] if session_id else []

        bounds = query_db(f"SELECT MIN(timestamp) as min_t, MAX(timestamp) as max_t FROM packets {where}", params, one=True)
        if not bounds or not bounds["min_t"] or bounds["min_t"] == bounds["max_t"]:
            return {"labels": [], "packets": [], "tcp": [], "udp": [], "other": []}

        min_t = bounds["min_t"]
        max_t = bounds["max_t"]
        duration = max_t - min_t
        step = max(duration / float(buckets), 1.0)

        # Retrieve packets grouped into bucket interval
        rows = query_db(f"""
            SELECT 
                CAST((timestamp - ?) / ? AS INT) as bucket,
                COUNT(*) as total_pkts,
                SUM(CASE WHEN protocol = 'TCP' THEN 1 ELSE 0 END) as tcp_pkts,
                SUM(CASE WHEN protocol = 'UDP' THEN 1 ELSE 0 END) as udp_pkts,
                SUM(CASE WHEN protocol NOT IN ('TCP', 'UDP') THEN 1 ELSE 0 END) as other_pkts
            FROM packets {where}
            GROUP BY bucket
            ORDER BY bucket ASC
        """, [min_t, step] + params)

        bucket_map = {r["bucket"]: r for r in rows}
        num_buckets = int(duration / step) + 1
        num_buckets = min(num_buckets, 50)

        labels = []
        packets = []
        tcp = []
        udp = []
        other = []

        from datetime import datetime
        for b in range(num_buckets):
            t_mid = min_t + (b * step)
            time_label = datetime.fromtimestamp(t_mid).strftime("%H:%M:%S")
            labels.append(time_label)
            if b in bucket_map:
                packets.append(bucket_map[b]["total_pkts"])
                tcp.append(bucket_map[b]["tcp_pkts"])
                udp.append(bucket_map[b]["udp_pkts"])
                other.append(bucket_map[b]["other_pkts"])
            else:
                packets.append(0)
                tcp.append(0)
                udp.append(0)
                other.append(0)

        return {
            "labels": labels,
            "packets": packets,
            "tcp": tcp,
            "udp": udp,
            "other": other
        }

    @staticmethod
    def get_incident_type_distribution(session_id=None):
        where = "WHERE session_id = ?" if session_id else ""
        params = [session_id] if session_id else []
        rows = query_db(f"""
            SELECT incident_type, COUNT(*) as count
            FROM incidents {where}
            GROUP BY incident_type
        """, params)
        return {r["incident_type"]: r["count"] for r in rows}
