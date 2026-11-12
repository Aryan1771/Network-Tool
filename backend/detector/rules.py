import json
from collections import defaultdict
from backend.database.db import query_db

class DetectionRules:
    """
    Forensic Network Incident Detection Rules.
    Encapsulates specific rule algorithms with configurable threshold checks.
    """

    @staticmethod
    def get_setting(key, default_val, val_type="int"):
        row = query_db("SELECT setting_value FROM detection_settings WHERE setting_key = ?", (key,), one=True)
        if not row:
            return default_val
        try:
            if val_type == "int":
                return int(row["setting_value"])
            elif val_type == "float":
                return float(row["setting_value"])
            elif val_type == "json":
                return json.loads(row["setting_value"])
            return row["setting_value"]
        except Exception:
            return default_val

    @classmethod
    def evaluate_port_scan(cls, packets):
        """
        Rule A: Port Scan Detection
        Condition: One source IP probes > threshold unique destination ports within window seconds.
        """
        threshold_ports = cls.get_setting("port_scan_threshold_ports", 20, "int")
        window_seconds = cls.get_setting("port_scan_window_seconds", 10, "int")

        # Group TCP/UDP packets by (src_ip, dst_ip)
        ip_targets = defaultdict(list)
        for p in packets:
            if p.get("protocol") in ("TCP", "UDP") and p.get("dst_port") is not None:
                src = p["src_ip"]
                dst = p["dst_ip"]
                # Exclude loopback to loopback non-scans if needed, but in demo mode we keep it
                ip_targets[(src, dst)].append(p)

        incidents = []
        for (src, dst), pkts in ip_targets.items():
            pkts.sort(key=lambda x: x["timestamp"])
            # Sliding window over packets
            left = 0
            for right in range(len(pkts)):
                while pkts[right]["timestamp"] - pkts[left]["timestamp"] > window_seconds:
                    left += 1
                
                window_slice = pkts[left:right+1]
                unique_ports = {p["dst_port"] for p in window_slice}
                
                if len(unique_ports) >= threshold_ports:
                    first_time = window_slice[0]["datetime_str"]
                    last_time = window_slice[-1]["datetime_str"]
                    first_ts = window_slice[0]["timestamp"]
                    last_ts = window_slice[-1]["timestamp"]
                    sample_ports = sorted(list(unique_ports))[:15]
                    
                    incidents.append({
                        "incident_type": "PORT_SCAN",
                        "severity": "MEDIUM",
                        "title": f"Port Scanning Activity from {src}",
                        "description": f"Host {src} probed {len(unique_ports)} unique destination ports on target {dst} within {window_seconds}s (Threshold: {threshold_ports} ports). Sample ports: {sample_ports}...",
                        "src_ip": src,
                        "dst_ip": dst,
                        "target_ports": ",".join(str(p) for p in sorted(list(unique_ports))),
                        "protocol": window_slice[0]["protocol"],
                        "rule_name": "RULE-01-PORT-SCAN",
                        "threshold_details": json.dumps({
                            "threshold_ports": threshold_ports,
                            "window_seconds": window_seconds,
                            "observed_unique_ports": len(unique_ports),
                            "first_time": first_time,
                            "last_time": last_time,
                            "sample_ports": sample_ports
                        }),
                        "first_timestamp": first_ts,
                        "last_timestamp": last_ts,
                        "triggering_packets": window_slice
                    })
                    break  # One alert per (src, dst) stream in this batch
        return incidents

    @classmethod
    def evaluate_syn_flood(cls, packets):
        """
        Rule B: SYN Flood Detection
        Condition: >100 SYN packets per second and <10% handshake completion ratio.
        """
        threshold_pps = cls.get_setting("syn_flood_threshold_pps", 100, "int")
        ratio_threshold = cls.get_setting("syn_flood_ratio_threshold", 0.10, "float")

        # Group by (src_ip, dst_ip)
        pairs = defaultdict(list)
        for p in packets:
            if p.get("protocol") == "TCP":
                pairs[(p["src_ip"], p["dst_ip"])].append(p)

        incidents = []
        for (src, dst), pkts in pairs.items():
            pkts.sort(key=lambda x: x["timestamp"])
            if not pkts:
                continue

            # Sliding 1-second (or up to 3s) windows
            left = 0
            for right in range(len(pkts)):
                t_diff = pkts[right]["timestamp"] - pkts[left]["timestamp"]
                while t_diff > 2.0 and left < right:
                    left += 1
                    t_diff = pkts[right]["timestamp"] - pkts[left]["timestamp"]

                window_slice = pkts[left:right+1]
                duration = max(t_diff, 0.1)

                syn_pkts = [p for p in window_slice if "SYN" in (p.get("tcp_flags") or "") and "ACK" not in (p.get("tcp_flags") or "")]
                ack_pkts = [p for p in window_slice if "ACK" in (p.get("tcp_flags") or "")]
                syn_count = len(syn_pkts)
                pps = syn_count / duration

                # Handshake completion ratio: ratio of SYN-ACK / ACK to SYN packets
                handshake_ratio = (len(ack_pkts) / syn_count) if syn_count > 0 else 1.0

                if (pps >= threshold_pps or syn_count >= threshold_pps) and handshake_ratio < ratio_threshold:
                    incidents.append({
                        "incident_type": "SYN_FLOOD",
                        "severity": "HIGH",
                        "title": f"TCP SYN Flood Attack Targeting {dst}",
                        "description": (
                            f"Host {src} generated {syn_count} SYN packets ({pps:.1f} SYN/sec) towards {dst}. "
                            f"Handshake completion ratio was {handshake_ratio * 100:.1f}%, far below the normal {ratio_threshold * 100:.0f}% threshold. "
                            f"Note: Incomplete PCAP captures may limit full bidirectional handshake observation."
                        ),
                        "src_ip": src,
                        "dst_ip": dst,
                        "target_ports": str(window_slice[0].get("dst_port")),
                        "protocol": "TCP",
                        "rule_name": "RULE-02-SYN-FLOOD",
                        "threshold_details": json.dumps({
                            "threshold_pps": threshold_pps,
                            "ratio_threshold": ratio_threshold,
                            "observed_syn_count": syn_count,
                            "observed_pps": round(pps, 2),
                            "handshake_ratio": round(handshake_ratio, 4),
                            "duration_seconds": round(duration, 2),
                            "limitation_note": "Handshake completion estimated based on captured ACK/SYN-ACK sequences in monitored window."
                        }),
                        "first_timestamp": window_slice[0]["timestamp"],
                        "last_timestamp": window_slice[-1]["timestamp"],
                        "triggering_packets": syn_pkts[:50]
                    })
                    break
        return incidents

    @classmethod
    def evaluate_brute_force(cls, packets):
        """
        Rule C: Brute-Force Login Detection
        Condition: >10 repeated connection attempts to the same service port within 60 seconds.
        """
        threshold_attempts = cls.get_setting("brute_force_threshold_attempts", 10, "int")
        window_seconds = cls.get_setting("brute_force_window_seconds", 60, "int")
        monitored_ports = set(cls.get_setting("brute_force_ports", [21, 22, 23, 25, 80, 443, 3389, 3306, 8080], "json"))

        # Group by (src_ip, dst_ip, dst_port)
        service_attempts = defaultdict(list)
        for p in packets:
            port = p.get("dst_port")
            if port in monitored_ports and p.get("protocol") == "TCP":
                # Connection establishment attempt is indicated by TCP SYN
                flags = p.get("tcp_flags") or ""
                if "SYN" in flags:
                    service_attempts[(p["src_ip"], p["dst_ip"], port)].append(p)

        port_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
        }

        incidents = []
        for (src, dst, port), pkts in service_attempts.items():
            pkts.sort(key=lambda x: x["timestamp"])
            left = 0
            for right in range(len(pkts)):
                while pkts[right]["timestamp"] - pkts[left]["timestamp"] > window_seconds:
                    left += 1

                window_slice = pkts[left:right+1]
                attempts = len(window_slice)

                if attempts >= threshold_attempts:
                    svc = port_services.get(port, f"Port {port}")
                    incidents.append({
                        "incident_type": "BRUTE_FORCE",
                        "severity": "MEDIUM",
                        "title": f"Brute-Force Authentication Attempt on {svc} ({port})",
                        "description": (
                            f"Host {src} initiated {attempts} repeated connection attempts to {svc} service on {dst}:{port} "
                            f"within {window_seconds}s (Threshold: {threshold_attempts} attempts). "
                            f"Clarification: Detects repeated network connection handshakes at transport layer; payload authentication outcomes require application auth audit logs."
                        ),
                        "src_ip": src,
                        "dst_ip": dst,
                        "target_ports": str(port),
                        "protocol": "TCP",
                        "rule_name": "RULE-03-BRUTE-FORCE",
                        "threshold_details": json.dumps({
                            "threshold_attempts": threshold_attempts,
                            "window_seconds": window_seconds,
                            "monitored_port": port,
                            "service_name": svc,
                            "observed_attempts": attempts,
                            "first_time": window_slice[0]["datetime_str"],
                            "last_time": window_slice[-1]["datetime_str"]
                        }),
                        "first_timestamp": window_slice[0]["timestamp"],
                        "last_timestamp": window_slice[-1]["timestamp"],
                        "triggering_packets": window_slice
                    })
                    break
        return incidents

    @classmethod
    def evaluate_data_exfiltration(cls, packets):
        """
        Rule D: Data Exfiltration Detection
        Condition: Outbound traffic volume exceeds 5x normal baseline for 5 minutes (or scaled window).
        """
        multiplier = cls.get_setting("data_exfil_multiplier", 5.0, "float")
        window_seconds = cls.get_setting("data_exfil_window_seconds", 300, "int")
        baseline_bytes = cls.get_setting("data_exfil_baseline_bytes", 50000, "int")

        # Group outbound volume by (src_ip, dst_ip)
        pairs = defaultdict(list)
        for p in packets:
            pairs[(p["src_ip"], p["dst_ip"])].append(p)

        threshold_volume = baseline_bytes * multiplier
        incidents = []

        for (src, dst), pkts in pairs.items():
            pkts.sort(key=lambda x: x["timestamp"])
            left = 0
            for right in range(len(pkts)):
                while pkts[right]["timestamp"] - pkts[left]["timestamp"] > window_seconds:
                    left += 1

                window_slice = pkts[left:right+1]
                vol_bytes = sum(p.get("packet_size", 0) for p in window_slice)

                if vol_bytes >= threshold_volume:
                    ratio = vol_bytes / baseline_bytes if baseline_bytes > 0 else multiplier
                    incidents.append({
                        "incident_type": "DATA_EXFILTRATION",
                        "severity": "HIGH",
                        "title": f"Abnormal Outbound Data Transfer from {src} to {dst}",
                        "description": (
                            f"Outbound network data volume from {src} to destination {dst} reached {vol_bytes:,} bytes "
                            f"({vol_bytes / 1024:.1f} KB), exceeding the baseline threshold of {baseline_bytes:,} bytes by {ratio:.1f}x "
                            f"(Configured Alert Multiplier: {multiplier}x)."
                        ),
                        "src_ip": src,
                        "dst_ip": dst,
                        "target_ports": str(window_slice[0].get("dst_port", 0)),
                        "protocol": window_slice[0].get("protocol", "TCP"),
                        "rule_name": "RULE-04-DATA-EXFILTRATION",
                        "threshold_details": json.dumps({
                            "baseline_bytes": baseline_bytes,
                            "multiplier": multiplier,
                            "threshold_bytes": threshold_volume,
                            "observed_bytes": vol_bytes,
                            "deviation_ratio": round(ratio, 2),
                            "window_seconds": window_seconds,
                            "first_time": window_slice[0]["datetime_str"],
                            "last_time": window_slice[-1]["datetime_str"]
                        }),
                        "first_timestamp": window_slice[0]["timestamp"],
                        "last_timestamp": window_slice[-1]["timestamp"],
                        "triggering_packets": window_slice[:50]
                    })
                    break
        return incidents
