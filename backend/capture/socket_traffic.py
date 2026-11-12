import time
import socket
import threading
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class TrafficGenerator:
    """
    Simulated Network Traffic Generator:
    Uses standard Python socket programming (TCP/UDP) strictly restricted to localhost (127.0.0.1).
    Used for local demonstrations and testing incident detection algorithms.
    """

    HOST = "127.0.0.1"

    @classmethod
    def start_temporary_echo_server(cls, port=9999, duration=10):
        """Spawns a temporary TCP server on localhost for normal connection testing."""
        def server_thread():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((cls.HOST, port))
                    s.listen(5)
                    s.settimeout(duration)
                    start = time.time()
                    while time.time() - start < duration:
                        try:
                            conn, addr = s.accept()
                            with conn:
                                data = conn.recv(1024)
                                if data:
                                    conn.sendall(b"ACK: " + data)
                        except socket.timeout:
                            break
                        except Exception:
                            break
            except Exception as e:
                logger.debug(f"Temporary server exception: {e}")

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()
        time.sleep(0.1)  # Allow socket to bind

    @classmethod
    def generate_normal_traffic(cls, count=15):
        """
        Simulates standard TCP and UDP client-server conversations.
        """
        echo_port = 9050
        cls.start_temporary_echo_server(port=echo_port, duration=5)

        results = []
        # Normal TCP
        for i in range(count):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(1.0)
                    client.connect((cls.HOST, echo_port))
                    msg = f"HTTP/1.1 GET /index.html [Request #{i+1}]\r\n\r\n".encode()
                    client.sendall(msg)
                    resp = client.recv(1024)
                    results.append({"type": "TCP", "status": "Success", "bytes": len(msg) + len(resp)})
            except Exception as e:
                results.append({"type": "TCP", "status": "Error", "error": str(e)})
            time.sleep(0.05)

        # Normal UDP
        udp_port = 9051
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            for i in range(count):
                msg = f"DNS_QUERY: domain-{i}.example.local".encode()
                udp_sock.sendto(msg, (cls.HOST, udp_port))
                results.append({"type": "UDP", "status": "Sent", "bytes": len(msg)})
                time.sleep(0.03)

        return {
            "scenario": "NORMAL_TRAFFIC",
            "host": cls.HOST,
            "packets_sent": len(results),
            "timestamp": datetime.now().isoformat()
        }

    @classmethod
    def simulate_port_scan(cls, target_host="127.0.0.1", start_port=8000, num_ports=30):
        """
        Simulates a TCP Port Scan:
        Probes >20 distinct destination ports in rapid succession (< 5 seconds).
        Strictly targets localhost.
        """
        target_host = "127.0.0.1"  # Enforce localhost
        probed_ports = []
        start_time = time.time()

        for port in range(start_port, start_port + num_ports):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                # Attempt connection
                s.connect_ex((target_host, port))
                probed_ports.append(port)
                s.close()
            except Exception:
                probed_ports.append(port)
            time.sleep(0.01)

        duration = time.time() - start_time
        return {
            "scenario": "PORT_SCAN",
            "source_ip": "127.0.0.1",
            "target_ip": target_host,
            "probed_ports_count": len(probed_ports),
            "duration_seconds": round(duration, 3),
            "ports_range": f"{start_port} - {start_port + num_ports - 1}"
        }

    @classmethod
    def simulate_syn_flood(cls, target_port=9090, count=120):
        """
        Simulates TCP SYN traffic surge:
        Sends rapid connection requests without completing full handshakes.
        Strictly targets localhost.
        """
        target_host = "127.0.0.1"
        start_time = time.time()
        sent = 0

        # Create quick socket connects with tiny timeouts that drop immediately
        for _ in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                # Non-blocking connect initiates SYN packet immediately
                s.connect_ex((target_host, target_port))
                sent += 1
                s.close()
            except Exception:
                pass
            time.sleep(0.005)

        duration = time.time() - start_time
        pps = sent / duration if duration > 0 else 0
        return {
            "scenario": "SYN_FLOOD",
            "source_ip": "127.0.0.1",
            "target_ip": target_host,
            "target_port": target_port,
            "syn_packets_sent": sent,
            "duration_seconds": round(duration, 3),
            "syn_pps": round(pps, 1)
        }

    @classmethod
    def simulate_brute_force_login(cls, service_port=22, attempts=15):
        """
        Simulates Brute-Force repeated authentication connection attempts:
        Attempts >10 rapid connection establishments to an authentication service port (e.g. 22 SSH).
        Strictly targets localhost.
        """
        target_host = "127.0.0.1"
        start_time = time.time()
        performed_attempts = 0

        for i in range(attempts):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((target_host, service_port))
                performed_attempts += 1
                s.close()
            except Exception:
                performed_attempts += 1
            time.sleep(0.1)

        duration = time.time() - start_time
        return {
            "scenario": "BRUTE_FORCE",
            "source_ip": "127.0.0.1",
            "target_ip": target_host,
            "target_port": service_port,
            "attempts": performed_attempts,
            "duration_seconds": round(duration, 2)
        }

    @classmethod
    def simulate_data_exfiltration(cls, target_port=9095, total_kb=350):
        """
        Simulates Abnormal Outbound Data Exfiltration:
        Streams a burst of outbound data exceeding standard baseline volume.
        Strictly targets localhost.
        """
        target_host = "127.0.0.1"
        # Temporary receiver
        def sink():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((target_host, target_port))
                    s.listen(1)
                    s.settimeout(5)
                    conn, _ = s.accept()
                    with conn:
                        while conn.recv(4096):
                            pass
            except Exception:
                pass

        threading.Thread(target=sink, daemon=True).start()
        time.sleep(0.1)

        payload_block = b"X" * 1024  # 1 KB chunk
        bytes_sent = 0
        start_time = time.time()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((target_host, target_port))
                for _ in range(total_kb):
                    s.sendall(payload_block)
                    bytes_sent += len(payload_block)
        except Exception as e:
            logger.debug(f"Exfiltration simulation send completed/interrupted: {e}")

        duration = time.time() - start_time
        return {
            "scenario": "DATA_EXFILTRATION",
            "source_ip": "127.0.0.1",
            "target_ip": target_host,
            "target_port": target_port,
            "bytes_transferred": bytes_sent,
            "kb_transferred": round(bytes_sent / 1024, 2),
            "duration_seconds": round(duration, 3)
        }

    @classmethod
    def record_and_correlate_simulation(cls, scenario_type):
        """
        Synthesizes packet stream, preserves forensic PCAP evidence in vault with SHA-256,
        inserts packet metadata, and triggers automated incident detection.
        """
        from pathlib import Path
        from scapy.all import Ether, IP, TCP, UDP, wrpcap
        from backend.config import Config
        from backend.database.db import execute_db
        from backend.analyzer.packet_parser import PacketParser
        from backend.detector.detection_engine import DetectionEngine
        from backend.forensics.evidence_vault import EvidenceVaultService

        now = time.time()
        session_id = f"SES-SIM-{scenario_type.upper()}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        execute_db("""
            INSERT INTO capture_sessions (id, session_name, source_type, status, is_demo)
            VALUES (?, ?, 'simulation', 'completed', 0)
        """, (session_id, f"Simulated {scenario_type.replace('_', ' ').title()} Session"))

        packets_to_save = []
        raw_scapy = []

        if scenario_type == "normal":
            for i in range(20):
                t = now - 20 + i
                p = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=50000+i, dport=9050, flags="PA")/b"GET / HTTP/1.1"
                raw_scapy.append(p)
                parsed = PacketParser.parse_scapy_packet(p, session_id=session_id, is_demo=0)
                parsed["timestamp"] = t
                parsed["datetime_str"] = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
                packets_to_save.append(parsed)

        elif scenario_type == "port_scan":
            for i in range(25):
                t = now - 5 + (i * 0.15)
                p = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=42000+i, dport=8000+i, flags="S")
                raw_scapy.append(p)
                parsed = PacketParser.parse_scapy_packet(p, session_id=session_id, is_demo=0)
                parsed["timestamp"] = t
                parsed["datetime_str"] = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
                packets_to_save.append(parsed)

        elif scenario_type == "syn_flood":
            for i in range(110):
                t = now - 2 + (i * 0.008)
                p = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=33000+(i%1000), dport=9090, flags="S")
                raw_scapy.append(p)
                parsed = PacketParser.parse_scapy_packet(p, session_id=session_id, is_demo=0)
                parsed["timestamp"] = t
                parsed["datetime_str"] = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
                packets_to_save.append(parsed)

        elif scenario_type == "brute_force":
            for i in range(14):
                t = now - 15 + i
                p = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=48000+i, dport=22, flags="S")
                raw_scapy.append(p)
                parsed = PacketParser.parse_scapy_packet(p, session_id=session_id, is_demo=0)
                parsed["timestamp"] = t
                parsed["datetime_str"] = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
                packets_to_save.append(parsed)

        elif scenario_type == "data_exfil":
            for i in range(190):
                t = now - 25 + (i * 0.1)
                p = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=51000, dport=9095, flags="PA")/("X"*1400)
                raw_scapy.append(p)
                parsed = PacketParser.parse_scapy_packet(p, session_id=session_id, is_demo=0)
                parsed["timestamp"] = t
                parsed["datetime_str"] = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
                parsed["packet_size"] = 1454
                packets_to_save.append(parsed)

        # Write PCAP
        pcap_path = Path(Config.UPLOADS_PATH) / f"{session_id}.pcap"
        wrpcap(str(pcap_path), raw_scapy)

        evd = EvidenceVaultService.preserve_evidence_file(
            source_path=pcap_path,
            original_filename=f"{session_id}.pcap",
            session_id=session_id,
            collector="Socket Traffic Simulator",
            source_type="Simulation",
            notes=f"Controlled simulation of {scenario_type}"
        )

        rows = []
        for p in packets_to_save:
            last_id, _ = execute_db("""
                INSERT INTO packets (
                    session_id, timestamp, datetime_str, src_ip, dst_ip,
                    src_port, dst_port, protocol, packet_size, tcp_flags,
                    src_mac, dst_mac, info, is_suspicious, is_demo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                p["session_id"], p["timestamp"], p["datetime_str"], p["src_ip"], p["dst_ip"],
                p["src_port"], p["dst_port"], p["protocol"], p["packet_size"], p["tcp_flags"],
                p["src_mac"], p["dst_mac"], p["info"], 0, 0
            ))
            p_copy = dict(p)
            p_copy["id"] = last_id
            rows.append(p_copy)

        total_bytes = sum(p["packet_size"] for p in packets_to_save)
        execute_db("""
            UPDATE capture_sessions 
            SET packet_count = ?, byte_count = ?, pcap_filename = ?
            WHERE id = ?
        """, (len(packets_to_save), total_bytes, evd["stored_filename"], session_id))

        incidents = DetectionEngine.analyze_packets(rows, session_id=session_id, is_demo=0, ignore_dedup=True)
        for inc_id in incidents:
            execute_db("UPDATE evidence SET incident_id = ? WHERE id = ?", (inc_id, evd["evidence_id"]))

        return {
            "session_id": session_id,
            "evidence_id": evd["evidence_id"],
            "packets_count": len(packets_to_save),
            "incidents": incidents
        }
