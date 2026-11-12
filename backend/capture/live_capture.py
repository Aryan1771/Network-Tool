import time
import psutil
import threading
import logging
from pathlib import Path
from datetime import datetime
from scapy.all import get_if_list, conf, wrpcap
from backend.config import Config
from backend.database.db import execute_db, query_db
from backend.analyzer.packet_parser import PacketParser
from backend.detector.detection_engine import DetectionEngine
from backend.forensics.evidence_vault import EvidenceVaultService

logger = logging.getLogger(__name__)

class LiveCaptureService:
    """
    Live Network Traffic Capture Engine:
    Manages concurrent network sniffing across selected interfaces,
    streams packet metadata to SQLite, enforces evidence preservation,
    and runs real-time incident detection.
    """

    _capture_thread = None
    _stop_event = threading.Event()
    _is_running = False
    _current_session_id = None
    _current_interface = None
    _captured_packets_cache = []
    _scapy_raw_packets = []
    _start_timestamp = None
    _packet_counter = 0

    @classmethod
    def get_network_interfaces(cls):
        """
        Enumerates all physical and logical network interfaces using psutil and Scapy.
        """
        interfaces = []
        net_addrs = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()

        # Scapy available interfaces
        try:
            scapy_ifaces = get_if_list()
        except Exception:
            scapy_ifaces = []

        for iface_name, addrs in net_addrs.items():
            ipv4 = "N/A"
            mac = "N/A"
            for a in addrs:
                if a.family == psutil.AF_LINK or str(a.family) == "AddressFamily.AF_LINK":
                    mac = a.address
                elif a.family == 2 or str(a.family) == "AddressFamily.AF_INET":
                    ipv4 = a.address

            stats = net_stats.get(iface_name)
            is_up = stats.isup if stats else False
            speed = f"{stats.speed} Mbps" if stats and stats.speed > 0 else "Unknown"

            # Match Scapy interface key
            scapy_match = None
            for s_if in scapy_ifaces:
                if iface_name in s_if or s_if in iface_name:
                    scapy_match = s_if
                    break

            interfaces.append({
                "name": iface_name,
                "display_name": f"{iface_name} ({ipv4})",
                "scapy_name": scapy_match or iface_name,
                "ipv4": ipv4,
                "mac": mac,
                "is_up": is_up,
                "speed": speed
            })

        return interfaces

    @classmethod
    def start_capture(cls, interface=None, packet_limit=1000):
        """
        Initiates live packet capture in a non-blocking background thread.
        """
        if cls._is_running:
            return False, "Capture session already active"

        cls._stop_event.clear()
        cls._captured_packets_cache = []
        cls._scapy_raw_packets = []
        cls._packet_counter = 0
        cls._current_interface = interface
        cls._start_timestamp = time.time()
        cls._current_session_id = f"SES-LIVE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # Register session in DB
        execute_db("""
            INSERT INTO capture_sessions (
                id, session_name, source_type, interface, status, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cls._current_session_id, f"Live Sniff on {interface or 'Default'}",
            "live", str(interface), "running", 0
        ))

        def capture_worker():
            from scapy.all import sniff
            cls._is_running = True

            def packet_handler(pkt):
                if cls._stop_event.is_set():
                    return True  # Stop sniffing

                cls._packet_counter += 1
                cls._scapy_raw_packets.append(pkt)

                parsed = PacketParser.parse_scapy_packet(pkt, session_id=cls._current_session_id, is_demo=0)

                # Insert to SQLite
                last_id, _ = execute_db("""
                    INSERT INTO packets (
                        session_id, timestamp, datetime_str, src_ip, dst_ip,
                        src_port, dst_port, protocol, packet_size, tcp_flags,
                        src_mac, dst_mac, info, is_suspicious, is_demo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    parsed["session_id"], parsed["timestamp"], parsed["datetime_str"],
                    parsed["src_ip"], parsed["dst_ip"], parsed["src_port"], parsed["dst_port"],
                    parsed["protocol"], parsed["packet_size"], parsed["tcp_flags"],
                    parsed["src_mac"], parsed["dst_mac"], parsed["info"], 0, 0
                ))
                parsed["id"] = last_id
                cls._captured_packets_cache.append(parsed)

                # Periodic batch incident detection evaluation (every 25 packets)
                if len(cls._captured_packets_cache) % 25 == 0:
                    try:
                        recent_window = cls._captured_packets_cache[-50:]
                        DetectionEngine.analyze_packets(recent_window, session_id=cls._current_session_id, is_demo=0)
                    except Exception as e:
                        logger.error(f"Live detection error: {e}")

                if cls._packet_counter >= packet_limit:
                    return True

            try:
                sniff(
                    iface=interface if interface and interface != "auto" else None,
                    prn=packet_handler,
                    stop_filter=lambda p: cls._stop_event.is_set(),
                    store=False,
                    count=packet_limit
                )
            except Exception as e:
                logger.error(f"Sniffer error on interface {interface}: {e}")
            finally:
                cls._is_running = False

        cls._capture_thread = threading.Thread(target=capture_worker, daemon=True)
        cls._capture_thread.start()
        return True, cls._current_session_id

    @classmethod
    def stop_capture(cls):
        """
        Stops live capture, dumps captured packets to PCAP, hashes artifact, and preserves evidence.
        """
        if not cls._is_running and not cls._current_session_id:
            return False, "No active capture session"

        cls._stop_event.set()
        cls._is_running = False

        if cls._capture_thread and cls._capture_thread.is_alive():
            cls._capture_thread.join(timeout=2.0)

        session_id = cls._current_session_id
        pkt_count = len(cls._scapy_raw_packets)

        evidence_info = None
        if pkt_count > 0:
            # Save captured packets as physical PCAP evidence
            dump_filename = f"{session_id}_live_capture.pcap"
            temp_pcap = Path(Config.UPLOADS_PATH) / dump_filename
            try:
                wrpcap(str(temp_pcap), cls._scapy_raw_packets)

                # Preserve in Evidence Vault with SHA-256
                evidence_info = EvidenceVaultService.preserve_evidence_file(
                    source_path=temp_pcap,
                    original_filename=dump_filename,
                    session_id=session_id,
                    collector="Live Capture Monitor",
                    source_type="Live Sniff",
                    notes=f"Captured {pkt_count} live packets on {cls._current_interface or 'default'}"
                )
            except Exception as e:
                logger.error(f"Failed to preserve live pcap: {e}")

        # Final sweep incident detection on full session cache
        if cls._captured_packets_cache:
            try:
                new_incidents = DetectionEngine.analyze_packets(cls._captured_packets_cache, session_id=session_id, is_demo=0)
                if evidence_info and new_incidents:
                    for inc_id in new_incidents:
                        execute_db("UPDATE evidence SET incident_id = ? WHERE id = ?", (inc_id, evidence_info["evidence_id"]))
            except Exception as e:
                logger.error(f"Final detection sweep error: {e}")

        # Update Session in DB
        execute_db("""
            UPDATE capture_sessions 
            SET status = 'completed', packet_count = ?, end_time = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (pkt_count, session_id))

        cls._current_session_id = None
        cls._captured_packets_cache = []
        cls._scapy_raw_packets = []

        return True, {
            "session_id": session_id,
            "packets_captured": pkt_count,
            "evidence": evidence_info
        }

    @classmethod
    def get_status(cls):
        """Returns the real-time capture engine state."""
        duration = round(time.time() - cls._start_timestamp, 1) if (cls._is_running and cls._start_timestamp) else 0
        return {
            "is_running": cls._is_running,
            "session_id": cls._current_session_id,
            "interface": cls._current_interface,
            "packet_count": cls._packet_counter,
            "duration_seconds": duration
        }
