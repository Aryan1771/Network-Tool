import os
import uuid
from pathlib import Path
from datetime import datetime
from scapy.all import rdpcap, PcapReader
from backend.database.db import execute_db, query_db
from backend.analyzer.packet_parser import PacketParser
from backend.detector.detection_engine import DetectionEngine
from backend.forensics.evidence_vault import EvidenceVaultService

class PCAPHandler:
    """
    Forensic PCAP File Processor:
    Ingests .pcap and .pcapng files, preserves evidence in vault with SHA-256 hash,
    extracts metadata, populates database, and executes detection algorithms.
    """

    @classmethod
    def validate_pcap(cls, file_path):
        """
        Validates whether file is a legitimate PCAP or PCAPNG capture file.
        """
        path = Path(file_path)
        if not path.is_file():
            return False, "File does not exist"

        if path.stat().st_size == 0:
            return False, "File is empty"

        # Inspect magic bytes
        with open(path, "rb") as f:
            magic = f.read(4)

        valid_magics = [
            b"\xd4\xc3\xb2\xa1",  # Standard pcap (little-endian)
            b"\xa1\xb2\xc3\xd4",  # Standard pcap (big-endian)
            b"\x4d\x3c\xb2\xa1",  # pcap nanosecond
            b"\xa1\xb2\x3c\x4d",  # pcap nanosecond
            b"\x0a\x0d\x0d\x0a"   # pcapng block header
        ]

        if any(magic.startswith(m) for m in valid_magics):
            return True, "Valid PCAP/PCAPNG header detected"

        # Fallback Scapy trial read
        try:
            with PcapReader(str(path)) as p:
                pkt = p.read_packet()
                if pkt:
                    return True, "Scapy successfully read sample packet"
        except Exception as e:
            return False, f"Not a valid capture file: {e}"

        return False, "Unrecognized capture format"

    @classmethod
    def process_pcap_file(cls, source_file_path, original_filename, is_demo=0, max_packets=5000):
        """
        Preserves original in Evidence Vault, parses packet headers, stores in SQLite,
        and executes automated incident detection rules.
        """
        valid, msg = cls.validate_pcap(source_file_path)
        if not valid:
            raise ValueError(f"Invalid PCAP file: {msg}")

        session_id = f"SES-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-{uuid.uuid4().hex[:8]}"

        # Register the session before evidence: evidence.session_id has a
        # foreign key to capture_sessions.id.
        execute_db("""
            INSERT INTO capture_sessions (
                id, session_name, source_type, pcap_filename, status, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session_id, f"Upload: {original_filename}", "pcap",
            original_filename, "completed", is_demo
        ))

        # 1. Preserve original file in Evidence Vault
        try:
            evidence_record = EvidenceVaultService.preserve_evidence_file(
                source_path=source_file_path,
                original_filename=original_filename,
                session_id=session_id,
                collector="Forensic PCAP Ingestion Module",
                source_type="PCAP Upload",
                notes=f"Processed capture session {session_id}"
            )
        except Exception:
            execute_db("DELETE FROM capture_sessions WHERE id = ?", (session_id,))
            raise
        evidence_id = evidence_record["evidence_id"]
        execute_db("""
            UPDATE capture_sessions SET pcap_filename = ? WHERE id = ?
        """, (evidence_record["stored_filename"], session_id))

        # 3. Read and Parse Packets
        parsed_packet_list = []
        total_bytes = 0

        try:
            scapy_pkts = rdpcap(str(source_file_path), count=max_packets)
            for pkt in scapy_pkts:
                parsed = PacketParser.parse_scapy_packet(pkt, session_id=session_id, is_demo=is_demo)
                parsed_packet_list.append(parsed)
                total_bytes += parsed["packet_size"]
        except Exception as e:
            # Fallback stream read if memory-efficient reading needed
            with PcapReader(str(source_file_path)) as reader:
                idx = 0
                for pkt in reader:
                    parsed = PacketParser.parse_scapy_packet(pkt, session_id=session_id, is_demo=is_demo)
                    parsed_packet_list.append(parsed)
                    total_bytes += parsed["packet_size"]
                    idx += 1
                    if idx >= max_packets:
                        break

        # 4. Batch Insert Packets into SQLite
        packet_rows_for_detector = []
        for p in parsed_packet_list:
            last_id, _ = execute_db("""
                INSERT INTO packets (
                    session_id, timestamp, datetime_str, src_ip, dst_ip,
                    src_port, dst_port, protocol, packet_size, tcp_flags,
                    src_mac, dst_mac, info, is_suspicious, is_demo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                p["session_id"], p["timestamp"], p["datetime_str"], p["src_ip"], p["dst_ip"],
                p["src_port"], p["dst_port"], p["protocol"], p["packet_size"], p["tcp_flags"],
                p["src_mac"], p["dst_mac"], p["info"], p["is_suspicious"], p["is_demo"]
            ))
            p_copy = dict(p)
            p_copy["id"] = last_id
            packet_rows_for_detector.append(p_copy)

        # Update Session packet and byte count
        execute_db("""
            UPDATE capture_sessions 
            SET packet_count = ?, byte_count = ?, end_time = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (len(parsed_packet_list), total_bytes, session_id))

        # 5. Run Automated Incident Detection Engine
        detected_incidents = DetectionEngine.analyze_packets(packet_rows_for_detector, session_id=session_id, is_demo=is_demo)

        # 6. Link newly created incidents to the evidence record
        for inc_id in detected_incidents:
            execute_db("UPDATE evidence SET incident_id = ? WHERE id = ?", (inc_id, evidence_id))

        return {
            "session_id": session_id,
            "evidence_id": evidence_id,
            "filename": original_filename,
            "packets_analyzed": len(parsed_packet_list),
            "total_bytes": total_bytes,
            "sha256_hash": evidence_record["sha256_hash"],
            "incidents_detected": len(detected_incidents),
            "incident_ids": detected_incidents
        }
