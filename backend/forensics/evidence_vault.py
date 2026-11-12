import os
import stat
import shutil
from pathlib import Path
from datetime import datetime
from backend.config import Config
from backend.database.db import query_db, execute_db
from backend.forensics.hasher import ForensicHasher
from backend.forensics.chain_of_custody import ChainOfCustodyService

class EvidenceVaultService:
    """
    Forensic Digital Evidence Vault:
    Preserves raw network capture artifacts, enforces cryptographic integrity,
    and manages chain-of-custody tracking.
    """

    @staticmethod
    def generate_evidence_id():
        row = query_db("SELECT COUNT(*) as count FROM evidence", one=True)
        count = (row["count"] if row else 0) + 1
        year = datetime.now().year
        return f"EVD-{year}-{count:04d}"

    @classmethod
    def preserve_evidence_file(cls, source_path, original_filename, incident_id=None, session_id=None,
                               collector="Automated Forensic Engine", source_type="PCAP Upload", notes=None):
        """
        Preserves an artifact file into the Evidence Vault:
        1. Copies to dedicated evidence directory.
        2. Sets read-only permissions to prevent accidental alteration.
        3. Computes cryptographic SHA-256 hash.
        4. Inserts evidence record into database.
        5. Registers Chain-of-Custody entries.
        """
        source_path = Path(source_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        evidence_id = cls.generate_evidence_id()
        timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{evidence_id}_{timestamp_prefix}_{Path(original_filename).name}"
        destination_path = Path(Config.EVIDENCE_PATH) / safe_filename

        # Copy original file to vault
        shutil.copy2(source_path, destination_path)

        # Set read-only attribute
        try:
            os.chmod(destination_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except Exception:
            pass

        # Compute SHA-256 hash
        sha256_hash = ForensicHasher.calculate_file_sha256(destination_path)
        file_size = destination_path.stat().st_size

        # Record into database
        execute_db("""
            INSERT INTO evidence (
                id, incident_id, session_id, original_filename, stored_filename,
                file_path, file_size_bytes, sha256_hash, collected_by, source_type,
                verification_status, is_readonly, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence_id, incident_id, session_id, original_filename, safe_filename,
            str(destination_path), file_size, sha256_hash, collector, source_type,
            "VERIFIED", 1, notes or f"Forensic artifact preserved via {source_type}"
        ))

        # Log Chain of Custody
        ChainOfCustodyService.record_action(
            evidence_id=evidence_id,
            action="EVIDENCE_COLLECTED",
            actor=collector,
            actor_role="Forensic Acquisition Agent",
            file_hash=sha256_hash,
            description=f"Original capture artifact '{original_filename}' collected from {source_type} source.",
            verification_result="ACQUIRED"
        )

        ChainOfCustodyService.record_action(
            evidence_id=evidence_id,
            action="HASH_CALCULATED",
            actor="Forensic Hashing Engine",
            actor_role="Cryptographic Module",
            file_hash=sha256_hash,
            description=f"Initial SHA-256 baseline hash computed: {sha256_hash}",
            verification_result="BASELINE_ESTABLISHED"
        )

        ChainOfCustodyService.record_action(
            evidence_id=evidence_id,
            action="EVIDENCE_PRESERVED",
            actor=collector,
            actor_role="Evidence Vault Custodian",
            file_hash=sha256_hash,
            description=f"Artifact secured in read-only Evidence Vault storage as {safe_filename} ({file_size:,} bytes).",
            verification_result="SECURED"
        )

        return {
            "evidence_id": evidence_id,
            "stored_filename": safe_filename,
            "file_path": str(destination_path),
            "sha256_hash": sha256_hash,
            "file_size": file_size,
            "verification_status": "VERIFIED"
        }

    @classmethod
    def verify_evidence_integrity(cls, evidence_id, verifier="Forensic Analyst"):
        """
        Recalculates file SHA-256 hash and compares with baseline hash.
        Flags TAMPER DETECTED if hash differs.
        """
        evd = query_db("SELECT * FROM evidence WHERE id = ?", (evidence_id,), one=True)
        if not evd:
            raise ValueError(f"Evidence ID {evidence_id} not found")

        stored_path = Path(evd["file_path"])
        if not stored_path.exists():
            status = "FILE_MISSING"
            description = f"CRITICAL: Evidence file at '{stored_path}' is missing or deleted from storage!"
            ChainOfCustodyService.record_action(
                evidence_id=evidence_id,
                action="TAMPER_DETECTED",
                actor=verifier,
                actor_role="Forensic Examiner",
                file_hash="MISSING",
                description=description,
                verification_result="TAMPER_DETECTED"
            )
            return {
                "evidence_id": evidence_id,
                "status": "TAMPER_DETECTED",
                "message": description,
                "original_hash": evd["sha256_hash"],
                "recalculated_hash": "N/A"
            }

        # Recalculate hash
        current_hash = ForensicHasher.calculate_file_sha256(stored_path)
        is_intact = (current_hash.upper() == evd["sha256_hash"].upper())
        status = "VERIFIED" if is_intact else "TAMPERED"

        # Update evidence table
        execute_db("""
            UPDATE evidence 
            SET verification_status = ?, last_verified_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (status, evidence_id))

        if is_intact:
            desc = f"Integrity verification PASSED. Recalculated SHA-256 matches baseline hash: {current_hash}"
            action = "INTEGRITY_VERIFIED"
            result_code = "PASSED"
        else:
            desc = (f"ALERT: TAMPER DETECTED! Recalculated SHA-256 ({current_hash}) differs from "
                    f"baseline hash ({evd['sha256_hash']}). Evidence modification detected!")
            action = "TAMPER_DETECTED"
            result_code = "FAILED_TAMPERED"

        ChainOfCustodyService.record_action(
            evidence_id=evidence_id,
            action=action,
            actor=verifier,
            actor_role="Forensic Examiner",
            file_hash=current_hash,
            description=desc,
            verification_result=result_code
        )

        return {
            "evidence_id": evidence_id,
            "status": "VERIFIED" if is_intact else "TAMPER_DETECTED",
            "is_intact": is_intact,
            "original_hash": evd["sha256_hash"],
            "recalculated_hash": current_hash,
            "message": desc
        }

    @classmethod
    def simulate_tampering_for_demo(cls, evidence_id):
        """
        Demonstration Tool:
        Intentionally flips 1 byte in a preserved evidence file to demonstrate
        how the cryptographic integrity verification immediately detects tampering.
        """
        evd = query_db("SELECT * FROM evidence WHERE id = ?", (evidence_id,), one=True)
        if not evd:
            raise ValueError(f"Evidence ID {evidence_id} not found")

        path = Path(evd["file_path"])
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Temporarily enable write permissions
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)

        # Alter the last byte or append a single byte
        with open(path, "r+b") as f:
            f.seek(0, os.SEEK_END)
            f.write(b"\x99")  # Injected tamper byte

        # Set back to read-only
        os.chmod(path, stat.S_IREAD)

        # Trigger verification check to record the tamper event in Chain of Custody
        return cls.verify_evidence_integrity(evidence_id, verifier="Simulated Adversary / Forensic Tester")
