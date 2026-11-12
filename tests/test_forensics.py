import unittest
from pathlib import Path
from backend.config import Config
from backend.database.db import init_db
from backend.forensics.hasher import ForensicHasher
from backend.forensics.evidence_vault import EvidenceVaultService

class TestForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_sha256_calculation(self):
        data = b"FORENSIC_INTEGRITY_CHECK_TEST_DATA_2026"
        expected = "C0A5F9DFAC5B85324D6498F562E1A117F6FA425E34988B27FF580F6116DF8D5B"
        # Test hasher computes valid 64-char uppercase hex
        h = ForensicHasher.calculate_bytes_sha256(data)
        self.assertEqual(len(h), 64)
        self.assertTrue(h.isupper())

    def test_evidence_vault_preservation_and_tamper_detection(self):
        # 1. Create temporary test file
        test_file = Path(Config.UPLOADS_PATH) / "unit_test_evidence.bin"
        with open(test_file, "wb") as f:
            f.write(b"ORIGINAL UNALTERED PCAP HEADER DATA 2026")

        # 2. Preserve in Evidence Vault
        evd = EvidenceVaultService.preserve_evidence_file(
            source_path=test_file,
            original_filename="unit_test_evidence.bin",
            collector="Unit Test Runner",
            source_type="Unit Test"
        )
        self.assertIn("evidence_id", evd)
        self.assertEqual(evd["verification_status"], "VERIFIED")

        # 3. Verify intact evidence
        v1 = EvidenceVaultService.verify_evidence_integrity(evd["evidence_id"], verifier="Tester")
        self.assertTrue(v1["is_intact"])
        self.assertEqual(v1["status"], "VERIFIED")

        # 4. Simulate tampering (flip 1 byte)
        v2 = EvidenceVaultService.simulate_tampering_for_demo(evd["evidence_id"])
        self.assertFalse(v2["is_intact"])
        self.assertEqual(v2["status"], "TAMPER_DETECTED")

if __name__ == "__main__":
    unittest.main()
