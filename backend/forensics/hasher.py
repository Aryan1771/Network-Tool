import hashlib
from pathlib import Path

class ForensicHasher:
    """
    Forensic Hashing Utility:
    Computes cryptographic SHA-256 hashes to guarantee data integrity
    and digital evidence admissibility.
    """

    @staticmethod
    def calculate_file_sha256(file_path):
        """
        Calculates SHA-256 cryptographic hash of a file in streaming chunks (64KB).
        Returns uppercase hex digest.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Target file for hashing does not exist: {file_path}")

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest().upper()

    @staticmethod
    def calculate_bytes_sha256(data_bytes):
        """
        Calculates SHA-256 cryptographic hash of in-memory raw bytes.
        """
        if isinstance(data_bytes, str):
            data_bytes = data_bytes.encode("utf-8")
        return hashlib.sha256(data_bytes).hexdigest().upper()
