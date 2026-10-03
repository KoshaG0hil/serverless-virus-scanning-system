"""ClamAV Scanner Module: Executes virus scans and computes cryptographic file hashes."""

import hashlib
import logging
import os
import subprocess
from typing import Any, Dict

logger = logging.getLogger(__name__)


class ClamAVScanner:
    """Interfaces with ClamAV binary or daemon to scan local files."""

    def __init__(self, binary_path: str = "clamscan"):
        self.binary_path = binary_path

    @staticmethod
    def compute_sha256(file_path: str) -> str:
        """Compute SHA-256 checksum of the target file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a file using ClamAV and return structured scan verdict."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        sha256_checksum = self.compute_sha256(file_path)

        # Check if clamdscan (fast daemon) or clamscan (fallback binary) should be used
        scanner_cmd = [self.binary_path, "--stdout", "--no-summary", file_path]
        logger.info(f"Executing ClamAV scan: {' '.join(scanner_cmd)}")

        try:
            # ClamAV exit codes: 0 = Clean, 1 = Infected, >1 = Error
            proc = subprocess.run(
                scanner_cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            exit_code = proc.returncode

            logger.info(f"ClamAV scan completed with exit code {exit_code}")

            if exit_code == 0:
                return {
                    "status": "CLEAN",
                    "signature": None,
                    "sha256": sha256_checksum,
                    "file_size": file_size,
                    "details": "No malware detected by ClamAV."
                }
            elif exit_code == 1 or "FOUND" in stdout:
                # Extract signature name (e.g. "/tmp/sample.txt: Eicar-Test-Signature FOUND")
                signature = "Unknown-Malware"
                if "FOUND" in stdout:
                    parts = stdout.split(":")
                    if len(parts) > 1:
                        signature = parts[1].replace("FOUND", "").strip()

                return {
                    "status": "INFECTED",
                    "signature": signature,
                    "sha256": sha256_checksum,
                    "file_size": file_size,
                    "details": stdout
                }
            else:
                logger.error(f"ClamAV returned non-standard code {exit_code}. Stderr: {stderr}")
                return {
                    "status": "ERROR",
                    "signature": None,
                    "sha256": sha256_checksum,
                    "file_size": file_size,
                    "details": f"ClamAV scan error (code {exit_code}): {stderr or stdout}"
                }

        except subprocess.TimeoutExpired:
            logger.error(f"ClamAV scan timed out for {file_path}")
            return {
                "status": "ERROR",
                "signature": None,
                "sha256": sha256_checksum,
                "file_size": file_size,
                "details": "ClamAV scan timed out."
            }
        except Exception as e:
            logger.exception(f"Unexpected error running ClamAV: {e}")
            return {
                "status": "ERROR",
                "signature": None,
                "sha256": sha256_checksum,
                "file_size": file_size,
                "details": str(e)
            }
