"""Unit tests for the ClamAV scanner and application routing logic."""

import os
import tempfile
import pytest
from src.scanner import ClamAVScanner


def test_sha256_computation():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("test content for hashing")
        temp_path = f.name

    try:
        scanner = ClamAVScanner()
        hash_val = scanner.compute_sha256(temp_path)
        assert len(hash_val) == 64
        assert isinstance(hash_val, str)
    finally:
        os.remove(temp_path)


def test_clean_file_mock_verdict(monkeypatch):
    class MockProcess:
        returncode = 0
        stdout = "/tmp/sample.txt: OK"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockProcess())

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("clean file")
        temp_path = f.name

    try:
        scanner = ClamAVScanner()
        verdict = scanner.scan_file(temp_path)
        assert verdict["status"] == "CLEAN"
        assert verdict["signature"] is None
    finally:
        os.remove(temp_path)


def test_eicar_infected_mock_verdict(monkeypatch):
    class MockInfectedProcess:
        returncode = 1
        stdout = "/tmp/sample.txt: Win.Test.EICAR_HDB-1 FOUND"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockInfectedProcess())

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        temp_path = f.name

    try:
        scanner = ClamAVScanner()
        verdict = scanner.scan_file(temp_path)
        assert verdict["status"] == "INFECTED"
        assert "EICAR" in verdict["signature"]
    finally:
        os.remove(temp_path)
