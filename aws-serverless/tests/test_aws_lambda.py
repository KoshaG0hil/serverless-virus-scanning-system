"""Unit tests for the AWS Lambda ClamAV handler."""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from lambda_function import compute_sha256, scan_file


def test_aws_compute_sha256():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("aws test payload")
        temp_path = f.name

    try:
        digest = compute_sha256(temp_path)
        assert len(digest) == 64
        assert isinstance(digest, str)
    finally:
        os.remove(temp_path)


def test_aws_scan_mock_clean(monkeypatch):
    class MockProcess:
        returncode = 0
        stdout = "/tmp/test.txt: OK"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockProcess())

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("safe clean document")
        temp_path = f.name

    try:
        verdict = scan_file(temp_path)
        assert verdict["status"] == "CLEAN"
        assert verdict["signature"] is None
    finally:
        os.remove(temp_path)


def test_aws_scan_mock_infected(monkeypatch):
    class MockInfectedProcess:
        returncode = 1
        stdout = "/tmp/test.txt: Win.Test.EICAR_HDB-1 FOUND"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockInfectedProcess())

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("eicar virus content")
        temp_path = f.name

    try:
        verdict = scan_file(temp_path)
        assert verdict["status"] == "INFECTED"
        assert "EICAR" in verdict["signature"]
    finally:
        os.remove(temp_path)
