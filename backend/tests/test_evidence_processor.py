"""Tests for evidence_processor.py — hashing, file type detection, and metadata."""
import hashlib
import tempfile
from pathlib import Path

import pytest

from app.services.evidence_processor import (
    calculate_hashes,
    detect_file_type,
    process_evidence,
)


class TestCalculateHashes:
    """Tests for incremental hashing without full-file memory load."""

    def test_returns_all_three_hashes(self, tmp_path):
        p = tmp_path / "evidence.bin"
        p.write_bytes(b"forensic evidence content")
        result = calculate_hashes(p)
        assert "md5" in result
        assert "sha1" in result
        assert "sha256" in result
        assert len(result["md5"]) == 32
        assert len(result["sha1"]) == 40
        assert len(result["sha256"]) == 64

    def test_hash_matches_manual_calculation(self, tmp_path):
        content = b"known test content for hashing"
        p = tmp_path / "test.bin"
        p.write_bytes(content)
        result = calculate_hashes(p)
        assert result["md5"] == hashlib.md5(content, usedforsecurity=False).hexdigest()
        assert result["sha256"] == hashlib.sha256(content).hexdigest()

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        result = calculate_hashes(p)
        assert result["sha256"] == hashlib.sha256(b"").hexdigest()

    def test_large_file_streaming(self, tmp_path):
        """Ensure a 5MB file is hashed without loading it all into RAM."""
        p = tmp_path / "large.bin"
        p.write_bytes(b"x" * (5 * 1024 * 1024))
        result = calculate_hashes(p)
        expected = hashlib.sha256(b"x" * (5 * 1024 * 1024)).hexdigest()
        assert result["sha256"] == expected


class TestDetectFileType:
    """Tests for magic-byte file type detection."""

    def test_png_detection(self, tmp_path):
        p = tmp_path / "image.png"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        mime, mismatch = detect_file_type(p, "png")
        assert mime == "image/png"
        assert mismatch is False

    def test_jpeg_detection(self, tmp_path):
        p = tmp_path / "photo.jpg"
        p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
        mime, mismatch = detect_file_type(p, "jpg")
        assert mime == "image/jpeg"
        assert mismatch is False

    def test_pdf_detection(self, tmp_path):
        p = tmp_path / "doc.pdf"
        p.write_bytes(b"%PDF-1.4" + b"\x00" * 100)
        mime, mismatch = detect_file_type(p, "pdf")
        assert mime == "application/pdf"
        assert mismatch is False

    def test_mismatch_detected(self, tmp_path):
        """A PNG file with .txt extension should flag a mismatch."""
        p = tmp_path / "image.txt"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        mime, mismatch = detect_file_type(p, "txt")
        assert mime == "image/png"
        assert mismatch is True

    def test_unknown_type_falls_back(self, tmp_path):
        p = tmp_path / "data.xyz"
        p.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 100)
        mime, _ = detect_file_type(p, "xyz")
        assert mime == "application/octet-stream"


class TestProcessEvidence:
    """Tests for the evidence metadata extraction dispatcher."""

    def test_text_file_returns_sample(self, tmp_path):
        p = tmp_path / "log.txt"
        p.write_text("line 1\nline 2\nline 3\n", encoding="utf-8")
        meta = process_evidence(p, "txt")
        assert meta["kind"] == "text"
        assert "line 1" in meta["sample"]

    def test_json_file_returns_sample(self, tmp_path):
        p = tmp_path / "data.json"
        p.write_text('{"key": "value"}', encoding="utf-8")
        meta = process_evidence(p, "json")
        assert meta["kind"] == "text"
        assert "key" in meta["sample"]

    def test_unsupported_extension(self, tmp_path):
        p = tmp_path / "binary.exe"
        p.write_bytes(b"\x00" * 100)
        meta = process_evidence(p, "exe")
        assert meta["kind"] == "unsupported"

    def test_malformed_file_returns_error(self, tmp_path):
        """A corrupted PDF should return an error, not crash."""
        p = tmp_path / "bad.pdf"
        p.write_bytes(b"%PDF-not-a-real-pdf")
        meta = process_evidence(p, "pdf")
        assert meta["kind"] == "error"
        assert "message" in meta


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
