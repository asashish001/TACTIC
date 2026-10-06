"""Tests for upload_validation.py — filename sanitization and content validation."""
import pytest

from app.services.upload_validation import (
    UploadValidationError,
    sanitize_evidence_filename,
    validate_evidence_content,
)


class TestSanitizeEvidenceFilename:
    """Tests for safe filename extraction."""

    def test_simple_filename(self):
        name, suffix = sanitize_evidence_filename("evidence.log")
        assert name == "evidence.log"
        assert suffix == "log"

    def test_path_rejected(self):
        with pytest.raises(UploadValidationError):
            sanitize_evidence_filename("../../../etc/passwd")

    def test_windows_path_rejected(self):
        with pytest.raises(UploadValidationError):
            sanitize_evidence_filename("C:\\Windows\\system32\\file.txt")

    def test_null_bytes_rejected(self):
        with pytest.raises(UploadValidationError):
            sanitize_evidence_filename("file\x00.txt")

    def test_unsupported_extension_rejected(self):
        with pytest.raises(UploadValidationError):
            sanitize_evidence_filename("file.xyz")

    def test_special_chars_sanitized(self):
        name, suffix = sanitize_evidence_filename("evidence@#$.log")
        assert "@" not in name
        assert "#" not in name
        assert suffix == "log"

    def test_bookmarks_extension_inferred(self):
        _name, suffix = sanitize_evidence_filename("Bookmarks")
        assert suffix == "json"

    def test_empty_filename_rejected(self):
        with pytest.raises(UploadValidationError):
            sanitize_evidence_filename("")

    def test_long_filename_rejected(self):
        with pytest.raises(UploadValidationError):
            sanitize_evidence_filename("a" * 256 + ".txt")


    def test_double_extension_filename(self):
        name, suffix = sanitize_evidence_filename("invoice.pdf.exe")
        assert name == "invoice.pdf.exe"
        assert suffix == "exe"

    def test_markdown_filename(self):
        name, suffix = sanitize_evidence_filename("README.md")
        assert name == "README.md"
        assert suffix == "md"


class TestValidateEvidenceContent:
    """Tests for evidence file content validation."""

    def test_valid_png_rejects_invalid_content(self, tmp_path):
        """PNG magic bytes without valid image data should be caught."""
        p = tmp_path / "image.png"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        with pytest.raises(UploadValidationError):
            validate_evidence_content(p, "png")

    def test_valid_pdf(self, tmp_path):
        p = tmp_path / "doc.pdf"
        p.write_bytes(b"%PDF-1.4" + b"\x00" * 100)
        mime = validate_evidence_content(p, "pdf")
        assert mime == "application/pdf"

    def test_empty_file_rejected(self, tmp_path):
        p = tmp_path / "empty.txt"
        p.write_bytes(b"")
        with pytest.raises(UploadValidationError):
            validate_evidence_content(p, "txt")

    def test_nonexistent_file_rejected(self, tmp_path):
        p = tmp_path / "missing.txt"
        with pytest.raises(UploadValidationError):
            validate_evidence_content(p, "txt")

    def test_content_type_mismatch(self, tmp_path):
        """PNG bytes with .txt extension should be rejected."""
        p = tmp_path / "image.txt"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        with pytest.raises(UploadValidationError):
            validate_evidence_content(p, "txt")

    def test_text_file_with_nul_rejected(self, tmp_path):
        p = tmp_path / "binary.txt"
        p.write_bytes(b"hello\x00world")
        with pytest.raises(UploadValidationError):
            validate_evidence_content(p, "txt")

    def test_valid_text_file(self, tmp_path):
        p = tmp_path / "log.txt"
        p.write_bytes(b"This is valid text content")
        mime = validate_evidence_content(p, "txt")
        assert mime is not None

    def test_valid_markdown_file(self, tmp_path):
        p = tmp_path / "README.md"
        p.write_bytes(b"# Manual Test Data Pack\nHarmless synthetic artifacts.\n")
        mime = validate_evidence_content(p, "md")
        assert mime is not None

    def test_double_extension_exe_sample(self, tmp_path):
        p = tmp_path / "invoice.pdf.exe"
        p.write_bytes(b"This is a harmless synthetic test file for double-extension testing.\n")
        mime = validate_evidence_content(p, "exe")
        assert mime is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
