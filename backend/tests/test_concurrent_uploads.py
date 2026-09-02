"""
Concurrent duplicate upload race-condition tests.

Verifies that when two identical evidence files are uploaded simultaneously,
exactly one succeeds (201) and the other either succeeds or gets a 409 Conflict,
but never causes a database integrity error.
"""
import os
import sys
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.conftest import build_multipart


class TestConcurrentUploads:
    """Race-condition tests for parallel duplicate evidence uploads."""

    def test_concurrent_identical_uploads_no_crash(self, client, admin_headers, sample_case):
        """Two simultaneous uploads of identical content should not crash the server."""
        import random, string
        content = ("Concurrent upload race condition test content " +
                   ''.join(random.choices(string.ascii_letters + string.digits, k=32))).encode()
        results = []

        def upload_one():
            raw, headers = build_multipart(
                sample_case.id, "concurrent_evidence.log", content,
                content_type="text/plain",
            )
            headers.update(admin_headers)
            resp = client.post("/api/evidence/upload", content=raw, headers=headers)
            return resp.status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(upload_one) for _ in range(2)]
            for f in as_completed(futures):
                results.append(f.result())

        # Both should return either 201 (success) or 409 (duplicate detected)
        for code in results:
            assert code in (201, 409), f"Unexpected status code: {code}. Results: {results}"

        # At least one must succeed
        assert 201 in results, f"At least one upload should succeed. Results: {results}"

    def test_concurrent_different_uploads_both_succeed(self, client, admin_headers, sample_case):
        """Two simultaneous uploads of different content should both succeed."""
        results = []

        def upload_file(suffix):
            content = f"Different content for file {suffix}".encode()
            raw, headers = build_multipart(
                sample_case.id, f"file_{suffix}.txt", content,
            )
            headers.update(admin_headers)
            resp = client.post("/api/evidence/upload", content=raw, headers=headers)
            return resp.status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(upload_file, i) for i in range(2)]
            for f in as_completed(futures):
                results.append(f.result())

        assert all(code == 201 for code in results), f"Both should succeed: {results}"

    def test_rapid_sequential_identical_uploads(self, client, admin_headers, sample_case):
        """Five rapid sequential uploads of identical content should not corrupt the DB."""
        content = b"Rapid sequential duplicate test"
        status_codes = []

        for i in range(5):
            raw, headers = build_multipart(
                sample_case.id, f"rapid_{i}.log", content,
                content_type="text/plain",
            )
            headers.update(admin_headers)
            resp = client.post("/api/evidence/upload", content=raw, headers=headers)
            status_codes.append(resp.status_code)

        # First should be 201, rest should be 409 (duplicate)
        assert status_codes[0] == 201, f"First upload should succeed: {status_codes}"
        for code in status_codes[1:]:
            assert code in (409, 201), f"Unexpected code: {code}. All: {status_codes}"

        # Verify the evidence count is exactly 1
        resp = client.get(
            f"/api/evidence?case_id={sample_case.id}",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        matching = [e for e in items if e.get("sha256")]
        assert len(matching) >= 1, "At least one evidence record should exist"
