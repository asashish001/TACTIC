import unittest
from unittest.mock import MagicMock

from app.services.duplicate_evidence import find_duplicate_evidence


class DuplicateEvidenceLookupTests(unittest.TestCase):
    def test_duplicate_upload_finds_same_hash_in_same_case(self):
        existing = object()
        query = MagicMock()
        query.filter.return_value.first.return_value = existing
        db = MagicMock()
        db.query.return_value = query

        result = find_duplicate_evidence(db, 12, "a" * 64)

        self.assertIs(existing, result)
        db.query.assert_called_once()
        query.filter.assert_called_once()

    def test_non_duplicate_upload_returns_none(self):
        query = MagicMock()
        query.filter.return_value.first.return_value = None
        db = MagicMock()
        db.query.return_value = query

        result = find_duplicate_evidence(db, 12, "b" * 64)

        self.assertIsNone(result)
        query.filter.return_value.first.assert_called_once()


if __name__ == "__main__":
    unittest.main()
