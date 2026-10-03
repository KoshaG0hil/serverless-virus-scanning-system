"""Google Cloud Firestore Logger: Stores scan verdicts, file hashes, and quarantine records."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
from google.cloud import firestore

logger = logging.getLogger(__name__)


class FirestoreLogger:
    """Records malware scan audit logs into Google Cloud Firestore."""

    def __init__(self, collection_name: str = "malware_scan_logs", mock_mode: bool = False):
        self.collection_name = collection_name
        self.mock_mode = mock_mode
        self._db = None if mock_mode else firestore.Client()

    def log_scan_event(self, record: Dict[str, Any]) -> str:
        """Write a scan audit record to Firestore."""
        record_with_ts = {
            **record,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if self.mock_mode:
            logger.info(f"[MOCK FIRESTORE] Logged record to collection '{self.collection_name}': {record_with_ts}")
            return "mock-doc-id-12345"

        try:
            doc_ref = self._db.collection(self.collection_name).document()
            doc_ref.set(record_with_ts)
            logger.info(f"Audit log stored in Firestore document {doc_ref.id}")
            return doc_ref.id
        except Exception as e:
            logger.error(f"Failed to write audit log to Firestore: {e}")
            return "error"
