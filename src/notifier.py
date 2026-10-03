"""Google Cloud Pub/Sub Alert Dispatcher: Sends real-time notifications for infected files."""

import json
import logging
from typing import Any, Dict, Optional
from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)


class PubSubNotifier:
    """Dispatches malware infection alerts via Google Cloud Pub/Sub."""

    def __init__(self, topic_id: Optional[str] = None, mock_mode: bool = False):
        self.topic_id = topic_id
        self.mock_mode = mock_mode or not topic_id
        self._publisher = None if self.mock_mode else pubsub_v1.PublisherClient()

    def send_alert(self, scan_result: Dict[str, Any], object_name: str, quarantine_path: str):
        """Publish alert for infected files."""
        payload = {
            "alert": "MALWARE_DETECTED",
            "severity": "CRITICAL",
            "filename": object_name,
            "signature": scan_result.get("signature", "Unknown"),
            "sha256": scan_result.get("sha256", ""),
            "quarantined_location": quarantine_path,
            "scanner": "ClamAV-GoogleCloudRun"
        }

        message_bytes = json.dumps(payload).encode("utf-8")

        if self.mock_mode or not self.topic_id:
            logger.warning(f"[MOCK PUB/SUB ALERT] Infected file alert: {payload}")
            return "mock-message-id"

        try:
            future = self._publisher.publish(self.topic_id, message_bytes)
            message_id = future.result()
            logger.info(f"Published malware alert to Pub/Sub topic {self.topic_id} (ID: {message_id})")
            return message_id
        except Exception as e:
            logger.error(f"Failed to publish Pub/Sub alert: {e}")
            return "error"
