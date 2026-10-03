"""Google Cloud Storage Handler: Manages file downloads, quarantine moves, and metadata tagging."""

import logging
import os
import shutil
from typing import Any, Dict, Optional
from google.cloud import storage

logger = logging.getLogger(__name__)


class GCSHandler:
    """Handles file transfers and metadata updates across Google Cloud Storage buckets."""

    def __init__(self, client: Optional[storage.Client] = None, mock_mode: bool = False):
        self.mock_mode = mock_mode
        self.client = client or (None if mock_mode else storage.Client())

    def download_file(self, bucket_name: str, object_name: str, destination_path: str):
        """Download an object from GCS to local disk for scanning."""
        if self.mock_mode:
            logger.info(f"[MOCK GCS] Simulating download: gs://{bucket_name}/{object_name} -> {destination_path}")
            return

        logger.info(f"Downloading gs://{bucket_name}/{object_name} to {destination_path}")
        bucket = self.client.bucket(bucket_name)
        blob = bucket.blob(object_name)
        blob.download_to_filename(destination_path)

    def route_file(
        self,
        source_bucket: str,
        object_name: str,
        target_bucket: str,
        scan_metadata: Dict[str, Any]
    ) -> str:
        """Copy object to clean/quarantine bucket with security metadata, then delete from source."""
        if self.mock_mode:
            logger.info(f"[MOCK GCS] Simulating move: gs://{source_bucket}/{object_name} -> gs://{target_bucket}/{object_name}")
            return f"gs://{target_bucket}/{object_name}"

        src_bucket_obj = self.client.bucket(source_bucket)
        src_blob = src_bucket_obj.blob(object_name)

        dest_bucket_obj = self.client.bucket(target_bucket)

        # Attach security audit metadata
        metadata = {
            "scan-status": scan_metadata.get("status", "UNKNOWN"),
            "scan-sha256": scan_metadata.get("sha256", ""),
            "scan-signature": scan_metadata.get("signature") or "None",
            "scanned-by": "ClamAV-GoogleCloudRun"
        }

        logger.info(f"Copying object to destination gs://{target_bucket}/{object_name}")
        new_blob = src_bucket_obj.copy_blob(src_blob, dest_bucket_obj, object_name)
        new_blob.metadata = metadata
        new_blob.patch()

        # Delete from untrusted landing bucket
        logger.info(f"Deleting scanned object from untrusted landing bucket gs://{source_bucket}/{object_name}")
        src_blob.delete()

        return f"gs://{target_bucket}/{object_name}"
