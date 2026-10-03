"""Google Cloud Run Webhook & ClamAV Orchestrator Application."""

import base64
import json
import logging
import os
import tempfile
import uuid
from flask import Flask, jsonify, request

from src.scanner import ClamAVScanner
from src.gcs_handler import GCSHandler
from src.database import FirestoreLogger
from src.notifier import PubSubNotifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CloudRunClamAV")

app = Flask(__name__)

# Environment configurations
CLEAN_BUCKET = os.environ.get("CLEAN_BUCKET", "my-clean-bucket")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "my-quarantine-bucket")
PUBSUB_TOPIC = os.environ.get("PUBSUB_TOPIC")
MOCK_MODE = os.environ.get("MOCK_MODE", "false").lower() in ("true", "1", "yes")

# Initialize modules
scanner = ClamAVScanner()
gcs = GCSHandler(mock_mode=MOCK_MODE)
db = FirestoreLogger(mock_mode=MOCK_MODE)
notifier = PubSubNotifier(topic_id=PUBSUB_TOPIC, mock_mode=MOCK_MODE)


@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    """Liveness probe for Google Cloud Run."""
    return jsonify({
        "status": "healthy",
        "service": "Google Cloud Run ClamAV Malware Scanner",
        "mock_mode": MOCK_MODE,
        "clean_bucket": CLEAN_BUCKET,
        "quarantine_bucket": QUARANTINE_BUCKET
    }), 200


@app.route("/scan", methods=["POST"])
def scan_endpoint():
    """Handles Cloud Storage Eventarc / PubSub audit notifications."""
    event_data = None

    # 1. Parse Eventarc CloudEvent or direct JSON
    if request.is_json:
        req_json = request.get_json()

        # Handle Pub/Sub push format
        if "message" in req_json and "data" in req_json["message"]:
            try:
                decoded = base64.b64decode(req_json["message"]["data"]).decode("utf-8")
                event_data = json.loads(decoded)
            except Exception as e:
                logger.error(f"Failed to decode Pub/Sub message data: {e}")
                return jsonify({"error": "Invalid Pub/Sub payload"}), 400
        else:
            # Direct JSON or Eventarc CloudEvent
            event_data = req_json

    if not event_data:
        return jsonify({"error": "No event payload provided"}), 400

    # Extract source bucket and object name from Eventarc or custom payload
    bucket_name = event_data.get("bucket") or event_data.get("bucketId")
    object_name = event_data.get("name") or event_data.get("objectId")

    if not bucket_name or not object_name:
        logger.warning(f"Ignored event without bucket/name: {event_data}")
        return jsonify({"message": "No bucket or object name in event, skipped."}), 200

    logger.info(f"Received scan request for object: gs://{bucket_name}/{object_name}")

    # Prepare local quarantine download path
    temp_dir = tempfile.gettempdir()
    local_path = os.path.join(temp_dir, f"{uuid.uuid4()}_{os.path.basename(object_name)}")

    try:
        # Download from GCS untrusted bucket
        gcs.download_file(bucket_name, object_name, local_path)

        # In mock mode, create dummy file if not exists
        if MOCK_MODE and not os.path.exists(local_path):
            with open(local_path, "w") as f:
                f.write("mock safe file content")

        # Scan with ClamAV
        scan_verdict = scanner.scan_file(local_path)
        status = scan_verdict.get("status", "UNKNOWN")

        # Determine target bucket based on scan result
        if status == "CLEAN":
            target_bucket = CLEAN_BUCKET
        else:
            target_bucket = QUARANTINE_BUCKET

        # Route file in Cloud Storage
        dest_uri = gcs.route_file(bucket_name, object_name, target_bucket, scan_verdict)

        # Dispatch alert if infected
        if status == "INFECTED":
            notifier.send_alert(scan_verdict, object_name, dest_uri)

        # Record scan log in Firestore
        audit_record = {
            "filename": object_name,
            "source_bucket": bucket_name,
            "destination_uri": dest_uri,
            "verdict": status,
            "signature": scan_verdict.get("signature"),
            "sha256": scan_verdict.get("sha256"),
            "file_size_bytes": scan_verdict.get("file_size")
        }
        db.log_scan_event(audit_record)

        return jsonify({
            "message": "Scan processed successfully",
            "verdict": status,
            "filename": object_name,
            "sha256": scan_verdict.get("sha256"),
            "destination": dest_uri
        }), 200

    except Exception as e:
        logger.exception(f"Error processing scan for gs://{bucket_name}/{object_name}: {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        # Secure cleanup: remove local file from container disk
        if os.path.exists(local_path):
            try:
                os.remove(local_path)
            except Exception as e:
                logger.warning(f"Failed to delete temp file {local_path}: {e}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
