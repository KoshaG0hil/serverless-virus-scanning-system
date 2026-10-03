"""AWS Lambda ClamAV Malware Detection and S3 File Quarantine Handler."""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import subprocess
import urllib.parse
from typing import Any, Dict
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 cryptographic checksum."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def scan_file(file_path: str, clamscan_bin: str = "/opt/clamav/bin/clamscan") -> Dict[str, Any]:
    """Execute ClamAV scan against the target file."""
    # Fallback to system clamscan if layer binary not present
    binary = clamscan_bin if os.path.exists(clamscan_bin) else "clamscan"

    try:
        proc = subprocess.run(
            [binary, "--stdout", "--no-summary", file_path],
            capture_output=True,
            text=True,
            timeout=120
        )
        stdout = proc.stdout.strip()
        exit_code = proc.returncode

        if exit_code == 0:
            return {"status": "CLEAN", "signature": None, "details": stdout}
        elif exit_code == 1 or "FOUND" in stdout:
            signature = "Malware-Threat"
            if "FOUND" in stdout:
                parts = stdout.split(":")
                if len(parts) > 1:
                    signature = parts[1].replace("FOUND", "").strip()
            return {"status": "INFECTED", "signature": signature, "details": stdout}
        else:
            return {"status": "ERROR", "signature": None, "details": proc.stderr}
    except Exception as e:
        logger.error(f"Error scanning file with ClamAV: {e}")
        return {"status": "ERROR", "signature": None, "details": str(e)}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda entrypoint triggered by S3 ObjectCreated events."""
    logger.info(f"Received S3 event: {json.dumps(event, default=str)}")

    s3 = boto3.client("s3")
    dynamodb = boto3.resource("dynamodb")
    sns = boto3.client("sns")

    clean_bucket = os.environ.get("CLEAN_BUCKET", "clean-safe-bucket")
    quarantine_bucket = os.environ.get("QUARANTINE_BUCKET", "quarantine-bucket")
    table_name = os.environ.get("DYNAMODB_TABLE", "VirusScanLogs")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    table = dynamodb.Table(table_name)
    processed_files = []

    for record in event.get("Records", []):
        source_bucket = record["s3"]["bucket"]["name"]
        raw_key = record["s3"]["object"]["key"]
        object_key = urllib.parse.unquote_plus(raw_key)

        download_path = f"/tmp/{os.path.basename(object_key)}"

        try:
            logger.info(f"Downloading s3://{source_bucket}/{object_key} to {download_path}")
            s3.download_file(source_bucket, object_key, download_path)

            # Compute hash and scan file
            sha256_hash = compute_sha256(download_path)
            file_size = os.path.getsize(download_path)
            scan_verdict = scan_file(download_path)
            status = scan_verdict.get("status", "ERROR")
            signature = scan_verdict.get("signature")

            logger.info(f"Scan verdict for {object_key}: {status} (Signature: {signature})")

            # Route file based on verdict
            if status == "CLEAN":
                target_bucket = clean_bucket
            else:
                target_bucket = quarantine_bucket

            # Copy to destination bucket with audit metadata
            logger.info(f"Copying {object_key} to s3://{target_bucket}/{object_key}")
            s3.copy_object(
                Bucket=target_bucket,
                Key=object_key,
                CopySource={"Bucket": source_bucket, "Key": object_key},
                MetadataDirective="REPLACE",
                Metadata={
                    "scan-status": status,
                    "scan-sha256": sha256_hash,
                    "scan-signature": signature or "None",
                    "scanned-by": "AWSLambda-ClamAV"
                }
            )

            # Delete from untrusted landing bucket
            logger.info(f"Deleting original untrusted object from s3://{source_bucket}/{object_key}")
            s3.delete_object(Bucket=source_bucket, Key=object_key)

            # Log audit record in DynamoDB
            now_iso = datetime.now(timezone.utc).isoformat()
            table.put_item(
                Item={
                    "filename": object_key,
                    "source_bucket": source_bucket,
                    "target_bucket": target_bucket,
                    "verdict": status,
                    "signature": signature or "None",
                    "sha256": sha256_hash,
                    "file_size_bytes": file_size,
                    "timestamp": now_iso
                }
            )

            # Publish real-time SNS security alert if infected
            if status == "INFECTED" and sns_topic_arn:
                alert_body = (
                    f"🚨 [MALWARE DETECTED] Malicious file quarantined!\n"
                    f"================================================\n"
                    f"• File Name:     {object_key}\n"
                    f"• Source Bucket: {source_bucket}\n"
                    f"• Threat Name:   {signature}\n"
                    f"• SHA-256 Hash:  {sha256_hash}\n"
                    f"• Quarantine:    s3://{target_bucket}/{object_key}\n"
                    f"• Timestamp:     {now_iso}\n"
                    f"================================================\n"
                )
                sns.publish(
                    TopicArn=sns_topic_arn,
                    Subject=f"Security Alert: Malware Quarantined ({signature})",
                    Message=alert_body
                )

            processed_files.append({
                "filename": object_key,
                "status": status,
                "destination": f"s3://{target_bucket}/{object_key}"
            })

        except Exception as e:
            logger.exception(f"Error processing file {object_key}: {e}")

        finally:
            if os.path.exists(download_path):
                os.remove(download_path)

    return {
        "statusCode": 200,
        "body": json.dumps({"processed": processed_files})
    }
