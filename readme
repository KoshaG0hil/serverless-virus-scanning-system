# 🛡️ Secure File Upload System with Virus Scanning (AWS + ClamAV)

This project demonstrates a secure, serverless virus scanning system using AWS Lambda, ClamAV, S3, SNS, and DynamoDB — all built within the AWS Free Tier.

## 🚀 Project Objective

To build a virus-scanning system where users can upload files to an S3 bucket. The file is automatically scanned by ClamAV running in a Lambda function, and:

- ✅ If clean: stored in a “safe files” S3 bucket.
- ❌ If infected: moved to a quarantine bucket.
- 📝 Metadata is logged in DynamoDB.
- 🔔 Notifications sent via SNS.

---

## 🧱 Architecture Overview

- **S3 Bucket**: Upload entry point (user file upload)
- **Lambda Function**: Triggered on file upload
  - Unzips & scans file using ClamAV (via Lambda Layer)
  - Stores result in DynamoDB
  - Publishes to SNS
- **ClamAV Layer**: Custom-built Lambda Layer (manual EC2 build)
- **SNS**: Notifies admin email
- **DynamoDB**: Stores logs (filename, status, timestamp)

---

## 🛠️ Technologies Used

| Service     | Purpose |
|-------------|---------|
| S3          | File storage (uploads + quarantine) |
| Lambda      | Virus scanning using ClamAV |
| ClamAV      | Open-source antivirus |
| DynamoDB    | Logging file metadata |
| SNS         | Email notifications |
| IAM         | Secure access controls |
| EC2         | Build ClamAV layer |

---

## 🧩 Folder Structure

```
virus-scanner-project/
│
├── lambda/
│   ├── scanner_function.py
│   └── requirements.txt
│
├── layer/
│   └── clamav-layer.zip (manually built on EC2)
│
├── postman/
│   └── test-upload-collection.json
│
└── README.md
```

---

## 📦 Setup Instructions

### 1. 🛠️ Build ClamAV Layer on EC2

- Launch EC2 Amazon Linux 2 instance
- SSH into EC2 and run:

```bash
sudo yum update -y
sudo yum install gcc openssl-devel libcurl-devel zlib-devel cmake unzip -y
mkdir clamav-layer && cd clamav-layer
wget https://www.clamav.net/downloads/production/clamav-0.103.2.tar.gz
tar -xvzf clamav-0.103.2.tar.gz
cd clamav-0.103.2
./configure --prefix=$(pwd)/install_dir
make -j2
make install
```

- Zip layer:

```bash
cd install_dir
mkdir -p clamav/lib clamav/bin
cp -r lib/* clamav/lib/
cp -r bin/* clamav/bin/
zip -r9 ../clamav-layer.zip clamav
```

- Download `clamav-layer.zip` and upload to Lambda > Layers

---

### 2. 🧬 Lambda Virus Scanner Function

#### `scanner_function.py`

```python
import boto3, os, subprocess
from datetime import datetime

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('VirusScanLogs')
    sns = boto3.client('sns')

    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        download_path = f'/tmp/{key}'
        s3.download_file(bucket, key, download_path)

        result = subprocess.run(['/opt/clamav/bin/clamscan', download_path], capture_output=True, text=True)
        status = 'CLEAN' if "OK" in result.stdout else 'INFECTED'

        table.put_item(Item={
            'filename': key,
            'status': status,
            'timestamp': datetime.utcnow().isoformat()
        })

        sns.publish(
            TopicArn=os.environ['SNS_TOPIC_ARN'],
            Subject='Scan Result',
            Message=f'{key} is {status}'
        )

        target_bucket = os.environ['SAFE_BUCKET'] if status == 'CLEAN' else os.environ['QUARANTINE_BUCKET']
        s3.copy_object(Bucket=target_bucket, CopySource=f'{bucket}/{key}', Key=key)
        s3.delete_object(Bucket=bucket, Key=key)

    return {'statusCode': 200, 'body': 'Scan completed'}
```
