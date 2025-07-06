# 🛡️ Secure File Upload System with Virus Scanning (AWS + ClamAV)

This project demonstrates a secure, serverless virus scanning system using AWS Lambda, ClamAV, S3, SNS, and DynamoDB — all built within the AWS Free Tier.

---

## 🚀 Project Objective

To build a virus-scanning system where users can upload files to an S3 bucket. The file is automatically scanned by ClamAV running in a Lambda function, and:

- ✅ If clean: stored in a “safe files” S3 bucket.
- ❌ If infected: moved to a quarantine bucket.
- 📝 Metadata is logged in DynamoDB.
- 🔔 Notifications sent via SNS.

---

## 🧱 Architecture Overview

- **S3 Buckets**: 
  - `incoming-uploads`: where users upload files.
  - `safe-files`: clean files are moved here.
  - `quarantine-files`: infected files go here.

- **Lambda Function**: 
  - Triggered by S3 event on file upload.
  - Downloads and scans the file using ClamAV.
  - Logs the result to DynamoDB.
  - Publishes result to SNS topic.
  - Moves file to appropriate bucket.

- **ClamAV Layer**: Custom-built and zipped on EC2 (Amazon Linux 2).

- **SNS**: Sends notifications on file scan results.

- **DynamoDB**: Stores logs for each file scanned.

---

## 🛠️ Technologies Used

| Service     | Purpose |
|-------------|---------|
| S3          | File storage |
| Lambda      | Execute scan logic |
| ClamAV      | Antivirus engine |
| DynamoDB    | Metadata logs |
| SNS         | Notifications |
| IAM         | Security roles |
| EC2         | Building ClamAV Layer |

---

## 📂 Folder Structure

```
secure-virus-scanner/
├── lambda/
│   ├── scanner_function.py
│   └── requirements.txt
├── layer/
│   └── clamav-layer.zip
├── postman/
│   └── test-upload-collection.json
└── README.md
```

---

## 📦 Full Setup Instructions

### ✅ Step 1: Create S3 Buckets
- Create three buckets:
  - `incoming-uploads`
  - `safe-files`
  - `quarantine-files`

### ✅ Step 2: Create DynamoDB Table
- Name: `VirusScanLogs`
- Primary key: `filename` (String)

### ✅ Step 3: Create SNS Topic
- Create a new topic.
- Add email subscription to receive scan results.
- Copy the **Topic ARN**.

### ✅ Step 4: Build ClamAV Layer on EC2
1. Launch EC2 (Amazon Linux 2)
2. SSH and install dependencies:

```bash
sudo yum update -y
sudo yum install gcc openssl-devel libcurl-devel zlib-devel cmake unzip -y
```

3. Download and compile ClamAV:

```bash
mkdir clamav-layer && cd clamav-layer
wget https://www.clamav.net/downloads/production/clamav-0.103.2.tar.gz
tar -xvzf clamav-0.103.2.tar.gz
cd clamav-0.103.2
./configure --prefix=$(pwd)/install_dir
make -j2
make install
```

4. Package the layer:

```bash
cd install_dir
mkdir -p clamav/lib clamav/bin
cp -r lib/* clamav/lib/
cp -r bin/* clamav/bin/
zip -r9 ../clamav-layer.zip clamav
```

5. Download the ZIP to your local machine.
6. Go to Lambda > Layers > Create Layer.
7. Upload ZIP and set compatible runtimes to Python 3.9.

---

### ✅ Step 5: Create IAM Role for Lambda
- Attach permissions:
  - `AmazonS3FullAccess`
  - `AmazonDynamoDBFullAccess`
  - `AmazonSNSFullAccess`
  - `AWSLambdaBasicExecutionRole`

---

### ✅ Step 6: Create Lambda Function
- Runtime: Python 3.9
- Upload `scanner_function.py`
- Attach the IAM role created earlier.
- Attach the ClamAV Lambda Layer you uploaded.
- Set the following environment variables:

```txt
SNS_TOPIC_ARN = <your-topic-arn>
SAFE_BUCKET = safe-files
QUARANTINE_BUCKET = quarantine-files
```

- Create an S3 trigger:
  - Source: `incoming-uploads`
  - Event type: PUT
  - Prefix: (leave blank)
  - Suffix: (e.g., `.zip` or leave blank for all files)

---

### ✅ Step 7: Lambda Code

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

---

## 🧪 Testing
- Use Postman or AWS CLI to upload test files to the `incoming-uploads` bucket.
- Monitor CloudWatch logs and verify:
  - Files moved to the correct bucket.
  - Scan logs written to DynamoDB.
  - Email notification is received.

---

## 🧹 Cleanup
- Delete EC2, S3 buckets, Lambda, DynamoDB, and SNS to avoid charges.

---

## 📧 Contact
Made with ❤️ by [YourName] – Reach out if you have questions!
