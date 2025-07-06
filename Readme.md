# 🛡️ Secure File Upload System with Virus Scanning (AWS + ClamAV)

This project demonstrates a secure, serverless virus scanning system using AWS Lambda, ClamAV, S3, SNS, and DynamoDB — all built within the AWS Free Tier.

---

## 🚀 Project Objective

To build a virus-scanning pipeline where users upload files to an S3 bucket. On upload:

- 🧪 File is scanned by ClamAV in a Lambda function
- ✅ If clean → stored in a "safe" bucket
- ❌ If infected → moved to a "quarantine" bucket
- 📝 Metadata is logged in DynamoDB
- 🔔 Admin is notified via SNS

---

## 🧱 Architecture Diagram

```text
[S3 Upload Bucket] --> (Trigger) --> [Lambda + ClamAV Layer]
                                      ├── ClamAV Scan
                                      ├── Write to DynamoDB
                                      ├── Notify via SNS
                                      └── Move file to SAFE or QUARANTINE bucket
```

---

## 🛠️ Services Used

| Service     | Purpose |
|-------------|---------|
| EC2         | Build ClamAV binaries for Lambda layer |
| Lambda      | Runs ClamAV scan logic |
| S3          | File upload, safe, and quarantine buckets |
| DynamoDB    | Stores scan logs |
| SNS         | Sends email alerts |
| IAM         | Permissions for Lambda and access |
| Postman     | Manual API testing |

---

## 📦 Folder Structure

```
virus-scanner-project/
│
├── lambda/
│   ├── scanner_function.py
│   └── requirements.txt
│
├── layer/
│   └── clamav-layer.zip (built from EC2)
│
├── postman/
│   └── test-upload-collection.json
│
└── README.md
```

---

## 🏗️ Setup Steps (Detailed)

### ✅ 1. Build ClamAV Layer on EC2

1. Launch EC2: Amazon Linux 2 t2.micro (Free Tier)
2. Connect using Instance Connect or SSH:
   ```bash
   ssh -i your-key.pem ec2-user@<public-ip>
   ```

3. Install dependencies:
   ```bash
   sudo yum update -y
   sudo yum install gcc openssl-devel libcurl-devel zlib-devel cmake unzip wget -y
   ```

4. Download & compile ClamAV:
   ```bash
   mkdir clamav-layer && cd clamav-layer
   wget https://www.clamav.net/downloads/production/clamav-0.103.2.tar.gz
   tar -xvzf clamav-0.103.2.tar.gz
   cd clamav-0.103.2
   ./configure --prefix=$(pwd)/install_dir
   make -j2
   make install
   ```

5. Package layer:
   ```bash
   cd install_dir
   mkdir -p clamav/bin clamav/lib
   cp -r bin/* clamav/bin/
   cp -r lib/* clamav/lib/
   zip -r9 ../clamav-layer.zip clamav
   ```

6. Download zip to local system and upload it to:
   - **AWS Lambda > Layers > Create Layer**
   - Name: `python39-clamav`
   - Runtime: Python 3.9
   - Upload: `clamav-layer.zip`

---

### ✅ 2. Create Lambda Function

- Runtime: Python 3.9
- Attach Layer: `python39-clamav`
- Set Environment Variables:
  - `SAFE_BUCKET`: your-safe-bucket
  - `QUARANTINE_BUCKET`: your-quarantine-bucket
  - `SNS_TOPIC_ARN`: arn:aws:sns:...

- Permissions (IAM Role):
  - AmazonS3FullAccess
  - AmazonDynamoDBFullAccess
  - AmazonSNSFullAccess
  - AWSLambdaBasicExecutionRole

- Upload the function code: `scanner_function.py`

---

### ✅ 3. Lambda Function Code

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

        target = os.environ['SAFE_BUCKET'] if status == 'CLEAN' else os.environ['QUARANTINE_BUCKET']
        s3.copy_object(Bucket=target, CopySource=f'{bucket}/{key}', Key=key)
        s3.delete_object(Bucket=bucket, Key=key)

    return {'statusCode': 200, 'body': 'Scan complete'}
```

---

### ✅ 4. Create Buckets

- Upload Bucket: `virus-upload-bucket`
- Safe Bucket: `virus-safe-bucket`
- Quarantine Bucket: `virus-quarantine-bucket`

Enable event trigger on **upload bucket** to invoke Lambda on `PUT`.

---

### ✅ 5. Create DynamoDB Table

- Name: `VirusScanLogs`
- Primary Key: `filename` (String)

---

### ✅ 6. Create SNS Topic

- Name: `VirusScanAlerts`
- Subscribe your email.
- Use the topic ARN in Lambda env vars.

---

### ✅ 7. Testing

Use Postman or AWS CLI to upload a file:

```bash
aws s3 cp testfile.txt s3://virus-upload-bucket/
```

- ✅ Clean → see in safe bucket
- ❌ Infected → in quarantine bucket
- Check logs in DynamoDB
- Check email notification


---

## 🙋‍♀️ Built By

**Kosha Gohil**  
Cloud Support Associate | AWS Solutions Architect Associate | CompTIA Security+  


---

## 💡 What I Learned

- Built Lambda layer from scratch on EC2
- Integrated 6+ AWS services securely
- Debugged permissions, 502 errors, zip issues
- Understood full serverless pipeline for antivirus scanning
