hands-on **AWS Macie: PII Guardrail Project** you can drop into a repo and demo in an hour—includes **Terraform IaC**, **AWS CLI**, and a **Python Lambda** that quarantines risky objects and alerts via **SNS**.

```
terraform fmt
terraform init
terraform validate
terraform plan -var="email=atul_kamble@hotmail.com"
terraform apply -auto-approve -var="atul_kamble@hotmail.com"
```

---

# 🚨 Project: Macie PII Guardrail for S3

**Goal:**
Continuously scan an S3 bucket with **Amazon Macie** for sensitive data (PII, credentials, etc.).
On **Medium/High** findings, automatically:

* **Quarantine** the offending object to a separate bucket
* **Tag** it (`pii=quarantined`)
* **Notify** via **SNS (email)**

**Repo name suggestion:** `aws-macie-pii-guardrail`

## 🧱 Architecture (high level)

```
S3 (data bucket)  ──► Macie (classification job)
       │                          │
       └──────────── EventBridge (Macie Finding) ──► Lambda (quarantine + notify) ──► SNS (email)
                                                    │
                                                    └─► S3 (quarantine bucket)
```

---

## Prereqs

* AWS CLI v2 configured with admin/appropriate permissions
* Terraform ≥ 1.6, AWS provider ≥ 5.x
* Python 3.9+ (for Lambda packaging)
* One AWS Region (e.g., `us-east-1`)—Macie is regional

---

# Option A — Terraform (recommended)

> Creates: 3 S3 buckets, enables Macie, a continuous classification job, findings export, SNS topic+subscription, Lambda, EventBridge rule, and IAM roles/policies.

### 1) Files & Structure

```
aws-macie-pii-guardrail/
├─ terraform/
│  ├─ main.tf
│  ├─ variables.tf
│  ├─ outputs.tf
├─ lambda/
│  ├─ handler.py
│  └─ requirements.txt
└─ README.md
```

### 2) `terraform/variables.tf`

```hcl
variable "region" { type = string, default = "us-east-1" }
variable "project" { type = string, default = "macie-pii-guardrail" }
variable "email"   { type = string } # SNS subscription email
```

### 3) `terraform/main.tf`

```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  suffix = substr(md5(var.project), 0, 6)
}

# Buckets
resource "aws_s3_bucket" "data" {
  bucket = "${var.project}-data-${local.suffix}"
}

resource "aws_s3_bucket" "quarantine" {
  bucket = "${var.project}-quarantine-${local.suffix}"
}

resource "aws_s3_bucket" "findings" {
  bucket = "${var.project}-findings-${local.suffix}"
}

# Enable Macie in account/region
resource "aws_macie2_account" "this" {}

# Export Macie findings (full findings JSON) to S3
resource "aws_macie2_classification_export_configuration" "export" {
  configuration {
    s3_destination {
      bucket_name   = aws_s3_bucket.findings.bucket
      key_prefix    = "macie-findings"
      kms_key_arn   = null
    }
  }
}

# Macie Classification Job (continuous)
resource "aws_macie2_classification_job" "job" {
  job_type      = "SCHEDULED"
  name          = "${var.project}-job"
  schedule_frequency {
    daily_schedule {}
  }

  sampling_percentage = 100

  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.me.account_id
      buckets    = [aws_s3_bucket.data.bucket]
    }
    scoping {} # scan all objects
  }

  depends_on = [aws_macie2_account.this]
}

data "aws_caller_identity" "me" {}

# SNS Topic + subscription
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.email
}

# IAM for Lambda
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect = "Allow"
    principals { type = "Service", identifiers = ["lambda.amazonaws.com"] }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "${var.project}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Permissions: S3 (get/copy/put/delete), logs, SNS publish
data "aws_iam_policy_document" "lambda_policy" {
  statement {
    actions = [
      "s3:GetObject", "s3:PutObjectTagging", "s3:PutObject", "s3:DeleteObject",
      "s3:CopyObject", "s3:GetBucketLocation", "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*",
      aws_s3_bucket.quarantine.arn, "${aws_s3_bucket.quarantine.arn}/*"
    ]
  }
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_policy" "lambda_policy" {
  name   = "${var.project}-lambda-policy"
  policy = data.aws_iam_policy_document.lambda_policy.json
}
resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Package Lambda
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/../lambda/lambda.zip"
}

resource "aws_lambda_function" "quarantine" {
  function_name    = "${var.project}-quarantine"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  timeout          = 30
  environment {
    variables = {
      QUARANTINE_BUCKET = aws_s3_bucket.quarantine.bucket
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
    }
  }
}

# EventBridge rule for Macie Findings
resource "aws_cloudwatch_event_rule" "macie_findings" {
  name        = "${var.project}-macie-findings"
  description = "Route Medium/High Macie findings to Lambda"
  event_pattern = jsonencode({
    "source": ["aws.macie"],
    "detail-type": ["Macie Finding"],
    "detail": {
      "severity": { "description": ["Medium", "High"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "to_lambda" {
  rule      = aws_cloudwatch_event_rule.macie_findings.name
  target_id = "macie-lambda"
  arn       = aws_lambda_function.quarantine.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.quarantine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.macie_findings.arn
}
```

### 4) `terraform/outputs.tf`

```hcl
output "data_bucket"       { value = aws_s3_bucket.data.bucket }
output "quarantine_bucket" { value = aws_s3_bucket.quarantine.bucket }
output "findings_bucket"   { value = aws_s3_bucket.findings.bucket }
output "sns_topic_arn"     { value = aws_sns_topic.alerts.arn }
output "lambda_name"       { value = aws_lambda_function.quarantine.function_name }
output "macie_job_name"    { value = aws_macie2_classification_job.job.name }
```

### 5) `lambda/handler.py`

```python
import json, os, boto3, urllib.parse

s3 = boto3.client("s3")
sns = boto3.client("sns")

QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
SNS_TOPIC_ARN     = os.environ["SNS_TOPIC_ARN"]

def lambda_handler(event, context):
    # EventBridge passes 'detail' with the Macie finding
    detail = event.get("detail", {})
    title  = detail.get("title", "Macie Finding")
    severity = detail.get("severity", {}).get("description", "Unknown")
    finding_type = detail.get("type", "UnknownType")

    # Extract S3 object info from the finding
    res = detail.get("resourcesAffected", {})
    s3obj = res.get("s3Object", {})
    bucket = s3obj.get("bucketName")
    key    = s3obj.get("key")
    if not (bucket and key):
        # Some findings are bucket-level. Skip if no object key.
        print("No object-level resource in finding; nothing to quarantine.")
        return {"status": "skipped"}

    # Decode URL-encoded keys if any
    key = urllib.parse.unquote_plus(key)

    quarantine_key = f"quarantined/{key}"

    # Copy object to quarantine bucket
    s3.copy_object(
        Bucket=QUARANTINE_BUCKET,
        Key=quarantine_key,
        CopySource={"Bucket": bucket, "Key": key},
        MetadataDirective="REPLACE",
        Metadata={"macie_finding": finding_type, "severity": severity}
    )

    # Tag the original object
    s3.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={"TagSet": [{"Key":"pii","Value":"quarantined"}]}
    )

    # (Optional) Delete original to prevent access
    # s3.delete_object(Bucket=bucket, Key=key)

    # Notify by SNS
    msg = {
        "title": title,
        "severity": severity,
        "finding_type": finding_type,
        "original_bucket": bucket,
        "original_key": key,
        "quarantine_bucket": QUARANTINE_BUCKET,
        "quarantine_key": quarantine_key
    }
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[Macie] {severity} finding: {title}",
        Message=json.dumps(msg, indent=2)
    )

    return {"status": "quarantined", "message": msg}
```

### 6) `lambda/requirements.txt`

```
boto3
```

### 7) Deploy

```bash
cd aws-macie-pii-guardrail/terraform

# Set your email for alerts
terraform init
terraform apply -var="email=you@example.com" -auto-approve
```

> Confirm the **SNS subscription** from your email before testing.

### 8) Test

Upload a file with fake PII to the **data bucket** (from outputs):

```bash
DATA_BUCKET=$(terraform output -raw data_bucket)
echo "CC: 4111-1111-1111-1111\nSSN: 123-45-6789" > pii.txt
aws s3 cp pii.txt s3://$DATA_BUCKET/demo/pii.txt
```

Macie’s scheduled job will pick it up (daily). For quicker tests, you can:

* Change the job to **one-time** or trigger **Run Classification Job** from Console
* Or temporarily set a **shorter schedule** (Macie supports Daily/Weekly/Monthly).
  Once a finding occurs, the Lambda should **copy to quarantine**, **tag original**, and **send SNS email**.

---

# Option B — Pure AWS CLI (quick path)

> Good for workshops/live demos without Terraform.

### 1) Buckets

```bash
REGION=us-east-1
PROJECT=macie-pii-guardrail
SUFFIX=$(openssl rand -hex 3)

DATA_BUCKET=${PROJECT}-data-${SUFFIX}
QUAR_BUCKET=${PROJECT}-quarantine-${SUFFIX}
FIND_BUCKET=${PROJECT}-findings-${SUFFIX}

aws s3api create-bucket --bucket $DATA_BUCKET --region $REGION --create-bucket-configuration LocationConstraint=$REGION
aws s3api create-bucket --bucket $QUAR_BUCKET --region $REGION --create-bucket-configuration LocationConstraint=$REGION
aws s3api create-bucket --bucket $FIND_BUCKET --region $REGION --create-bucket-configuration LocationConstraint=$REGION
```

### 2) Enable Macie + Findings export

```bash
aws macie2 enable-macie --status ENABLED --finding-publishing-frequency FIFTEEN_MINUTES

aws macie2 put-classification-export-configuration --configuration '{
  "s3Destination": {
    "bucketName": "'$FIND_BUCKET'",
    "keyPrefix": "macie-findings"
  }
}'
```

### 3) Create a classification job (daily)

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws macie2 create-classification-job --name "$PROJECT-job" --job-type SCHEDULED \
  --s3-job-definition '{
    "bucketDefinitions":[{"accountId":"'"$ACCOUNT_ID"'","buckets":["'"$DATA_BUCKET"'"]}]
  }' \
  --schedule-frequency '{"dailySchedule":{}}' \
  --sampling-percentage 100
```

### 4) SNS + subscription

```bash
TOPIC_ARN=$(aws sns create-topic --name ${PROJECT}-alerts --query TopicArn --output text)
aws sns subscribe --topic-arn $TOPIC_ARN --protocol email --notification-endpoint you@example.com
echo "Check your email and confirm the SNS subscription."
```

### 5) Lambda role & policy

```bash
aws iam create-role --role-name ${PROJECT}-lambda-role \
  --assume-role-policy-document '{
    "Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }'

cat > lambda-policy.json <<'POLICY'
{
  "Version":"2012-10-17",
  "Statement":[
    {"Effect":"Allow","Action":["s3:GetObject","s3:PutObjectTagging","s3:PutObject","s3:DeleteObject","s3:CopyObject","s3:GetBucketLocation","s3:ListBucket"],"Resource":"*"},
    {"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"},
    {"Effect":"Allow","Action":["sns:Publish"],"Resource":"*"}
  ]
}
POLICY

aws iam put-role-policy --role-name ${PROJECT}-lambda-role --policy-name ${PROJECT}-lambda-inline --policy-document file://lambda-policy.json
```

### 6) Package & deploy Lambda

```bash
mkdir -p lambda && cd lambda
cat > handler.py <<'PY'
# (paste the same handler.py from Terraform section)
PY
echo "boto3" > requirements.txt
pip3 install -r requirements.txt -t .
zip -r ../lambda.zip .
cd ..

aws lambda create-function \
  --function-name ${PROJECT}-quarantine \
  --runtime python3.12 \
  --handler handler.lambda_handler \
  --role arn:aws:iam::${ACCOUNT_ID}:role/${PROJECT}-lambda-role \
  --zip-file fileb://lambda.zip \
  --timeout 30 \
  --environment "Variables={QUARANTINE_BUCKET=${QUAR_BUCKET},SNS_TOPIC_ARN=${TOPIC_ARN}}"
```

### 7) EventBridge rule ➜ Lambda

```bash
aws events put-rule --name ${PROJECT}-macie-findings \
  --event-pattern '{
    "source": ["aws.macie"],
    "detail-type": ["Macie Finding"],
    "detail": { "severity": { "description": ["Medium","High"] } }
  }'

aws lambda add-permission \
  --function-name ${PROJECT}-quarantine \
  --statement-id AllowEventBridgeInvoke \
  --action "lambda:InvokeFunction" \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${PROJECT}-macie-findings

aws events put-targets --rule ${PROJECT}-macie-findings --targets "Id"="1","Arn"="$(aws lambda get-function --function-name ${PROJECT}-quarantine --query 'Configuration.FunctionArn' --output text)"
```

### 8) Test upload

```bash
echo "email john@example.com, cc 4111-1111-1111-1111" > sample.txt
aws s3 cp sample.txt s3://$DATA_BUCKET/demo/sample.txt
```

---

## 🔧 Notes & Tips

* **Data identifiers:** Macie uses **managed data identifiers** by default (no extra config needed). For custom regex (e.g., PAN numbers), you can add **custom data identifiers** and re-run jobs.
* **Bucket-level findings:** Some findings are bucket-wide (policy, public access). The Lambda skips when no `key` is present.
* **Delete original?** The code leaves a commented `DeleteObject`—enable only after validating your workflow.
* **Costs:** Macie charges per object/classification. Use small test files and clean up after the demo.
* **Cleanup:** `terraform destroy` or reverse CLI steps. Also **disable Macie** if no longer needed:

  ```bash
  aws macie2 disable-macie
  ```

---

If you want, I can spin this into a polished **README** with screenshots and a **GitHub Actions workflow** to plan/apply Terraform automatically.
