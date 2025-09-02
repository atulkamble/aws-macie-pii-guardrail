terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  suffix = substr(md5(var.project), 0, 6)
}

# -------------------
# S3 Buckets
# -------------------
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
      bucket_name = aws_s3_bucket.findings.bucket
      key_prefix  = "macie-findings"
      kms_key_arn = null
    }
  }
}

data "aws_caller_identity" "me" {}

# -------------------
# Macie Classification Job (daily scan)
# -------------------
resource "aws_macie2_classification_job" "job" {
  job_type = "SCHEDULED"
  name     = "${var.project}-job"

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

# -------------------
# SNS Topic + email subscription (you must confirm the email)
# -------------------
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.email
}

# -------------------
# IAM for Lambda
# -------------------
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "${var.project}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Permissions: S3 (get/put/delete), logs, SNS publish
data "aws_iam_policy_document" "lambda_policy" {
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObjectTagging",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:GetBucketLocation",
      "s3:ListBucket"
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

# -------------------
# Package & Create Lambda
# -------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/../lambda/lambda.zip"
}

resource "aws_lambda_function" "quarantine" {
  function_name = "${var.project}-quarantine"
  role          = aws_iam_role.lambda_role.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  filename      = data.archive_file.lambda_zip.output_path
  timeout       = 30

  environment {
    variables = {
      QUARANTINE_BUCKET = aws_s3_bucket.quarantine.bucket
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
    }
  }
}

# -------------------
# EventBridge: Macie Findings (Medium/High) -> Lambda
# -------------------
resource "aws_cloudwatch_event_rule" "macie_findings" {
  name        = "${var.project}-macie-findings"
  description = "Route Medium/High Macie findings to Lambda"

  event_pattern = jsonencode({
    source        = ["aws.macie"]
    "detail-type" = ["Macie Finding"]
    detail = {
      severity = { description = ["Medium", "High"] }
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
