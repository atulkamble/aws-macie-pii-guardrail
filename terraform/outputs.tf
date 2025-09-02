output "data_bucket" {
  value       = aws_s3_bucket.data.bucket
  description = "Source data bucket scanned by Macie"
}

output "quarantine_bucket" {
  value       = aws_s3_bucket.quarantine.bucket
  description = "Bucket where offending objects are moved"
}

output "findings_bucket" {
  value       = aws_s3_bucket.findings.bucket
  description = "Bucket receiving exported Macie findings"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.alerts.arn
  description = "SNS topic for alerts"
}

output "lambda_name" {
  value       = aws_lambda_function.quarantine.function_name
  description = "Quarantine Lambda function name"
}

output "macie_job_name" {
  value       = aws_macie2_classification_job.job.name
  description = "Macie classification job name"
}

