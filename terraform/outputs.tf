output "data_bucket"       { value = aws_s3_bucket.data.bucket }
output "quarantine_bucket" { value = aws_s3_bucket.quarantine.bucket }
output "findings_bucket"   { value = aws_s3_bucket.findings.bucket }
output "sns_topic_arn"     { value = aws_sns_topic.alerts.arn }
output "lambda_name"       { value = aws_lambda_function.quarantine.function_name }
output "macie_job_name"    { value = aws_macie2_classification_job.job.name }
