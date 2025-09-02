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
