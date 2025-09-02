import json
import os
import boto3

s3 = boto3.client("s3")
sns = boto3.client("sns")

QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

def lambda_handler(event, context):
    # EventBridge passes Macie Finding detail; you can enrich this later.
    # This stub just proves wiring is correct.
    message = {
        "received": True,
        "records": event.get("detail", {}),
        "quarantine_bucket": QUARANTINE_BUCKET
    }

    # Example: publish a simple alert
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="Macie Finding (Medium/High) received",
        Message=json.dumps(message, default=str)
    )

    return {"statusCode": 200, "body": json.dumps(message)}
