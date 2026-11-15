import os
from typing import Any
from urllib.parse import unquote_plus

import boto3

from filevet import Policy, scan

MAX_BYTES = 50 << 20
CLEAN = os.environ["CLEAN_BUCKET"]
QUARANTINE = os.environ["QUARANTINE_BUCKET"]
POLICY = Policy.load("strict")
s3 = boto3.client("s3")


def handler(event: dict[str, Any], context: object) -> None:
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        data = s3.get_object(Bucket=bucket, Key=key)["Body"].read(MAX_BYTES + 1)
        verdict = "block"
        if len(data) <= MAX_BYTES:
            verdict = scan(data, name=key.rsplit("/", 1)[-1], policy=POLICY).verdict
        target = CLEAN if verdict in {"pass", "pass_with_findings"} else QUARANTINE
        s3.copy_object(
            Bucket=target,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Tagging=f"filevet-verdict={verdict}",
            TaggingDirective="REPLACE",
        )
        s3.delete_object(Bucket=bucket, Key=key)
