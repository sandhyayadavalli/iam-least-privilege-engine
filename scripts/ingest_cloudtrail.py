"""
ingest_cloudtrail.py
Week 2: Pull raw CloudTrail events for our test roles and normalize them
into IAM action format (e.g. GetObject -> s3:GetObject).

Saves: data/cloudtrail_events.json
Usage: python3 scripts/ingest_cloudtrail.py
"""

import boto3
import json
import os
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = os.path.join("data", "cloudtrail_events.json")
INVENTORY_PATH = os.path.join("data", "iam_inventory.json")

# How far back to look (CloudTrail lookup_events max is 90 days)
LOOKBACK_DAYS = 90

# Maps CloudTrail eventSource -> IAM action prefix
# e.g. "s3.amazonaws.com" -> "s3"
EVENT_SOURCE_TO_PREFIX = {
    "s3.amazonaws.com": "s3",
    "ec2.amazonaws.com": "ec2",
    "iam.amazonaws.com": "iam",
    "sts.amazonaws.com": "sts",
    "kms.amazonaws.com": "kms",
    "lambda.amazonaws.com": "lambda",
    "dynamodb.amazonaws.com": "dynamodb",
    "rds.amazonaws.com": "rds",
    "sns.amazonaws.com": "sns",
    "sqs.amazonaws.com": "sqs",
    "logs.amazonaws.com": "logs",
    "cloudtrail.amazonaws.com": "cloudtrail",
    "secretsmanager.amazonaws.com": "secretsmanager",
    "ssm.amazonaws.com": "ssm",
}

# A handful of known exceptions where eventName doesn't map cleanly to IAM action
# Format: (eventSource, eventName) -> iam_action
KNOWN_OVERRIDES = {
    ("s3.amazonaws.com", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3.amazonaws.com", "HeadBucket"): "s3:ListBucket",
    ("s3.amazonaws.com", "HeadObject"): "s3:GetObject",
    ("iam.amazonaws.com", "GetAccountPasswordPolicy"): "iam:GetAccountPasswordPolicy",
}


def load_test_role_arns():
    """Load the set of test role ARNs from the inventory file."""
    with open(INVENTORY_PATH) as f:
        inventory = json.load(f)
    return {r["role_arn"] for r in inventory["roles"]}


def event_to_iam_action(event):
    """
    Convert a CloudTrail event to an IAM action string.
    Returns None if we can't map it (e.g. unknown event source).
    """
    source = event.get("EventSource", "")
    name = event.get("EventName", "")

    override = KNOWN_OVERRIDES.get((source, name))
    if override:
        return override

    prefix = EVENT_SOURCE_TO_PREFIX.get(source)
    if not prefix:
        return None

    return f"{prefix}:{name}"


def extract_resource(event):
    """Pull the first meaningful resource ARN from the event, if present."""
    resources = event.get("Resources") or []
    for r in resources:
        arn = r.get("ARN", "")
        if arn and arn != "Unknown":
            return arn
    return None


def get_assumed_role_arn(event):
    """
    Extract the role ARN from the userIdentity of the event.
    For assumed-role sessions the ARN looks like:
      arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME
    We convert it back to the IAM role ARN format.
    """
    raw = event.get("CloudTrailEvent")
    if not raw:
        return None
    try:
        detail = json.loads(raw)
        identity = detail.get("userIdentity", {})
        if identity.get("type") != "AssumedRole":
            return None
        # arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION
        arn = identity.get("arn", "")
        # Convert to IAM role ARN
        # assumed-role/ROLE_NAME/SESSION -> role/ROLE_NAME
        if ":assumed-role/" in arn:
            parts = arn.split(":assumed-role/")
            account_part = parts[0]  # arn:aws:sts::ACCOUNT
            role_and_session = parts[1].rsplit("/", 1)[0]  # ROLE_NAME
            account_id = account_part.split(":")[-1]
            return f"arn:aws:iam::{account_id}:role/{role_and_session}"
    except Exception:
        pass
    return None


def pull_events(test_role_arns):
    client = boto3.client("cloudtrail")
    start_time = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)

    print(f"Pulling CloudTrail events from the last {LOOKBACK_DAYS} days...")

    all_events = []
    paginator = client.get_paginator("lookup_events")
    pages = paginator.paginate(
        StartTime=start_time,
        PaginationConfig={"PageSize": 50},
    )

    for page in pages:
        for event in page.get("Events", []):
            role_arn = get_assumed_role_arn(event)
            if role_arn not in test_role_arns:
                continue

            iam_action = event_to_iam_action(event)
            if not iam_action:
                continue

            all_events.append({
                "role_arn": role_arn,
                "role_name": role_arn.split("/")[-1],
                "iam_action": iam_action,
                "event_name": event.get("EventName"),
                "event_source": event.get("EventSource"),
                "timestamp": event.get("EventTime").isoformat(),
                "resource": extract_resource(event),
                "event_id": event.get("EventId"),
            })

    return all_events


def main():
    test_role_arns = load_test_role_arns()
    print(f"Watching {len(test_role_arns)} test roles.\n")

    events = pull_events(test_role_arns)

    os.makedirs("data", exist_ok=True)
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "events": events,
    }
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nFound {len(events)} events across your test roles.")

    # Summary per role
    from collections import defaultdict
    by_role = defaultdict(list)
    for e in events:
        by_role[e["role_name"]].append(e["iam_action"])

    print("\nEvents per role:")
    for role, actions in sorted(by_role.items()):
        print(f"  {role}: {len(actions)} events")
        for a in sorted(set(actions)):
            print(f"    - {a}")

    print(f"\nSaved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
