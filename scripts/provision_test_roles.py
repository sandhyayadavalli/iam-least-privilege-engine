"""
provision_test_roles.py

Provisions a deliberately varied set of IAM roles in a sandbox AWS account,
designed to simulate a realistic mix of overprivileged, dormant, tightly-scoped,
and sensitive roles for the IAM Least-Privilege Automation Engine project.

Run this ONCE to set up your test dataset. Re-running is safe — it skips
roles that already exist.

IMPORTANT: Only run this against a sandbox/personal AWS account you control.
Never run this kind of provisioning script against a production or shared account.
"""

import boto3
import json
import time
from botocore.exceptions import ClientError

iam = boto3.client("iam")
sts = boto3.client("sts")

ACCOUNT_ID = sts.get_caller_identity()["Account"]

# Trust policy: allows YOUR OWN account's users/roles to assume each test role.
# This lets you later call sts:assume-role to generate realistic CloudTrail activity.
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
            "Action": "sts:AssumeRole",
        }
    ],
}

# Each entry: role name, description, and the inline policy document attached to it.
ROLE_DEFINITIONS = [
    {
        "name": "role-wildcard-admin",
        "description": "Worst-case pattern: full wildcard action and resource.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
    },
    {
        "name": "role-s3-wildcard",
        "description": "Wildcard within a single service (all S3 actions, all buckets).",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        },
    },
    {
        "name": "role-overprivileged-ec2",
        "description": "Broad EC2 access granted, but only DescribeInstances will ever be used.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}],
        },
    },
    {
        "name": "role-tight-scoped",
        "description": "Tightly scoped baseline: only s3:GetObject on one bucket.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::iam-project-test-bucket/*",
                }
            ],
        },
    },
    {
        "name": "role-dormant-unused",
        "description": "Has permissions but will never be invoked - pure dormancy case.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
                    "Resource": "*",
                }
            ],
        },
    },
    {
        "name": "role-dormant-iam",
        "description": "Has IAM read permissions, never used - another dormant case.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:ListUsers", "iam:ListRoles"],
                    "Resource": "*",
                }
            ],
        },
    },
    {
        "name": "role-sensitive-iam-star",
        "description": "Dangerous pattern: full IAM wildcard. Should be flagged regardless of usage.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
        },
    },
    {
        "name": "role-cross-account-sts",
        "description": "Risky cross-account trust pattern: AssumeRole on all resources.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
            ],
        },
    },
]


def create_role(role_def):
    role_name = role_def["name"]
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
            Description=role_def["description"],
            Tags=[{"Key": "Project", "Value": "iam-least-privilege-engine"}],
        )
        print(f"[CREATED] {role_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"[SKIPPED] {role_name} already exists")
        else:
            print(f"[ERROR] Failed to create {role_name}: {e}")
            return

    # Attach the inline policy regardless (safe to re-run / update)
    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps(role_def["policy"]),
        )
        print(f"  -> attached inline policy '{role_name}-policy'")
    except ClientError as e:
        print(f"  -> [ERROR] failed to attach policy to {role_name}: {e}")


def main():
    print(f"Provisioning test IAM roles in account {ACCOUNT_ID}...\n")
    for role_def in ROLE_DEFINITIONS:
        create_role(role_def)
        time.sleep(1)  # small delay to avoid throttling
    print("\nDone. Run 'aws iam list-roles' or check the IAM console to verify.")


if __name__ == "__main__":
    main()
