"""
simulate_role_activity.py
Week 2: Assume each test role and make realistic API calls so CloudTrail
has event-level data to analyze.

Dormant roles are intentionally skipped — that's the signal we want to
detect later (permissions granted but never used).

Usage:
    python scripts/simulate_role_activity.py
"""

import boto3
import json
import time

ACCOUNT_ID = "385864241096"

# Each entry: (role_name, list of call functions to run as that role)
# Dormant roles are omitted on purpose.
ROLE_SCENARIOS = {
    "role-wildcard-admin": ["s3", "ec2", "iam", "sts"],
    "role-s3-wildcard": ["s3"],
    "role-sensitive-iam-star": ["iam"],
    "role-overprivileged-ec2": ["ec2"],
    "role-cross-account-sts": ["sts"],
    "role-tight-scoped": ["s3_readonly"],
    # role-dormant-iam and role-dormant-unused intentionally absent
}


def assume_role(role_name):
    sts = boto3.client("sts")
    arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"
    try:
        resp = sts.assume_role(RoleArn=arn, RoleSessionName="iam-sim")
        creds = resp["Credentials"]
        return {
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        }
    except Exception as e:
        print(f"    [!] Could not assume {role_name}: {e}")
        return None


def make_client(service, creds):
    return boto3.client(service, **creds)


def run_s3_calls(creds):
    s3 = make_client("s3", creds)
    calls = [
        ("ListBuckets", lambda: s3.list_buckets()),
        ("GetBucketLocation", lambda: s3.get_bucket_location(Bucket="non-existent-bucket-iam-sim-12345")),
        ("ListObjectsV2", lambda: s3.list_objects_v2(Bucket="non-existent-bucket-iam-sim-12345")),
        ("PutObject", lambda: s3.put_object(Bucket="non-existent-bucket-iam-sim-12345", Key="test.txt", Body=b"x")),
        ("DeleteObject", lambda: s3.delete_object(Bucket="non-existent-bucket-iam-sim-12345", Key="test.txt")),
    ]
    _run_calls(calls)


def run_s3_readonly_calls(creds):
    s3 = make_client("s3", creds)
    calls = [
        ("ListBuckets", lambda: s3.list_buckets()),
        ("GetObject", lambda: s3.get_object(Bucket="non-existent-bucket-iam-sim-12345", Key="readme.txt")),
    ]
    _run_calls(calls)


def run_ec2_calls(creds):
    ec2 = make_client("ec2", creds)
    calls = [
        ("DescribeInstances", lambda: ec2.describe_instances()),
        ("DescribeSecurityGroups", lambda: ec2.describe_security_groups()),
        ("DescribeVpcs", lambda: ec2.describe_vpcs()),
        ("DescribeSubnets", lambda: ec2.describe_subnets()),
        ("DescribeImages", lambda: ec2.describe_images(Owners=["self"])),
        ("DescribeKeyPairs", lambda: ec2.describe_key_pairs()),
        ("StopInstances", lambda: ec2.stop_instances(InstanceIds=["i-00000000000000000"])),
        ("TerminateInstances", lambda: ec2.terminate_instances(InstanceIds=["i-00000000000000000"])),
    ]
    _run_calls(calls)


def run_iam_calls(creds):
    iam = make_client("iam", creds)
    calls = [
        ("ListUsers", lambda: iam.list_users()),
        ("ListRoles", lambda: iam.list_roles()),
        ("ListPolicies", lambda: iam.list_policies(Scope="Local")),
        ("GetAccountSummary", lambda: iam.get_account_summary()),
        ("CreateRole", lambda: iam.create_role(
            RoleName="sim-test-role-delete-me",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )),
        ("DeleteRole", lambda: iam.delete_role(RoleName="sim-test-role-delete-me")),
    ]
    _run_calls(calls)


def run_sts_calls(creds):
    sts = make_client("sts", creds)
    calls = [
        ("GetCallerIdentity", lambda: sts.get_caller_identity()),
        ("GetSessionToken", lambda: sts.get_session_token()),
    ]
    _run_calls(calls)


def _run_calls(calls):
    for name, fn in calls:
        try:
            fn()
            print(f"      {name}: OK")
        except Exception as e:
            # Access denied / NoSuchBucket still generates a CloudTrail event — that's what we want.
            msg = str(e)
            short = msg.split(":")[-1].strip()[:80]
            print(f"      {name}: {short}")
        time.sleep(0.3)


CALL_MAP = {
    "s3": run_s3_calls,
    "s3_readonly": run_s3_readonly_calls,
    "ec2": run_ec2_calls,
    "iam": run_iam_calls,
    "sts": run_sts_calls,
}


def main():
    print("Starting role activity simulation...\n")
    for role_name, services in ROLE_SCENARIOS.items():
        print(f"[{role_name}]")
        creds = assume_role(role_name)
        if not creds:
            print("  Skipping (could not assume role)\n")
            continue
        for svc in services:
            print(f"  Running {svc} calls:")
            CALL_MAP[svc](creds)
        print()

    print("Done. CloudTrail events should appear within 5-10 minutes.")
    print("Run scripts/ingest_cloudtrail.py after that to pull them.")


if __name__ == "__main__":
    main()
