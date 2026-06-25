"""
inventory_iam_roles.py

Week 1 deliverable: pulls every IAM role in the account, along with all
inline and attached managed policies, parses out the granted permissions,
and saves a clean structured JSON inventory to data/iam_inventory.json.

This is the foundation dataset that later scripts (CloudTrail usage cross-
reference, risk scoring, policy generation) will build on top of.

Usage:
    python scripts/inventory_iam_roles.py
"""

import boto3
import json
import os
from datetime import datetime, timezone

iam = boto3.client("iam")

OUTPUT_PATH = os.path.join("data", "iam_inventory.json")


def get_inline_policies(role_name):
    """Return a list of {policy_name, document} for all inline policies on a role."""
    policies = []
    paginator = iam.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for policy_name in page["PolicyNames"]:
            response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            policies.append(
                {
                    "policy_name": policy_name,
                    "policy_type": "inline",
                    "document": response["PolicyDocument"],
                }
            )
    return policies


def get_attached_managed_policies(role_name):
    """Return a list of {policy_name, document} for all attached managed policies on a role."""
    policies = []
    paginator = iam.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for attached in page["AttachedPolicies"]:
            policy_arn = attached["PolicyArn"]
            policy_meta = iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy_meta["DefaultVersionId"]
            version = iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            policies.append(
                {
                    "policy_name": attached["PolicyName"],
                    "policy_type": "managed",
                    "policy_arn": policy_arn,
                    "document": version["PolicyVersion"]["Document"],
                }
            )
    return policies


def extract_permissions(policy_document):
    """
    Flatten a policy document's Statement block into a list of
    {effect, actions, resources, has_wildcard_action, has_wildcard_resource}.
    Handles Action/Resource being either a single string or a list.
    """
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    extracted = []
    for stmt in statements:
        effect = stmt.get("Effect", "Unknown")

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_action = any(a == "*" or a.endswith(":*") for a in actions)
        has_wildcard_resource = any(r == "*" for r in resources)

        extracted.append(
            {
                "effect": effect,
                "actions": actions,
                "resources": resources,
                "has_wildcard_action": has_wildcard_action,
                "has_wildcard_resource": has_wildcard_resource,
            }
        )
    return extracted


def inventory_role(role):
    role_name = role["RoleName"]
    print(f"  -> inventorying {role_name}")

    inline = get_inline_policies(role_name)
    managed = get_attached_managed_policies(role_name)
    all_policies = inline + managed

    permissions = []
    for policy in all_policies:
        stmt_perms = extract_permissions(policy["document"])
        for p in stmt_perms:
            p["source_policy"] = policy["policy_name"]
            p["policy_type"] = policy["policy_type"]
            permissions.append(p)

    return {
        "role_name": role_name,
        "role_arn": role["Arn"],
        "create_date": role["CreateDate"].isoformat(),
        "policy_count": len(all_policies),
        "policies": all_policies,
        "permissions": permissions,
        "has_any_wildcard_action": any(p["has_wildcard_action"] for p in permissions),
        "has_any_wildcard_resource": any(
            p["has_wildcard_resource"] for p in permissions
        ),
    }


def main():
    print("Pulling all IAM roles in the account...")
    all_roles = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        all_roles.extend(page["Roles"])

    print(f"Found {len(all_roles)} total roles. Inventorying each...\n")

    inventory = []
    for role in all_roles:
        # Skip AWS service-linked roles - they clutter the dataset and
        # aren't relevant to a least-privilege analysis of YOUR roles.
        if role["Path"].startswith("/aws-service-role/"):
            continue
        inventory.append(inventory_role(role))

    os.makedirs("data", exist_ok=True)
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": boto3.client("sts").get_caller_identity()["Account"],
        "role_count": len(inventory),
        "roles": inventory,
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nDone. Inventoried {len(inventory)} roles.")
    print(f"Saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
