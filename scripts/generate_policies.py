"""
generate_policies.py
Week 4: Auto-generate tightened IAM policy JSON per role based only on
actions actually observed in CloudTrail.

Inputs:
  data/risk_scores.json   - used_actions and granted_actions per role

Output:
  data/policies/<role_name>.json   - least-privilege policy per role
  data/policies/summary.json       - summary of reduction per role

Usage: python3 scripts/generate_policies.py
"""

import json
import os
from datetime import datetime, timezone

SCORES_PATH = os.path.join("data", "risk_scores.json")
POLICIES_DIR = os.path.join("data", "policies")


def group_actions_by_service(actions):
    """Group a flat list of iam actions into {service: [actions]} dict."""
    grouped = {}
    for action in sorted(actions):
        if ":" not in action:
            continue
        service, _ = action.split(":", 1)
        grouped.setdefault(service, []).append(action)
    return grouped


def build_policy(role):
    """
    Build a least-privilege IAM policy document using only the actions
    actually observed in CloudTrail. Dormant roles get an explicit deny-all.
    """
    used_actions = role.get("used_actions", [])
    is_dormant = role.get("is_dormant", False)

    if is_dormant or not used_actions:
        # No observed usage — generate a policy with no permissions
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyAll",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {},
                }
            ],
        }

    # Group actions by service for cleaner policy statements
    by_service = group_actions_by_service(used_actions)

    statements = []
    for service, actions in sorted(by_service.items()):
        statements.append(
            {
                "Sid": f"Allow{service.capitalize()}UsedActions",
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": "*",
            }
        )

    return {"Version": "2012-10-17", "Statement": statements}


def compute_reduction(role):
    granted = role.get("granted_action_count", 0)
    used = role.get("used_action_count", 0)
    wildcard_grants = role.get("wildcard_grants", [])

    if wildcard_grants:
        # Wildcards grant unlimited actions — reduction is conceptually massive
        reduction_pct = 99.0
        note = f"Had wildcard grants {wildcard_grants} — reduced to {used} specific actions"
    elif granted == 0:
        reduction_pct = 0.0
        note = "No granted actions found"
    else:
        reduction_pct = round((1 - used / granted) * 100, 1)
        note = f"Reduced from {granted} granted to {used} used actions"

    return reduction_pct, note


def main():
    with open(SCORES_PATH) as f:
        data = json.load(f)

    os.makedirs(POLICIES_DIR, exist_ok=True)

    summary = []
    print(f"\n{'ROLE':<30} {'RISK':<8} {'USED ACTIONS':>12}  REDUCTION")
    print("=" * 70)

    for role in data["roles"]:
        role_name = role["role_name"]
        policy = build_policy(role)
        policy_path = os.path.join(POLICIES_DIR, f"{role_name}.json")

        with open(policy_path, "w") as f:
            json.dump(policy, f, indent=2)

        reduction_pct, note = compute_reduction(role)

        summary.append(
            {
                "role_name": role_name,
                "role_arn": role["role_arn"],
                "risk_level": role["risk_level"],
                "risk_score": role["risk_score"],
                "granted_action_count": role["granted_action_count"],
                "used_action_count": role["used_action_count"],
                "reduction_pct": reduction_pct,
                "is_dormant": role["is_dormant"],
                "note": note,
                "policy_file": policy_path,
            }
        )

        used = role["used_action_count"]
        level = role["risk_level"]
        dormant_tag = " [DORMANT]" if role["is_dormant"] else ""
        print(
            f"{role_name:<30} {level:<8} {used:>12}  -{reduction_pct:.0f}%{dormant_tag}"
        )

    summary_path = os.path.join(POLICIES_DIR, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(
            {"generated_at": datetime.now(timezone.utc).isoformat(), "roles": summary},
            f,
            indent=2,
        )

    print("=" * 70)
    print(f"\nPolicies saved to {POLICIES_DIR}/")
    print(f"Summary saved to {summary_path}")


if __name__ == "__main__":
    main()
