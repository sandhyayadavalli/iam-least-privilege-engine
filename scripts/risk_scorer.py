"""
risk_scorer.py
Week 3: Diff granted vs used permissions per role and produce a risk score.

Inputs:
  data/iam_inventory.json      - what each role was granted
  data/cloudtrail_events.json  - what each role actually used

Output:
  data/risk_scores.json        - ranked list of roles by risk score

Risk scoring model (0-100):
  - Wildcard actions (*, service:*)     up to 30 pts
  - Unused permission %                 up to 25 pts
  - Sensitive actions present           up to 25 pts
  - Dormant / never used                up to 20 pts

Usage: python3 scripts/risk_scorer.py
"""

import json
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict

INVENTORY_PATH = os.path.join("data", "iam_inventory.json")
EVENTS_PATH = os.path.join("data", "cloudtrail_events.json")
OUTPUT_PATH = os.path.join("data", "risk_scores.json")

# Actions that are high-risk regardless of usage
SENSITIVE_ACTIONS = {
    "iam:*",
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "s3:DeleteBucket",
    "s3:PutBucketPolicy",
    "ec2:TerminateInstances",
    "ec2:StopInstances",
    "*",
}

DORMANT_THRESHOLD_DAYS = 30


def load_data():
    with open(INVENTORY_PATH) as f:
        inventory = json.load(f)
    with open(EVENTS_PATH) as f:
        events = json.load(f)
    return inventory["roles"], events["events"]


def extract_granted_actions(role):
    """Flatten all Allow statements into a set of granted action strings."""
    actions = set()
    for perm in role.get("permissions", []):
        if perm.get("effect") != "Allow":
            continue
        for action in perm.get("actions", []):
            actions.add(action.lower())
    return actions


def build_used_actions_by_role(events):
    """Build a dict of role_name -> {set of iam_actions used, last_used datetime}."""
    used = defaultdict(lambda: {"actions": set(), "last_used": None})
    for event in events:
        role = event["role_name"]
        used[role]["actions"].add(event["iam_action"].lower())
        ts = datetime.fromisoformat(event["timestamp"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if used[role]["last_used"] is None or ts > used[role]["last_used"]:
            used[role]["last_used"] = ts
    return used


def is_covered_by_wildcard(action, granted):
    """Check if an action is covered by a wildcard in granted set."""
    if "*" in granted:
        return True
    service = action.split(":")[0] if ":" in action else ""
    if f"{service}:*" in granted:
        return True
    return False


def compute_unused(granted, used_actions):
    """
    Return (unused_specific, wildcard_grants).
    unused_specific: granted actions not seen in CloudTrail (excluding wildcards)
    wildcard_grants: wildcard entries in granted
    """
    wildcards = {a for a in granted if a == "*" or a.endswith(":*")}
    specific_grants = granted - wildcards

    unused = set()
    for action in specific_grants:
        if action not in used_actions and not is_covered_by_wildcard(action, used_actions):
            unused.add(action)

    return unused, wildcards


def score_role(role, used_data):
    role_name = role["role_name"]
    granted = extract_granted_actions(role)
    used_info = used_data.get(role_name, {"actions": set(), "last_used": None})
    used_actions = used_info["actions"]
    last_used = used_info["last_used"]

    unused_specific, wildcards = compute_unused(granted, used_actions)

    # --- Wildcard score (0-60) ---
    # * and iam:* are instant HIGH territory by themselves
    wildcard_score = 0
    if "*" in wildcards:
        wildcard_score = 60
    elif any(w.startswith("iam:") for w in wildcards):
        wildcard_score = 55
    elif wildcards:
        wildcard_score = 20 + min((len(wildcards) - 1) * 5, 15)

    # --- Sensitive actions score (0-30) ---
    sensitive_found = set()
    sensitive_lower = {s.lower() for s in SENSITIVE_ACTIONS}
    for action in granted:
        if action in sensitive_lower:
            sensitive_found.add(action)
        if action.startswith("iam:") and "*" in action:
            sensitive_found.add(action)
    # Don't double-count wildcards already scored above
    non_wildcard_sensitive = sensitive_found - wildcards
    sensitive_score = min(len(non_wildcard_sensitive) * 10, 30)

    # --- Unused % score (0-20) ---
    specific_grants = granted - wildcards
    if specific_grants:
        unused_pct = len(unused_specific) / len(specific_grants) * 100
    else:
        unused_pct = 0.0
    unused_score = round(unused_pct / 100 * 20)

    # --- Dormant score (0-20) ---
    dormant_score = 0
    days_since_last_use = None
    if last_used is None:
        dormant_score = 20
        days_since_last_use = None
    else:
        now = datetime.now(timezone.utc)
        days_since_last_use = (now - last_used).days
        if days_since_last_use >= DORMANT_THRESHOLD_DAYS:
            dormant_score = 20
        elif days_since_last_use >= 7:
            dormant_score = 10

    total_score = wildcard_score + unused_score + sensitive_score + dormant_score
    total_score = min(total_score, 100)

    if total_score >= 55:
        risk_level = "HIGH"
    elif total_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "role_name": role_name,
        "role_arn": role["role_arn"],
        "risk_score": total_score,
        "risk_level": risk_level,
        "granted_action_count": len(granted),
        "used_action_count": len(used_actions),
        "unused_action_count": len(unused_specific),
        "unused_pct": round(unused_pct, 1),
        "wildcard_grants": sorted(wildcards),
        "sensitive_actions_found": sorted(sensitive_found),
        "is_dormant": last_used is None,
        "days_since_last_use": days_since_last_use,
        "unused_actions": sorted(unused_specific),
        "used_actions": sorted(used_actions),
        "risk_factors": {
            "wildcard_score": wildcard_score,
            "unused_score": unused_score,
            "sensitive_score": sensitive_score,
            "dormant_score": dormant_score,
        },
    }


def print_summary(scored_roles):
    print("\n" + "=" * 60)
    print(f"{'ROLE':<30} {'SCORE':>5}  {'LEVEL':<8}  {'UNUSED%':>7}  {'DORMANT'}")
    print("=" * 60)
    for r in scored_roles:
        dormant = "YES" if r["is_dormant"] else "no"
        print(
            f"{r['role_name']:<30} {r['risk_score']:>5}  {r['risk_level']:<8}"
            f"  {r['unused_pct']:>6.1f}%  {dormant}"
        )
    print("=" * 60)


def main():
    roles, events = load_data()
    used_data = build_used_actions_by_role(events)

    scored = [score_role(role, used_data) for role in roles]
    scored.sort(key=lambda r: r["risk_score"], reverse=True)

    print_summary(scored)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "role_count": len(scored),
        "roles": scored,
    }
    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nSaved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
