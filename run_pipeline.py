"""
run_pipeline.py
End-to-end runner for the IAM Least-Privilege Engine.

Runs all steps in order:
  1. Inventory IAM roles
  2. Ingest CloudTrail events
  3. Score roles by risk
  4. Generate least-privilege policies
  5. (Optional) Open GitHub PR with proposals

Usage:
    python3 run_pipeline.py              # full pipeline, skip PR
    python3 run_pipeline.py --pr         # full pipeline + open GitHub PR
    python3 run_pipeline.py --from step3 # resume from a specific step
    python3 run_pipeline.py --skip-sim   # skip activity simulation

Steps:
    step1 - IAM inventory
    step2 - CloudTrail ingestion
    step3 - Risk scoring
    step4 - Policy generation
    step5 - GitHub PR (requires --pr flag)
"""

import subprocess
import sys
import os
import time
import argparse
from datetime import datetime

STEPS = [
    ("step1", "IAM Inventory",          "scripts/inventory_iam_roles.py"),
    ("step2", "CloudTrail Ingestion",   "scripts/ingest_cloudtrail.py"),
    ("step3", "Risk Scoring",           "scripts/risk_scorer.py"),
    ("step4", "Policy Generation",      "scripts/generate_policies.py"),
    ("step5", "GitHub PR",              "scripts/open_pr.py"),
]

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════╗
║       IAM Least-Privilege Engine — Pipeline      ║
╚══════════════════════════════════════════════════╝{RESET}
""")


def print_step(n, total, name):
    print(f"\n{BOLD}[{n}/{total}] {name}{RESET}")
    print("─" * 50)


def run_step(script, step_name):
    start = time.time()
    result = subprocess.run(
        [sys.executable, script],
        capture_output=False,
    )
    elapsed = time.time() - start

    if result.returncode == 0:
        print(f"\n{GREEN}✓ {step_name} completed in {elapsed:.1f}s{RESET}")
        return True
    else:
        print(f"\n{RED}✗ {step_name} failed (exit code {result.returncode}){RESET}")
        return False


def check_prerequisites():
    """Check AWS credentials and required data files exist."""
    issues = []

    # Check boto3
    try:
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        account = identity["Account"]
        print(f"{GREEN}✓ AWS credentials valid — Account: {account}{RESET}")
    except Exception as e:
        issues.append(f"AWS credentials not configured: {e}")

    # Check data directory
    os.makedirs("data", exist_ok=True)

    if issues:
        print(f"\n{RED}Prerequisites failed:{RESET}")
        for issue in issues:
            print(f"  • {issue}")
        sys.exit(1)


def simulate_activity():
    """Run the role activity simulation before CloudTrail ingestion."""
    print(f"\n{YELLOW}Running role activity simulation...{RESET}")
    print("(This generates CloudTrail events — waiting 10s after for events to land)\n")
    result = subprocess.run([sys.executable, "scripts/simulate_role_activity.py"])
    if result.returncode == 0:
        print(f"\n{YELLOW}Waiting 10 seconds for CloudTrail to ingest events...{RESET}")
        time.sleep(10)
    return result.returncode == 0


def print_summary(results):
    print(f"\n{BOLD}{'═' * 50}")
    print("Pipeline Summary")
    print(f"{'═' * 50}{RESET}")
    for step_id, name, passed in results:
        icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        print(f"  {icon}  {name}")
    all_passed = all(p for _, _, p in results)
    print(f"\n{'═' * 50}")
    if all_passed:
        print(f"{GREEN}{BOLD}All steps completed successfully.{RESET}")
        print(f"\nNext: run the dashboard with:")
        print(f"  {CYAN}streamlit run dashboard.py{RESET}")
    else:
        failed = [n for _, n, p in results if not p]
        print(f"{RED}Failed steps: {', '.join(failed)}{RESET}")
    print()


def parse_args():
    parser = argparse.ArgumentParser(description="IAM Least-Privilege Engine pipeline runner")
    parser.add_argument("--pr", action="store_true", help="Open GitHub PR after generating policies")
    parser.add_argument("--skip-sim", action="store_true", help="Skip role activity simulation")
    parser.add_argument(
        "--from",
        dest="from_step",
        choices=["step1", "step2", "step3", "step4", "step5"],
        default="step1",
        help="Resume pipeline from a specific step",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    banner()

    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print("Checking prerequisites...")
    check_prerequisites()

    # Determine which steps to run
    from_idx = next(i for i, (sid, _, _) in enumerate(STEPS) if sid == args.from_step)
    steps_to_run = STEPS[from_idx:]

    # Skip PR step unless --pr flag is set
    if not args.pr:
        steps_to_run = [(sid, name, script) for sid, name, script in steps_to_run if sid != "step5"]

    # Validate GitHub env vars if PR step is included
    if args.pr and not os.environ.get("GITHUB_TOKEN"):
        print(f"{RED}--pr requires GITHUB_TOKEN and GITHUB_REPO env vars to be set.{RESET}")
        print("  export GITHUB_TOKEN=ghp_...")
        print("  export GITHUB_REPO=youruser/iam-least-privilege-engine")
        sys.exit(1)

    # Optionally simulate activity before CloudTrail ingestion
    if not args.skip_sim and args.from_step in ("step1", "step2"):
        sim_ok = simulate_activity()
        if not sim_ok:
            print(f"{YELLOW}Simulation failed or was skipped — continuing with existing CloudTrail data.{RESET}")

    results = []
    total = len(steps_to_run)

    for n, (step_id, name, script) in enumerate(steps_to_run, 1):
        print_step(n, total, name)
        passed = run_step(script, name)
        results.append((step_id, name, passed))

        if not passed:
            print(f"{RED}Stopping pipeline at failed step.{RESET}")
            # Fill remaining steps as skipped
            for remaining in steps_to_run[n:]:
                results.append((remaining[0], remaining[1], False))
            break

    print_summary(results)


if __name__ == "__main__":
    main()
