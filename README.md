# IAM Least-Privilege Engine

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20CloudTrail-orange?logo=amazon-aws)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red?logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-green)

A CloudTrail-driven tool that automatically identifies overprivileged IAM roles, scores them by risk, and proposes least-privilege replacement policies — with a visual dashboard and GitHub PR automation.

---

## The Problem

AWS IAM roles are routinely over-provisioned. Teams grant broad permissions to move fast and rarely audit what's actually being used. The result: roles with `iam:*` or `s3:*` wildcards sitting in production, most permissions never touched — a silent blast radius waiting to be exploited.

AWS's built-in "Last Accessed" report tells you *when* a service was used, but not *which specific actions* were called. This tool goes deeper: it ingests raw CloudTrail event-level data, maps every API call back to its IAM action, and produces a per-role diff of what was granted vs. what was actually used.

---

## What It Does

```
IAM Inventory → CloudTrail Ingestion → Risk Scoring → Policy Generation → GitHub PR
```

1. **Inventories** all IAM roles with their full granted permissions
2. **Ingests** raw CloudTrail events and maps them to IAM action strings (`GetObject` → `s3:GetObject`)
3. **Scores** each role by risk: wildcard grants, unused permission %, sensitive actions, dormancy
4. **Generates** tightened least-privilege policy JSON using only observed actions
5. **Opens a GitHub PR** proposing the new policies as reviewable file diffs
6. **Visualizes** everything in a Streamlit dashboard

---

## Results (on 8 test roles)

| Role | Risk | Granted | Used | Reduction |
|---|---|---|---|---|
| `role-wildcard-admin` | 🔴 HIGH | `*` wildcard | 18 actions | **-99%** |
| `role-sensitive-iam-star` | 🔴 HIGH | `iam:*` wildcard | 6 actions | **-99%** |
| `role-dormant-iam` | 🟠 MEDIUM | 8 actions | 0 | **-100%** |
| `role-dormant-unused` | 🟠 MEDIUM | 6 actions | 0 | **-100%** |
| `role-cross-account-sts` | 🟠 MEDIUM | 1 action | 0 used | **-100%** |
| `role-overprivileged-ec2` | 🟡 LOW | 8 actions | 8 actions | **-99%** |

**Average permission reduction: 99%** across all analyzed roles.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AWS Account                          │
│                                                         │
│   IAM Roles ──────────────────► inventory_iam_roles.py  │
│                                        │                │
│   CloudTrail Events ──────────► ingest_cloudtrail.py    │
│         (90-day lookback)              │                │
└────────────────────────────────────────┼────────────────┘
                                         │
                              ┌──────────▼──────────┐
                              │    risk_scorer.py    │
                              │  (diff + risk model) │
                              └──────────┬──────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
          ┌─────────▼────────┐  ┌───────▼────────┐  ┌───────▼──────┐
          │ generate_         │  │  dashboard.py  │  │  open_pr.py  │
          │ policies.py       │  │  (Streamlit)   │  │  (GitHub PR) │
          └──────────────────┘  └────────────────┘  └──────────────┘
```

---

## Quick Start

### Prerequisites
- Python 3.10+
- AWS credentials configured (`aws configure`)
- The IAM user/role needs: `iam:List*`, `iam:Get*`, `cloudtrail:LookupEvents`

### Install

```bash
git clone https://github.com/sandhyayadavalli/iam-least-privilege-engine
cd iam-least-privilege-engine
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Run the full pipeline

```bash
python3 run_pipeline.py
```

### Or run individual steps

```bash
# 1. Inventory all IAM roles
python3 scripts/inventory_iam_roles.py

# 2. Pull CloudTrail events (last 90 days)
python3 scripts/ingest_cloudtrail.py

# 3. Score roles by risk
python3 scripts/risk_scorer.py

# 4. Generate least-privilege policies
python3 scripts/generate_policies.py

# 5. Open a GitHub PR with proposals
export GITHUB_TOKEN=ghp_...
export GITHUB_REPO=youruser/your-repo
python3 scripts/open_pr.py
```

### Launch the dashboard

```bash
streamlit run dashboard.py
```

Open `http://localhost:8501` in your browser.

---

## Risk Scoring Model

Each role is scored 0–100 across four dimensions:

| Factor | Max Points | What it catches |
|---|---|---|
| Wildcard grants (`*`, `iam:*`) | 60 | Full admin or service-level wildcards |
| Sensitive actions present | 30 | `iam:CreateRole`, `ec2:TerminateInstances`, etc. |
| Unused permission % | 20 | Permissions granted but never seen in CloudTrail |
| Dormancy | 20 | Zero CloudTrail activity in 90 days |

**Thresholds:** HIGH ≥ 55 · MEDIUM ≥ 30 · LOW < 30

---

## Project Structure

```
iam-least-privilege-engine/
├── scripts/
│   ├── inventory_iam_roles.py     # Step 1: pull IAM role inventory
│   ├── simulate_role_activity.py  # (Dev) generate CloudTrail test data
│   ├── ingest_cloudtrail.py       # Step 2: pull + normalize CloudTrail events
│   ├── risk_scorer.py             # Step 3: diff granted vs used, score risk
│   ├── generate_policies.py       # Step 4: generate least-privilege policies
│   └── open_pr.py                 # Step 5: open GitHub PR with proposals
├── data/
│   ├── iam_inventory.json         # Role inventory output
│   ├── cloudtrail_events.json     # Normalized CloudTrail events
│   ├── risk_scores.json           # Risk scores per role
│   └── policies/                  # Generated least-privilege policies
├── dashboard.py                   # Streamlit dashboard
├── run_pipeline.py                # End-to-end pipeline runner
└── requirements.txt
```

---

## Tech Stack

- **Python + boto3** — AWS API interaction
- **CloudTrail `lookup_events`** — raw event ingestion (no S3 trail required, stays in free tier)
- **Custom mapping layer** — translates CloudTrail `eventName` → IAM action strings
- **Streamlit + Plotly** — interactive risk dashboard
- **GitHub REST API** — automated PR creation

---

## Key Engineering Decisions

**Why raw CloudTrail instead of IAM Access Advisor?**
Access Advisor reports service-level last-accessed dates. CloudTrail gives you individual API calls — so you can see `s3:GetObject` was used but `s3:DeleteBucket` never was, and generate a policy that reflects that exactly.

**Why a PR instead of direct policy application?**
Automated policy changes in production IAM are high risk. The PR model creates an audit trail, forces human review, and lets teams apply changes incrementally.

**CloudTrail event-to-IAM action mapping**
AWS doesn't publish a clean 1:1 mapping. This tool builds its own mapping layer (`EVENT_SOURCE_TO_PREFIX` + `KNOWN_OVERRIDES`) covering the most common services, with documented exceptions.

---

## License

MIT
