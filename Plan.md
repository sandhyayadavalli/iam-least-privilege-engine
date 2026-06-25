Good choices — both add real depth signal. CloudTrail event-level analysis shows you can work with raw, messy data (not just AWS's pre-digested "last accessed" report), and a Streamlit dashboard makes the project demoable in an interview in 2 minutes instead of requiring someone to read code. Worth the extra time.
Here's the adjusted plan — this pushes you to roughly 5-6 weeks instead of 4, given the added complexity:
Revised Week-by-Week Plan
Week 1: Foundation — IAM Data Collection
(unchanged from before)
Set up a sandbox AWS account, create 8-10 test roles with deliberately varied permission patterns (wildcards, unused, overprivileged, tightly scoped)
Python + boto3 script to inventory all roles/users/policies into structured JSON
Deliverable: Clean IAM inventory script + output

Week 2: Generate Realistic Activity + Raw CloudTrail Ingestion
Goal: Get real event-level usage data, not just AWS's summary.

Script your test roles to make a realistic spread of API calls over a few days (S3, EC2, IAM, STS calls) — vary it so some roles look "active" and some look "dormant"
Pull raw events via CloudTrail.lookup_events() (note: only 90-day lookback, and it's eventName/eventSource level — you'll need to map eventName like GetObject/ListBucket back to IAM action format like s3:GetObject)
Build a mapping table: CloudTrail event name → IAM action string (this is genuinely fiddly — AWS doesn't make this 1:1 trivial, so budget real time here)
Store parsed events: role_arn, action_used, timestamp, resource

Deliverable: A script producing a clean "actions actually invoked per role" dataset from raw CloudTrail, with the event-name-to-IAM-action mapping documented (this mapping logic itself is a good talking point in interviews).
Week 3: Diff Engine + Risk Scoring

Build the granted_permissions vs used_permissions diff per role
Risk scoring model (weighted, documented):

Wildcard actions/resources
% unused permissions
Sensitive action presence (curated list: iam:*, s3:DeleteBucket, cross-account sts:AssumeRole, etc.)
Recency of last use


Output: ranked JSON/CSV of all roles by risk score

Deliverable: Working risk-scoring engine with documented methodology.
Week 4: Least-Privilege Policy Generator + PR Automation

Auto-generate tightened policy JSON per role (only actually-used actions, scoped resources)
GitHub API integration: auto-open a PR proposing the new policy as a file diff in your repo
Test end-to-end: inventory → diff → score → generate policy → open PR

Deliverable: Full pipeline working end-to-end, PRs opening automatically.
Week 5: Streamlit Dashboard
Goal: Visual layer — this is what you'll actually demo in interviews/screen shares.

Role-by-role risk table (sortable, color-coded by risk score)
Detail view per role: granted vs used permissions side-by-side, with unused permissions highlighted
Summary metrics at top: total roles scanned, average unused-permission %, count of high-risk roles, wildcard count
A simple bar chart of risk scores across all roles (Streamlit + plotly/altair)
Link/button to view the generated policy diff or the opened PR

Deliverable: A working dashboard you can run locally and screen-share in 90 seconds.
Week 6: Polish + Documentation

Architecture diagram (I can help you build this as an artifact when you're ready)
README: problem framing, architecture, setup instructions, screenshots of the dashboard, quantified results section
Record a 2-3 min Loom/demo video walkthrough (huge value-add for sharing on LinkedIn or in applications — many candidates skip this and it's a strong differentiator)
Clean up commit history, add a .gitignore, make sure no AWS credentials are anywhere in the repo (use IAM roles/env vars, double check before pushing)


Two things worth flagging now, before you start:
CloudTrail event-to-IAM-action mapping is the hardest technical part of this whole project. It's not officially documented as a clean lookup table anywhere — you'll need to build your own mapping for the actions you care about (probably 30-40 common ones covers most of it). This is actually a feature for your story ("I built a mapping layer to bridge CloudTrail's event taxonomy with IAM's policy language") but budget real time for it in Week 2.
Cost control: CloudTrail management events are free for the last 90 days of lookup via the API, so you're fine cost-wise as long as you don't enable a CloudTrail trail with S3 data event logging (that costs money at volume). Stick to lookup_events() API calls and you're in free-tier territory.
Want to start Week 1 right now — I can help you write the IAM inventory script and the Terraform/script to provision the 8-10 test roles with varied permission patterns?
