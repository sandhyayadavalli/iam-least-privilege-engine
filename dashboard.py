"""
dashboard.py
Week 5: Streamlit dashboard for the IAM Least-Privilege Engine.

Usage:
    streamlit run dashboard.py
"""

import json
import os
import streamlit as st
import pandas as pd
import plotly.express as px

SCORES_PATH = os.path.join("data", "risk_scores.json")
POLICIES_DIR = os.path.join("data", "policies")
SUMMARY_PATH = os.path.join(POLICIES_DIR, "summary.json")

RISK_COLORS = {"HIGH": "#ef4444", "MEDIUM": "#f97316", "LOW": "#22c55e"}


@st.cache_data
def load_scores():
    with open(SCORES_PATH) as f:
        return json.load(f)


@st.cache_data
def load_summary():
    with open(SUMMARY_PATH) as f:
        return json.load(f)


def load_policy(role_name):
    path = os.path.join(POLICIES_DIR, f"{role_name}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def risk_badge(level):
    color = RISK_COLORS.get(level, "#6b7280")
    return f'<span style="background:{color};color:white;padding:2px 10px;border-radius:12px;font-size:0.8rem;font-weight:bold">{level}</span>'


# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IAM Least-Privilege Engine",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 IAM Least-Privilege Engine")
st.caption("CloudTrail-driven permission analysis and policy recommendations")

data = load_scores()
summary_data = load_summary()
roles = data["roles"]
summary_roles = {r["role_name"]: r for r in summary_data["roles"]}

# ── Summary metrics ───────────────────────────────────────────────────────────
st.markdown("### Overview")
col1, col2, col3, col4 = st.columns(4)

high_count = sum(1 for r in roles if r["risk_level"] == "HIGH")
medium_count = sum(1 for r in roles if r["risk_level"] == "MEDIUM")
dormant_count = sum(1 for r in roles if r["is_dormant"])
wildcard_count = sum(1 for r in roles if r["wildcard_grants"])
avg_unused = sum(r["unused_pct"] for r in roles) / len(roles) if roles else 0

col1.metric("Total Roles Scanned", len(roles))
col2.metric("High Risk Roles", high_count, delta=f"+{high_count} need attention", delta_color="inverse")
col3.metric("Dormant Roles", dormant_count, help="Roles with zero CloudTrail activity")
col4.metric("Avg Unused Permissions", f"{avg_unused:.0f}%")

st.divider()

# ── Risk score bar chart ──────────────────────────────────────────────────────
st.markdown("### Risk Scores by Role")

df = pd.DataFrame([
    {
        "Role": r["role_name"],
        "Risk Score": r["risk_score"],
        "Risk Level": r["risk_level"],
        "Unused %": r["unused_pct"],
        "Dormant": "Yes" if r["is_dormant"] else "No",
    }
    for r in roles
]).sort_values("Risk Score", ascending=False)

fig = px.bar(
    df,
    x="Role",
    y="Risk Score",
    color="Risk Level",
    color_discrete_map=RISK_COLORS,
    text="Risk Score",
    hover_data=["Unused %", "Dormant"],
)
fig.update_layout(
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    yaxis_range=[0, 100],
    showlegend=True,
)
fig.update_traces(textposition="outside")
st.plotly_chart(fig, use_container_width=True)

st.divider()

# ── Role risk table ───────────────────────────────────────────────────────────
st.markdown("### Role Risk Table")

for r in roles:
    badge = risk_badge(r["risk_level"])
    dormant_tag = " 💤 DORMANT" if r["is_dormant"] else ""
    wildcard_tag = f" ⚠️ `{'`, `'.join(r['wildcard_grants'])}`" if r["wildcard_grants"] else ""

    with st.expander(f"{r['role_name']}  —  Score: {r['risk_score']}{dormant_tag}"):
        st.markdown(f"**Risk Level:** {badge}{wildcard_tag}", unsafe_allow_html=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk Score", r["risk_score"])
        m2.metric("Granted Actions", r["granted_action_count"])
        m3.metric("Used Actions", r["used_action_count"])
        m4.metric("Unused %", f"{r['unused_pct']:.0f}%")

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("**Used Actions** (seen in CloudTrail)")
            if r["used_actions"]:
                for a in r["used_actions"]:
                    st.markdown(f"- ✅ `{a}`")
            else:
                st.markdown("_None — role is dormant_")

        with col_b:
            st.markdown("**Unused Actions** (granted but never used)")
            if r["wildcard_grants"]:
                for w in r["wildcard_grants"]:
                    st.markdown(f"- 🚨 `{w}` _(wildcard — grants unlimited actions)_")
            elif r["unused_actions"]:
                for a in r["unused_actions"]:
                    st.markdown(f"- ❌ `{a}`")
            else:
                st.markdown("_All granted actions were used_")

        # Proposed policy
        policy = load_policy(r["role_name"])
        if policy:
            sr = summary_roles.get(r["role_name"], {})
            reduction = sr.get("reduction_pct", 0)
            st.markdown(f"**Proposed Least-Privilege Policy** _(permission reduction: -{reduction:.0f}%)_")
            st.json(policy)

st.divider()
st.caption(f"Data generated at: {data['generated_at']} · {len(roles)} roles analyzed")
