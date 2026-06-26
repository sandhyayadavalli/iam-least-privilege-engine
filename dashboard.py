"""
dashboard.py
Streamlit dashboard for the IAM Least-Privilege Engine.

A visual layer over the risk-scoring output: KPI cards, risk distribution,
risk-factor breakdown, filterable role explorer, and per-role least-privilege
policy proposals.

Usage:
    streamlit run dashboard.py
"""

import json
import os
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

SCORES_PATH = os.path.join("data", "risk_scores.json")
POLICIES_DIR = os.path.join("data", "policies")
SUMMARY_PATH = os.path.join(POLICIES_DIR, "summary.json")

RISK_COLORS = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}
RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# ── Data loaders (cached) ─────────────────────────────────────────────────────
@st.cache_data
def load_scores():
    with open(SCORES_PATH) as f:
        return json.load(f)


@st.cache_data
def load_summary():
    with open(SUMMARY_PATH) as f:
        return json.load(f)


@st.cache_data
def load_all_policies():
    policies = {}
    for fname in os.listdir(POLICIES_DIR):
        if fname.endswith(".json") and fname != "summary.json":
            role_name = fname.replace(".json", "")
            with open(os.path.join(POLICIES_DIR, fname)) as f:
                policies[role_name] = json.load(f)
    return policies


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IAM Least-Privilege Engine",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom theme ──────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
      .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1400px; }

      /* Hero banner */
      .hero {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 28px 32px;
        margin-bottom: 24px;
      }
      .hero h1 { margin: 0; font-size: 2rem; color: #f8fafc; font-weight: 700; }
      .hero p { margin: 6px 0 0; color: #94a3b8; font-size: 0.95rem; }
      .hero .acct {
        display: inline-block; margin-top: 12px; padding: 4px 12px;
        background: #1e3a5f; color: #93c5fd; border-radius: 8px;
        font-family: monospace; font-size: 0.85rem;
      }

      /* KPI cards */
      .kpi {
        background: #1e293b; border: 1px solid #334155; border-radius: 14px;
        padding: 20px 22px; height: 100%;
      }
      .kpi .label { color: #94a3b8; font-size: 0.8rem; text-transform: uppercase;
                    letter-spacing: 0.05em; margin-bottom: 8px; }
      .kpi .value { color: #f8fafc; font-size: 2.2rem; font-weight: 700; line-height: 1; }
      .kpi .sub { font-size: 0.8rem; margin-top: 8px; }
      .kpi.accent-red { border-left: 4px solid #ef4444; }
      .kpi.accent-amber { border-left: 4px solid #f59e0b; }
      .kpi.accent-green { border-left: 4px solid #22c55e; }
      .kpi.accent-blue { border-left: 4px solid #3b82f6; }

      /* Role cards */
      .role-card {
        background: #1e293b; border: 1px solid #334155; border-radius: 14px;
        padding: 18px 22px; margin-bottom: 14px;
      }
      .role-head { display: flex; justify-content: space-between; align-items: center; }
      .role-name { font-size: 1.1rem; font-weight: 700; color: #f8fafc; font-family: monospace; }
      .badge {
        padding: 3px 12px; border-radius: 999px; font-size: 0.75rem;
        font-weight: 700; color: white; letter-spacing: 0.03em;
      }
      .pill {
        display: inline-block; padding: 2px 9px; border-radius: 6px;
        font-size: 0.72rem; font-family: monospace; margin: 2px 4px 2px 0;
      }
      .pill-red { background: #450a0a; color: #fca5a5; }
      .pill-green { background: #052e16; color: #86efac; }
      .pill-amber { background: #451a03; color: #fcd34d; }

      /* Reduction bar */
      .redbar-track { background: #334155; border-radius: 999px; height: 10px; overflow: hidden; margin-top: 6px; }
      .redbar-fill { background: linear-gradient(90deg, #22c55e, #16a34a); height: 100%; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Load data ─────────────────────────────────────────────────────────────────
data = load_scores()
summary_data = load_summary()
roles = data["roles"]
summary_roles = {r["role_name"]: r for r in summary_data["roles"]}
all_policies = load_all_policies()
account_id = roles[0]["role_arn"].split(":")[4] if roles else "unknown"

# ── Hero ──────────────────────────────────────────────────────────────────────
st.markdown(
    f"""
    <div class="hero">
      <h1>🔐 IAM Least-Privilege Engine</h1>
      <p>CloudTrail-driven permission analysis · automated least-privilege policy recommendations</p>
      <span class="acct">AWS Account: {account_id}</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Sidebar filters ───────────────────────────────────────────────────────────
st.sidebar.header("Filters")
level_filter = st.sidebar.multiselect(
    "Risk level",
    options=["HIGH", "MEDIUM", "LOW"],
    default=["HIGH", "MEDIUM", "LOW"],
)
search = st.sidebar.text_input("Search role name", "").strip().lower()
dormant_only = st.sidebar.checkbox("Dormant roles only", value=False)
sort_by = st.sidebar.selectbox(
    "Sort by", ["Risk score (high→low)", "Unused % (high→low)", "Name (A→Z)"]
)

st.sidebar.divider()
st.sidebar.caption(f"Data generated:\n{data['generated_at'][:19].replace('T', ' ')} UTC")
st.sidebar.caption(f"{len(roles)} roles analyzed")

# Apply filters
filtered = [
    r for r in roles
    if r["risk_level"] in level_filter
    and (search in r["role_name"].lower() if search else True)
    and (r["is_dormant"] if dormant_only else True)
]
if sort_by == "Risk score (high→low)":
    filtered.sort(key=lambda r: r["risk_score"], reverse=True)
elif sort_by == "Unused % (high→low)":
    filtered.sort(key=lambda r: r["unused_pct"], reverse=True)
else:
    filtered.sort(key=lambda r: r["role_name"])

# ── KPI cards ─────────────────────────────────────────────────────────────────
high_count = sum(1 for r in filtered if r["risk_level"] == "HIGH")
dormant_count = sum(1 for r in filtered if r["is_dormant"])
wildcard_count = sum(1 for r in filtered if r["wildcard_grants"])
avg_unused = sum(r["unused_pct"] for r in filtered) / len(filtered) if filtered else 0
avg_reduction = (
    sum(summary_roles.get(r["role_name"], {}).get("reduction_pct", 0) for r in filtered) / len(filtered)
    if filtered else 0
)
scanned_label = f"{len(filtered)} of {len(roles)}" if len(filtered) != len(roles) else f"{len(roles)}"

k1, k2, k3, k4, k5 = st.columns(5)
k1.markdown(
    f'<div class="kpi accent-blue"><div class="label">Roles Shown</div>'
    f'<div class="value">{scanned_label}</div><div class="sub" style="color:#94a3b8">match current filters</div></div>',
    unsafe_allow_html=True,
)
k2.markdown(
    f'<div class="kpi accent-red"><div class="label">High Risk</div>'
    f'<div class="value">{high_count}</div><div class="sub" style="color:#fca5a5">need immediate attention</div></div>',
    unsafe_allow_html=True,
)
k3.markdown(
    f'<div class="kpi accent-amber"><div class="label">Dormant</div>'
    f'<div class="value">{dormant_count}</div><div class="sub" style="color:#fcd34d">zero activity in 90d</div></div>',
    unsafe_allow_html=True,
)
k4.markdown(
    f'<div class="kpi accent-red"><div class="label">Wildcard Grants</div>'
    f'<div class="value">{wildcard_count}</div><div class="sub" style="color:#fca5a5">roles with * or service:*</div></div>',
    unsafe_allow_html=True,
)
k5.markdown(
    f'<div class="kpi accent-green"><div class="label">Avg Reduction</div>'
    f'<div class="value">{avg_reduction:.0f}%</div><div class="sub" style="color:#86efac">proposed permission cut</div></div>',
    unsafe_allow_html=True,
)

st.write("")

if not filtered:
    st.info("No roles match the current filters. Adjust the filters in the sidebar.")
    st.stop()

# ── Charts row ────────────────────────────────────────────────────────────────
c_left, c_right = st.columns([2, 1])

with c_left:
    st.markdown("#### Risk Score by Role")
    df = pd.DataFrame([
        {
            "Role": r["role_name"],
            "Risk Score": r["risk_score"],
            "Risk Level": r["risk_level"],
            "Unused %": r["unused_pct"],
            "Dormant": "Yes" if r["is_dormant"] else "No",
        }
        for r in sorted(filtered, key=lambda r: r["risk_score"], reverse=True)
    ])
    fig = px.bar(
        df, x="Risk Score", y="Role", orientation="h",
        color="Risk Level", color_discrete_map=RISK_COLORS,
        text="Risk Score", hover_data=["Unused %", "Dormant"],
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        xaxis_range=[0, 100], height=380,
        margin=dict(l=0, r=0, t=10, b=0),
        yaxis=dict(autorange="reversed", title=None),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        font=dict(color="#cbd5e1"),
    )
    fig.update_traces(textposition="outside", cliponaxis=False)
    fig.add_vline(x=55, line_dash="dash", line_color="#ef4444", opacity=0.4,
                  annotation_text="HIGH", annotation_position="top")
    fig.add_vline(x=30, line_dash="dash", line_color="#f59e0b", opacity=0.4,
                  annotation_text="MED", annotation_position="top")
    st.plotly_chart(fig, use_container_width=True)

with c_right:
    st.markdown("#### Risk Distribution")
    dist = {lvl: sum(1 for r in filtered if r["risk_level"] == lvl) for lvl in ["HIGH", "MEDIUM", "LOW"]}
    donut = go.Figure(go.Pie(
        labels=list(dist.keys()), values=list(dist.values()), hole=0.62,
        marker=dict(colors=[RISK_COLORS[k] for k in dist.keys()]),
        textinfo="value", textfont=dict(size=16, color="white"),
    ))
    donut.update_layout(
        showlegend=True, height=380,
        margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5),
        annotations=[dict(text=f"{len(filtered)}<br>roles", x=0.5, y=0.5,
                          font=dict(size=18, color="#f8fafc"), showarrow=False)],
        font=dict(color="#cbd5e1"),
    )
    st.plotly_chart(donut, use_container_width=True)

# ── Risk factor breakdown ─────────────────────────────────────────────────────
st.markdown("#### What's Driving the Risk")
st.caption("Each role's score broken down by contributing factor")

factor_df = pd.DataFrame([
    {
        "Role": r["role_name"],
        "Wildcard": r["risk_factors"]["wildcard_score"],
        "Sensitive": r["risk_factors"]["sensitive_score"],
        "Unused": r["risk_factors"]["unused_score"],
        "Dormant": r["risk_factors"]["dormant_score"],
    }
    for r in sorted(filtered, key=lambda r: r["risk_score"], reverse=True)
])
factor_fig = px.bar(
    factor_df, x="Role", y=["Wildcard", "Sensitive", "Unused", "Dormant"],
    color_discrete_map={
        "Wildcard": "#ef4444", "Sensitive": "#f97316",
        "Unused": "#eab308", "Dormant": "#8b5cf6",
    },
)
factor_fig.update_layout(
    barmode="stack", plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
    height=320, margin=dict(l=0, r=0, t=10, b=0),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, title=None),
    yaxis=dict(title="Risk points"), xaxis=dict(title=None),
    font=dict(color="#cbd5e1"),
)
st.plotly_chart(factor_fig, use_container_width=True)

st.divider()

# ── Role explorer ─────────────────────────────────────────────────────────────
st.markdown(f"#### Role Explorer  ·  {len(filtered)} of {len(roles)} shown")

if not filtered:
    st.info("No roles match the current filters.")

for r in filtered:
    level = r["risk_level"]
    color = RISK_COLORS[level]
    reduction = summary_roles.get(r["role_name"], {}).get("reduction_pct", 0)
    dormant_tag = ' <span class="pill pill-amber">💤 DORMANT</span>' if r["is_dormant"] else ""
    wc_tag = ""
    if r["wildcard_grants"]:
        wc_tag = " ".join(f'<span class="pill pill-red">⚠️ {w}</span>' for w in r["wildcard_grants"])

    with st.container():
        st.markdown(
            f"""
            <div class="role-card">
              <div class="role-head">
                <span class="role-name">{r['role_name']}</span>
                <span class="badge" style="background:{color}">{level} · {r['risk_score']}</span>
              </div>
              <div style="margin-top:8px">{wc_tag}{dormant_tag}</div>
              <div style="display:flex;justify-content:space-between;color:#94a3b8;font-size:0.8rem;margin-top:14px">
                <span>Granted: <b style="color:#f8fafc">{r['granted_action_count']}</b></span>
                <span>Used: <b style="color:#86efac">{r['used_action_count']}</b></span>
                <span>Unused: <b style="color:#fca5a5">{r['unused_action_count']}</b></span>
                <span>Permission reduction: <b style="color:#86efac">-{reduction:.0f}%</b></span>
              </div>
              <div class="redbar-track"><div class="redbar-fill" style="width:{min(reduction,100)}%"></div></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander("View details & proposed policy"):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**✅ Used Actions** (seen in CloudTrail)")
                if r["used_actions"]:
                    st.markdown(
                        " ".join(f'<span class="pill pill-green">{a}</span>' for a in r["used_actions"]),
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown("_None — role is dormant_")
            with col_b:
                st.markdown("**❌ Unused / Wildcard** (granted but not used)")
                if r["wildcard_grants"]:
                    st.markdown(
                        " ".join(f'<span class="pill pill-red">{w} (unlimited)</span>' for w in r["wildcard_grants"]),
                        unsafe_allow_html=True,
                    )
                elif r["unused_actions"]:
                    st.markdown(
                        " ".join(f'<span class="pill pill-red">{a}</span>' for a in r["unused_actions"]),
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown("_All granted actions were used_")

            policy = all_policies.get(r["role_name"])
            if policy:
                st.markdown(f"**📄 Proposed Least-Privilege Policy** — _reduces permissions by {reduction:.0f}%_")
                st.json(policy, expanded=False)

st.divider()
st.caption(
    f"IAM Least-Privilege Engine · Account {account_id} · "
    f"{len(roles)} roles · generated {data['generated_at'][:19].replace('T', ' ')} UTC"
)
