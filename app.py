# app.py
# CloudForce: Cloud Authentication Attack Surface & Brute-Force Visualizer

from pathlib import Path
from typing import List, Optional, Tuple
import io
import time
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from generate_cloudforce_data import COUNTRY_GEOLOCATION, CLOUD_SERVICES, generate_data
from visualize_cloudforce import (
    PALETTE,
    build_attack_origins_map,
    build_failed_logins_timeline,
    build_top_attacking_ips,
)

# -----------------------------------------------------------------------------
# 1. FILE & ENVIRONMENT CONFIGURATION
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "cloudforce_logs.xlsx"

REQUIRED_COLUMNS = [
    "log_id",
    "timestamp",
    "ip_address",
    "country",
    "user_id",
    "cloud_service",
    "login_status",
    "traffic_type",
    "latitude",
    "longitude",
    "hour_bucket",
]

# -----------------------------------------------------------------------------
# 2. STREAMLIT PAGE CONFIGURATION & RESTRAINED STYLING
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CloudForce - Authentication Security Analysis",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    /* Global sans-serif typography */
    html, body, [class*="css"] {
        font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: #e2e8f0;
    }
    
    /* Technical monospace elements */
    code, pre, .mono-text {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
        font-size: 0.86rem;
    }

    /* Metric cards with text wrapping for IP addresses */
    [data-testid="stMetric"] {
        background-color: #161f2e;
        border: 1px solid #27354a;
        border-radius: 4px;
        padding: 14px 18px;
    }
    [data-testid="stMetricValue"] {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 1.45rem;
        font-weight: 600;
        color: #e2e8f0;
        word-break: break-word;
        overflow-wrap: break-word;
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
        margin-bottom: 4px;
    }
    [data-testid="stMetricDelta"] {
        font-size: 0.82rem;
        font-weight: 500;
    }

    /* Structured panel containers */
    .dashboard-panel {
        background-color: #161f2e;
        border: 1px solid #27354a;
        border-radius: 4px;
        padding: 16px 20px;
        margin-bottom: 16px;
    }

    /* Severity badges */
    .status-badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 3px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid #ef4444;
    }
    .badge-normal {
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid #10b981;
    }
    .badge-info {
        background-color: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid #38bdf8;
    }

    /* Form styling and buttons */
    .stButton > button {
        border-radius: 4px;
        font-weight: 500;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# 3. DATA LOADING & VALIDATION ROUTINES
# -----------------------------------------------------------------------------
@st.cache_data
def load_and_validate_data(file_path: Path) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """
    Loads telemetry workbook from disk and performs strict schema validation.
    Returns (DataFrame, None) on success, or (None, error_message) on failure.
    """
    if not file_path.exists():
        return None, f"File not found: '{file_path.name}' does not exist in the project directory."

    try:
        excel_file = pd.ExcelFile(file_path, engine="openpyxl")
        if "Logs" not in excel_file.sheet_names:
            return None, f"Workbook '{file_path.name}' is missing the required sheet 'Logs'. Found: {excel_file.sheet_names}"

        df = pd.read_excel(excel_file, sheet_name="Logs")
        if df.empty:
            return None, f"Workbook '{file_path.name}' (sheet 'Logs') is empty."

        missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_cols:
            return None, f"Dataset is missing required columns: {missing_cols}"

        # Validate values used by the dashboard so malformed workbooks fail clearly.
        required_values = [
            "timestamp", "ip_address", "country", "user_id", "cloud_service",
            "login_status", "traffic_type", "latitude", "longitude", "hour_bucket",
        ]
        missing_values = [col for col in required_values if df[col].isna().any()]
        if missing_values:
            return None, f"Dataset contains blank values in required columns: {missing_values}"

        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="raise")
            df["hour_bucket"] = pd.to_datetime(df["hour_bucket"], errors="raise")
            df["latitude"] = pd.to_numeric(df["latitude"], errors="raise")
            df["longitude"] = pd.to_numeric(df["longitude"], errors="raise")
        except (TypeError, ValueError) as exc:
            return None, f"Dataset contains invalid timestamps or coordinates: {exc}"

        invalid_status = sorted(set(df["login_status"].astype(str)) - {"Success", "Failed"})
        if invalid_status:
            return None, f"Dataset contains unsupported login_status values: {invalid_status}"
        invalid_traffic = sorted(set(df["traffic_type"].astype(str)) - {"Normal", "Brute-Force"})
        if invalid_traffic:
            return None, f"Dataset contains unsupported traffic_type values: {invalid_traffic}"
        invalid_coords = (
            ~df["latitude"].between(-90, 90)
            | ~df["longitude"].between(-180, 180)
        )
        if invalid_coords.any():
            return None, f"Dataset contains {int(invalid_coords.sum())} out-of-range geographic coordinates."

        return df, None
    except Exception as e:
        return None, f"Failed to read '{file_path.name}': {str(e)}"


# -----------------------------------------------------------------------------
# 4. SIDEBAR NAVIGATION & TELEMETRY CONTROLS
# -----------------------------------------------------------------------------
st.sidebar.markdown(
    """
    <div style='padding-bottom: 6px;'>
        <div style='font-size: 1.15rem; font-weight: 700; color: #e2e8f0; letter-spacing: 0.03em;'>CLOUDFORCE</div>
        <div style='font-size: 0.76rem; color: #94a3b8; letter-spacing: 0.04em;'>Authentication Security Analyzer</div>
    </div>
    <hr style='border: 0; border-top: 1px solid #27354a; margin: 10px 0;'>
    """,
    unsafe_allow_html=True,
)

nav_page = st.sidebar.radio(
    "Navigation",
    ["Security Dashboard", "Simulation Engine", "Raw Telemetry"],
    index=0,
    label_visibility="collapsed",
)

st.sidebar.markdown("<hr style='border: 0; border-top: 1px solid #27354a; margin: 12px 0;'>", unsafe_allow_html=True)

# Load data safely
raw_data, load_error = load_and_validate_data(DATA_FILE)

# Sidebar Filter State
filtered_data = raw_data
if raw_data is not None:
    st.sidebar.markdown("<div style='font-size: 0.82rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px;'>Telemetry Filters</div>", unsafe_allow_html=True)

    # Cloud service filter
    services_available = ["All Services"] + sorted(raw_data["cloud_service"].dropna().unique().tolist())
    selected_service = st.sidebar.selectbox("Cloud Service", services_available, index=0)

    # Traffic type filter
    traffic_available = ["All Traffic"] + sorted(raw_data["traffic_type"].dropna().unique().tolist())
    selected_traffic = st.sidebar.selectbox("Traffic Type", traffic_available, index=0)

    # Status filter
    status_available = ["All Statuses"] + sorted(raw_data["login_status"].dropna().unique().tolist())
    selected_status = st.sidebar.selectbox("Login Status", status_available, index=0)

    # Apply active filters
    mask = pd.Series(True, index=raw_data.index)
    if selected_service != "All Services":
        mask &= (raw_data["cloud_service"] == selected_service)
    if selected_traffic != "All Traffic":
        mask &= (raw_data["traffic_type"] == selected_traffic)
    if selected_status != "All Statuses":
        mask &= (raw_data["login_status"] == selected_status)

    filtered_data = raw_data[mask].copy()

    is_filtered = (selected_service != "All Services") or (selected_traffic != "All Traffic") or (selected_status != "All Statuses")
    if is_filtered:
        st.sidebar.markdown(
            f"<div style='font-size: 0.78rem; color: #38bdf8; font-family: monospace; margin-top: 8px;'>"
            f"Active: {len(filtered_data):,} of {len(raw_data):,} events"
            f"</div>",
            unsafe_allow_html=True,
        )

# Project Metadata in Sidebar (No academic/student names)
st.sidebar.markdown("<hr style='border: 0; border-top: 1px solid #27354a; margin: 16px 0;'>", unsafe_allow_html=True)
st.sidebar.markdown(
    """
    <div style='font-size: 0.75rem; color: #94a3b8; line-height: 1.45;'>
        <div><b>System:</b> CloudForce Visualizer</div>
        <div><b>Telemetry Mode:</b> Synthetic Simulation</div>
        <div style='margin-top: 6px; color: #64748b;'>Simulated Authentication Telemetry</div>
    </div>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# 5. VIEW: SECURITY DASHBOARD
# -----------------------------------------------------------------------------
if nav_page == "Security Dashboard":
    # Header Banner
    st.markdown(
        """
        <div style='display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 18px; border-bottom: 1px solid #27354a; padding-bottom: 12px;'>
            <div>
                <h2 style='margin: 0; font-size: 1.5rem; font-weight: 600; color: #e2e8f0;'>Security Overview</h2>
                <p style='margin: 4px 0 0 0; color: #94a3b8; font-size: 0.88rem;'>
                    Analysis of synthetic cloud authentication logs and credential-guessing activity.
                </p>
            </div>
            <div style='display: flex; gap: 8px;'>
                <span class='status-badge badge-info'>Mode: Simulation</span>
                <span class='status-badge badge-normal'>Data: Synchronized</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Empty State & File Error Handling
    if raw_data is None:
        st.error(f"Dataset load failure: {load_error}")
        st.info("The application requires 'cloudforce_logs.xlsx' containing authentication records.")
        
        c_fix, _ = st.columns([1, 2])
        with c_fix:
            if st.button("Generate Baseline Dataset", type="primary", use_container_width=True):
                with st.spinner("Generating 5,900 baseline logs..."):
                    generate_data(DATA_FILE)
                    st.cache_data.clear()
                    time.sleep(0.5)
                    st.rerun()
        st.stop()

    if filtered_data.empty:
        st.warning(
            f"No records match the active filters (Service: '{selected_service}', "
            f"Traffic: '{selected_traffic}', Status: '{selected_status}'). "
            "Broaden filter options in the sidebar to view data."
        )
        st.stop()

    # Dynamic KPI Metrics
    total_attempts = len(filtered_data)
    failed_sub = filtered_data[filtered_data["login_status"] == "Failed"]
    total_failed = len(failed_sub)
    failure_rate = (total_failed / total_attempts * 100) if total_attempts > 0 else 0.0

    # Top threat IP identification
    if not failed_sub.empty:
        top_ip_counts = failed_sub["ip_address"].value_counts()
        top_threat_ip = str(top_ip_counts.index[0])
        top_threat_failures = int(top_ip_counts.iloc[0])
    else:
        top_threat_ip = "None"
        top_threat_failures = 0

    # Breached administrative accounts in active view
    compromised_records = filtered_data[
        (filtered_data["traffic_type"] == "Brute-Force") &
        (filtered_data["login_status"] == "Success")
    ]
    breach_count = len(compromised_records)
    breached_users = compromised_records["user_id"].unique().tolist()

    # KPI Layout
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
    with kpi_col1:
        st.metric(
            label="Total Authentications",
            value=f"{total_attempts:,}",
            help="Total login events logged in the active view."
        )
    with kpi_col2:
        st.metric(
            label="Failed Logins",
            value=f"{total_failed:,}",
            delta=f"{failure_rate:.1f}% failure rate",
            delta_color="inverse",
            help="Rejected authentication attempts."
        )
    with kpi_col3:
        st.metric(
            label="Primary Source IP",
            value=top_threat_ip,
            delta=f"{top_threat_failures:,} failures" if top_threat_failures > 0 else "0 failures",
            delta_color="inverse" if top_threat_failures > 50 else "off",
            help="IP address with the highest number of failed login attempts."
        )
    with kpi_col4:
        breach_label = f"{breach_count} account" if breach_count == 1 else f"{breach_count} accounts"
        st.metric(
            label="Compromised Identities",
            value=breach_label,
            delta="Breach detected" if breach_count > 0 else "No breaches",
            delta_color="inverse" if breach_count > 0 else "normal",
            help="Targeted accounts successfully accessed via brute-force attack."
        )

    # Dynamic Alert Panel
    bf_slice = filtered_data[filtered_data["traffic_type"] == "Brute-Force"]
    if not bf_slice.empty:
        bf_ips = bf_slice["ip_address"].unique().tolist()
        bf_countries = bf_slice["country"].unique().tolist()
        bf_services = bf_slice["cloud_service"].unique().tolist()
        bf_targets = bf_slice["user_id"].unique().tolist()
        bf_min_ts = bf_slice["timestamp"].min()
        bf_max_ts = bf_slice["timestamp"].max()
        bf_duration_min = max(0.5, (bf_max_ts - bf_min_ts).total_seconds() / 60.0)
        bf_velocity = len(bf_slice) / bf_duration_min

        st.markdown(
            f"""
            <div style='background-color: #1a1622; border: 1px solid #ef4444; border-left: 4px solid #ef4444; border-radius: 4px; padding: 14px 18px; margin: 18px 0 14px 0;'>
                <div style='display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;'>
                    <span style='font-size: 0.88rem; font-weight: 600; color: #ef4444; text-transform: uppercase; letter-spacing: 0.04em;'>
                        High-Severity Finding: Concentrated Credential Guessing
                    </span>
                    <span style='font-size: 0.76rem; color: #94a3b8; font-family: monospace;'>Simulated Event</span>
                </div>
                <div style='font-size: 0.86rem; color: #e2e8f0; line-height: 1.5;'>
                    The active dataset reflects a high-frequency authentication surge from IP 
                    <code class='mono-text'>{', '.join(bf_ips)}</code> ({', '.join(bf_countries)}) 
                    targeting <b>{', '.join(bf_services)}</b> accounts ({', '.join([f'<code>{u}</code>' for u in bf_targets])}). 
                    A total of {len(bf_slice):,} attempts occurred across a {bf_duration_min:.1f}-minute window 
                    (~{bf_velocity:.1f} attempts/min). 
                    Outcome: {'<span style=\"color:#ef4444; font-weight:600;\">Final attempt succeeded (' + ', '.join(breached_users) + ' compromised)</span>' if breach_count > 0 else 'All attempts rejected'}.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style='background-color: #161f2e; border: 1px solid #27354a; border-radius: 4px; padding: 10px 16px; margin: 14px 0;'>
                <span style='color: #94a3b8; font-size: 0.84rem;'>
                    <b>Normal Baseline:</b> No simulated brute-force telemetry detected within the active filter combination.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Middle Row: Timeline Chart
    st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
    timeline_fig = build_failed_logins_timeline(filtered_data)
    st.plotly_chart(timeline_fig, use_container_width=True)

    # Bottom Row: Two Equal-Width Analytical Visuals
    col_chart_left, col_chart_right = st.columns([1, 1])
    with col_chart_left:
        ips_fig = build_top_attacking_ips(filtered_data, top_n=10)
        st.plotly_chart(ips_fig, use_container_width=True)

    with col_chart_right:
        map_fig = build_attack_origins_map(filtered_data)
        st.plotly_chart(map_fig, use_container_width=True)

    # Analytical Observations & Mitigation Reference
    st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
    with st.expander("Analytical Observations and Recommended Mitigations", expanded=False):
        f1, f2 = st.columns(2)
        with f1:
            st.markdown(
                """
                **Statistical Observations (Simulated Scenario)**
                - **Volume Disparity:** Normal hourly failures average 0–7 events (median ~2/hour). During the simulated attack window, failures surge by two orders of magnitude.
                - **Request Velocity:** The calculated rate (~45 attempts/minute) exceeds plausible human interaction, indicating an automated script.
                - **Target Concentration:** Benign traffic is distributed across 200 standard user IDs; the adversary focused strictly on administrative credentials (`ADMIN_01`, `ADMIN_02`, `ROOT_USER`).
                - **Detection Threshold:** A condition flagging `>10 failures per IP within 1 hour` cleanly identifies the anomaly in this baseline dataset.
                """
            )
        with f2:
            st.markdown(
                """
                **Recommended Mitigation Policies**
                1. **Account Lockout Thresholds:** Enforce temporary lockout (e.g. 15 minutes) after 5 consecutive failed attempts on any single account.
                2. **Endpoint Rate Limiting:** Implement IP-level rate limiting on identity endpoints to throttle automated guessing scripts.
                3. **FIDO2 Hardware MFA:** Require multi-factor authentication for administrative consoles to prevent single-factor password compromises.
                4. **Conditional Access Policies:** Restrict privileged administrative logins to approved corporate IP ranges and authorized geographies.
                """
            )


# -----------------------------------------------------------------------------
# 6. VIEW: SIMULATION ENGINE
# -----------------------------------------------------------------------------
elif nav_page == "Simulation Engine":
    st.markdown(
        """
        <div style='border-bottom: 1px solid #27354a; padding-bottom: 12px; margin-bottom: 18px;'>
            <h2 style='margin: 0; font-size: 1.5rem; font-weight: 600; color: #e2e8f0;'>Simulation Engine</h2>
            <p style='margin: 4px 0 0 0; color: #94a3b8; font-size: 0.88rem;'>
                Configure and generate synthetic cloud authentication logs with controlled intrusion parameters.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    sim_col1, sim_col2 = st.columns([1.25, 0.75])

    with sim_col1:
        st.markdown("<div style='font-size: 0.92rem; font-weight: 600; color: #e2e8f0; margin-bottom: 8px;'>Simulation Parameters</div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style='font-size: 0.82rem; color: #94a3b8; margin-bottom: 12px;'>
                All settings below directly control the NumPy synthetic generation pipeline.
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.form("simulation_form"):
            c_p1, c_p2 = st.columns(2)
            with c_p1:
                form_normal_events = st.number_input(
                    "Normal Authentication Events",
                    min_value=1000,
                    max_value=25000,
                    value=5000,
                    step=500,
                    help="Volume of benign multi-user logins across 7 days."
                )
                form_sim_seed = st.number_input(
                    "Random Generator Seed",
                    min_value=1,
                    max_value=99999,
                    value=42,
                    step=1,
                    help="Seed for deterministic generation (Project default is 42)."
                )
                form_attack_country = st.selectbox(
                    "Attacker Origin Country",
                    list(COUNTRY_GEOLOCATION.keys()),
                    index=list(COUNTRY_GEOLOCATION.keys()).index("Russia") if "Russia" in COUNTRY_GEOLOCATION else 0,
                    help="Country assigned to the brute-force traffic."
                )
            with c_p2:
                form_attack_events = st.number_input(
                    "Injected Attack Attempts",
                    min_value=100,
                    max_value=5000,
                    value=900,
                    step=100,
                    help="Number of automated password attempts injected into the attack window."
                )
                form_attack_service = st.selectbox(
                    "Target Cloud Service",
                    CLOUD_SERVICES,
                    index=0,
                    help="Cloud authentication platform targeted."
                )
                form_attack_ip = st.text_input(
                    "Attacker Source IPv4",
                    value="185.220.101.45",
                    help="Source IP address simulated for the brute-force attack."
                )

            form_target_users = st.multiselect(
                "Target Privileged Accounts",
                options=["ADMIN_01", "ADMIN_02", "ROOT_USER", "SUPER_ADMIN", "DEVOPS_LEAD"],
                default=["ADMIN_01", "ADMIN_02", "ROOT_USER"],
                help="Privileged accounts targeted during the attack."
            )

            st.markdown("<div style='margin-top: 8px;'></div>", unsafe_allow_html=True)
            submit_generate = st.form_submit_button(
                "Generate Telemetry Dataset",
                type="primary",
                use_container_width=True,
            )

        # Handle form submission
        if submit_generate:
            if not form_target_users:
                st.error("Please select at least one target administrative account.")
            else:
                with st.spinner("Generating synthetic telemetry dataset..."):
                    start_time = time.time()
                    try:
                        df_new = generate_data(
                            output_path=DATA_FILE,
                            seed=int(form_sim_seed),
                            n_normal=int(form_normal_events),
                            n_attack=int(form_attack_events),
                            attack_service=form_attack_service,
                            attack_ip=form_attack_ip.strip(),
                            attack_country=form_attack_country,
                            target_accounts=form_target_users,
                        )
                        elapsed = time.time() - start_time

                        # Clear data cache and reload
                        st.cache_data.clear()
                        st.success(
                            f"Generation complete in {elapsed:.2f}s. "
                            f"Created {len(df_new):,} records "
                            f"({(df_new['login_status'] == 'Failed').sum():,} failures). "
                            f"Saved to '{DATA_FILE.name}'."
                        )
                        time.sleep(0.8)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Synthesis error: {e}")

        st.markdown("<div style='margin-top: 8px;'></div>", unsafe_allow_html=True)
        if st.button("Reset to Baseline Scenario (5,900 Rows, Seed 42)", use_container_width=True):
            with st.spinner("Restoring baseline dataset..."):
                generate_data(
                    output_path=DATA_FILE,
                    seed=42,
                    n_normal=5000,
                    n_attack=900,
                    attack_service="AWS Console",
                    attack_ip="185.220.101.45",
                    attack_country="Russia",
                    target_accounts=["ADMIN_01", "ADMIN_02", "ROOT_USER"],
                )
                st.cache_data.clear()
                time.sleep(0.5)
                st.rerun()

    with sim_col2:
        st.markdown("<div style='font-size: 0.92rem; font-weight: 600; color: #e2e8f0; margin-bottom: 8px;'>Active Dataset Summary</div>", unsafe_allow_html=True)
        if raw_data is not None:
            normal_ct = (raw_data['traffic_type'] == 'Normal').sum()
            attack_ct = (raw_data['traffic_type'] == 'Brute-Force').sum()
            failed_ct = (raw_data['login_status'] == 'Failed').sum()
            success_ct = (raw_data['login_status'] == 'Success').sum()
            services_ct = raw_data['cloud_service'].nunique()

            st.markdown(
                f"""
                <div class='dashboard-panel'>
                    <div style='font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: #94a3b8; margin-bottom: 8px;'>
                        Dataset Properties
                    </div>
                    <ul style='color: #e2e8f0; font-size: 0.84rem; padding-left: 18px; margin: 0; line-height: 1.6;'>
                        <li><b>File:</b> <code class='mono-text'>{DATA_FILE.name}</code></li>
                        <li><b>Total Rows:</b> {len(raw_data):,}</li>
                        <li><b>Normal Events:</b> {normal_ct:,}</li>
                        <li><b>Attack Events:</b> {attack_ct:,}</li>
                        <li><b>Failed Attempts:</b> {failed_ct:,}</li>
                        <li><b>Successful Logins:</b> {success_ct:,}</li>
                        <li><b>Target Services:</b> {services_ct} platforms</li>
                        <li><b>Date Range:</b> {raw_data['timestamp'].min().strftime('%Y-%m-%d')} to {raw_data['timestamp'].max().strftime('%Y-%m-%d')}</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.info("No active dataset found on disk. Use the form to generate one.")


# -----------------------------------------------------------------------------
# 7. VIEW: RAW TELEMETRY
# -----------------------------------------------------------------------------
elif nav_page == "Raw Telemetry":
    st.markdown(
        """
        <div style='border-bottom: 1px solid #27354a; padding-bottom: 12px; margin-bottom: 18px;'>
            <h2 style='margin: 0; font-size: 1.5rem; font-weight: 600; color: #e2e8f0;'>Raw Telemetry Logs</h2>
            <p style='margin: 4px 0 0 0; color: #94a3b8; font-size: 0.88rem;'>
                Inspect individual simulated authentication records, filter by adversary attributes, and export logs.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if raw_data is None:
        st.error(f"Dataset load failure: {load_error}")
        st.stop()

    # Search & Page size controls
    search_c1, search_c2 = st.columns([3, 1])
    with search_c1:
        search_term = st.text_input("Filter records by IP, user, country, or service", placeholder="e.g. 185.220.101.45, ROOT_USER, Russia, AWS Console")
    with search_c2:
        row_limit = st.selectbox("Display Limit", [100, 500, 1000, 2500, "All Records"], index=1)

    display_df = filtered_data.copy()
    if search_term:
        st_term = search_term.strip().lower()
        search_mask = (
            display_df["ip_address"].astype(str).str.lower().str.contains(st_term) |
            display_df["user_id"].astype(str).str.lower().str.contains(st_term) |
            display_df["country"].astype(str).str.lower().str.contains(st_term) |
            display_df["cloud_service"].astype(str).str.lower().str.contains(st_term) |
            display_df["login_status"].astype(str).str.lower().str.contains(st_term) |
            display_df["traffic_type"].astype(str).str.lower().str.contains(st_term)
        )
        display_df = display_df[search_mask]

    st.markdown(
        f"<div style='font-size: 0.8rem; color: #94a3b8; margin-bottom: 8px;'>"
        f"Showing <b>{len(display_df):,}</b> matching records (Filtered from {len(raw_data):,} total rows)</div>",
        unsafe_allow_html=True,
    )

    view_slice = display_df if row_limit == "All Records" else display_df.head(int(row_limit))

    # Formatted interactive table
    st.dataframe(
        view_slice,
        use_container_width=True,
        hide_index=True,
        column_config={
            "log_id": st.column_config.NumberColumn("Log ID", format="%d"),
            "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
            "ip_address": st.column_config.TextColumn("IP Address"),
            "country": st.column_config.TextColumn("Country"),
            "user_id": st.column_config.TextColumn("User Account"),
            "cloud_service": st.column_config.TextColumn("Cloud Service"),
            "login_status": st.column_config.TextColumn("Status"),
            "traffic_type": st.column_config.TextColumn("Traffic Type"),
            "latitude": st.column_config.NumberColumn("Latitude", format="%.2f"),
            "longitude": st.column_config.NumberColumn("Longitude", format="%.2f"),
            "hour_bucket": st.column_config.DatetimeColumn("Hour Bucket", format="YYYY-MM-DD HH:00"),
        },
    )

    # Export controls
    st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
    exp_c1, exp_c2, _ = st.columns([1, 1, 2])
    with exp_c1:
        csv_bytes = display_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Export CSV",
            data=csv_bytes,
            file_name="cloudforce_telemetry_export.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with exp_c2:
        xlsx_buffer = io.BytesIO()
        with pd.ExcelWriter(xlsx_buffer, engine="openpyxl") as writer:
            display_df.to_excel(writer, index=False, sheet_name="Exported_Logs")
        st.download_button(
            label="Export Excel",
            data=xlsx_buffer.getvalue(),
            file_name="cloudforce_telemetry_export.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )

    # Schema & Column Reference
    st.markdown("<div style='margin-top: 12px;'></div>", unsafe_allow_html=True)
    with st.expander("Telemetry Schema and Column Descriptions", expanded=False):
        st.markdown(
            """
            | Column Name | Data Type | Description |
            | :--- | :--- | :--- |
            | `log_id` | Integer | Unique identifier for each authentication record (1 to N). |
            | `timestamp` | Datetime | Timestamp of the authentication attempt (UTC). |
            | `ip_address` | String (IPv4) | Source IP address originating the transaction. |
            | `country` | String | Sovereign jurisdiction mapped from the source IP address. |
            | `user_id` | String | Target username or identity identifier. |
            | `cloud_service` | String | Cloud platform targeted (`AWS Console`, `Azure AD`, `Google Cloud IAM`, `Office 365`). |
            | `login_status` | String | Outcome: `Success` or `Failed`. |
            | `traffic_type` | String | Ground-truth simulation label: `Normal` or `Brute-Force`. |
            | `latitude` | Float | Representative latitude coordinate for geographic visualization. |
            | `longitude` | Float | Representative longitude coordinate for geographic visualization. |
            | `hour_bucket` | Datetime | Timestamp rounded to the hour for time-series aggregation. |
            """
        )
