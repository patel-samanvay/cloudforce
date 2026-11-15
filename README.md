# CloudForce: Cloud Authentication Attack Surface & Brute-Force Visualizer

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://cloudforce.streamlit.app)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)]()
[![Platform](https://img.shields.io/badge/Framework-Streamlit-FF4B4B.svg?logo=streamlit&logoColor=white)]()
[![Analytics](https://img.shields.io/badge/Visuals-Plotly-3F4F75.svg?logo=plotly&logoColor=white)]()
[![BI](https://img.shields.io/badge/BI-Power%20BI-F2C811.svg?logo=powerbi&logoColor=black)]()

> **Interactive Threat Intelligence Platform:** A full-stack cybersecurity telemetry generator and visual analytics dashboard designed to model, detect, and analyze cloud authentication attack surfaces and high-velocity brute-force intrusions.

Authors: V.Mouli (240031101631054) & Samanvay Patel (240031101631040)
B.Tech CSE Sem-5 | SITAICS | Rashtriya Raksha University Gandhinagar

🔗 **Live Interactive Application:** [https://cloudforce.streamlit.app](https://cloudforce.streamlit.app)

---

## 📌 Executive Summary

Cloud identity endpoints (AWS Management Console, Microsoft Azure AD, Google Cloud IAM, Office 365) are primary targets in modern enterprise attack vectors. Because production authentication telemetry contains sensitive organizational data, **CloudForce** synthesizes a mathematically modeled 7-day multi-cloud authentication stream with an injected credential-exhaustion attack.

The platform provides end-to-end telemetry modeling, anomaly detection, statistical investigation, and visual intelligence through:
1. **Mathematical Telemetry Synthesis:** Generates realistic normal user authentication behavior combined with targeted adversary patterns using NumPy and pandas.
2. **SOC Web Dashboard:** An enterprise-grade, dark-themed Streamlit threat intelligence center with dynamic filtering, real-time KPI metrics, and anomaly investigation banners.
3. **Interactive Analytical Visualizations:** Resampled time-series failure timelines, ranked threat actor bar charts, and global scatter maps powered by Plotly.
4. **Live Simulation Engine:** An on-the-fly parameter tuning interface to re-synthesize attack scenarios and immediately observe forensic impacts.
5. **Business Intelligence Integration:** A pre-configured Power BI Desktop report (`CloudForce.pbix`) paired with a custom dark theme (`cloudforce_theme.json`).

---

## 🏛️ System Architecture & Data Flow

```
                           ┌─────────────────────────────────────┐
                           │     generate_cloudforce_data.py     │
                           │   NumPy / Pandas Generator Engine   │
                           └──────────────────┬──────────────────┘
                                              │
                                    Generates │ Canonical Dataset
                                              ▼
                                ┌───────────────────────────┐
                                │   cloudforce_logs.xlsx    │
                                │     (Sheet: "Logs")       │
                                └─────────────┬─────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
                    ▼                         ▼                         ▼
       ┌─────────────────────────┐ ┌────────────────────┐ ┌─────────────────────────┐
       │ visualize_cloudforce.py │ │   CloudForce.pbix  │ │         app.py          │
       │   Plotly Express Engine │ │  Power BI Desktop  │ │ Streamlit Threat Center │
       └────────────┬────────────┘ └──────────┬─────────┘ └────────────┬────────────┘
                    │                         │                        │
        Standalone HTML Charts       Interactive BI Model      Live Cloud Application
        - chart1_timeline.html       - cloudforce_theme.json   - Dynamic IoC Banners
        - chart2_top_ips.html                                  - Real-time Filters & KPIs
                                                               - Live Simulation Form
                                                               - Raw Log Search & Export
```

---

## 📊 Dataset Schema (`cloudforce_logs.xlsx`)

The canonical dataset consists of **5,900 records** across **11 telemetry dimensions**, persisted in the `Logs` sheet:

| Field | Type | Sample Value | Description |
| :--- | :--- | :--- | :--- |
| `log_id` | Integer | `1042` | Unique autoincrementing record identifier. |
| `timestamp` | Datetime | `2026-11-04 02:14:12` | UTC timestamp of the authentication attempt. |
| `ip_address` | String | `185.220.101.45` | Source IPv4 address originating the request. |
| `country` | String | `Russia` | Geolocation mapped from source IP address. |
| `user_id` | String | `ROOT_USER` | Targeted identity (`USER_1`–`USER_200`, `ADMIN_01`, `ADMIN_02`, `ROOT_USER`). |
| `cloud_service` | String | `AWS Console` | Identity endpoint (`AWS Console`, `Azure AD`, `Google Cloud IAM`, `Office 365`). |
| `login_status` | String | `Failed` | Authentication result: `Success` or `Failed`. |
| `traffic_type` | String | `Brute-Force` | Ground-truth simulation label: `Normal` or `Brute-Force`. |
| `latitude` | Float | `61.5240` | Representative latitude coordinate for geographic mapping. |
| `longitude` | Float | `105.3188` | Representative longitude coordinate for geographic mapping. |
| `hour_bucket` | Datetime | `2026-11-04 02:00:00` | Hourly floored timestamp for time-series aggregation. |

---

## 🔍 Threat Scenario & Empirical Findings

### Baseline Normal Telemetry (5,000 Records)
* **Temporal Span:** 7 continuous days (Nov 1 – Nov 7, 2026).
* **Geographic Distribution:** Multi-national spread across 10 sovereign nations (India 30%, USA 20%, UK 10%, Germany 8%, etc.).
* **Error Rate:** ~7.6% natural baseline failure rate simulating common user typos and transient network timeouts.
* **Service Allocation:** Uniformly distributed across AWS, Azure, Google Cloud, and Office 365.

### Injected Brute-Force Intrusion (900 Records)
* **Adversary Profile:** Single persistent adversary IP: `185.220.101.45` (Russia).
* **Target Objective:** `AWS Console` targeting privileged identities (`ADMIN_01`, `ADMIN_02`, `ROOT_USER`).
* **Velocity Anomaly:** 900 authentication attempts compressed into a **20-minute window** (`2026-11-04 02:00:00` to `2026-11-04 02:19:59`) at an attack velocity of **45 attempts/minute**.
* **Breach Progression:** Attempts 1 through 899 are rejected (`Failed`). Attempt #900 at index 5,899 succeeds (`Success` on `ROOT_USER`), modeling a successful credential compromise.

### Key Forensic Insights
1. **Extreme Velocity Anomaly:** Hourly authentication failure volume surges from a baseline median of **2 failures/hour** to **900 failures in a single hour** (>100× spike).
2. **Service Skew:** AWS Console absorbs **78.2% of all authentication failures** across the entire 7-day period.
3. **Geographic Concentration:** Traffic originating from Russia displays an **80.2% failure rate**, compared to a **7.3%** combined failure rate across all other nations.
4. **Deterministic Rule Flag:** A simple threshold rule (`failures.groupby(['ip_address', 'hour_bucket']).size() > 10`) identifies the adversary IP with zero false positives.

---

## 🖥️ Web Application Tour (`app.py`)

The Streamlit web application is structured into three dedicated functional modules:

### 1. Security Dashboard
* **Dynamic Header & Status Badges:** Displays active simulation metadata, synchronized status, and live dataset row counters.
* **Top Metric Cards:** 
  * Total Authentication Telemetry
  * Normal Authentication Traffic
  * Simulated Attack Incidents (and failure percentage)
  * System Breach Status (highlighting compromised identities in critical crimson)
* **Dynamic Incident Investigation Banner:** Automatically extracts attacker IP, target cloud service, burst duration, velocity, and compromise status directly from the active dataset.
* **Interactive Visualizations:**
  * **Failure Timeline:** Full-width hourly velocity chart isolating the attack spike.
  * **Top Attacking IPs:** Ranked horizontal bar chart highlighting threat sources with count labels.
  * **Geographic Map:** Dark Carto-based bubble map representing failure origin hotspots.

### 2. Simulation Engine
* **Interactive Scenario Controls:** Adjust Normal Event Count, Attack Duration, Attack Event Count, Attacker IP (with IPv4 validation), and Target Cloud Service.
* **Seed Reproducibility:** Pin random seed for consistent demonstrations.
* **One-Click Reset:** "Restore Default Scenario" button to regenerate the canonical 5,900-record baseline.

### 3. Raw Telemetry Explorer
* **Dynamic Filtering:** Search across IP addresses, user IDs, and countries.
* **Forensic Auditing:** Inspect granular log fields with formatted status badges.
* **Dual Format Export:** One-click downloads for **CSV** and formatted **Excel (.xlsx)**.

---

## ⚡ Quickstart & Local Installation

### Prerequisites
* Python 3.10, 3.11, 3.12, or 3.13
* Windows, macOS, or Linux

### 1. Clone the Repository
```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/CloudForce.git
cd CloudForce
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Application
```bash
streamlit run app.py
```
The application will launch in your default browser at `http://localhost:8501`.

---

## 🛠️ CLI Pipeline & Standalone Visuals

If you prefer running the data processing and visualization pipeline from the command line:

```bash
# Step 1: Synthesize the dataset (outputs cloudforce_logs.xlsx)
python generate_cloudforce_data.py

# Step 2: Build standalone interactive HTML charts
python visualize_cloudforce.py

# Step 3 (Windows): Run the full master orchestration script
python run_all.py
```

Generated standalone deliverables:
* `chart1_failed_logins_timeline.html`: Interactive hourly failure timeline.
* `chart2_top_attacking_ips.html`: Interactive top attacking IP bar chart.
* `cloudforce_theme.json`: Power BI JSON theme file.

---

## 📈 Power BI Desktop Integration

A ready-to-use Power BI dashboard is included in the root directory:

1. Open `CloudForce.pbix` in **Power BI Desktop**.
2. If prompted or if moving directories:
   * Go to **Home** > **Transform data** > **Data source settings**.
   * Select **Change Source** and browse to your local `cloudforce_logs.xlsx`.
   * Click **Close & Apply**.
3. To apply the unified dark design system, navigate to **View** > **Themes** > **Browse for themes** and select `cloudforce_theme.json`.

---

## 🛡️ Enterprise Defensive Recommendations

Based on the empirical findings from the CloudForce dataset, the following mitigation controls are recommended:

1. **Adaptive Account Lockout:** Automatically throttle or lock accounts for 15 minutes after 5 consecutive failed authentications.
2. **IP-Level API Rate Limiting:** Enforce API gateway rate limits (>10 requests/minute/IP) to prevent high-velocity scripted attacks.
3. **Mandatory FIDO2 Hardware MFA:** Eliminate single-factor password vulnerability on administrative and root identities.
4. **Conditional Access & Geo-fencing:** Restrict root and admin access to approved sovereign IP ranges or corporate VPN gateways.
5. **Automated SIEM Anomaly Alarms:** Trigger automated SOC alerting when hourly failure volume exceeds 10 attempts for a single identity or source IP.

---

## 📂 Repository File Structure

```
CloudForce/
│
├── .streamlit/
│   └── config.toml                  # Dark theme UI configuration
│
├── app.py                           # Main Streamlit SOC Web Application
├── generate_cloudforce_data.py      # Telemetry synthesis engine
├── visualize_cloudforce.py          # Plotly visualization module
├── run_all.py                       # Automated pipeline runner
│
├── cloudforce_logs.xlsx             # Canonical 5,900-row Excel dataset (Sheet: Logs)
├── cloudforce_theme.json            # Power BI dark theme definition
├── CloudForce.pbix                  # Power BI Desktop report
│
├── chart1_failed_logins_timeline.html  # Standalone interactive timeline
├── chart2_top_attacking_ips.html       # Standalone interactive bar chart
│
├── requirements.txt                 # Project dependencies
├── .gitignore                       # Git ignore configuration
└── README.md                        # Project documentation
```

---

## 📄 License & Simulation Notice

This project is created for educational research, threat modeling demonstrations, and visual analytics. All telemetry records, IP addresses, credentials, and attack patterns are synthetically generated.
