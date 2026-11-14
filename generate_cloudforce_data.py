# generate_cloudforce_data.py
# CloudForce: Cloud Authentication Attack Surface & Brute-Force Visualizer

from pathlib import Path
from typing import List, Optional, Union
import ipaddress
import numpy as np
import pandas as pd

# Default project directory resolution
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_FILE = BASE_DIR / "cloudforce_logs.xlsx"

# Standard reference geolocation coordinates for simulation countries
COUNTRY_GEOLOCATION = {
    "India":          (20.59,  78.96),
    "United States":  (37.09, -95.71),
    "United Kingdom": (55.38,  -3.44),
    "Germany":        (51.17,  10.45),
    "Singapore":      ( 1.35, 103.82),
    "Australia":      (-25.27, 133.78),
    "Brazil":         (-14.24, -51.93),
    "Russia":         (61.52, 105.32),
    "China":          (35.86, 104.20),
    "Nigeria":        ( 9.08,   8.68),
}

CLOUD_SERVICES = ["AWS Console", "Azure AD", "Google Cloud IAM", "Office 365"]


def generate_data(
    output_path: Optional[Union[str, Path]] = DEFAULT_DATA_FILE,
    seed: int = 42,
    n_normal: int = 5000,
    n_attack: int = 900,
    attack_service: str = "AWS Console",
    attack_ip: str = "185.220.101.45",
    attack_country: str = "Russia",
    target_accounts: Optional[List[str]] = None,
    attack_start: str = "2026-11-04 02:00:00",
    attack_duration_minutes: int = 20,
) -> pd.DataFrame:
    """
    Generates a synthetic cloud login log dataset with an injected brute-force attack.
    
    Simulation Model:
    - Normal traffic: Baseline multi-user activity over 7 days with realistic password typo rate (~8%).
    - Injected attack: Concentrated automated password-guessing attempts against privileged accounts.
    - Reproducibility: Fully deterministic when initialized with the specified random seed.
    """
    if target_accounts is None:
        target_accounts = ["ADMIN_01", "ADMIN_02", "ROOT_USER"]

    if not isinstance(n_normal, int) or n_normal < 0:
        raise ValueError("n_normal must be a non-negative integer.")
    if not isinstance(n_attack, int) or n_attack < 1:
        raise ValueError("n_attack must be a positive integer.")
    if not isinstance(attack_duration_minutes, int) or attack_duration_minutes < 1:
        raise ValueError("attack_duration_minutes must be a positive integer.")
    if not target_accounts or any(not str(account).strip() for account in target_accounts):
        raise ValueError("target_accounts must contain at least one non-empty account name.")
    try:
        ipaddress.IPv4Address(attack_ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"attack_ip must be a valid IPv4 address: {attack_ip!r}.") from exc
    if attack_country not in COUNTRY_GEOLOCATION:
        raise ValueError(f"attack_country must be one of: {', '.join(COUNTRY_GEOLOCATION)}.")
    if attack_service not in CLOUD_SERVICES:
        raise ValueError(f"attack_service must be one of: {', '.join(CLOUD_SERVICES)}.")

    rng = np.random.default_rng(seed=seed)

    # ------------------------------------------------------------------
    # 1. BASELINE NORMAL TRAFFIC (7 Days)
    # ------------------------------------------------------------------
    sim_start = pd.Timestamp("2026-11-01 00:00:00")
    total_seconds = 7 * 24 * 3600

    # Normal timestamps spread across 7 days
    normal_offsets = rng.integers(0, total_seconds, size=n_normal)
    normal_timestamps = sim_start + pd.to_timedelta(normal_offsets, unit="s")

    # Synthetic normal IPv4 generation (random unique IPs across internet address space)
    ip_octets = rng.integers(1, 255, size=(n_normal, 4))
    normal_ips = [".".join(map(str, row)) for row in ip_octets]

    # Weighted country distribution for realistic international traffic
    countries_list = list(COUNTRY_GEOLOCATION.keys())
    country_weights = [0.30, 0.20, 0.10, 0.08, 0.07, 0.06, 0.05, 0.05, 0.05, 0.04]
    normal_countries = rng.choice(countries_list, size=n_normal, p=country_weights)

    # Cloud services distribution
    normal_services = rng.choice(CLOUD_SERVICES, size=n_normal)

    # Standard workforce user accounts (USER_1 to USER_200)
    normal_users = np.char.add("USER_", rng.integers(1, 201, size=n_normal).astype(str))

    # Baseline success/failure distribution (92% success, 8% benign typo failure)
    normal_status = rng.choice(["Success", "Failed"], size=n_normal, p=[0.92, 0.08])

    normal_df = pd.DataFrame({
        "timestamp": normal_timestamps,
        "ip_address": normal_ips,
        "country": normal_countries,
        "user_id": normal_users,
        "cloud_service": normal_services,
        "login_status": normal_status,
        "traffic_type": "Normal",
    })

    # ------------------------------------------------------------------
    # 2. INJECTED BRUTE-FORCE ATTACK
    # ------------------------------------------------------------------
    attack_start_ts = pd.Timestamp(attack_start)
    duration_seconds = max(60, attack_duration_minutes * 60)

    # Keep the final successful event at the latest timestamp after sorting.
    attack_offsets = np.sort(rng.integers(0, duration_seconds, size=n_attack))
    attack_offsets[-1] = duration_seconds - 1
    attack_timestamps = attack_start_ts + pd.to_timedelta(attack_offsets, unit="s")

    # Attacker targets privileged identities
    attack_targets = np.array(target_accounts)
    attack_users = rng.choice(attack_targets, size=n_attack)

    # Every attempt is rejected except the last chronological attempt.
    attack_status = np.array(["Failed"] * (n_attack - 1) + ["Success"])

    attack_df = pd.DataFrame({
        "timestamp": attack_timestamps,
        "ip_address": attack_ip,
        "country": attack_country,
        "user_id": attack_users,
        "cloud_service": attack_service,
        "login_status": attack_status,
        "traffic_type": "Brute-Force",
    })

    # ------------------------------------------------------------------
    # 3. MERGE, ENRICH, AND SORT
    # ------------------------------------------------------------------
    df = pd.concat([normal_df, attack_df], ignore_index=True)
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Helper columns for analysis and visualization
    df.insert(0, "log_id", np.arange(1, len(df) + 1))
    
    # Map coordinates safely (fallback to 0.0, 0.0 if country not in lookup)
    df["latitude"] = df["country"].map(lambda c: COUNTRY_GEOLOCATION.get(c, (0.0, 0.0))[0])
    df["longitude"] = df["country"].map(lambda c: COUNTRY_GEOLOCATION.get(c, (0.0, 0.0))[1])
    df["hour_bucket"] = df["timestamp"].dt.floor("1h")

    # ------------------------------------------------------------------
    # 4. EXPORT WORKBOOK (SHEET: "Logs")
    # ------------------------------------------------------------------
    if output_path:
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        df.to_excel(out_file, index=False, sheet_name="Logs", engine="openpyxl")
        print(f"[CloudForce] Generated {len(df):,} records -> {out_file}")
        print(f"[CloudForce] Failed Logins: {(df['login_status'] == 'Failed').sum():,}")
        print(f"[CloudForce] Injected Adversary IP: {attack_ip} ({attack_country})")

    return df


if __name__ == "__main__":
    generate_data(DEFAULT_DATA_FILE)
