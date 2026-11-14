# run_all.py
# CloudForce: Cloud Authentication Attack Surface & Brute-Force Visualizer
# Runner script: generates data, builds charts, writes Power BI theme, and opens deliverables.

import json
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)


def run_script(script_name: str) -> None:
    script_path = BASE_DIR / script_name
    print(f"\n>>> [CloudForce Runner] Executing {script_name}...")
    subprocess.run([sys.executable, str(script_path)], check=True)


if __name__ == "__main__":
    print("=" * 70)
    print(" CloudForce: Authentication Security Analysis Pipeline")
    print("=" * 70)

    # 1. Synthesize dataset
    run_script("generate_cloudforce_data.py")

    # 2. Build Plotly Express interactive charts
    run_script("visualize_cloudforce.py")

    # 3. Ensure Power BI theme exists
    theme = {
        "name": "CloudForce Dark",
        "dataColors": [
            "#38BDF8",
            "#0284C7",
            "#EF4444",
            "#F59E0B",
            "#10B981",
            "#8B5CF6"
        ],
        "background": "#0F141C",
        "foreground": "#E2E8F0",
        "tableAccent": "#38BDF8",
        "visualStyles": {
            "page": {"*": {"background": [{"color": {"solid": {"color": "#0F141C"}}, "transparency": 0}]}},
            "*": {"*": {
                "background": [{"color": {"solid": {"color": "#161F2E"}}, "transparency": 0}],
                "title": [{"fontColor": {"solid": {"color": "#E2E8F0"}}}]
            }}
        }
    }
    theme_file = BASE_DIR / "cloudforce_theme.json"
    with open(theme_file, "w", encoding="utf-8") as f:
        json.dump(theme, f, indent=2)
    print(f"\n>>> [CloudForce Runner] Theme verified: {theme_file}")

    # 4. Open HTML charts in default browser
    for chart_name in ["chart1_failed_logins_timeline.html", "chart2_top_attacking_ips.html"]:
        chart_path = BASE_DIR / chart_name
        if chart_path.exists():
            webbrowser.open(chart_path.as_uri())
            time.sleep(0.5)

    # 5. Launch Power BI dashboard if on Windows and file is present
    pbix_file = BASE_DIR / "CloudForce.pbix"
    if pbix_file.exists():
        if hasattr(os, "startfile"):
            print(f">>> [CloudForce Runner] Opening Power BI Dashboard: {pbix_file.name}")
            os.startfile(str(pbix_file))
        else:
            print(f">>> [CloudForce Runner] Non-Windows environment detected. Open {pbix_file} manually in Power BI.")
    else:
        print(f">>> [CloudForce Runner] Note: {pbix_file} not found.")

    print("\n" + "=" * 70)
    print(" Pipeline complete. To launch the interactive web dashboard:")
    print(" streamlit run app.py")
    print("=" * 70)
