# visualize_cloudforce.py
# CloudForce: Cloud Authentication Attack Surface & Brute-Force Visualizer

from pathlib import Path
from typing import Optional
import sys
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_FILE = BASE_DIR / "cloudforce_logs.xlsx"

# Restrained palette aligned with Streamlit dark theme
PALETTE = {
    "bg": "#0f141c",
    "surface": "#161f2e",
    "border": "#27354a",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "accent": "#38bdf8",
    "critical": "#ef4444",
    "warning": "#f59e0b",
    "normal": "#10b981",
    "font_main": "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    "font_mono": "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
}


def _build_empty_figure(title: str, message: str = "No data available for the active selection.") -> go.Figure:
    """Creates a consistent, restrained empty state chart."""
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        showarrow=False,
        font=dict(color=PALETTE["muted"], size=12, family=PALETTE["font_main"]),
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
    )
    fig.update_layout(
        template="plotly_dark",
        title=dict(
            text=f"<b>{title}</b>",
            font=dict(color=PALETTE["text"], size=13, family=PALETTE["font_main"]),
            x=0.02,
            y=0.95,
        ),
        paper_bgcolor=PALETTE["surface"],
        plot_bgcolor=PALETTE["bg"],
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(l=30, r=30, t=45, b=30),
        height=360,
    )
    return fig


def build_failed_logins_timeline(df: pd.DataFrame) -> go.Figure:
    """
    Builds a time-series line chart of failed login attempts grouped by hour.
    """
    title_text = "Failed Login Attempts over Time (Hourly Buckets)"
    if df is None or df.empty:
        return _build_empty_figure(title_text, "No telemetry data provided.")

    failed = df[df["login_status"] == "Failed"].copy()
    if failed.empty:
        return _build_empty_figure(title_text, "Zero failed login events found in active selection.")

    try:
        failed["timestamp"] = pd.to_datetime(failed["timestamp"])
        hourly = (
            failed.set_index("timestamp")
            .resample("1h")
            .size()
            .reset_index(name="failed_attempts")
        )

        fig = px.line(
            hourly,
            x="timestamp",
            y="failed_attempts",
            title=f"<b>{title_text}</b>",
            labels={"timestamp": "Timestamp (UTC)", "failed_attempts": "Failed Attempts"},
            template="plotly_dark",
        )
        fig.update_traces(
            line=dict(color=PALETTE["accent"], width=2),
            mode="lines",
            hovertemplate="<b>Time:</b> %{x|%Y-%m-%d %H:%M}<br><b>Failed Logins:</b> %{y:,}<extra></extra>",
        )

        # Highlight anomaly peak if significantly elevated
        max_val = hourly["failed_attempts"].max()
        mean_val = hourly["failed_attempts"].mean()
        if max_val > 15 and (max_val > 2.5 * mean_val):
            max_idx = hourly["failed_attempts"].idxmax()
            max_row = hourly.loc[max_idx]
            fig.add_annotation(
                x=max_row["timestamp"],
                y=max_row["failed_attempts"],
                text=f"Peak: {max_row['failed_attempts']:,} failures ({max_row['timestamp'].strftime('%b %d, %H:%M')})",
                showarrow=True,
                arrowhead=2,
                arrowcolor=PALETTE["critical"],
                arrowsize=1.0,
                arrowwidth=1.5,
                ax=30,
                ay=-35,
                bgcolor=PALETTE["surface"],
                bordercolor=PALETTE["critical"],
                borderwidth=1,
                font=dict(color=PALETTE["critical"], size=11, family=PALETTE["font_mono"]),
            )

        fig.update_layout(
            paper_bgcolor=PALETTE["surface"],
            plot_bgcolor=PALETTE["bg"],
            font=dict(color=PALETTE["text"], family=PALETTE["font_main"]),
            title=dict(x=0.02, y=0.95, font=dict(size=13, color=PALETTE["text"])),
            xaxis=dict(
                title=dict(text="Timestamp (UTC)", font=dict(color=PALETTE["muted"], size=11)),
                gridcolor=PALETTE["border"],
                showgrid=True,
                tickfont=dict(color=PALETTE["muted"], size=10),
            ),
            yaxis=dict(
                title=dict(text="Failed Attempts", font=dict(color=PALETTE["muted"], size=11)),
                gridcolor=PALETTE["border"],
                showgrid=True,
                tickfont=dict(color=PALETTE["muted"], size=10),
            ),
            margin=dict(l=50, r=30, t=45, b=40),
            height=360,
        )
        return fig
    except Exception as e:
        print(f"[CloudForce] Timeline rendering error: {e}", file=sys.stderr)
        return _build_empty_figure(title_text, "Unable to render timeline for current selection.")


def build_top_attacking_ips(df: pd.DataFrame, top_n: int = 10) -> go.Figure:
    """
    Builds a horizontal bar chart displaying top source IPs sorted by failed attempts.
    """
    title_text = f"Top {top_n} Source IPs by Failed Attempts"
    if df is None or df.empty:
        return _build_empty_figure(title_text, "No telemetry data provided.")

    failed = df[df["login_status"] == "Failed"]
    if failed.empty:
        return _build_empty_figure(title_text, "Zero failed login events found in active selection.")

    try:
        top_ips = failed["ip_address"].value_counts().head(top_n).reset_index()
        top_ips.columns = ["ip_address", "failed_attempts"]

        if top_ips.empty:
            return _build_empty_figure(title_text, "No IP records identified.")

        # Outlier highlighting: critical anomaly in red, others in accent blue
        mean_failures = top_ips["failed_attempts"].mean()
        colors = [
            PALETTE["critical"] if count > max(10, mean_failures * 2) else PALETTE["accent"]
            for count in top_ips["failed_attempts"]
        ]

        fig = px.bar(
            top_ips,
            x="failed_attempts",
            y="ip_address",
            orientation="h",
            title=f"<b>Top {len(top_ips)} Source IPs by Failed Attempts</b>",
            labels={"ip_address": "Source IP", "failed_attempts": "Failed Attempts"},
            template="plotly_dark",
            text="failed_attempts",
        )
        fig.update_traces(
            marker_color=colors,
            marker_line_color=PALETTE["border"],
            marker_line_width=1,
            textposition="outside",
            cliponaxis=False,
            textfont=dict(family=PALETTE["font_mono"], size=10, color=PALETTE["text"]),
            hovertemplate="<b>IP:</b> %{y}<br><b>Failed Logins:</b> %{x:,}<extra></extra>",
        )

        # Leave room after the longest bar for its outside count label.
        max_failures = int(top_ips["failed_attempts"].max())
        fig.update_xaxes(range=[0, max_failures * 1.18 if max_failures > 0 else 1])

        # A ranked chart is visually uninformative when every source is tied.
        if top_ips["failed_attempts"].nunique() == 1 and int(top_ips["failed_attempts"].iloc[0]) == 1:
            fig.add_annotation(
                text="All displayed sources have 1 failure; their order is arbitrary.",
                showarrow=False,
                xref="paper",
                yref="paper",
                x=0.5,
                y=-0.22,
                font=dict(color=PALETTE["muted"], size=10, family=PALETTE["font_main"]),
            )
        fig.update_layout(
            paper_bgcolor=PALETTE["surface"],
            plot_bgcolor=PALETTE["bg"],
            font=dict(color=PALETTE["text"], family=PALETTE["font_main"]),
            title=dict(x=0.02, y=0.95, font=dict(size=13, color=PALETTE["text"])),
            xaxis=dict(
                title=dict(text="Failed Attempts", font=dict(color=PALETTE["muted"], size=11)),
                gridcolor=PALETTE["border"],
                showgrid=True,
                tickfont=dict(color=PALETTE["muted"], size=10),
            ),
            yaxis=dict(
                title=dict(text="Source IP", font=dict(color=PALETTE["muted"], size=11)),
                type="category",
                autorange="reversed",
                gridcolor=PALETTE["border"],
                tickfont=dict(family=PALETTE["font_mono"], color=PALETTE["text"], size=10),
            ),
            margin=dict(l=110, r=55, t=45, b=58 if top_ips["failed_attempts"].nunique() == 1 and int(top_ips["failed_attempts"].iloc[0]) == 1 else 40),
            height=360,
        )
        return fig
    except Exception as e:
        print(f"[CloudForce] Top IPs rendering error: {e}", file=sys.stderr)
        return _build_empty_figure(title_text, "Unable to render IP distribution for current selection.")


def build_attack_origins_map(df: pd.DataFrame) -> go.Figure:
    """
    Builds a geographic bubble map showing the origin of failed login attempts.
    """
    title_text = "Geographic Distribution of Failed Authentications"
    if df is None or df.empty:
        return _build_empty_figure(title_text, "No telemetry data provided.")

    failed = df[df["login_status"] == "Failed"]
    if failed.empty:
        return _build_empty_figure(title_text, "Zero failed login events found in active selection.")

    try:
        # The generator uses (0, 0) as its fallback for countries without a
        # coordinate. Do not plot that fallback as a real location.
        valid_geo = failed[
            failed["latitude"].between(-90, 90)
            & failed["longitude"].between(-180, 180)
            & ~((failed["latitude"] == 0) & (failed["longitude"] == 0))
        ]
        if valid_geo.empty:
            return _build_empty_figure(title_text, "No valid geographic coordinates in the active selection.")

        geo = (
            valid_geo.groupby(["country", "latitude", "longitude"])
            .agg(
                failed_attempts=("log_id", "count"),
                services=("cloud_service", lambda s: ", ".join(sorted(s.unique()))),
            )
            .reset_index()
        )

        map_kwargs = dict(
            lat="latitude",
            lon="longitude",
            size="failed_attempts",
            color="failed_attempts",
            hover_name="country",
            hover_data={
                "failed_attempts": ":,",
                "services": True,
                "latitude": False,
                "longitude": False,
            },
            color_continuous_scale=[
                [0.0, PALETTE["accent"]],
                [0.3, PALETTE["warning"]],
                [1.0, PALETTE["critical"]],
            ],
            size_max=32,
            zoom=0.75,
            title=f"<b>{title_text}</b>",
        )

        if hasattr(px, "scatter_map"):
            fig = px.scatter_map(geo, map_style="carto-darkmatter", **map_kwargs)
        else:
            fig = px.scatter_mapbox(geo, mapbox_style="carto-darkmatter", **map_kwargs)

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor=PALETTE["surface"],
            font=dict(color=PALETTE["text"], family=PALETTE["font_main"]),
            title=dict(x=0.02, y=0.95, font=dict(size=13, color=PALETTE["text"])),
            margin=dict(l=10, r=10, t=45, b=10),
            height=360,
            coloraxis_colorbar=dict(
                title=dict(text="Failures", font=dict(color=PALETTE["muted"], size=11)),
                tickfont=dict(color=PALETTE["muted"], size=10, family=PALETTE["font_mono"]),
                thickness=12,
                len=0.7,
            ),
        )
        return fig
    except Exception as e:
        print(f"[CloudForce] Map rendering error: {e}", file=sys.stderr)
        return _build_empty_figure(title_text, "Unable to render geographic map for current selection.")


if __name__ == "__main__":
    print(f"[CloudForce] Reading {DEFAULT_DATA_FILE} for standalone chart generation...")
    if not DEFAULT_DATA_FILE.exists():
        print(f"[CloudForce] File not found: {DEFAULT_DATA_FILE}. Run generate_cloudforce_data.py first.")
    else:
        raw_df = pd.read_excel(DEFAULT_DATA_FILE, sheet_name="Logs", engine="openpyxl")

        fig1 = build_failed_logins_timeline(raw_df)
        out_chart1 = BASE_DIR / "chart1_failed_logins_timeline.html"
        fig1.write_html(str(out_chart1))

        fig2 = build_top_attacking_ips(raw_df)
        out_chart2 = BASE_DIR / "chart2_top_attacking_ips.html"
        fig2.write_html(str(out_chart2))

        print(f"[CloudForce] Standalone charts generated:\n - {out_chart1}\n - {out_chart2}")
