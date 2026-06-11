#!/usr/bin/env python3
"""Generate SVG line charts from the DSPX-2754 benchmark results.

Pure Python standard library only (no matplotlib, no network), so it runs on a
fresh clone with just `python3`. Reads results.csv (written by the Go harness)
and emits three log-log charts comparing the static subject-mapping path against
the dynamic value-mapping path:

    charts/construction_time.svg
    charts/heap_memory.svg
    charts/decision_latency.svg

Usage:
    python3 plot.py [results.csv] [charts_dir]
"""

import csv
import math
import os
import sys

WIDTH, HEIGHT = 760, 460
MARGIN_L, MARGIN_R, MARGIN_T, MARGIN_B = 90, 150, 56, 64
PLOT_W = WIDTH - MARGIN_L - MARGIN_R
PLOT_H = HEIGHT - MARGIN_T - MARGIN_B

STATIC_COLOR = "#c1121f"   # red
DYNAMIC_COLOR = "#0353a4"  # blue
GRID_COLOR = "#d9d9d9"
AXIS_COLOR = "#333333"
TEXT_COLOR = "#222222"

LOG_FLOOR = 1e-3  # clamp non-positive values so log scales stay valid


def read_rows(path):
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            rows.append(
                {
                    "mode": r["mode"],
                    "n": int(r["n"]),
                    "construct_ms": float(r["construct_ms"]),
                    "heap_mb": float(r["heap_mb"]),
                    "decision_mean_us": float(r["decision_mean_us"]),
                }
            )
    return rows


def series_for(rows, key):
    """Return {mode: [(n, value), ...]} sorted by n."""
    out = {}
    for r in rows:
        out.setdefault(r["mode"], []).append((r["n"], r[key]))
    for mode in out:
        out[mode].sort(key=lambda p: p[0])
    return out


def log10_clamped(v):
    return math.log10(max(v, LOG_FLOOR))


def nice_log_bounds(values):
    lo = min(log10_clamped(v) for v in values)
    hi = max(log10_clamped(v) for v in values)
    lo = math.floor(lo)
    hi = math.ceil(hi)
    if lo == hi:
        hi = lo + 1
    return lo, hi


def fmt_pow10(exp):
    if exp >= 6:
        return f"1e{exp}"
    val = 10 ** exp
    if val >= 1:
        return f"{int(val):,}"
    return f"{val:g}"


def fmt_value(v):
    if v >= 1000:
        return f"{v:,.0f}"
    if v >= 1:
        return f"{v:.1f}"
    return f"{v:.3f}"


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def svg_chart(title, ylabel, ydata, out_path):
    """ydata: {mode: [(n, value), ...]}. X is subject-mapping count (log), Y log."""
    all_x = [n for pts in ydata.values() for (n, _) in pts]
    all_y = [v for pts in ydata.values() for (_, v) in pts]
    xlo, xhi = nice_log_bounds(all_x)
    ylo, yhi = nice_log_bounds(all_y)

    def px(n):
        t = (log10_clamped(n) - xlo) / (xhi - xlo)
        return MARGIN_L + t * PLOT_W

    def py(v):
        t = (log10_clamped(v) - ylo) / (yhi - ylo)
        return MARGIN_T + (1 - t) * PLOT_H

    parts = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" font-family="Helvetica,Arial,sans-serif">'
    )
    parts.append(f'<rect width="{WIDTH}" height="{HEIGHT}" fill="white"/>')
    parts.append(
        f'<text x="{WIDTH/2:.0f}" y="28" text-anchor="middle" font-size="17" '
        f'font-weight="bold" fill="{TEXT_COLOR}">{esc(title)}</text>'
    )

    # Y gridlines + labels (one per power of 10)
    for exp in range(ylo, yhi + 1):
        y = py(10 ** exp)
        parts.append(
            f'<line x1="{MARGIN_L}" y1="{y:.1f}" x2="{MARGIN_L+PLOT_W}" y2="{y:.1f}" '
            f'stroke="{GRID_COLOR}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{MARGIN_L-10}" y="{y+4:.1f}" text-anchor="end" font-size="12" '
            f'fill="{TEXT_COLOR}">{esc(fmt_pow10(exp))}</text>'
        )

    # X gridlines + labels (one per power of 10)
    for exp in range(xlo, xhi + 1):
        x = px(10 ** exp)
        parts.append(
            f'<line x1="{x:.1f}" y1="{MARGIN_T}" x2="{x:.1f}" y2="{MARGIN_T+PLOT_H}" '
            f'stroke="{GRID_COLOR}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{MARGIN_T+PLOT_H+20:.1f}" text-anchor="middle" '
            f'font-size="12" fill="{TEXT_COLOR}">{esc(fmt_pow10(exp))}</text>'
        )

    # Axes
    parts.append(
        f'<rect x="{MARGIN_L}" y="{MARGIN_T}" width="{PLOT_W}" height="{PLOT_H}" '
        f'fill="none" stroke="{AXIS_COLOR}" stroke-width="1.5"/>'
    )
    parts.append(
        f'<text x="{MARGIN_L+PLOT_W/2:.0f}" y="{HEIGHT-18}" text-anchor="middle" '
        f'font-size="13" fill="{TEXT_COLOR}">Total subject mappings (N, log scale)</text>'
    )
    ymid = MARGIN_T + PLOT_H / 2
    parts.append(
        f'<text x="22" y="{ymid:.0f}" text-anchor="middle" font-size="13" '
        f'fill="{TEXT_COLOR}" transform="rotate(-90 22 {ymid:.0f})">{esc(ylabel)}</text>'
    )

    # Series
    order = [m for m in ("static", "dynamic") if m in ydata]
    colors = {"static": STATIC_COLOR, "dynamic": DYNAMIC_COLOR}
    labels = {"static": "Static subject mappings", "dynamic": "Dynamic value mapping"}
    legend_y = MARGIN_T + 6
    for mode in order:
        pts = ydata[mode]
        color = colors.get(mode, "#555555")
        poly = " ".join(f"{px(n):.1f},{py(v):.1f}" for (n, v) in pts)
        parts.append(
            f'<polyline points="{poly}" fill="none" stroke="{color}" stroke-width="2.5"/>'
        )
        for (n, v) in pts:
            parts.append(
                f'<circle cx="{px(n):.1f}" cy="{py(v):.1f}" r="3.5" fill="{color}"/>'
            )
        # legend entry
        lx = MARGIN_L + PLOT_W + 14
        parts.append(
            f'<line x1="{lx}" y1="{legend_y}" x2="{lx+22}" y2="{legend_y}" '
            f'stroke="{color}" stroke-width="2.5"/>'
        )
        parts.append(
            f'<circle cx="{lx+11}" cy="{legend_y}" r="3.5" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{lx+28}" y="{legend_y+4}" font-size="12" fill="{TEXT_COLOR}">'
            f'{esc(labels.get(mode, mode))}</text>'
        )
        legend_y += 22

    parts.append("</svg>")
    with open(out_path, "w") as fh:
        fh.write("\n".join(parts))
    print(f"wrote {out_path}")


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
    charts_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(csv_path)), "charts"
    )
    os.makedirs(charts_dir, exist_ok=True)
    rows = read_rows(csv_path)

    svg_chart(
        "PDP Construction Time vs Subject-Mapping Count",
        "Construction time (ms)",
        series_for(rows, "construct_ms"),
        os.path.join(charts_dir, "construction_time.svg"),
    )
    svg_chart(
        "Retained Policy Heap vs Subject-Mapping Count",
        "Retained heap (MB)",
        series_for(rows, "heap_mb"),
        os.path.join(charts_dir, "heap_memory.svg"),
    )
    svg_chart(
        "Single GetDecision Latency vs Subject-Mapping Count",
        "Mean decision latency (us)",
        series_for(rows, "decision_mean_us"),
        os.path.join(charts_dir, "decision_latency.svg"),
    )


if __name__ == "__main__":
    main()
