#!/usr/bin/env python3
"""Generate consolidated SVG charts from the DSPX-2754 benchmark results.

Pure Python standard library only (no matplotlib, no network), so it runs on a
fresh clone with just `python3`. It emits two multi-panel, log-log figures, each
with a single shared static-vs-dynamic legend:

    charts/in_memory.svg     3 panels: construction time, retained heap, decision latency
    charts/db_load_seed.svg  2 panels: seed time, load time   (only if a DB CSV is given)

Usage:
    python3 plot.py [results.csv] [charts_dir] [db_results.csv]

The in-memory figure is built from results.csv (columns: mode,n,construct_ms,
heap_mb,decision_mean_us,...). The DB figure is built from the optional third
argument (columns: mode,n,seed_ms,load_ms,...); if it is omitted or missing the
DB figure is skipped.
"""

import csv
import math
import os
import sys

# Per-panel plot box, and the figure margins around a row of panels.
PANEL_W, PANEL_H = 300, 300
PANEL_GAP = 78               # horizontal space between panels (room for y labels)
MARGIN_L, MARGIN_R = 70, 28
MARGIN_T, MARGIN_B = 86, 58  # title + shared legend on top, x-axis label on bottom

STATIC_COLOR = "#c1121f"   # red
DYNAMIC_COLOR = "#0353a4"  # blue
GRID_COLOR = "#d9d9d9"
AXIS_COLOR = "#333333"
TEXT_COLOR = "#222222"

X_LABEL = "Total subject mappings (N, log scale)"
MODE_ORDER = ("static", "dynamic")
MODE_COLORS = {"static": STATIC_COLOR, "dynamic": DYNAMIC_COLOR}
MODE_LABELS = {"static": "Static subject mappings", "dynamic": "Dynamic value mapping"}

LOG_FLOOR = 1e-3  # clamp non-positive values so log scales stay valid


def read_rows(path):
    """Read a benchmark CSV. Returns rows of {mode, n, <numeric columns as float>}."""
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            row = {"mode": r["mode"], "n": int(r["n"])}
            for k, v in r.items():
                if k in ("mode", "n"):
                    continue
                try:
                    row[k] = float(v)
                except ValueError:
                    row[k] = v
            rows.append(row)
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


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def draw_panel(parts, box, panel, xlo, xhi):
    """Render one panel into `box` = (left, top). X bounds are shared (xlo, xhi);
    Y bounds are computed from this panel's data so each metric keeps its units."""
    left, top = box
    ydata = panel["ydata"]
    all_y = [v for pts in ydata.values() for (_, v) in pts]
    ylo, yhi = nice_log_bounds(all_y)

    def px(n):
        t = (log10_clamped(n) - xlo) / (xhi - xlo)
        return left + t * PANEL_W

    def py(v):
        t = (log10_clamped(v) - ylo) / (yhi - ylo)
        return top + (1 - t) * PANEL_H

    # Panel subtitle.
    parts.append(
        f'<text x="{left + PANEL_W / 2:.0f}" y="{top - 12:.0f}" text-anchor="middle" '
        f'font-size="14" font-weight="bold" fill="{TEXT_COLOR}">{esc(panel["subtitle"])}</text>'
    )

    # Y gridlines + labels (one per power of 10).
    for exp in range(ylo, yhi + 1):
        y = py(10 ** exp)
        parts.append(
            f'<line x1="{left:.1f}" y1="{y:.1f}" x2="{left + PANEL_W:.1f}" y2="{y:.1f}" '
            f'stroke="{GRID_COLOR}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{left - 8:.1f}" y="{y + 4:.1f}" text-anchor="end" font-size="11" '
            f'fill="{TEXT_COLOR}">{esc(fmt_pow10(exp))}</text>'
        )

    # X gridlines + labels (one per power of 10).
    for exp in range(xlo, xhi + 1):
        x = px(10 ** exp)
        parts.append(
            f'<line x1="{x:.1f}" y1="{top:.1f}" x2="{x:.1f}" y2="{top + PANEL_H:.1f}" '
            f'stroke="{GRID_COLOR}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{top + PANEL_H + 18:.1f}" text-anchor="middle" '
            f'font-size="11" fill="{TEXT_COLOR}">{esc(fmt_pow10(exp))}</text>'
        )

    # Axis box.
    parts.append(
        f'<rect x="{left:.1f}" y="{top:.1f}" width="{PANEL_W}" height="{PANEL_H}" '
        f'fill="none" stroke="{AXIS_COLOR}" stroke-width="1.5"/>'
    )

    # Y-axis (units) label, rotated.
    ymid = top + PANEL_H / 2
    parts.append(
        f'<text x="{left - 50:.0f}" y="{ymid:.0f}" text-anchor="middle" font-size="12" '
        f'fill="{TEXT_COLOR}" transform="rotate(-90 {left - 50:.0f} {ymid:.0f})">'
        f'{esc(panel["ylabel"])}</text>'
    )

    # Series.
    for mode in [m for m in MODE_ORDER if m in ydata]:
        color = MODE_COLORS.get(mode, "#555555")
        pts = ydata[mode]
        poly = " ".join(f"{px(n):.1f},{py(v):.1f}" for (n, v) in pts)
        parts.append(
            f'<polyline points="{poly}" fill="none" stroke="{color}" stroke-width="2.5"/>'
        )
        for (n, v) in pts:
            parts.append(f'<circle cx="{px(n):.1f}" cy="{py(v):.1f}" r="3.2" fill="{color}"/>')


def svg_panel_figure(title, panels, out_path):
    """Render a row of panels sharing one X scale and one legend, to out_path."""
    n = len(panels)
    width = MARGIN_L + n * PANEL_W + (n - 1) * PANEL_GAP + MARGIN_R
    height = MARGIN_T + PANEL_H + MARGIN_B

    # Shared X bounds across all panels so the N axis reads the same in each.
    all_x = [x for p in panels for pts in p["ydata"].values() for (x, _) in pts]
    xlo, xhi = nice_log_bounds(all_x)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Helvetica,Arial,sans-serif">',
        f'<rect width="{width}" height="{height}" fill="white"/>',
        f'<text x="{width / 2:.0f}" y="26" text-anchor="middle" font-size="18" '
        f'font-weight="bold" fill="{TEXT_COLOR}">{esc(title)}</text>',
    ]

    # Shared legend, centered under the title.
    present = [m for m in MODE_ORDER if any(m in p["ydata"] for p in panels)]
    entry_w = 200
    legend_w = entry_w * len(present)
    lx = width / 2 - legend_w / 2
    ly = 52
    for mode in present:
        color = MODE_COLORS[mode]
        parts.append(
            f'<line x1="{lx:.0f}" y1="{ly}" x2="{lx + 24:.0f}" y2="{ly}" '
            f'stroke="{color}" stroke-width="2.5"/>'
        )
        parts.append(f'<circle cx="{lx + 12:.0f}" cy="{ly}" r="3.2" fill="{color}"/>')
        parts.append(
            f'<text x="{lx + 32:.0f}" y="{ly + 4}" font-size="13" fill="{TEXT_COLOR}">'
            f'{esc(MODE_LABELS.get(mode, mode))}</text>'
        )
        lx += entry_w

    # Panels left to right.
    for i, panel in enumerate(panels):
        left = MARGIN_L + i * (PANEL_W + PANEL_GAP)
        draw_panel(parts, (left, MARGIN_T), panel, xlo, xhi)

    # Shared X-axis label, centered under the row.
    parts.append(
        f'<text x="{width / 2:.0f}" y="{height - 16}" text-anchor="middle" '
        f'font-size="13" fill="{TEXT_COLOR}">{esc(X_LABEL)}</text>'
    )

    parts.append("</svg>")
    with open(out_path, "w") as fh:
        fh.write("\n".join(parts))
    print(f"wrote {out_path}")


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
    charts_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(csv_path)), "charts"
    )
    db_csv = sys.argv[3] if len(sys.argv) > 3 else None
    os.makedirs(charts_dir, exist_ok=True)

    rows = read_rows(csv_path)
    svg_panel_figure(
        "In-Memory PDP: Static Subject Mappings vs Dynamic Value Mapping",
        [
            {
                "subtitle": "Construction time",
                "ylabel": "Construction time (ms)",
                "ydata": series_for(rows, "construct_ms"),
            },
            {
                "subtitle": "Retained heap",
                "ylabel": "Retained heap (MB)",
                "ydata": series_for(rows, "heap_mb"),
            },
            {
                "subtitle": "Decision latency (mean)",
                "ylabel": "Mean decision latency (us)",
                "ydata": series_for(rows, "decision_mean_us"),
            },
        ],
        os.path.join(charts_dir, "in_memory.svg"),
    )

    if db_csv and os.path.exists(db_csv):
        db_rows = read_rows(db_csv)
        svg_panel_figure(
            "Database: Seed and Load Cost at NG SAP Scale",
            [
                {
                    "subtitle": "Seed time",
                    "ylabel": "Seed time (ms)",
                    "ydata": series_for(db_rows, "seed_ms"),
                },
                {
                    "subtitle": "Load time (paged list)",
                    "ylabel": "Load time (ms)",
                    "ydata": series_for(db_rows, "load_ms"),
                },
            ],
            os.path.join(charts_dir, "db_load_seed.svg"),
        )
    elif db_csv:
        print(f"skipping DB figure: {db_csv} not found")


if __name__ == "__main__":
    main()
