#!/usr/bin/env python3
"""Generate consolidated SVG charts for the CEL benchmark CSVs.

Pure Python standard library only (no matplotlib, no network), so it runs on a
fresh clone with just `python3`. It emits one multi-panel, log-log figure per
layer, each with a single shared legend. The CSV schema is auto-detected by
header:

    operator CSV (header has `groups`):      charts/operator.svg
        2 panels: legacy and decomposed per-evaluation latency (native, cel)
    entitlements CSV (header has `mappings`): charts/entitlements.svg
        2 panels: per-decision latency; per-decision allocations (native, cel)

Usage:
    python3 plot.py <results.csv> [charts_dir]
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

GRID_COLOR = "#d9d9d9"
AXIS_COLOR = "#333333"
TEXT_COLOR = "#222222"
RED, BLUE, GREEN, GRAY = "#c1121f", "#0353a4", "#2a9d3f", "#8a8a8a"

LOG_FLOOR = 1e-3  # clamp non-positive values so log scales stay valid


def log10_clamped(v):
    return math.log10(max(v, LOG_FLOOR))


def nice_log_bounds(values):
    lo = math.floor(min(log10_clamped(v) for v in values))
    hi = math.ceil(max(log10_clamped(v) for v in values))
    return (lo, hi) if hi > lo else (lo, lo + 1)


def fmt_pow10(exp):
    if exp >= 6:
        return f"1e{exp}"
    val = 10 ** exp
    return f"{int(val):,}" if val >= 1 else f"{val:g}"


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def draw_panel(parts, box, panel, xlo, xhi, colors, order):
    """Render one panel into `box` = (left, top). X bounds are shared (xlo, xhi);
    Y bounds are computed from this panel's data so each metric keeps its units."""
    left, top = box
    ydata = panel["ydata"]
    all_y = [v for pts in ydata.values() for (_, v) in pts]
    ylo, yhi = nice_log_bounds(all_y)

    def px(n):
        return left + (log10_clamped(n) - xlo) / (xhi - xlo) * PANEL_W

    def py(v):
        return top + (1 - (log10_clamped(v) - ylo) / (yhi - ylo)) * PANEL_H

    parts.append(
        f'<text x="{left + PANEL_W / 2:.0f}" y="{top - 12:.0f}" text-anchor="middle" '
        f'font-size="14" font-weight="bold" fill="{TEXT_COLOR}">{esc(panel["subtitle"])}</text>'
    )

    for exp in range(ylo, yhi + 1):
        y = py(10 ** exp)
        parts.append(f'<line x1="{left:.1f}" y1="{y:.1f}" x2="{left + PANEL_W:.1f}" y2="{y:.1f}" '
                     f'stroke="{GRID_COLOR}" stroke-width="1"/>')
        parts.append(f'<text x="{left - 8:.1f}" y="{y + 4:.1f}" text-anchor="end" font-size="11" '
                     f'fill="{TEXT_COLOR}">{esc(fmt_pow10(exp))}</text>')

    for exp in range(xlo, xhi + 1):
        x = px(10 ** exp)
        parts.append(f'<line x1="{x:.1f}" y1="{top:.1f}" x2="{x:.1f}" y2="{top + PANEL_H:.1f}" '
                     f'stroke="{GRID_COLOR}" stroke-width="1"/>')
        parts.append(f'<text x="{x:.1f}" y="{top + PANEL_H + 18:.1f}" text-anchor="middle" '
                     f'font-size="11" fill="{TEXT_COLOR}">{esc(fmt_pow10(exp))}</text>')

    parts.append(f'<rect x="{left:.1f}" y="{top:.1f}" width="{PANEL_W}" height="{PANEL_H}" '
                 f'fill="none" stroke="{AXIS_COLOR}" stroke-width="1.5"/>')

    ymid = top + PANEL_H / 2
    parts.append(f'<text x="{left - 50:.0f}" y="{ymid:.0f}" text-anchor="middle" font-size="12" '
                 f'fill="{TEXT_COLOR}" transform="rotate(-90 {left - 50:.0f} {ymid:.0f})">'
                 f'{esc(panel["ylabel"])}</text>')

    for name in [m for m in order if m in ydata]:
        color = colors.get(name, "#555555")
        pts = ydata[name]
        poly = " ".join(f"{px(n):.1f},{py(v):.1f}" for (n, v) in pts)
        parts.append(f'<polyline points="{poly}" fill="none" stroke="{color}" stroke-width="2.5"/>')
        for (n, v) in pts:
            parts.append(f'<circle cx="{px(n):.1f}" cy="{py(v):.1f}" r="3.2" fill="{color}"/>')


def svg_panel_figure(title, x_label, panels, colors, labels, order, out_path):
    """Render a row of panels sharing one X scale and one legend, to out_path."""
    n = len(panels)
    width = MARGIN_L + n * PANEL_W + (n - 1) * PANEL_GAP + MARGIN_R
    height = MARGIN_T + PANEL_H + MARGIN_B

    all_x = [x for p in panels for pts in p["ydata"].values() for (x, _) in pts]
    xlo, xhi = nice_log_bounds(all_x)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Helvetica,Arial,sans-serif">',
        f'<rect width="{width}" height="{height}" fill="white"/>',
        f'<text x="{width / 2:.0f}" y="26" text-anchor="middle" font-size="18" '
        f'font-weight="bold" fill="{TEXT_COLOR}">{esc(title)}</text>',
    ]

    present = [m for m in order if any(m in p["ydata"] for p in panels)]
    entry_w = 200
    lx = width / 2 - entry_w * len(present) / 2
    ly = 52
    for name in present:
        color = colors[name]
        parts.append(f'<line x1="{lx:.0f}" y1="{ly}" x2="{lx + 24:.0f}" y2="{ly}" '
                     f'stroke="{color}" stroke-width="2.5"/>')
        parts.append(f'<circle cx="{lx + 12:.0f}" cy="{ly}" r="3.2" fill="{color}"/>')
        parts.append(f'<text x="{lx + 32:.0f}" y="{ly + 4}" font-size="13" fill="{TEXT_COLOR}">'
                     f'{esc(labels.get(name, name))}</text>')
        lx += entry_w

    for i, panel in enumerate(panels):
        left = MARGIN_L + i * (PANEL_W + PANEL_GAP)
        draw_panel(parts, (left, MARGIN_T), panel, xlo, xhi, colors, order)

    parts.append(f'<text x="{width / 2:.0f}" y="{height - 16}" text-anchor="middle" '
                 f'font-size="13" fill="{TEXT_COLOR}">{esc(x_label)}</text>')
    parts.append("</svg>")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as fh:
        fh.write("\n".join(parts))
    print(f"wrote {out_path}")


def series_for(rows, x_of, ykey):
    """Return {arm: [(x, value), ...]} sorted by x."""
    out = {}
    for r in rows:
        out.setdefault(r["arm"], []).append((x_of(r), float(r[ykey])))
    for arm in out:
        out[arm].sort(key=lambda p: p[0])
    return out


def plot_operator(rows, charts_dir):
    colors = {"native": BLUE, "cel": RED}
    labels = {"native": "native (Go switch)", "cel": "cel (precompiled, per-eval)"}
    order = ("native", "cel")

    def x_of(r):
        return int(r["groups"]) * int(r["conds"])

    panels = []
    for ops, subtitle in (("legacy", "Legacy operators"), ("decomposed", "Decomposed operators (#3335)")):
        sub = [r for r in rows if r.get("ops") == ops and r["arm"] in ("native", "cel")]
        panels.append({"subtitle": subtitle, "ylabel": "ns/op (log scale)",
                       "ydata": series_for(sub, x_of, "ns_op")})

    svg_panel_figure(
        "CEL vs native operator evaluation",
        "Conditions per subject set (log scale)",
        panels, colors, labels, order, os.path.join(charts_dir, "operator.svg"),
    )


def plot_entitlements(rows, charts_dir):
    colors = {"native": BLUE, "cel": RED}
    labels = {"native": "native (Go switch, v2)", "cel": "cel (precompiled)"}
    order = ("native", "cel")

    def x_of(r):
        return int(r["mappings"])

    svg_panel_figure(
        "Entitlements evaluation vs subject mappings (v2)",
        "Total subject mappings (log scale)",
        [
            {"subtitle": "Per-decision latency", "ylabel": "ns/op", "ydata": series_for(rows, x_of, "ns_op")},
            {"subtitle": "Per-decision allocations", "ylabel": "allocs/op", "ydata": series_for(rows, x_of, "allocs_op")},
        ],
        colors, labels, order, os.path.join(charts_dir, "entitlements.svg"),
    )


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
    charts_dir = sys.argv[2] if len(sys.argv) > 2 else "charts"
    with open(csv_path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print(f"no rows in {csv_path}", file=sys.stderr)
        return 1
    header = rows[0].keys()
    if "groups" in header:
        plot_operator(rows, charts_dir)
    elif "mappings" in header:
        plot_entitlements(rows, charts_dir)
    else:
        print(f"unrecognized CSV schema in {csv_path}: {list(header)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
