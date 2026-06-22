#!/usr/bin/env python3
"""Generate SVG charts from the DSPX-2541 benchmark CSVs.

Pure Python standard library only (no matplotlib, no network), so it runs on a
fresh clone with just `python3`. It auto-detects the CSV schema by header:

  DB fetch CSV  (header has `ms`):     charts/fetch_ms.svg   (fullload vs byfqns)
  In-memory PDP (header has `op`):     charts/pdp_<op>_latency.svg, charts/pdp_<op>_heap.svg
                                       for op in {decision, entitlements} (full vs scoped)

Usage:
    python3 plot.py [results.csv] [charts_dir]
"""

import csv
import math
import os
import sys

W, H = 760, 460
ML, MR, MT, MB = 78, 190, 56, 64  # margins (right margin holds the legend)
PLOT_W = W - ML - MR
PLOT_H = H - MT - MB
GRID, AXIS, TEXT = "#d9d9d9", "#333333", "#222222"
RED, BLUE = "#c1121f", "#0353a4"
LOG_FLOOR = 1e-3


def lg(v):
    return math.log10(max(v, LOG_FLOOR))


def bounds(vals):
    lo, hi = math.floor(min(lg(v) for v in vals)), math.ceil(max(lg(v) for v in vals))
    return (lo, hi) if hi > lo else (lo, lo + 1)


def render_chart(title, y_label, series, colors, labels, order, dest):
    """series: {name: [(x, y), ...]}; draws a log-log line chart to dest (SVG)."""
    xs = [x for pts in series.values() for x, _ in pts]
    ys = [y for pts in series.values() for _, y in pts]
    if not xs:
        return
    xlo, xhi = bounds(xs)
    ylo, yhi = bounds(ys)

    def px(n):
        return ML + (lg(n) - xlo) / (xhi - xlo) * PLOT_W

    def py(v):
        return MT + PLOT_H - (lg(v) - ylo) / (yhi - ylo) * PLOT_H

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="sans-serif">',
           f'<rect width="{W}" height="{H}" fill="white"/>',
           f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" fill="{TEXT}">{title}</text>']

    for e in range(xlo, xhi + 1):
        x = px(10 ** e)
        out.append(f'<line x1="{x:.1f}" y1="{MT}" x2="{x:.1f}" y2="{MT+PLOT_H}" stroke="{GRID}"/>')
        out.append(f'<text x="{x:.1f}" y="{MT+PLOT_H+18}" text-anchor="middle" font-size="11" fill="{TEXT}">1e{e}</text>')
    for e in range(ylo, yhi + 1):
        y = py(10 ** e)
        out.append(f'<line x1="{ML}" y1="{y:.1f}" x2="{ML+PLOT_W}" y2="{y:.1f}" stroke="{GRID}"/>')
        out.append(f'<text x="{ML-8}" y="{y+4:.1f}" text-anchor="end" font-size="11" fill="{TEXT}">1e{e}</text>')

    out.append(f'<rect x="{ML}" y="{MT}" width="{PLOT_W}" height="{PLOT_H}" fill="none" stroke="{AXIS}"/>')
    out.append(f'<text x="{ML+PLOT_W/2}" y="{H-18}" text-anchor="middle" font-size="13" fill="{TEXT}">'
               'Total subject mappings (N, log scale)</text>')
    out.append(f'<text x="18" y="{MT+PLOT_H/2}" text-anchor="middle" font-size="13" fill="{TEXT}" '
               f'transform="rotate(-90 18 {MT+PLOT_H/2})">{y_label}</text>')

    ly = MT + 8
    for name in order:
        pts = series.get(name)
        if not pts:
            continue
        pts = sorted(pts, key=lambda p: p[0])
        color = colors.get(name, "#666")
        path = " ".join(f"{'M' if i == 0 else 'L'}{px(x):.1f},{py(y):.1f}" for i, (x, y) in enumerate(pts))
        out.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.5"/>')
        for x, y in pts:
            out.append(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="3" fill="{color}"/>')
        lx = ML + PLOT_W + 14
        out.append(f'<line x1="{lx}" y1="{ly}" x2="{lx+22}" y2="{ly}" stroke="{color}" stroke-width="2.5"/>')
        out.append(f'<text x="{lx+28}" y="{ly+4}" font-size="11" fill="{TEXT}">{labels.get(name, name)}</text>')
        ly += 22

    out.append("</svg>")
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "w") as fh:
        fh.write("\n".join(out))
    print(f"wrote {dest}")


def plot_db(rows, charts_dir):
    colors = {"fullload": RED, "byfqns": BLUE}
    labels = {"fullload": "fullload (list all attrs + SMs)", "byfqns": "byfqns (GetEntitleableAttributesByFqns)"}
    series = {}
    for r in rows:
        series.setdefault(r["mode"], []).append((int(r["n"]), float(r["ms"])))
    render_chart("Entitlements fetch latency vs total subject mappings (DSPX-2541)",
                 "Fetch latency (ms, log scale)", series, colors, labels,
                 ("fullload", "byfqns"), os.path.join(charts_dir, "fetch_ms.svg"))


def plot_pdp(rows, charts_dir):
    colors = {"full": RED, "scoped": BLUE}
    labels = {"full": "full (PDP over all policy)", "scoped": "scoped (PDP over needed subset)"}
    ops = sorted({r["op"] for r in rows})
    for op in ops:
        op_rows = [r for r in rows if r["op"] == op]
        lat, heap = {}, {}
        for r in op_rows:
            lat.setdefault(r["mode"], []).append((int(r["n"]), float(r["op_p50_us"])))
            heap.setdefault(r["mode"], []).append((int(r["n"]), float(r["heap_mb"])))
        render_chart(f"PDP {op} p50 latency vs N (DSPX-2541)", "p50 latency (us, log scale)",
                     lat, colors, labels, ("full", "scoped"), os.path.join(charts_dir, f"pdp_{op}_latency.svg"))
        render_chart(f"PDP {op} retained heap vs N (DSPX-2541)", "Retained heap (MB, log scale)",
                     heap, colors, labels, ("full", "scoped"), os.path.join(charts_dir, f"pdp_{op}_heap.svg"))


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
    charts_dir = sys.argv[2] if len(sys.argv) > 2 else "charts"
    with open(csv_path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print(f"no rows in {csv_path}", file=sys.stderr)
        return 1
    header = rows[0].keys()
    if "op" in header:
        plot_pdp(rows, charts_dir)
    elif "ms" in header:
        plot_db(rows, charts_dir)
    else:
        print(f"unrecognized CSV schema in {csv_path}: {list(header)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
