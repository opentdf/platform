#!/usr/bin/env python3
"""Generate an SVG chart from the DSPX-2541 entitlements fetch benchmark.

Pure Python standard library only (no matplotlib, no network), so it runs on a
fresh clone with just `python3`. It emits a single log-log line chart comparing
the two fetch paths' latency as the total subject-mapping count (N) grows:

    charts/fetch_ms.svg   fullload vs byfqns, ms (y, log) over N (x, log)

Usage:
    python3 plot.py [results.csv] [charts_dir]
"""

import csv
import math
import os
import sys

W, H = 760, 460
ML, MR, MT, MB = 78, 170, 56, 64  # margins (right margin holds the legend)
PLOT_W = W - ML - MR
PLOT_H = H - MT - MB

COLORS = {"fullload": "#c1121f", "byfqns": "#0353a4"}
LABELS = {"fullload": "fullload (list all attrs + SMs)", "byfqns": "byfqns (GetEntitleableAttributesByFqns)"}
ORDER = ("fullload", "byfqns")
GRID, AXIS, TEXT = "#d9d9d9", "#333333", "#222222"
LOG_FLOOR = 1e-3


def read_rows(path):
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            rows.append({"mode": r["mode"], "n": int(r["n"]), "ms": float(r["ms"])})
    return rows


def series(rows):
    out = {}
    for r in rows:
        out.setdefault(r["mode"], []).append((r["n"], r["ms"]))
    for m in out:
        out[m].sort(key=lambda p: p[0])
    return out


def lg(v):
    return math.log10(max(v, LOG_FLOOR))


def bounds(vals):
    lo, hi = math.floor(min(lg(v) for v in vals)), math.ceil(max(lg(v) for v in vals))
    return (lo, hi) if hi > lo else (lo, lo + 1)


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
    charts_dir = sys.argv[2] if len(sys.argv) > 2 else "charts"
    rows = read_rows(csv_path)
    if not rows:
        print(f"no rows in {csv_path}", file=sys.stderr)
        return 1
    s = series(rows)

    xs = [r["n"] for r in rows]
    ys = [r["ms"] for r in rows]
    xlo, xhi = bounds(xs)
    ylo, yhi = bounds(ys)

    def px(n):
        return ML + (lg(n) - xlo) / (xhi - xlo) * PLOT_W

    def py(ms):
        return MT + PLOT_H - (lg(ms) - ylo) / (yhi - ylo) * PLOT_H

    out = []
    out.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="sans-serif">')
    out.append(f'<rect width="{W}" height="{H}" fill="white"/>')
    out.append(f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" fill="{TEXT}">'
               'Entitlements fetch latency vs total subject mappings (DSPX-2541)</text>')

    # gridlines + axis ticks (powers of 10)
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
               f'transform="rotate(-90 18 {MT+PLOT_H/2})">Fetch latency (ms, log scale)</text>')

    # series
    legend_y = MT + 8
    for mode in ORDER:
        pts = s.get(mode)
        if not pts:
            continue
        color = COLORS.get(mode, "#666")
        path = " ".join(f"{'M' if i == 0 else 'L'}{px(n):.1f},{py(ms):.1f}" for i, (n, ms) in enumerate(pts))
        out.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.5"/>')
        for n, ms in pts:
            out.append(f'<circle cx="{px(n):.1f}" cy="{py(ms):.1f}" r="3" fill="{color}"/>')
        lx = ML + PLOT_W + 14
        out.append(f'<line x1="{lx}" y1="{legend_y}" x2="{lx+22}" y2="{legend_y}" stroke="{color}" stroke-width="2.5"/>')
        out.append(f'<text x="{lx+28}" y="{legend_y+4}" font-size="11" fill="{TEXT}">{LABELS.get(mode, mode)}</text>')
        legend_y += 22

    out.append("</svg>")

    os.makedirs(charts_dir, exist_ok=True)
    dest = os.path.join(charts_dir, "fetch_ms.svg")
    with open(dest, "w") as fh:
        fh.write("\n".join(out))
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
