#!/usr/bin/env python3
"""Build app/static/viz/land-110m.svgpath.txt: the world's land as one SVG path (equirectangular, 720 x 360 box,
x = (lon + 180) * 2, y = (90 - lat) * 2) for the toolbox world map.

Source: Natural Earth 1:110m land (public domain) via the pinned npm package world-atlas@2.0.2 (TopoJSON).
The download is cached in .cache/ and verified against EXPECTED_SHA256. The output file is committed, so the
app never needs the network (the CSP allows no CDN). Run again only to regenerate.

    python3 scripts/build_worldmap.py            # uses .cache/ if present
    python3 scripts/build_worldmap.py --refresh  # re-download
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

URL = "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/land-110m.json"
EXPECTED_SHA256 = "ead5f68119c49a9250902e7da303bcb209341bbb8fefe7369a439b48b704658a"
ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "land-110m.json"
OUT = ROOT / "app" / "static" / "viz" / "land-110m.svgpath.txt"
MAX_BYTES = 150 * 1024


def fetch(refresh: bool) -> bytes:
    if CACHE.exists() and not refresh:
        return CACHE.read_bytes()
    req = urllib.request.Request(URL, headers={"User-Agent": "bmh-devtools-build/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (pinned https URL)
        data = r.read()
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_bytes(data)
    return data


def decode_arcs(topo: dict) -> list[list[tuple[float, float]]]:
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    arcs = []
    for arc in topo["arcs"]:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append((x * sx + tx, y * sy + ty))
        arcs.append(pts)
    return arcs


def ring_points(ring: list[int], arcs) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    for i in ring:
        pts = arcs[~i][::-1] if i < 0 else arcs[i]
        out.extend(pts if not out else pts[1:])
    return out


def polygons(geom) -> list[list[list[int]]]:
    t = geom["type"]
    if t == "Polygon":
        return [geom["arcs"]]
    if t == "MultiPolygon":
        return geom["arcs"]
    if t == "GeometryCollection":
        return [p for g in geom["geometries"] for p in polygons(g)]
    return []


def unwrap(px: list[tuple[float, float]]):
    """Make longitudes continuous across the antimeridian. Returns (points, net_offset); net_offset != 0 means the
    ring encloses a pole (Antarctica) and is better left as it is."""
    out, off, prev = [], 0.0, None
    for x, y in px:
        if prev is not None:
            if x - prev > 360:
                off -= 720
            elif x - prev < -360:
                off += 720
        prev = x
        out.append((x + off, y))
    return out, off


def ring_path(pts: list[tuple[float, float]], decimals: int) -> str:
    dedup = [p for i, p in enumerate(pts) if i == 0 or p != pts[i - 1]]
    if len(dedup) < 4:
        return ""
    cmds = [f"M{dedup[0][0]:g} {dedup[0][1]:g}"]
    px0, py0 = dedup[0]
    for x, y in dedup[1:]:
        cmds.append(f"l{round(x - px0, decimals):g} {round(y - py0, decimals):g}")
        px0, py0 = x, y
    cmds.append("z")
    return "".join(cmds)


def to_path(topo: dict, decimals: int = 1) -> str:
    arcs = decode_arcs(topo)
    parts = []
    for obj in topo["objects"].values():
        for poly in polygons(obj):
            for ring in poly:
                pts = ring_points(ring, arcs)
                px = [(round((lon + 180) * 2, decimals), round((90 - lat) * 2, decimals)) for lon, lat in pts]
                unwrapped, net = unwrap(px)
                if net != 0:  # pole-enclosing ring: use as is
                    parts.append(ring_path(px, decimals))
                    continue
                parts.append(ring_path(unwrapped, decimals))
                lo, hi = min(p[0] for p in unwrapped), max(p[0] for p in unwrapped)
                # a ring that crosses the +-180 line is drawn again shifted by one map width, so both halves show
                if hi > 720:
                    parts.append(ring_path([(x - 720, y) for x, y in unwrapped], decimals))
                if lo < 0:
                    parts.append(ring_path([(x + 720, y) for x, y in unwrapped], decimals))
    return "".join(p for p in parts if p)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args()
    raw = fetch(args.refresh)
    digest = hashlib.sha256(raw).hexdigest()
    if EXPECTED_SHA256 and digest != EXPECTED_SHA256:
        print(f"sha256 mismatch: got {digest}, expected {EXPECTED_SHA256}", file=sys.stderr)
        return 2
    if not EXPECTED_SHA256:
        print(f"first download; record this in EXPECTED_SHA256: {digest}")
    topo = json.loads(raw)
    path = ""
    for dec in (1, 0):
        path = to_path(topo, dec)
        if len(path.encode()) <= MAX_BYTES:
            break
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(path, encoding="ascii")
    print(f"wrote {OUT} ({len(path.encode())} bytes)")
    return 0 if len(path.encode()) <= MAX_BYTES else 1


if __name__ == "__main__":
    sys.exit(main())
