"""Connectivity view of a prefix: layered AS graph built from every looking-glass path.

Pure functions (no network). ``build(lg, names)`` takes the RIPEstat looking-glass result
(``ripestat.looking_glass``) and an optional {asn: name} map and returns the ``connectivity`` block of the
prefix report. Edges point towards the origin; depth = hops from the origin (origin 0, its upstream 1, ...).
"""
from __future__ import annotations

import statistics
from collections import Counter

MAX_NODES = 60
TIER1 = frozenset({174, 209, 286, 701, 1239, 1299, 2828, 2914, 3257, 3320, 3356, 3491, 5511, 6453, 6461, 6762,
                   6830, 7018, 12956})


def _collapse(path: list[int]) -> tuple[list[int], int]:
    """(path without consecutive repeats, longest run of one AS)."""
    out: list[int] = []
    run = longest = 0
    for a in path:
        if out and out[-1] == a:
            run += 1
        else:
            out.append(a)
            run = 1
        longest = max(longest, run)
    return out, longest


def collect_paths(lg: dict | None) -> list[dict]:
    """Every looking-glass path as {'raw', 'path', 'peer'} (prepending collapsed in 'path')."""
    out = []
    for rrc in (lg or {}).get("rrcs", []):
        for p in rrc.get("peers", []):
            raw = [a for a in p.get("as_path") or [] if isinstance(a, int)]
            if not raw:
                continue
            path, _ = _collapse(raw)
            out.append({"raw": raw, "path": path, "peer": (rrc.get("rrc"), p.get("peer"))})
    return out


def graph_asns(lg: dict | None, limit: int = MAX_NODES) -> list[int]:
    """ASNs that would appear in the graph, most-used first (used to resolve names before building)."""
    c: Counter = Counter()
    for p in collect_paths(lg):
        c.update(set(p["path"]))
    return [a for a, _ in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def build(lg: dict | None, names: dict[int, str | None] | None = None) -> dict | None:
    paths = collect_paths(lg)
    if not paths:
        return None
    names = names or {}
    total = len(paths)
    origins = {p["path"][-1] for p in paths}
    depth: dict[int, int] = {}
    node_paths: Counter = Counter()
    edges: Counter = Counter()
    upstream_paths: Counter = Counter()
    first_hops: set[int] = set()
    lengths: list[int] = []
    prepend_runs: dict[int, list[int]] = {}
    for p in paths:
        path = p["path"]
        n = len(path)
        lengths.append(n)
        first_hops.add(path[0])
        for i, a in enumerate(path):
            d = n - 1 - i
            if a not in depth or d < depth[a]:
                depth[a] = d
        for a in set(path):
            node_paths[a] += 1
        for a, b in zip(path, path[1:]):
            edges[(a, b)] += 1
        if n >= 2:
            upstream_paths[path[-2]] += 1
        run, prev = 0, None
        runs: dict[int, int] = {}
        for a in p["raw"]:
            run = run + 1 if a == prev else 1
            prev = a
            runs[a] = max(runs.get(a, 0), run)
        for a, r in runs.items():
            if r > 1:
                prepend_runs.setdefault(a, []).append(r)

    upstream_set = {a for a in upstream_paths if a not in origins}

    def role(a: int) -> str:
        if a in origins:
            return "origin"
        if a in upstream_set:
            return "upstream"
        if a in first_hops:
            return "peer"
        return "transit"

    keep = sorted(depth, key=lambda a: (a not in origins, -node_paths[a], depth[a], a))[:MAX_NODES]
    kept = set(keep)
    nodes = [{"id": f"AS{a}", "asn": a, "name": names.get(a), "role": role(a), "tier1": a in TIER1,
              "depth": depth[a], "paths": node_paths[a], "share": round(node_paths[a] / total, 3)} for a in keep]
    nodes.sort(key=lambda x: (x["depth"], -x["paths"], x["asn"]))
    edge_list = [{"from": f"AS{a}", "to": f"AS{b}", "count": c}
                 for (a, b), c in sorted(edges.items(), key=lambda kv: (-kv[1], kv[0])) if a in kept and b in kept]
    upstreams = [{"asn": a, "name": names.get(a), "paths": c, "share": round(c / total, 3), "tier1": a in TIER1}
                 for a, c in sorted(upstream_paths.items(), key=lambda kv: (-kv[1], kv[0])) if a not in origins]
    hist = Counter(lengths)
    peers = {p["peer"] for p in paths}
    prepending = [{"asn": a, "max_repeat": max(rs), "paths": len(rs)} for a, rs in prepend_runs.items()]
    prepending.sort(key=lambda x: (-x["paths"], -x["max_repeat"], x["asn"]))
    return {"graph": {"nodes": nodes, "edges": edge_list}, "upstreams": upstreams, "paths_total": total,
            "collector_peers": len(peers),
            "path_length": {"min": min(lengths), "median": statistics.median_low(lengths), "max": max(lengths),
                            "hist": {str(k): v for k, v in sorted(hist.items())}},
            "prepending": prepending}
