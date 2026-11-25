"""BGP report aggregators for the looking-glass UI: ``asn_report`` and ``prefix_report``.

Both gather many RIPEstat / PeeringDB calls concurrently under one time budget (12 s). Whatever
did not finish is listed in ``missing`` (with the reason in ``errors``); the report is still
returned, so the API never needs to answer 500 for a slow upstream. Network access goes through
the injectable ``fetch`` (same signature as ``fetch_json``).
"""
from __future__ import annotations

import asyncio
import functools
import ipaddress
import json
import time
from pathlib import Path
from typing import Any, Awaitable

from app.core import irr as irrmod
from app.core import pathgraph, peeringdb, prefixwhois, ripestat
from app.core.ripestat import RipeStatError, parse_asn
from app.core.validate import is_public_ip

BUDGET = 12.0
PREFIX_CAP = 500        # prefixes returned in the list
RPKI_SAMPLE = 100       # prefixes validated against RPKI
TOP_N = 25              # neighbours per role
NAME_TOP = 6            # neighbours per role whose AS name is resolved
CONCURRENCY = 8
MAX_PATHS = 10
_COLLECTORS = Path(__file__).resolve().parent.parent / "data" / "ris_collectors.json"
_RANK = {"fail": 3, "warn": 2, "pass": 1, "info": 0}


class BgpInputError(ValueError):
    """The ASN / prefix / IP asked for is malformed or not a public resource."""


@functools.lru_cache(maxsize=1)
def load_collectors() -> dict[str, dict]:
    doc = json.loads(_COLLECTORS.read_text(encoding="utf-8"))
    return {c["id"].lower(): c for c in doc["collectors"]}


def finding(id_: str, status: str, title: str, meaning: str, fix: str = "", details: Any = None) -> dict:
    return {"id": id_, "status": status, "title": title, "meaning": meaning, "fix": fix, "details": details}


def worst(findings: list[dict]) -> str:
    top = max((f["status"] for f in findings), key=lambda s: _RANK.get(s, 0), default="pass")
    return "pass" if top == "info" else top


async def gather_bounded(jobs: dict[str, Awaitable], deadline: float) -> tuple[dict, dict]:
    """Run named coroutines concurrently until ``deadline`` (monotonic). Returns (results, errors);
    jobs that raise or are still running at the deadline end up in ``errors`` (and are cancelled)."""
    tasks = {k: asyncio.ensure_future(c) for k, c in jobs.items()}
    if not tasks:
        return {}, {}
    try:
        _done, pending = await asyncio.wait(tasks.values(), timeout=max(deadline - time.monotonic(), 0.0))
    finally:
        for t in tasks.values():
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks.values(), return_exceptions=True)
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for k, t in tasks.items():
        if t in pending:
            errors[k] = "timed out"
        elif t.cancelled():
            errors[k] = "cancelled"
        elif t.exception() is not None:
            exc = t.exception()
            errors[k] = str(exc)[:200] or type(exc).__name__
        else:
            results[k] = t.result()
    return results, errors


def rpki_coverage(states: list[str | None]) -> dict:
    """states: 'valid' | 'invalid' | 'unknown' (= no ROA) | None (not checked)."""
    checked = [s for s in states if s is not None]
    valid, invalid = checked.count("valid"), checked.count("invalid")
    unknown = len(checked) - valid - invalid
    n = len(checked)
    pct = lambda x: round(100 * x / n, 1) if n else None  # noqa: E731
    return {"checked": n, "valid": valid, "invalid": invalid, "unknown": unknown,
            "covered_pct": pct(valid + invalid), "valid_pct": pct(valid), "no_roa_pct": pct(unknown)}


def _pct_text(p: float) -> str:
    return "<1" if 0 < p < 1 else f"{p:.0f}" if abs(p - round(p)) < 0.05 else f"{p:.1f}"


def _label(asn: int | None, name: str | None) -> str:
    return f"AS{asn} {name}" if asn and name else f"AS{asn}"


# ------------------------------------------------------------------------------------------
# ASN report
# ------------------------------------------------------------------------------------------
def build_graph(asn: int, name: str | None, neighbours: dict, names: dict[int, str | None]) -> dict:
    """Nodes/edges for a layered SVG layout. ``layer``: 0 upstream row, 1 target (and peers), 2 downstream row."""
    nodes = [{"id": f"AS{asn}", "asn": asn, "name": name, "role": "target", "power": None, "layer": 1}]
    edges = []
    spec = (("upstreams", "upstream", 0), ("downstreams", "downstream", 2), ("uncertain", "peer", 1))
    seen = {asn}
    for key, role, layer in spec:
        for nb in (neighbours.get(key) or [])[:TOP_N]:
            if nb["asn"] in seen:
                continue
            seen.add(nb["asn"])
            nid = f"AS{nb['asn']}"
            nodes.append({"id": nid, "asn": nb["asn"], "name": names.get(nb["asn"]), "role": role,
                          "power": nb["power"], "layer": layer})
            if role == "upstream":
                edges.append({"source": nid, "target": f"AS{asn}", "type": "transit", "power": nb["power"]})
            elif role == "downstream":
                edges.append({"source": f"AS{asn}", "target": nid, "type": "transit", "power": nb["power"]})
            else:
                edges.append({"source": f"AS{asn}", "target": nid, "type": "peer", "power": nb["power"]})
    return {"nodes": nodes, "edges": edges}


def asn_findings(asn: int, overview: dict | None, pfx: dict | None, cov: dict | None,
                 neighbours: dict | None, pdb: dict | None, ix: dict | None) -> list[dict]:
    out: list[dict] = []
    if pfx is not None:
        if pfx["count"] == 0 or (overview is not None and not overview["announced"]):
            out.append(finding("announcing", "fail", f"AS{asn} is not announcing any prefixes",
                               "No route originated by this AS is visible in the global routing table, so nothing behind it is reachable.",
                               "Check the BGP sessions and network statements on your routers, and that your upstream accepts your prefixes."))
        else:
            out.append(finding("announcing", "pass", f"Announcing {pfx['count']} prefixes ({pfx['v4']} IPv4, {pfx['v6']} IPv6)",
                               "The AS originates routes that are visible in the global table."))
        if pfx["v4"] and not pfx["v6"]:
            out.append(finding("ipv6", "info", "No IPv6 prefixes announced",
                               "Only IPv4 is routed from this AS; IPv6-only visitors cannot reach services here.",
                               "Request an IPv6 allocation and announce it alongside your IPv4 space."))
    if cov and cov["checked"]:
        sample = "" if not pfx or pfx["count"] <= cov["checked"] else f" (first {cov['checked']} of {pfx['count']} checked)"
        det = {**cov}
        if cov["invalid"]:
            out.append(finding("rpki", "fail", f"{cov['invalid']} of {cov['checked']} prefixes are RPKI-invalid{sample}",
                               "A ROA exists but does not match how the prefix is announced, so networks that drop RPKI-invalid routes will not carry them.",
                               "Fix the ROA (origin AS and max length) or the announcement so they agree.", det))
        elif cov["unknown"]:
            out.append(finding("rpki", "fail" if cov["no_roa_pct"] >= 50 else "warn",
                               f"{_pct_text(cov['no_roa_pct'])}% of your prefixes have no ROA{sample}, so RPKI-invalid hijacks can't be filtered",
                               "Without a ROA anyone can originate your prefix and validators cannot tell it is a hijack.",
                               "Create ROAs for every announced prefix in your RIR portal (MyAPNIC, ARIN, RIPE LIR portal).", det))
        else:
            out.append(finding("rpki", "pass", f"All {cov['checked']} checked prefixes are covered by a valid ROA{sample}",
                               "RPKI validators can verify your announcements and reject forged ones.", "", det))
    if neighbours is not None:
        ups = neighbours["counts"].get("left") or len(neighbours["upstreams"])
        if ups == 0:
            out.append(finding("upstreams", "warn", "No upstream detected",
                               "RIPE route collectors see no provider above this AS: it may not be announced, or visibility is too low to tell.",
                               "Confirm the announcements are live and check them again later."))
        elif ups == 1:
            out.append(finding("upstreams", "warn", "Single upstream: no transit redundancy",
                               "If that one provider has an outage or drops your routes, the whole AS goes offline.",
                               "Add a second transit provider or join an IXP so there is a second path.",
                               {"upstreams": [n["asn"] for n in neighbours["upstreams"]]}))
        else:
            out.append(finding("upstreams", "pass", f"{ups} upstreams: transit is redundant",
                               "Traffic can fail over to another provider when one path breaks."))
    if pdb is not None and not pdb.get("partial"):
        if not pdb.get("found"):
            out.append(finding("peeringdb", "warn", "No PeeringDB record for this AS",
                               "Peering coordinators look networks up in PeeringDB; without a record most will not answer peering requests.",
                               "Create a PeeringDB account and register the AS with contact details and peering policy."))
        else:
            if ix is not None and not ix.get("partial") and ix.get("count") == 0:
                out.append(finding("ix", "warn", "No IX presence listed in PeeringDB",
                                   "No exchange ports are published, so peers cannot find where to connect with you; traffic stays on paid transit.",
                                   "List your IXP ports in PeeringDB, or join a nearby exchange (for example NIXI in India)."))
            if not pdb.get("irr_as_set"):
                out.append(finding("irr", "info", "No IRR as-set in PeeringDB",
                                   "Peers build their prefix filters from your as-set; without one they may filter you out or ask for manual lists.",
                                   "Publish an as-set object (e.g. AS-EXAMPLE) in an IRR and add it to your PeeringDB record."))
    return out


def asn_summary(asn: int, overview: dict | None, pfx: dict | None, neighbours: dict | None, cov: dict | None) -> str:
    name = (overview or {}).get("name") or (overview or {}).get("holder")
    s = f"AS{asn}" + (f" ({name})" if name else "")
    if pfx is not None:
        s += f" announces {pfx['count']} prefixes ({pfx['v4']} IPv4, {pfx['v6']} IPv6)"
    elif overview is not None:
        s += " is announced" if overview["announced"] else " is not announced"
    if neighbours is not None:
        s += f" with {len(neighbours['upstreams'])} upstream and {len(neighbours['downstreams'])} downstream neighbours seen"
    if cov and cov["checked"]:
        s += f"; {_pct_text(cov['covered_pct'])}% of the checked prefixes are covered by a ROA"
    return s + "."


async def asn_report(asn: Any, *, fetch: ripestat.Fetch | None = None, budget: float = BUDGET) -> dict:
    t0 = time.monotonic()
    deadline = t0 + budget
    try:
        n = parse_asn(asn)
    except ValueError as exc:
        raise BgpInputError(str(exc)) from exc
    r, errs = await gather_bounded({
        "overview": ripestat.as_overview(n, fetch), "prefixes": ripestat.announced_prefixes(n, fetch),
        "neighbours": ripestat.asn_neighbours(n, fetch), "peeringdb": peeringdb.net_by_asn(n, fetch),
        "ix": peeringdb.ix_presence(n, fetch), "facilities": peeringdb.facilities(n, fetch)}, deadline)
    overview, pfx, nb = r.get("overview"), r.get("prefixes"), r.get("neighbours")
    pdb, ix, fac = r.get("peeringdb"), r.get("ix"), r.get("facilities")

    # phase 2: RPKI state for the first RPKI_SAMPLE prefixes + names of the strongest neighbours
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(coro: Awaitable) -> Any:
        async with sem:
            return await coro

    plist = list(pfx["prefixes"]) if pfx else []
    sample = [p["prefix"] for p in plist[:RPKI_SAMPLE]]
    jobs: dict[str, Awaitable] = {f"rpki:{p}": bounded(ripestat.rpki_validation(n, p, fetch)) for p in sample}
    if nb:
        for key in ("upstreams", "downstreams", "uncertain"):
            for x in nb[key][:NAME_TOP]:
                jobs.setdefault(f"name:{x['asn']}", bounded(ripestat.as_overview(x["asn"], fetch)))
    r2, _e2 = await gather_bounded(jobs, deadline)
    states = [(r2[f"rpki:{p}"]["state"] if f"rpki:{p}" in r2 else None) for p in sample]
    for p, st in zip(plist, states + [None] * (len(plist) - len(states))):
        p["rpki"] = st
    cov = rpki_coverage(states) if sample else None
    names = {int(k[5:]): v["name"] for k, v in r2.items() if k.startswith("name:")}
    if overview:
        names[n] = overview["name"]

    missing = [k for k in ("overview", "prefixes", "neighbours", "peeringdb", "ix", "facilities") if k in errs]
    for k, v in (("peeringdb", pdb), ("ix", ix), ("facilities", fac)):
        if v and v.get("partial") and k not in missing:
            missing.append(k)
    if sample and cov and cov["checked"] < len(sample):
        missing.append("rpki")
        errs["rpki"] = f"validated {cov['checked']} of {len(sample)} sampled prefixes"

    findings = asn_findings(n, overview, pfx, cov, nb, pdb, ix)
    notes = sorted({note for v in (pdb, ix, fac) if v for note in v.get("notes", [])})
    prefixes = None
    if pfx:
        prefixes = {"count": pfx["count"], "v4": pfx["v4"], "v6": pfx["v6"], "list": plist[:PREFIX_CAP],
                    "truncated": pfx["count"] > PREFIX_CAP, "rpki_checked": len(sample)}
    neigh = None
    if nb:
        neigh = {"counts": nb["counts"], "upstreams": _named(nb["upstreams"][:TOP_N], names),
                 "downstreams": _named(nb["downstreams"][:TOP_N], names), "peers": _named(nb["uncertain"][:TOP_N], names)}
    return {
        "asn": n, "name": (overview or {}).get("name"), "holder": (overview or {}).get("holder"),
        "announced": (overview or {}).get("announced"), "status": worst(findings) if findings else "unknown",
        "summary": asn_summary(n, overview, pfx, nb, cov), "findings": findings,
        "prefixes": prefixes, "neighbours": neigh, "rpki": cov,
        "peeringdb": None if not pdb else {**{k: v for k, v in pdb.items() if k not in ("notes",)},
                                           "ix_list": (ix or {}).get("ixs", []), "ix_count": (ix or {}).get("count"),
                                           "unique_ix": (ix or {}).get("unique_ix"),
                                           "facilities": (fac or {}).get("facilities", []),
                                           "facility_count": (fac or {}).get("count")},
        "graph": build_graph(n, (overview or {}).get("name"), nb, names) if nb else {"nodes": [{"id": f"AS{n}", "asn": n, "name": (overview or {}).get("name"), "role": "target", "power": None, "layer": 1}], "edges": []},
        "notes": notes, "missing": missing, "errors": {k: errs[k] for k in errs if not k.startswith(("rpki:", "name:"))},
        "partial": bool(missing), "elapsed_ms": round((time.monotonic() - t0) * 1000),
    }


def _named(items: list[dict], names: dict[int, str | None]) -> list[dict]:
    return [{**x, "name": names.get(x["asn"])} for x in items]


# ------------------------------------------------------------------------------------------
# Prefix report
# ------------------------------------------------------------------------------------------
def parse_resource(raw: str) -> tuple[str, bool]:
    """Return (canonical text, is_single_ip). Only public resources are accepted."""
    s = str(raw or "").strip()
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            first, is_ip = net.network_address, False
        else:
            first, is_ip = ipaddress.ip_address(s), True
            net = None
    except ValueError as exc:
        raise BgpInputError("enter an IP address or a prefix such as 1.1.1.0/24") from exc
    if not is_public_ip(str(first)):
        raise BgpInputError("only public IP space can be looked up")
    return (str(first) if is_ip else str(net)), is_ip


def join_collectors(vis: dict | None) -> dict:
    """Join RIPEstat per-collector visibility with ris_collectors.json (coordinates for the map)."""
    known = load_collectors()
    entries: dict[str, dict] = {}
    for c in (vis or {}).get("collectors", []):
        meta = known.get(c["id"], {})
        entries[c["id"]] = {
            "id": c["id"], "name": meta.get("name") or c.get("ixp"), "city": meta.get("city") or c.get("city"),
            "country": meta.get("country") or c.get("country"), "lat": meta.get("lat", c.get("lat")),
            "lon": meta.get("lon", c.get("lon")), "approx": bool(meta.get("approx")), "seen": c["seen"],
            "total": c["total"], "is_seen": c["is_seen"] if c["total"] else None, "no_data": c["total"] == 0}
    if vis is not None:
        for cid, meta in known.items():
            if cid not in entries:
                entries[cid] = {"id": cid, "name": meta["name"], "city": meta["city"], "country": meta["country"],
                                "lat": meta["lat"], "lon": meta["lon"], "approx": bool(meta.get("approx")), "seen": 0,
                                "total": 0, "is_seen": None, "no_data": True}
    lst = sorted(entries.values(), key=lambda e: e["id"])
    counted = [e for e in lst if e["total"] > 0]
    return {"collectors": lst, "seen_collectors": sum(1 for e in counted if e["is_seen"]), "total_collectors": len(counted),
            "seen_peers": sum(e["seen"] for e in counted), "total_peers": sum(e["total"] for e in counted)}


def collapse_path(path: list[int]) -> tuple[list[int], bool]:
    out: list[int] = []
    for a in path:
        if not out or out[-1] != a:
            out.append(a)
    return out, len(out) != len(path)


def top_paths(lg: dict | None, limit: int = MAX_PATHS) -> list[dict]:
    """Deduplicated AS paths (prepending collapsed), most-seen first, shorter first on ties."""
    agg: dict[tuple, dict] = {}
    for rrc in (lg or {}).get("rrcs", []):
        for p in rrc["peers"]:
            path, prepended = collapse_path(p["as_path"])
            e = agg.setdefault(tuple(path), {"path": path, "origin": path[-1], "count": 0, "prepended": False, "collectors": set()})
            e["count"] += 1
            e["prepended"] = e["prepended"] or prepended
            e["collectors"].add(rrc["rrc"])
    out = sorted(agg.values(), key=lambda e: (-e["count"], len(e["path"]), e["path"]))[:limit]
    return [{**e, "collectors": sorted(e["collectors"])} for e in out]


def _plen(prefix: str) -> int | None:
    try:
        return int(prefix.rsplit("/", 1)[1])
    except (IndexError, ValueError):
        return None


def maxlength_loose(prefix: str, roas: list[dict]) -> int | None:
    """Largest max-length of a VALID ROA that allows more-specifics than the announcement, else None."""
    plen = _plen(prefix)
    if plen is None:
        return None
    longest = [r["max_length"] for r in roas if r.get("validity") == "valid" and r.get("max_length") is not None]
    top = max(longest, default=None)
    return top if top is not None and top > plen else None


def irr_findings(prefix: str, origins: list[dict], irr: dict | None, verdict: str) -> list[dict]:
    out: list[dict] = []
    if irr is None or not irr.get("available") or not origins:
        return out
    asns = [o["asn"] for o in origins]
    listed = sorted({o["asn"] for o in irr["objects"] if o["exact"]} or {o["asn"] for o in irr["objects"]})
    names = ", ".join(f"AS{a}" for a in asns)
    if verdict == "missing":
        out.append(finding("irr-missing", "warn", "No route object for this prefix in any IRR registry",
                           "Many transit providers and IXP route servers build their prefix filters from IRR route objects. "
                           "Without one your announcement can be filtered or need a manual exception.",
                           "Create a route object (route/route6) for the prefix with your origin AS in your RIR's IRR (for example MyAPNIC for APNIC) "
                           "and make sure your upstreams use that registry.", {"prefix": prefix}))
    elif verdict == "mismatch":
        missing = [a for a in asns if a not in listed]
        out.append(finding("irr-mismatch", "warn",
                           f"IRR route objects exist but none names the announcing AS ({', '.join(f'AS{a}' for a in missing) or names})",
                           f"The IRR lists {', '.join(f'AS{a}' for a in listed)} as origin for this prefix, but BGP shows it announced by {names}. "
                           "Networks that filter on IRR data may reject or deprioritise the route, and a stale object can also look like a hijack.",
                           "Create a route object with the correct origin AS in the same registry and delete the outdated one. "
                           "Keep the ROA and the route object consistent.",
                           {"bgp_origins": asns, "irr_origins": listed, "sources": irr["sources"]}))
    elif verdict == "match":
        out.append(finding("irr-match", "pass", f"IRR route object matches the announcing AS ({names})",
                           "A route object in the IRR names the AS that announces this prefix, so IRR-based filters at your upstreams and "
                           "IXPs will accept it.", "", {"sources": sorted({o["source"] for o in irr["objects"] if o["matches_bgp"]})}))
        rel = [o for o in irr["objects"] if o["exact"]] or irr["objects"]
        stale = sorted({(o["source"], o["asn"]) for o in rel if o["asn"] not in asns})
        if stale:
            who = ", ".join(f"AS{a} in {s}" for s, a in stale)
            out.append(finding("irr-stale", "warn", f"Outdated route object with a different origin also exists ({who})",
                               "Besides the correct object, the IRR still holds a route object naming another AS for this prefix. "
                               "Filters built from the IRR then also allow that AS to announce your space, and tools report "
                               "\"multiple route objects with different origins\".",
                               "If that AS should no longer announce the prefix, delete its route object in the registry "
                               "(and remove its ROA too if one exists).", {"stale": [{"source": s, "asn": a} for s, a in stale]}))
    return out


def prefix_findings(prefix: str, origins: list[dict], moas: bool, announced: bool | None, vis: dict | None,
                    status: dict | None, history: dict | None, irr: dict | None = None,
                    irr_verdict: str = "unknown") -> list[dict]:
    out: list[dict] = []
    if announced is False or (status is not None and not origins and not status["origins"]):
        out.append(finding("announced", "fail", f"{prefix} is not announced",
                           "No route for this prefix is visible in the global routing table, so the address space is unreachable from the internet.",
                           "Check that the BGP announcement is configured and that your upstream is not filtering it."))
    if vis and vis["total_collectors"]:
        s, t = vis["seen_collectors"], vis["total_collectors"]
        if s == t:
            out.append(finding("visibility", "pass", f"Visible on {s} of {t} collectors",
                               "RIPE RIS collectors on every continent see this route.", "", {"seen": s, "total": t}))
        else:
            st = "fail" if s == 0 else "warn" if s / t >= 0.5 else "fail"
            out.append(finding("visibility", st, f"Visible on {s} of {t} collectors" if s else "Not visible on any collector",
                               "Some parts of the internet do not have this route: a provider may filter it, or it may be too new or too narrow (/25 and longer are usually dropped).",
                               "Check the announcement with your upstreams and compare with the list of collectors below.",
                               {"seen": s, "total": t, "not_seen": [c["id"] for c in vis["collectors"] if c["is_seen"] is False]}))
    for o in origins:
        rp = o.get("rpki")
        if not rp:
            continue
        if rp["state"] == "valid":
            out.append(finding(f"rpki-AS{o['asn']}", "pass", f"RPKI valid for AS{o['asn']}",
                               "A ROA authorises this AS to originate the prefix.", "", {"roas": rp["roas"]}))
        elif rp["state"] == "invalid":
            why = {"asn": "origin AS doesn't match the ROA", "length": "prefix is longer than the ROA allows"}.get(rp["reason"], "announcement contradicts the ROA")
            out.append(finding(f"rpki-AS{o['asn']}", "fail", f"RPKI invalid: {why}",
                               "A ROA covers this prefix but not this announcement. Networks that enforce RPKI drop the route, or it is a hijack.",
                               "Update the ROA (origin AS, max length) or stop announcing the prefix from the wrong AS.", {"asn": o["asn"], "roas": rp["roas"]}))
        else:
            out.append(finding(f"rpki-AS{o['asn']}", "warn", f"No ROA covers this prefix (AS{o['asn']})",
                               "Without a ROA the origin cannot be validated and a hijack looks identical to the real route.",
                               "Create a ROA for the prefix in your RIR portal.", {"asn": o["asn"]}))
    for o in origins:
        loose = maxlength_loose(prefix, (o.get("rpki") or {}).get("roas") or [])
        if loose is not None:
            plen = _plen(prefix)
            out.append(finding("roa-maxlength-loose", "warn" if loose - plen >= 2 else "info",
                               f"ROA for AS{o['asn']} allows up to /{loose}, longer than the /{plen} announced",
                               "A ROA with a max length above the announced length lets anyone announce a more-specific prefix with your AS "
                               "as the origin (a forged-origin sub-prefix hijack) and still be RPKI-valid.",
                               f"Set the ROA max length to /{plen}, or create separate ROAs for the more-specific prefixes you really announce.",
                               {"asn": o["asn"], "max_length": loose, "announced_length": plen}))
    out.extend(irr_findings(prefix, origins, irr, irr_verdict))
    if moas:
        out.append(finding("moas", "warn", "Announced by multiple origin ASes: " + ", ".join(f"AS{o['asn']}" for o in origins),
                           "Several ASes originate this exact prefix (MOAS). That is normal for anycast and multi-provider setups, but also what a hijack looks like.",
                           "Confirm every origin is expected and has a ROA.", {"origins": [o["asn"] for o in origins]}))
    if status:
        known = {o["asn"] for o in origins}
        odd = [m for m in status["more_specifics"] if m["origin"] is not None and m["origin"] not in known]
        if odd:
            plen = odd[0]["prefix"].split("/")[-1]
            out.append(finding("more-specific-other-as", "warn", f"More-specific /{plen} announced by a different AS: possible hijack or customer route",
                               "A longer prefix inside this block is originated by another AS and wins traffic for that range over the aggregate.",
                               "If you did not delegate it, ask the origin and its upstream to withdraw it and publish ROAs with a tight max length.",
                               {"examples": odd[:10], "count": len(odd)}))
    if history and len({h["origin"] for h in history["origins"] if h["origin"] is not None}) > 1:
        seq = []
        for t in history["timeline"]:
            if not seq or seq[-1] != t["origin"]:
                seq.append(t["origin"])
        out.append(finding("origin-change", "warn", f"Origin AS changed in the last {history['days']} days: " + " > ".join(f"AS{a}" for a in seq[:6]),
                           "The AS originating this prefix was not the same all month. That is expected after a migration, suspicious if you did not move it.",
                           "Verify the change was intended.", {"origins": history["origins"]}))
    return out


async def prefix_report(prefix_or_ip: str, *, fetch: ripestat.Fetch | None = None, budget: float = BUDGET) -> dict:
    t0 = time.monotonic()
    deadline = t0 + budget
    res, is_ip = parse_resource(prefix_or_ip)
    missing: list[str] = []
    errors: dict[str, str] = {}
    prefix, queried_ip = res, None
    if is_ip:
        queried_ip = res
        r0, e0 = await gather_bounded({"network_info": ripestat.network_info(res, fetch)}, deadline)
        errors.update(e0)
        if "network_info" in r0 and r0["network_info"]["prefix"]:
            prefix = r0["network_info"]["prefix"]
        elif "network_info" in e0:
            missing.append("network_info")
    r, errs = await gather_bounded({
        "routing_status": ripestat.routing_status(prefix, fetch), "visibility": ripestat.visibility(prefix, fetch),
        "overview": ripestat.prefix_overview(prefix, fetch), "looking_glass": ripestat.looking_glass(prefix, fetch),
        "history": ripestat.routing_history(prefix, 30, fetch), "whois": ripestat.whois_prefix(prefix, fetch),
        "abuse": ripestat.abuse_contact(prefix, fetch), "irr": irrmod.lookup(prefix, fetch)}, deadline)
    errors.update(errs)
    status, vis, ov, lg, hist = (r.get(k) for k in ("routing_status", "visibility", "overview", "looking_glass", "history"))

    # origin ASes: routing-status, else prefix-overview, else the looking-glass paths
    asns: list[int] = list(status["origins"]) if status else []
    if not asns and ov:
        asns = [a["asn"] for a in ov["asns"] if a["asn"] is not None]
    if not asns and lg:
        asns = sorted({p["as_path"][-1] for rrc in lg["rrcs"] for p in rrc["peers"]})
    holders = {a["asn"]: a["holder"] for a in (ov["asns"] if ov else [])}
    asns = asns[:5]
    r2, e2 = await gather_bounded({f"rpki:{a}": ripestat.rpki_validation(a, prefix, fetch) for a in asns}, deadline)
    origins = [{"asn": a, "holder": holders.get(a), "name": ripestat._name_from_holder(holders.get(a)), "rpki": r2.get(f"rpki:{a}")} for a in asns]
    if e2:
        errors["rpki"] = "; ".join(f"{k[5:]}: {v}" for k, v in e2.items())
        missing.append("rpki")
    for k, part in (("routing_status", "routing_status"), ("visibility", "visibility"), ("overview", "overview"),
                    ("looking_glass", "as_paths"), ("history", "history"), ("whois", "whois"), ("irr", "irr")):
        if k in errs:
            missing.append(part)
    whois, abuse, irr_entries = r.get("whois"), r.get("abuse"), r.get("irr")

    # connectivity: AS names (PeeringDB in bulk, RIPEstat for the few that are still unknown)
    names: dict[int, str | None] = {o["asn"]: o["name"] for o in origins if o["name"]}
    if lg:
        names.update(await _resolve_names(pathgraph.graph_asns(lg), names, fetch, deadline))
    connectivity = pathgraph.build(lg, names) if lg else None

    irr_block = irrmod.build(irr_entries, prefix, [o["asn"] for o in origins])
    irr_verdict = irr_block.pop("verdict")
    irr_rir = irr_block.pop("rir")
    validation = None
    if origins or irr_entries is not None:
        rpki_rows = []
        for o in origins:
            rp = o.get("rpki")
            if rp:
                rpki_rows.append({"asn": o["asn"], "state": rp["state"], "reason": rp["reason"], "roas": rp["roas"],
                                  "maxlength_loose": maxlength_loose(prefix, rp["roas"]) is not None})
        states = {x["state"] for x in rpki_rows}
        rpki_sum = "invalid" if "invalid" in states else "unknown" if (not states or "unknown" in states) else "valid"
        validation = {"rpki": rpki_rows, "irr": irr_block, "summary": {"rpki": rpki_sum, "irr": irr_verdict}}
    overview_block = prefixwhois.overview(prefix, whois, abuse, irr_rir)

    moas = len(asns) > 1
    joined = join_collectors(vis) if vis else None
    announced = ov["announced"] if ov else (bool(asns) if (status or lg) else None)
    findings = prefix_findings(prefix, origins, moas, announced, joined, status, hist, irr_block, irr_verdict)
    st = worst(findings) if findings else "unknown"
    return {
        "prefix": prefix, "queried": queried_ip or prefix, "is_ip": is_ip, "announced": announced,
        "status": st, "summary": prefix_summary(prefix, origins, moas, joined, announced),
        "origins": origins, "moas": moas,
        "visibility": None if not joined else {**joined, "routing_status": status["visibility"] if status else None},
        "less_specifics": status["less_specifics"] if status else None,
        "more_specifics": status["more_specifics"] if status else None,
        "more_specifics_total": status["more_specifics_total"] if status else None,
        "first_seen": status["first_seen"] if status else None, "last_seen": status["last_seen"] if status else None,
        "history": None if not hist else {"days": hist["days"], "origins": hist["origins"], "timeline": hist["timeline"]},
        "as_paths": top_paths(lg) if lg else None,
        "block": ov["block"] if ov else None,
        "overview": overview_block, "connectivity": connectivity, "validation": validation,
        "findings": findings, "missing": missing, "errors": errors, "partial": bool(missing),
        "elapsed_ms": round((time.monotonic() - t0) * 1000),
    }


async def _resolve_names(asns: list[int], known: dict[int, str | None], fetch, deadline: float) -> dict[int, str | None]:
    """Names for ASNs on the graph: PeeringDB in one bulk call, then RIPEstat as-overview for at most 10 leftovers.
    Cosmetic, so every failure is swallowed."""
    todo = [a for a in asns if not known.get(a)]
    if not todo:
        return {}
    r, _e = await gather_bounded({"pdb": peeringdb.names_bulk(todo, fetch)}, deadline)
    names: dict[int, str | None] = dict(r.get("pdb") or {})
    rest = [a for a in todo if not names.get(a)][:10]
    if rest:
        r2, _e2 = await gather_bounded({f"n:{a}": ripestat.as_overview(a, fetch) for a in rest}, deadline)
        for k, v in r2.items():
            names[int(k[2:])] = v.get("name") or v.get("holder")
    return names


def prefix_summary(prefix: str, origins: list[dict], moas: bool, vis: dict | None, announced: bool | None) -> str:
    if announced is False and not origins:
        return f"{prefix} is not announced in the global routing table."
    if not origins:
        return f"{prefix}: origin AS could not be determined."
    if moas:
        who = f"originated by {len(origins)} ASes (MOAS): " + ", ".join(f"AS{o['asn']}" for o in origins)
    else:
        o = origins[0]
        who = f"originated by {_label(o['asn'], o.get('name'))}"
    s = f"{prefix} is {who}"
    states = {(o.get("rpki") or {}).get("state") for o in origins} - {None}
    if states:
        s += ", RPKI " + ("/".join(sorted(states)) if len(states) > 1 else next(iter(states)))
    if vis and vis["total_collectors"]:
        s += f", seen by {vis['seen_collectors']} of {vis['total_collectors']} RIS collectors"
    return s + "."
