"""Globalping (globalping.io) client: create a measurement, poll it, stream per-probe results.

Public targets only (validated with ``app.core.target``), so probes are never pointed at private
space or our blocked networks. Network access is injectable (``post`` / ``get``) for tests.
The token is optional (``GLOBALPING_TOKEN``); anonymous use has a small hourly credit budget.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any, AsyncIterator, Awaitable, Callable

import httpx

from app.core.httpjson import FetchError, _guard, fetch_json
from app.core.target import TargetError, parse_target, resolve_public

API = "https://api.globalping.io/v1"
TYPES = ("ping", "traceroute", "mtr", "dns", "http")
MAX_LIMIT = 10
DEFAULT_LIMIT = 4
DEFAULT_BUDGET = 25.0
POLL_INTERVAL = 1.0
RATE_MSG = ("Globalping rate limit or probe credits exhausted. Anonymous use has a small hourly budget: "
            "wait a few minutes and try again, or configure GLOBALPING_TOKEN on the server.")
_ID = re.compile(r"^[A-Za-z0-9]{8,64}$")
_DNS_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA", "DS", "DNSKEY"}
_HTTP_PORTS = {80, 443, 8080, 8443}

Post = Callable[..., Awaitable[tuple[int, Any]]]
Get = Callable[..., Awaitable[Any]]


class GlobalpingError(Exception):
    def __init__(self, msg: str, status: int = 502, code: str | None = None) -> None:
        super().__init__(msg)
        self.status = status
        self.code = code


def _headers() -> dict:
    tok = os.environ.get("GLOBALPING_TOKEN")
    return {"Authorization": f"Bearer {tok}"} if tok else {}


# --- locations ---------------------------------------------------------------------------
PRESETS: dict[str, list[dict]] = {
    "india": [{"country": "IN", "city": "Mumbai"}, {"country": "IN", "city": "Delhi"},
              {"country": "IN", "city": "Bengaluru"}, {"country": "IN", "city": "Chennai"}],
    "asia": [{"continent": "AS"}],
    "europe": [{"continent": "EU"}],
    "north america": [{"continent": "NA"}],
    "world": [{"continent": c} for c in ("NA", "EU", "AS", "OC", "SA", "AF")],
}
_LOC_KEYS = {"continent", "region", "country", "state", "city", "asn", "network", "tags", "magic"}


def _parse_loc(item: Any) -> list[dict]:
    if isinstance(item, dict):
        d = {k: v for k, v in item.items() if k in _LOC_KEYS and v not in (None, "")}
        if not d:
            raise GlobalpingError("empty location", 422)
        return [d]
    s = str(item).strip()
    if not s or len(s) > 64:
        raise GlobalpingError("invalid location", 422)
    if s.lower() in PRESETS:
        return [dict(x) for x in PRESETS[s.lower()]]
    if re.fullmatch(r"(?i)AS\d{1,10}", s):
        return [{"asn": int(s[2:])}]
    if re.fullmatch(r"[A-Za-z]{2}", s):
        return [{"country": s.upper()}]
    m = re.fullmatch(r"([^,]{3,48}),\s*([A-Za-z]{2})", s)
    if m:
        return [{"city": m[1].strip(), "country": m[2].upper()}]
    if re.fullmatch(r"[\w .'-]{2,48}", s):
        return [{"city": s}]
    raise GlobalpingError(f"invalid location: {s!r}", 422)


def build_locations(locations: Any, limit: int) -> list[dict]:
    """Preset name / 'City, CC' / country code / dict(s) -> API locations whose per-location
    limits sum to ``limit`` (<= 10)."""
    limit = max(1, min(DEFAULT_LIMIT if limit is None else int(limit), MAX_LIMIT))
    if locations in (None, "", []):
        locations = "World"
    items = locations if isinstance(locations, (list, tuple)) else [locations]
    locs: list[dict] = []
    for it in items:
        if isinstance(it, str) and "," in it and it.strip().lower() not in PRESETS \
                and not re.fullmatch(r"[^,]{3,48},\s*[A-Za-z]{2}", it.strip()):
            for part in it.split(","):
                locs += _parse_loc(part)
        else:
            locs += _parse_loc(it)
    if len(locs) > MAX_LIMIT:
        raise GlobalpingError("too many locations (max 10)", 422)
    if limit < len(locs):
        locs = locs[:limit]
    base, extra = divmod(limit, len(locs))
    for i, loc in enumerate(locs):
        loc["limit"] = base + (1 if i < extra else 0)
    return locs


# --- target + options validation ---------------------------------------------------------
async def _public_host(raw: str, resolve: Callable[..., Awaitable[Any]], *, need_resolution: bool = True) -> str:
    try:
        host, is_ip = parse_target(raw)
        if not is_ip and need_resolution:
            await resolve(host)  # every A/AAAA must be public
    except TargetError as exc:
        raise GlobalpingError(str(exc), 422) from exc
    return host


def _intopt(v: Any, lo: int, hi: int, name: str) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise GlobalpingError(f"{name} must be a number", 422)
    if not lo <= n <= hi:
        raise GlobalpingError(f"{name} must be {lo}-{hi}", 422)
    return n


async def build_options(type_: str, options: dict | None, resolve: Callable[..., Awaitable[Any]]) -> dict:
    """Whitelist flat user options into Globalping's ``measurementOptions``."""
    o = options or {}
    out: dict[str, Any] = {}
    if type_ in ("ping", "mtr") and o.get("packets") is not None:
        out["packets"] = _intopt(o["packets"], 1, 16, "packets")
    if type_ in ("traceroute", "mtr"):
        if o.get("protocol"):
            p = str(o["protocol"]).upper()
            if p not in ("ICMP", "TCP", "UDP"):
                raise GlobalpingError("protocol must be ICMP, TCP or UDP", 422)
            out["protocol"] = p
        if o.get("port") is not None:
            out["port"] = _intopt(o["port"], 1, 65535, "port")
    if type_ == "dns":
        qt = str(o.get("query_type") or o.get("type") or "A").upper()
        if qt not in _DNS_TYPES:
            raise GlobalpingError(f"unsupported DNS type {qt}", 422)
        out["query"] = {"type": qt}
        if o.get("protocol"):
            p = str(o["protocol"]).upper()
            if p not in ("UDP", "TCP"):
                raise GlobalpingError("DNS protocol must be UDP or TCP", 422)
            out["protocol"] = p
    if type_ in ("dns", "http") and o.get("resolver"):
        out["resolver"] = await _public_host(str(o["resolver"]), resolve)
    if type_ == "http":
        req: dict[str, Any] = {"method": str(o.get("method") or "HEAD").upper()}
        if req["method"] not in ("GET", "HEAD"):
            raise GlobalpingError("method must be GET or HEAD", 422)
        path = str(o.get("path") or "/")
        if not path.startswith("/") or len(path) > 512 or re.search(r"[\s\x00-\x1f\x7f]", path):
            raise GlobalpingError("invalid path", 422)
        req["path"] = path
        if o.get("query"):
            q = str(o["query"])
            if len(q) > 512 or re.search(r"[\s\x00-\x1f\x7f]", q):
                raise GlobalpingError("invalid query string", 422)
            req["query"] = q
        out["request"] = req
        if o.get("protocol"):
            p = str(o["protocol"]).upper()
            if p not in ("HTTP", "HTTPS", "HTTP2"):
                raise GlobalpingError("protocol must be HTTP, HTTPS or HTTP2", 422)
            out["protocol"] = p
        if o.get("port") is not None:
            port = _intopt(o["port"], 1, 65535, "port")
            if port not in _HTTP_PORTS:
                raise GlobalpingError("port must be one of 80, 443, 8080, 8443", 422)
            out["port"] = port
    return out


# --- transport ---------------------------------------------------------------------------
async def _post_json(url: str, body: dict, headers: dict, timeout: float = 10.0) -> tuple[int, Any]:
    try:
        await _guard(url)
    except FetchError as exc:
        raise GlobalpingError(str(exc)) from exc
    hdrs = {"Accept": "application/json", "User-Agent": "BookMyHost-DevTools/1.2 (+https://bookmyhost.com/tools/)", **headers}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as c:
            r = await c.post(url, json=body, headers=hdrs)
            raw = r.content[:262144]
    except httpx.HTTPError as exc:
        raise GlobalpingError(f"Globalping request failed: {type(exc).__name__}") from exc
    try:
        return r.status_code, json.loads(raw) if raw else {}
    except ValueError:
        return r.status_code, {}


def _err_message(doc: Any) -> str:
    e = doc.get("error") if isinstance(doc, dict) else None
    return str(e.get("message") if isinstance(e, dict) else e or "")[:200]


async def create_measurement(type: str, target: str, locations: Any = "World", limit: int = DEFAULT_LIMIT,  # noqa: A002
                             options: dict | None = None, *, post: Post | None = None,
                             resolve: Callable[..., Awaitable[Any]] | None = None) -> dict:
    """POST /measurements. Returns {id, probes_count, type, target}. Raises GlobalpingError."""
    if type not in TYPES:
        raise GlobalpingError(f"type must be one of {', '.join(TYPES)}", 422)
    res = resolve or resolve_public
    # DNS measurements only ask resolvers about a name, so the name need not resolve to a public IP.
    host = await _public_host(target, res, need_resolution=type != "dns")
    body = {"type": type, "target": host, "locations": build_locations(locations, limit),
            "measurementOptions": await build_options(type, options, res)}
    if not body["measurementOptions"]:
        del body["measurementOptions"]
    status, doc = await (post or _post_json)(f"{API}/measurements", body, _headers())
    if status in (200, 201, 202) and isinstance(doc, dict) and doc.get("id"):
        return {"id": doc["id"], "probes_count": doc.get("probesCount"), "type": type, "target": host}
    if status in (402, 429):
        raise GlobalpingError(RATE_MSG, 429, "rate_limited")
    if status in (400, 422):
        raise GlobalpingError(_err_message(doc) or "Globalping rejected the request (no matching probes?)", 422, "rejected")
    raise GlobalpingError(f"Globalping returned HTTP {status}", 502)


# --- result normalisation ----------------------------------------------------------------
def _num(v: Any) -> float | None:
    try:
        return round(float(v), 2)
    except (TypeError, ValueError):
        return None


def _probe(p: dict) -> dict:
    return {"city": p.get("city") or None, "country": p.get("country") or None, "asn": p.get("asn"),
            "network": p.get("network") or None, "lat": p.get("latitude"), "lon": p.get("longitude"),
            "continent": p.get("continent") or None, "state": p.get("state") or None}


def _hop_rtts(h: dict) -> list[float]:
    return [r for r in (_num(t.get("rtt")) for t in h.get("timings") or [] if isinstance(t, dict)) if r is not None]


def normalise_result(type_: str, item: dict) -> dict:
    """One Globalping per-probe result -> {probe, status, stats, hops, detail, raw_output}."""
    r = item.get("result") or {}
    out: dict[str, Any] = {"probe": _probe(item.get("probe") or {}), "status": r.get("status") or "in-progress",
                           "resolved_address": r.get("resolvedAddress"),
                           "stats": {"min": None, "avg": None, "max": None, "loss": None}, "hops": [], "detail": {},
                           "raw_output": (r.get("rawOutput") or "")[:4000]}
    if type_ == "ping":
        s = r.get("stats") or {}
        out["stats"] = {"min": _num(s.get("min")), "avg": _num(s.get("avg")), "max": _num(s.get("max")),
                        "loss": _num(s.get("loss"))}
        out["detail"] = {"sent": s.get("total"), "received": s.get("rcv")}
    elif type_ in ("traceroute", "mtr"):
        hops = []
        for i, h in enumerate(r.get("hops") or [], 1):
            ip = h.get("resolvedAddress") or None
            hop: dict[str, Any] = {"hop": i, "ip": ip, "host": h.get("resolvedHostname") if ip else None, "rtt_ms": None}
            if type_ == "mtr":
                st = h.get("stats") or {}
                hop.update(rtt_ms=_num(st.get("avg")), min=_num(st.get("min")), max=_num(st.get("max")),
                           loss=_num(st.get("loss")), asn=h.get("asn") or [])
                if hop["loss"] is not None and hop["loss"] >= 100:
                    hop["ip"] = ip if ip else None
            else:
                rt = _hop_rtts(h)
                if rt:
                    hop.update(rtt_ms=round(sum(rt) / len(rt), 2), min=min(rt), max=max(rt))
            hops.append(hop)
        out["hops"] = hops
        last = next((h for h in reversed(hops) if h["ip"] and h["rtt_ms"] is not None), None)
        dest = r.get("resolvedAddress")
        reached = bool(last and (not dest or last["ip"] == dest))
        if type_ == "mtr" and hops:
            lh = hops[-1]
            out["stats"] = {"min": lh.get("min"), "avg": lh.get("rtt_ms"), "max": lh.get("max"), "loss": lh.get("loss")}
        elif last:
            out["stats"] = {"min": last.get("min"), "avg": last["rtt_ms"], "max": last.get("max"),
                            "loss": 0.0 if reached else 100.0}
        out["detail"] = {"reached": reached}
    elif type_ == "dns":
        t = r.get("timings") or {}
        out["stats"]["avg"] = _num(t.get("total"))
        out["detail"] = {"answers": [{"name": a.get("name"), "type": a.get("type"), "ttl": a.get("ttl"),
                                      "value": str(a.get("value"))[:300]} for a in (r.get("answers") or [])[:30]],
                         "resolver": r.get("resolver"), "status_code": r.get("statusCodeName") or r.get("statusCode")}
    elif type_ == "http":
        t = r.get("timings") or {}
        out["stats"]["avg"] = _num(t.get("total"))
        hdrs = r.get("headers") or {}
        keep = ("server", "content-type", "location", "cache-control", "strict-transport-security", "via", "cf-ray")
        out["detail"] = {"status_code": r.get("statusCode"), "status_text": r.get("statusCodeName"),
                         "timings": {k: _num(v) for k, v in t.items()},
                         "headers": {k: hdrs[k] for k in hdrs if k.lower() in keep},
                         "tls": ({"protocol": (r.get("tls") or {}).get("protocol"),
                                  "issuer": ((r.get("tls") or {}).get("issuer") or {}).get("O")}
                                 if r.get("tls") else None)}
        out["raw_output"] = ""
    return out


async def get_measurement(mid: str, *, get: Get | None = None) -> dict:
    if not _ID.match(str(mid)):
        raise GlobalpingError("invalid measurement id", 422)
    try:
        doc = await (get or fetch_json)(f"{API}/measurements/{mid}", None, 10.0, _headers())
    except FetchError as exc:
        if "429" in str(exc):
            raise GlobalpingError(RATE_MSG, 429, "rate_limited") from exc
        raise GlobalpingError(f"Globalping: {exc}", exc.status) from exc
    if not isinstance(doc, dict):
        raise GlobalpingError("Globalping returned an unexpected response")
    typ = doc.get("type") or "ping"
    probes = [normalise_result(typ, it) for it in doc.get("results") or []]
    finished = doc.get("status") == "finished" or (bool(probes) and all(p["status"] != "in-progress" for p in probes))
    return {"id": doc.get("id", mid), "type": typ, "target": doc.get("target"), "status": "finished" if finished else "in-progress",
            "finished": finished, "probes_count": doc.get("probesCount", len(probes)), "probes": probes}


async def run(type: str, target: str, locations: Any = "World", limit: int = DEFAULT_LIMIT,  # noqa: A002
              options: dict | None = None, *, budget: float = DEFAULT_BUDGET, interval: float = POLL_INTERVAL,
              post: Post | None = None, get: Get | None = None, resolve: Callable[..., Awaitable[Any]] | None = None,
              sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
              clock: Callable[[], float] = time.monotonic) -> AsyncIterator[dict]:
    """Create a measurement and poll it, yielding events:
    created -> probe* (each probe as it finishes) -> done | timeout | error.
    Never raises GlobalpingError; failures arrive as an ``error`` event (status/message/code)."""
    try:
        made = await create_measurement(type, target, locations, limit, options, post=post, resolve=resolve)
    except GlobalpingError as exc:
        yield {"event": "error", "status": exc.status, "code": exc.code, "message": str(exc)}
        return
    yield {"event": "created", **made}
    deadline = clock() + budget
    emitted: set[int] = set()
    while True:
        try:
            m = await get_measurement(made["id"], get=get)
        except GlobalpingError as exc:
            yield {"event": "error", "status": exc.status, "code": exc.code, "message": str(exc), "id": made["id"]}
            return
        for i, p in enumerate(m["probes"]):
            if i not in emitted and p["status"] != "in-progress":
                emitted.add(i)
                yield {"event": "probe", "index": i, "probe": p}
        if m["finished"]:
            yield {"event": "done", **m}
            return
        remaining = deadline - clock()
        if remaining <= 0:
            pending = sum(1 for p in m["probes"] if p["status"] == "in-progress")
            yield {"event": "timeout", "pending": pending,
                   "message": f"Stopped waiting after {budget:g}s; {pending} probe(s) had not answered.", **m}
            return
        await sleep(min(interval, remaining))


async def run_collect(*args: Any, **kw: Any) -> dict:
    """Convenience: drain ``run`` and return {id, status, probes, timed_out, error}."""
    res: dict[str, Any] = {"id": None, "status": "error", "probes": [], "timed_out": False, "error": None}
    async for ev in run(*args, **kw):
        if ev["event"] == "created":
            res["id"] = ev["id"]
        elif ev["event"] in ("done", "timeout"):
            res.update(status=ev["status"], probes=ev["probes"], timed_out=ev["event"] == "timeout")
        elif ev["event"] == "error":
            res["error"] = {"status": ev["status"], "code": ev.get("code"), "message": ev["message"]}
    return res
