"""Registry (whois) view of a prefix: parsed records with plain-English meanings, IRR route objects, abuse contact
and the holder's geofeed rows for this prefix.

Registry records come from RIPEstat ``whois`` + ``abuse-contact-finder``; the geofeed (RFC 8805 CSV) is fetched
through the SSRF-guarded fetcher in ``app.core.httpjson`` (https only, public hosts, 512 KB, 5 s).
"""
from __future__ import annotations

import csv
import datetime as dt
import functools
import io
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from app.core import ripestat
from app.core.httpjson import FetchError, fetch_text

_MEANINGS = Path(__file__).resolve().parent.parent / "data" / "whois_meanings.json"
GEOFEED_MAX_BYTES = 512 * 1024
GEOFEED_TIMEOUT = 5.0
GEOFEED_MAX_ROWS = 20
RAW_MAX = 20000
_GEOFEED_REMARK = re.compile(r"geofeed\s+(https?://\S+)", re.I)


@functools.lru_cache(maxsize=1)
def meanings() -> dict:
    return json.loads(_MEANINGS.read_text(encoding="utf-8"))


def norm_status(value: str | None) -> str:
    return re.sub(r"[\s_-]+", " ", str(value or "").strip()).upper()


def status_meaning(value: str | None) -> str | None:
    s = norm_status(value)
    if not s:
        return None
    table = meanings()["status"]
    if s in table:
        return table[s]
    return table.get(s.split(" #")[0])


def key_meaning(key: str, value: str | None = None) -> str | None:
    k = str(key).strip().lower()
    if k in ("status", "nettype"):
        return status_meaning(value) or meanings()["keys"].get(k)
    return meanings()["keys"].get(k)


# --- parsing ----------------------------------------------------------------------------------------
def parse_records(data: dict | None) -> tuple[list[list[dict]], list[list[dict]], list[str]]:
    """(records with meaning, irr_records, authorities) from a trimmed ``ripestat.whois_prefix`` result."""
    records = []
    for rec in (data or {}).get("records", []):
        rows = [{"key": kv["key"], "value": kv["value"], "meaning": key_meaning(kv["key"], kv["value"])} for kv in rec]
        if rows:
            records.append(rows)
    irr = [[{"key": kv["key"], "value": kv["value"]} for kv in rec] for rec in (data or {}).get("irr_records", []) if rec]
    return records, irr, list((data or {}).get("authorities") or [])


def _first(records: list[list[dict]], *keys: str) -> str | None:
    """First value of any of ``keys`` (in priority order), looking at the first (most specific) record first."""
    for key in keys:
        for rec in records:
            for kv in rec:
                if kv["key"].lower() == key and kv["value"]:
                    return kv["value"]
    return None


def find_geofeed_url(records: list[list[dict]]) -> str | None:
    url = _first(records[:1], "geofeed")
    if not url:
        for rec in records[:1]:
            for kv in rec:
                if kv["key"].lower() in ("remarks", "remark", "comment"):
                    m = _GEOFEED_REMARK.search(kv["value"])
                    if m:
                        return m.group(1)
    return url


def overview_fields(records: list[list[dict]], authorities: list[str]) -> dict:
    status = _first(records, "status", "nettype")
    registered = _first(records, "created", "regdate", "reg-date")
    return {
        "rir": (authorities[0].upper() if authorities else None) or ((_first(records, "source") or "").split() or [None])[0],
        "country": _first(records, "country"),
        "netname": _first(records, "netname"),
        "holder": _first(records, "orgname", "org-name", "owner", "organization", "descr"),
        "inetnum": _first(records, "inetnum", "inet6num", "netrange", "cidr"),
        "reg_status": status,
        "reg_status_meaning": status_meaning(status),
        "registered": registered[:10] if registered else None,
    }


def age_days(registered: str | None, today: dt.date | None = None) -> int | None:
    if not registered:
        return None
    try:
        d = dt.date.fromisoformat(registered[:10])
    except ValueError:
        return None
    return max(((today or dt.datetime.now(dt.timezone.utc).date()) - d).days, 0)


def size_of(prefix: str) -> dict:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return {"addresses": None, "slash24s": None, "slash48s": None}
    n = net.num_addresses
    if net.version == 4:
        return {"addresses": n, "slash24s": max(n // 256, 1) if n >= 256 else 0, "slash48s": None}
    return {"addresses": n, "slash24s": None, "slash48s": 1 << (48 - net.prefixlen) if net.prefixlen <= 48 else 0}


def raw_text(data: dict | None) -> str:
    blocks = []
    for group in ((data or {}).get("records", []), (data or {}).get("irr_records", [])):
        for rec in group:
            if rec:
                blocks.append("\n".join(f"{kv['key']}: {kv['value']}" for kv in rec))
    return "\n\n".join(blocks)[:RAW_MAX]


# --- geofeed ----------------------------------------------------------------------------------------
def parse_geofeed(text: str, prefix: str, limit: int = GEOFEED_MAX_ROWS) -> list[dict]:
    """Rows of an RFC 8805 CSV (prefix,country,region,city,zip) that overlap ``prefix``."""
    try:
        target = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return []
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    rows = []
    for cols in csv.reader(io.StringIO("\n".join(lines))):
        if not cols:
            continue
        cols = [c.strip() for c in cols] + [""] * 5
        try:
            net = ipaddress.ip_network(cols[0], strict=False)
        except ValueError:
            continue
        if net.version != target.version or not net.overlaps(target):
            continue
        rows.append({"prefix": str(net), "country": cols[1][:2].upper(), "region": cols[2][:16],
                     "city": cols[3][:80], "zip": cols[4][:16]})
        if len(rows) >= limit:
            break
    return rows


async def geofeed(url: str, prefix: str, text_fetch=None) -> dict:
    """{'url', 'rows', 'error'}; never raises."""
    f = text_fetch or fetch_text
    try:
        text = await f(url, None, GEOFEED_TIMEOUT, None, GEOFEED_MAX_BYTES)
    except FetchError as exc:
        return {"url": url, "rows": [], "error": str(exc)[:200]}
    except Exception as exc:  # noqa: BLE001 - optional card, must not break the response
        return {"url": url, "rows": [], "error": type(exc).__name__}
    return {"url": url, "rows": parse_geofeed(text, prefix), "error": None}


# --- report -----------------------------------------------------------------------------------------
async def report(prefix: str, *, fetch=None, text_fetch=None) -> dict:
    """Body of GET /prefix-whois. The registry record is required (RipeStatError propagates); abuse and
    geofeed are optional and degrade to null."""
    data = await ripestat.whois_prefix(prefix, fetch)
    try:
        abuse = (await ripestat.abuse_contact(prefix, fetch)).get("email")
    except ripestat.RipeStatError:
        abuse = None
    records, irr, authorities = parse_records(data)
    gurl = find_geofeed_url(records)
    gf: dict | None = await geofeed(gurl, prefix, text_fetch) if gurl else None
    return {"prefix": prefix, "records": records, "irr_records": irr, "authorities": authorities,
            "abuse_email": abuse, "geofeed": gf, "raw": raw_text(data),
            "fetched_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def overview(prefix: str, whois: dict | None, abuse: dict | None, irr_rir: str | None = None) -> dict | None:
    """The ``overview`` block of the prefix report (None when neither whois nor abuse is known)."""
    if whois is None and abuse is None:
        return None
    records, _irr, authorities = parse_records(whois)
    f = overview_fields(records, authorities)
    f["rir"] = f["rir"] or (irr_rir.upper() if irr_rir else None) or (abuse or {}).get("rir")
    return {**f, "age_days": age_days(f["registered"]), "size": size_of(prefix),
            "abuse_email": (abuse or {}).get("email")}
