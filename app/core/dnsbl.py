"""DNS blocklist (DNSBL / RHSBL) checker for IPs and domains.

* Lists live in ``app/data/dnsbl.json`` (name, zone, type ip|domain, delist_url, weight 1-3, requires_key, ipv6).
* ``iter_check`` yields one row per list as each answers (stream-friendly); ``check`` aggregates into a CheckResult.
* Return codes: 127.0.0.x = listed. 127.255.255.x (Spamhaus "query refused / error"), a list's own refused codes
  (URIBL 127.0.0.1) and anything outside 127.0.0.0/8 (resolver hijack / wildcard) are errors and NEVER counted as listed.
* Spamhaus lists need a DQS key: read from env ``SPAMHAUS_DQS_KEY`` at call time; without it the row is "skipped".
* Resolver: env ``BMH_TOOLS_DNSBL_RESOLVER`` (comma separated IPs) else the system resolver. NOTE: many lists refuse
  queries from big public resolvers (8.8.8.8, 1.1.1.1), so use your own recursive resolver in production.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, AsyncIterator

from app.core.mailcheck.models import CheckResult, clean_domain
from app.core.mailcheck.resolver import DnsResolver, Resolver
from app.core.validate import ValidationError, is_ip_literal, is_public_ip

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "dnsbl.json"
CONCURRENCY = 20
OVERALL_TIMEOUT = 15.0
_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_REFUSED_NET = ipaddress.ip_network("127.255.255.0/24")


@lru_cache(maxsize=1)
def load_lists() -> tuple[dict, ...]:
    with DATA_FILE.open(encoding="utf-8") as f:
        return tuple(json.load(f)["lists"])


def get_dnsbl_resolver() -> DnsResolver:
    raw = os.environ.get("BMH_TOOLS_DNSBL_RESOLVER", "").strip()
    ips = [p.strip() for p in raw.split(",") if p.strip()]
    return DnsResolver(nameservers=ips or None, timeout=2.0, lifetime=3.0)


def dqs_key() -> str | None:
    k = os.environ.get("SPAMHAUS_DQS_KEY", "").strip()
    return k if re.fullmatch(r"[A-Za-z0-9]{8,64}", k) else None


def reverse_ip(ip: str) -> str:
    """IPv4: 1.2.3.4 -> 4.3.2.1 ; IPv6: 32 reversed nibbles separated by dots."""
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(str(a).split(".")))
    return ".".join(reversed(a.exploded.replace(":", "")))


def build_query(entry: dict, target: str, key: str | None = None) -> str:
    """Query name for ``target`` (IP or domain) against ``entry`` (uses the DQS zone when a key is given)."""
    zone = entry["zone"]
    if entry.get("requires_key"):
        if not key:
            raise ValueError("this list needs a DQS key")
        zone = f"{key}.{entry['dqs_zone']}"
    left = reverse_ip(target) if entry["type"] == "ip" else target.rstrip(".").lower()
    return f"{left}.{zone}"


def interpret(entry: dict, codes: list[str]) -> tuple[str, str | None, str | None]:
    """Map A-record answers to (status, code, note). status: listed | error."""
    good: list[str] = []
    for c in codes:
        try:
            a = ipaddress.ip_address(c)
        except ValueError:
            return "error", c, "the answer was not an IP address"
        if a.version != 4 or a not in _LOOPBACK:
            return "error", c, "answer outside 127.0.0.0/8: your resolver is rewriting DNS answers (or a wildcard)"
        if a in _REFUSED_NET:
            return "error", c, "the list refused the query (resolver blocked or over its free quota)"
        if c in entry.get("refused_codes", []):
            return "error", c, "the list refused the query (resolver blocked)"
        good.append(c)
    if not good:
        return "error", None, "empty answer"
    known = entry.get("codes", {})
    code = next((c for c in good if c in known), good[0])
    return "listed", code, known.get(code)


def classify(target: str) -> tuple[str, str]:
    """('ip'|'domain', normalised). Only public IPs and plain domains are allowed."""
    target = target.strip()
    if is_ip_literal(target):
        ip = target.strip("[]")
        if not is_public_ip(ip):
            raise ValidationError("only public IP addresses can be checked")
        return "ip", str(ipaddress.ip_address(ip))
    return "domain", clean_domain(target)


def _row(entry: dict, status: str, **kw: Any) -> dict:
    row = {"name": entry["name"], "zone": entry["zone"], "type": entry["type"], "status": status, "listed": status == "listed",
           "code": None, "reason": None, "weight": entry["weight"], "delist_url": entry["delist_url"], "query": None,
           "ms": None, "note": entry.get("note")}
    row.update(kw)
    return row


async def _query_list(entry: dict, kind: str, target: str, r: Resolver, key: str | None) -> dict:
    qname = build_query(entry, target, key)
    shown = qname.replace(key, "<key>") if key else qname
    t0 = time.perf_counter()
    ans = await r.query(qname, "A")
    ms = round((time.perf_counter() - t0) * 1000, 1)
    if ans.status in ("nxdomain", "noanswer"):
        return _row(entry, "clear", query=shown, ms=ms)
    if ans.status == "timeout":
        return _row(entry, "timeout", query=shown, ms=ms, note="no answer from the list in time")
    if ans.status != "ok":
        return _row(entry, "error", query=shown, ms=ms, note=f"resolver returned {ans.status}")
    status, code, note = interpret(entry, ans.records)
    if status != "listed":
        return _row(entry, "error", query=shown, ms=ms, code=code, note=note)
    reason = note
    try:  # best-effort human reason from the TXT record
        txt = await asyncio.wait_for(r.query(qname, "TXT"), 2.5)
        if txt.ok:
            reason = txt.records[0].replace(key, "<key>")[:300] if key else txt.records[0][:300]
    except Exception:  # noqa: BLE001
        pass
    return _row(entry, "listed", query=shown, ms=ms, code=code, reason=reason, note=note if reason != note else entry.get("note"))


def _skip_reason(entry: dict, ip_version: int | None, key: str | None) -> str | None:
    if entry.get("requires_key") and not key:
        return "Skipped: needs a Spamhaus DQS key (set SPAMHAUS_DQS_KEY). Spamhaus refuses queries from public resolvers."
    if ip_version == 6 and not entry.get("ipv6"):
        return "Skipped: this list does not support IPv6 addresses."
    return None


async def iter_check(ip_or_domain: str, resolver: Resolver | None = None, *, timeout: float = OVERALL_TIMEOUT,
                     concurrency: int = CONCURRENCY, lists: list[dict] | None = None,
                     semaphore: asyncio.Semaphore | None = None) -> AsyncIterator[dict]:
    """Yield one result row per list as each finishes (skipped rows first, then by completion time)."""
    kind, target = classify(ip_or_domain)
    r = resolver or get_dnsbl_resolver()
    key = dqs_key()
    ver = ipaddress.ip_address(target).version if kind == "ip" else None
    entries = [e for e in (lists if lists is not None else load_lists()) if e["type"] == kind]
    sem = semaphore or asyncio.Semaphore(concurrency)
    todo: list[dict] = []
    for e in entries:
        why = _skip_reason(e, ver, key)
        if why:
            yield _row(e, "skipped", note=why)
        else:
            todo.append(e)

    async def run(e: dict) -> dict:
        async with sem:
            try:
                return await _query_list(e, kind, target, r, key if e.get("requires_key") else None)
            except Exception as exc:  # noqa: BLE001
                return _row(e, "error", note=f"check failed: {type(exc).__name__}")

    tasks = {asyncio.create_task(run(e)): e for e in todo}
    pending = set(tasks)
    deadline = time.monotonic() + timeout
    try:
        while pending:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            done, pending = await asyncio.wait(pending, timeout=left, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                yield t.result()
        for t in list(pending):
            t.cancel()
            yield _row(tasks[t], "timeout", note="overall time budget used up before this list answered")
    finally:
        for t in pending:
            t.cancel()


def _slug(zone: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", zone.lower()).strip("_")


def summarize(target: str, kind: str, rows: list[dict]) -> CheckResult:
    res = CheckResult("dnsbl", target)
    rows = sorted(rows, key=lambda x: (x["status"] != "listed", x["name"]))
    counts = {s: sum(r["status"] == s for r in rows) for s in ("listed", "clear", "skipped", "error", "timeout")}
    counts["checked"] = counts["listed"] + counts["clear"]
    lw = sum(r["weight"] for r in rows if r["listed"])
    res.data = {"kind": kind, "target": target, "rows": rows, "counts": counts, "listed_weight": lw,
                "total_weight": sum(r["weight"] for r in rows if r["status"] in ("listed", "clear"))}
    for r in rows:
        if not r["listed"]:
            continue
        pbl = r["code"] in ("127.0.0.10", "127.0.0.11")
        fix = ["Open the removal page below and read why it was listed.",
               "Find and stop the cause first (a hacked mailbox or website form, malware, an open relay, or sending to purchased lists). "
               "A removal without a fix is usually reversed within days.",
               "Check your outgoing mail log for unusual volume, change the passwords of affected mailboxes and turn on 2-step login.",
               f"Then request removal here: {r['delist_url']} (many lists also expire listings by themselves after a few days of clean behaviour)."]
        meaning = (f"{r['name']} says {target} has sent or been used for unwanted mail" if kind == "ip" else
                   f"{r['name']} flags the domain {target} as used in spam or abuse") + \
                  (f" ({r['reason']})." if r["reason"] else ".") + \
                  f" Receivers that use this list may reject or junk your mail (list weight {r['weight']} of 3)."
        if pbl:
            meaning = (f"{r['name']} lists this address in a range meant for home/office connections, which should not send mail directly "
                       "(Spamhaus PBL). Servers that use PBL reject mail sent straight from it.")
            fix = ["If this is a mail server: ask your hosting provider or ISP to confirm the IP is for server use, then use the PBL removal tool at " + r["delist_url"] + ".",
                   "If it is a home/office connection: send mail through your provider's SMTP server (smarthost) instead of directly."]
        res.add(f"dnsbl_listed_{_slug(r['zone'])}", "fail" if r["weight"] >= 2 else "warn", f"Listed on {r['name']}", meaning, fix,
                zone=r["zone"], code=r["code"], reason=r["reason"], delist_url=r["delist_url"], weight=r["weight"], target=target)
    if any(r["status"] == "skipped" and "DQS" in (r["note"] or "") for r in rows):
        res.add("dnsbl_spamhaus_skipped", "info", "Spamhaus was not checked",
                "Spamhaus (the most widely used blocklist) only answers servers with a registered query key. Without one we skip it, "
                "so a clean result here does not rule out a Spamhaus listing.",
                ["Check your IP/domain manually at https://check.spamhaus.org/ ."])
    bad = counts["error"] + counts["timeout"]
    if bad:
        res.add("dnsbl_incomplete", "info", f"{bad} list(s) could not be checked",
                "These lists did not answer, refused our queries or timed out. Big public resolvers are often refused by blocklists, so the check "
                "is only complete from a resolver that is allowed.", ["Use your own recursive resolver for blocklist checks."], count=bad)
    if counts["checked"] == 0 and rows:
        res.finalize("No blocklist could be queried from this server.", score=50, status="error")
        return res
    if not lw:
        res.add("dnsbl_clear", "pass", "Not listed", f"{target} is not on any of the {counts['checked']} blocklists we could query.")
        summary = f"Not listed on {counts['clear']} of {counts['checked']} blocklists checked."
    else:
        summary = f"Listed on {counts['listed']} of {counts['checked']} blocklists checked (weighted {lw})."
    return res.finalize(summary, score=max(0, 100 - 15 * lw))


async def check(ip_or_domain: str, resolver: Resolver | None = None, **kw: Any) -> CheckResult:
    kind, target = classify(ip_or_domain)
    rows = [row async for row in iter_check(target, resolver, **kw)]
    return summarize(target, kind, rows)


async def check_many(ips: list[str], resolver: Resolver | None = None, **kw: Any) -> CheckResult:
    """Check several IPs (e.g. the MX hosts) and merge into one result. One shared concurrency limit."""
    kw.setdefault("semaphore", asyncio.Semaphore(CONCURRENCY))
    results = await asyncio.gather(*(check(ip, resolver, **kw) for ip in ips))
    if len(results) == 1:
        return results[0]
    merged = CheckResult("dnsbl", ", ".join(ips))
    merged.data = {"kind": "ip", "ips": [{"ip": ip, **res.data} for ip, res in zip(ips, results)]}
    seen: set[str] = set()
    for ip, res in zip(ips, results):
        for f in res.findings:
            if f.id in ("dnsbl_spamhaus_skipped", "dnsbl_incomplete", "dnsbl_clear") and f.id in seen:
                continue
            seen.add(f.id)
            if f.id.startswith("dnsbl_listed"):
                f.title = f"{f.title} ({ip})"
            merged.findings.append(f)
    worst = min(res.score for res in results)
    listed = sum(res.data["counts"]["listed"] for res in results if "counts" in res.data)
    errs = all(res.status == "error" for res in results)
    merged.finalize(f"{len(ips)} IPs checked, {listed} listing(s) in total." if listed else f"None of the {len(ips)} IPs is listed.",
                    score=worst, status="error" if errs else None)
    return merged
