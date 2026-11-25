"""DMARC check (RFC 7489): policy, reporting addresses, external report authorisation, org-domain fallback.

LIMITATION: the organizational domain is found with a small built-in list of common multi-label public
suffixes (co.uk, com.au, co.in, ...), not the full Public Suffix List. For an unusual suffix the fallback
may pick the wrong parent; the record at the domain itself is always checked first."""
from __future__ import annotations

import asyncio
import re
import time

from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.resolver import Resolver, get_default_resolver

_MULTI = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "res.in", "gov.in", "nic.in",
    "com.br", "net.br", "org.br", "gov.br", "com.ar", "com.mx", "com.co", "com.pe", "com.ve", "com.uy",
    "co.za", "org.za", "net.za", "gov.za", "com.ng", "co.ke", "or.ke", "com.eg", "com.gh",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "org.hk", "com.tw", "org.tw", "com.sg", "edu.sg",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.my", "com.ph", "co.id", "or.id", "web.id",
    "com.pk", "com.bd", "com.np", "com.lk", "com.vn", "co.th", "in.th", "com.tr", "com.ua", "com.ru", "com.pl",
    "co.il", "org.il", "com.sa", "com.qa", "co.ae", "com.kw", "com.lb", "com.cy", "com.mt",
}


def org_domain(domain: str) -> str:
    """Heuristic organizational domain: last two labels, or three when the last two are a known public suffix."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip().lower()
            if k and k not in tags:
                tags[k] = v.strip()
    return tags


def is_dmarc(text: str) -> bool:
    return bool(re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", text, re.I))


async def fetch_policy(r: Resolver, domain: str) -> dict:
    """Find the DMARC record that applies to ``domain`` (own record, else org-domain). Used by bimi too.
    Returns {"record","tags","found_at","inherited","multiple","status"}; status 'ok'|'none'|'error'|'nxdomain'."""
    candidates = [domain]
    org = org_domain(domain)
    if org != domain:
        candidates.append(org)
    out = {"record": None, "tags": {}, "found_at": None, "inherited": False, "multiple": [], "status": "none"}
    for i, d in enumerate(candidates):
        ans = await r.query(f"_dmarc.{d}", "TXT")
        if ans.failed:
            out["status"] = "error"
            return out
        recs = [t for t in ans.records if is_dmarc(t)]
        if recs:
            out.update(record=recs[0], tags=parse_tags(recs[0]), found_at=d, inherited=i > 0, status="ok",
                       multiple=recs if len(recs) > 1 else [])
            return out
    return out


ACTION = {"none": "delivered normally (only reported)", "quarantine": "sent to spam / junk", "reject": "rejected (bounced)"}
STRENGTH = {"none": 0, "quarantine": 1, "reject": 2}


def _rollout(domain: str, rua: str) -> list[str]:
    return [
        f"Step 1 (now): keep p=none and make sure reports reach {rua}. Collect 2-4 weeks of reports to see who sends as {domain}.",
        "Step 2: fix every legitimate sender that fails (add it to SPF, enable DKIM signing for it with your own domain).",
        "Step 3: change to p=quarantine; pct=25, then raise pct to 50, then 100 over a few weeks.",
        "Step 4: when reports stay clean, change to p=reject (the goal: spoofed mail is blocked).",
    ]


async def check(domain: str, resolver: Resolver | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    res = CheckResult("dmarc", domain)
    t0 = time.perf_counter()
    pol = await fetch_policy(r, domain)
    res.timings_ms["policy"] = round((time.perf_counter() - t0) * 1000, 1)
    if pol["status"] == "error":
        return error_result("dmarc", domain, "DNS lookup for the DMARC record failed or timed out.")
    base = {"record": None, "tags": {}, "inherited": False, "found_at": None, "policy": None}
    starter = f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}; fo=1"

    if pol["status"] == "none":
        res.add("dmarc_missing", "fail", "No DMARC record found",
                "DMARC tells receivers what to do with mail that pretends to be from your domain and sends you reports about who is "
                "sending as you. Without it anyone can spoof your domain more easily, and Gmail/Yahoo/Microsoft require it from bulk senders.",
                [f"Create a mailbox or alias dmarc@{domain} to receive reports (or use a free DMARC report service and use its address).",
                 f"Add a TXT record with host _dmarc (full name _dmarc.{domain}) and the value below.",
                 "Start with p=none (monitor only). It cannot block any of your legitimate mail.",
                 "After 2-4 weeks of reports, move to quarantine and then reject."],
                fix_record=starter)
        res.data = {**base, "flow": _flow(None, {}), "starter": starter}
        return res.finalize("No DMARC record published.")

    tags, record = pol["tags"], pol["record"]
    found_at = pol["found_at"]
    res.data = {**base, "record": record, "tags": tags, "inherited": pol["inherited"], "found_at": found_at}
    if pol["inherited"]:
        res.add("dmarc_inherited", "info", f"Using the DMARC record of {found_at}",
                f"{domain} has no DMARC record of its own, so receivers apply the one at {found_at} (the organizational domain). "
                "That is normal; the sp= tag there controls sub-domains.")
    if pol["multiple"]:
        res.add("dmarc_multiple", "fail", "More than one DMARC record",
                "When several DMARC records exist, receivers ignore all of them, so you effectively have no DMARC.",
                [f"Delete the extra TXT records at _dmarc.{found_at} and keep one."], records=pol["multiple"])
    # --- syntax ---
    first = record.split(";")[0].strip().lower().replace(" ", "")
    if first != "v=dmarc1":
        res.add("dmarc_version", "fail", "The record must start with v=DMARC1", "Receivers ignore records that do not start with v=DMARC1.",
                ["Make v=DMARC1 the first tag."])
    p = tags.get("p", "").lower()
    rua_raw = tags.get("rua", "")
    if not p:
        if rua_raw:
            res.add("dmarc_no_p", "warn", "The p= policy tag is missing",
                    "Without p= the record is treated as p=none (monitor only) if a valid rua= is present, but p= is required by the standard.",
                    ["Add p=none (or quarantine/reject) right after v=DMARC1."], fix_record=f"v=DMARC1; p=none; {record.split(';',1)[1].strip()}" if ";" in record else None)
        else:
            res.add("dmarc_invalid", "fail", "The record has no p= policy",
                    "A DMARC record needs a p= tag (none, quarantine or reject). Without it the record is invalid and ignored.",
                    ["Add p=none as the second tag to start monitoring."], fix_record=starter)
    elif p not in STRENGTH:
        res.add("dmarc_bad_p", "fail", f"Unknown policy p={p}", "p must be none, quarantine or reject. Receivers ignore a record with another value.",
                ["Change p to none, quarantine or reject."])
        p = ""
    sp = tags.get("sp", "").lower()
    if sp and sp not in STRENGTH:
        res.add("dmarc_bad_sp", "warn", f"Unknown sub-domain policy sp={sp}", "sp must be none, quarantine or reject.", ["Fix or remove sp."])
        sp = ""
    np_ = tags.get("np", "").lower()
    try:
        pct = int(tags.get("pct", "100"))
        if not 0 <= pct <= 100:
            raise ValueError
    except ValueError:
        res.add("dmarc_bad_pct", "warn", f"Invalid pct={tags.get('pct')}", "pct must be a whole number from 0 to 100; invalid values are treated as 100.",
                ["Set pct to a number from 0 to 100 (or remove it)."])
        pct = 100
    for tag, default in (("adkim", "r"), ("aspf", "r")):
        v = tags.get(tag, default).lower()
        if v not in ("r", "s"):
            res.add(f"dmarc_bad_{tag}", "warn", f"Invalid {tag}={v}", f"{tag} must be r (relaxed) or s (strict).", [f"Use {tag}=r or {tag}=s."])
    fo = tags.get("fo")
    if fo and not all(x in "01ds" for x in fo.replace(":", "")):
        res.add("dmarc_bad_fo", "warn", f"Invalid fo={fo}", "fo accepts 0, 1, d, s (separated by colons).", ["Use fo=1 for the most reports."])

    # --- policy grade ---
    rua_addr = rua_raw.split(",")[0].replace("mailto:", "").split("!")[0].strip() if rua_raw else f"dmarc@{domain}"
    if p == "none":
        step = f"v=DMARC1; p=quarantine; pct=25; rua=mailto:{rua_addr}; fo=1"
        res.add("dmarc_policy_none", "warn", "Policy is p=none: monitoring only",
                "p=none makes no difference to delivery. Spoofed mail is still delivered; you only get reports. It is the right "
                "first step, but not the finish line.",
                _rollout(domain, rua_addr), fix_record=step)
    elif p in ("quarantine", "reject"):
        if pct < 100:
            res.add("dmarc_pct_partial", "warn", f"Policy applies to only {pct}% of failing mail",
                    f"With pct={pct}, only {pct} out of 100 messages that fail DMARC get the {p} treatment; the rest are delivered normally.",
                    ["Raise pct step by step (25, 50, 100) when reports look clean, then remove pct."],
                    fix_record=re.sub(r"pct\s*=\s*\d+", "pct=100", record))
        elif p == "quarantine":
            res.add("dmarc_policy_quarantine", "pass", "Policy is p=quarantine",
                    "Mail that fails DMARC is sent to spam. Good protection.",
                    ["When reports show no legitimate failures, move to p=reject for full protection."])
        else:
            res.add("dmarc_policy_reject", "pass", "Policy is p=reject", "Mail that fails DMARC is refused. This is the strongest setting.")
    if sp and p and sp != p and STRENGTH.get(sp, 0) < STRENGTH.get(p, 0):
        res.add("dmarc_sp_weaker", "warn", f"Sub-domains use a weaker policy (sp={sp})",
                f"Mail from sub-domains such as mail.{domain} is only {ACTION[sp]}, so attackers can spoof a sub-domain instead.",
                [f"Remove sp= (sub-domains then follow p={p}) or set sp={p}."])
    if np_ and np_ not in STRENGTH:
        res.add("dmarc_bad_np", "warn", f"Unknown np={np_}", "np (policy for non-existent sub-domains) must be none, quarantine or reject.", ["Fix or remove np."])

    # --- reports ---
    rua_uris = [u.strip() for u in rua_raw.split(",") if u.strip()]
    ruf_uris = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
    if not rua_uris:
        res.add("dmarc_no_rua", "warn", "No aggregate report address (rua=)",
                "Without rua= you receive no reports, so you cannot see who sends mail as your domain or safely move to a stricter policy.",
                [f"Add rua=mailto:dmarc@{domain} (any mailbox you read, or the address of a DMARC reporting service)."],
                fix_record=(record.rstrip("; ") + f"; rua=mailto:dmarc@{domain}"))
    auth_checks = []
    bad_uris = []
    for u in rua_uris:
        m = re.match(r"^mailto:([^@\s!]+)@([A-Za-z0-9.-]+)(![0-9]+[kmgt]?)?$", u, re.I)
        if not m:
            bad_uris.append(u)
            continue
        rdomain = m.group(2).lower()
        if org_domain(rdomain) != org_domain(found_at):
            auth_checks.append((u, rdomain))
    if bad_uris:
        res.add("dmarc_bad_rua", "warn", "Report address is not a valid mailto: URI",
                "rua must look like mailto:name@domain (several separated by commas). Other values are ignored, so you may get no reports.",
                ["Write each report address as mailto:someone@example.com."], uris=bad_uris)
    auth_results = []
    if auth_checks:
        answers = await asyncio.gather(*(r.query(f"{found_at}._report._dmarc.{rd}", "TXT") for _, rd in auth_checks))
        for (u, rd), a in zip(auth_checks, answers):
            ok = any(is_dmarc(t) for t in a.records)
            auth_results.append({"uri": u, "report_domain": rd, "authorised": ok, "checked": f"{found_at}._report._dmarc.{rd}"})
            if not ok and not a.failed:
                res.add("dmarc_rua_unauthorised", "fail", f"Reports to {rd} are not authorised",
                        f"Your rua address is at a different domain ({rd}). To prevent abuse, receivers only send reports there if {rd} has "
                        f"published permission with a TXT record named {found_at}._report._dmarc.{rd}. That record is missing, so most "
                        "providers will silently skip your reports.",
                        [f"Ask the owner of {rd} (your DMARC report service or mail provider) to add that TXT record with the value v=DMARC1.",
                         f"Or send reports to an address on {found_at} itself."],
                        fix_record=f"{found_at}._report._dmarc.{rd}.  IN TXT  \"v=DMARC1\"   ; must be published by {rd}", uri=u)
    if ruf_uris:
        res.add("dmarc_ruf", "info", "Forensic reports (ruf=) are requested",
                "Few providers (Gmail and Microsoft send none) deliver forensic reports, and they can contain parts of messages. "
                "Do not rely on them.")
    res.data.update({
        "policy": p or None, "sp": sp or None, "np": np_ or None, "pct": pct, "rua": rua_uris, "ruf": ruf_uris,
        "adkim": tags.get("adkim", "r").lower(), "aspf": tags.get("aspf", "r").lower(), "fo": fo,
        "rua_authorisation": auth_results, "flow": _flow(p or None, {**tags, "pct": str(pct)}),
    })
    if p in ("quarantine", "reject") and pct == 100 and not any(f.status in ("warn", "fail") for f in res.findings):
        summary = f"DMARC is enforced (p={p}); failing mail is {ACTION[p]}."
    elif p == "none":
        summary = "DMARC exists but only monitors (p=none): spoofed mail is still delivered."
    elif p:
        summary = f"DMARC p={p} found; {sum(f.status in ('warn','fail') for f in res.findings)} thing(s) to fix."
    else:
        summary = "DMARC record found but invalid."
    return res.finalize(summary)


def _flow(p: str | None, tags: dict[str, str]) -> dict:
    """Policy-flow diagram data: message -> SPF/DKIM alignment -> DMARC result -> action."""
    pct = int(tags.get("pct", "100")) if str(tags.get("pct", "100")).isdigit() else 100
    action = ACTION.get(p or "", "no DMARC policy: receiver decides alone")
    return {
        "steps": [
            {"id": "message", "label": "Message arrives claiming to be from your domain"},
            {"id": "spf", "label": "SPF passes and the SPF domain aligns with the From: domain?",
             "alignment": "strict" if tags.get("aspf", "r").lower() == "s" else "relaxed"},
            {"id": "dkim", "label": "A DKIM signature is valid and aligns with the From: domain?",
             "alignment": "strict" if tags.get("adkim", "r").lower() == "s" else "relaxed"},
        ],
        "pass": {"when": "SPF aligned OR DKIM aligned", "result": "Delivered normally"},
        "fail": {"when": "neither aligned", "policy": p, "pct": pct, "result": action.capitalize()
                 if p else "No policy"},
    }
