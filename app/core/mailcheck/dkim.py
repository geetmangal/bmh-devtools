"""DKIM check: fetch + grade one selector, or probe common selectors.

DKIM selectors cannot be listed in DNS, so without a selector we only find the common ones below. A "not found"
result therefore never proves DKIM is missing; the finding tells the user how to learn the real selector."""
from __future__ import annotations

import asyncio
import base64
import binascii
import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.resolver import Resolver, get_default_resolver
from app.core.validate import ValidationError

PROBE_SELECTORS = [
    "google", "selector1", "selector2", "k1", "k2", "k3", "default", "dkim", "mail", "s1", "s2", "smtp", "mx",
    "zoho", "zmail", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3", "mandrill", "mailjet",
    "amazonses", "everlytickey1", "everlytickey2", "cm", "sig1",
]  # "sendgrid" is covered by s1/s2
PROBE_CONCURRENCY = 10

HINTS = {
    "google": "Google Workspace", "selector1": "Microsoft 365", "selector2": "Microsoft 365",
    "k1": "Mailchimp / MailerLite", "k2": "Mailchimp / MailerLite", "k3": "Mailchimp / MailerLite",
    "s1": "SendGrid or similar", "s2": "SendGrid or similar", "zoho": "Zoho Mail", "zmail": "Zoho Mail",
    "protonmail": "Proton Mail", "protonmail2": "Proton Mail", "protonmail3": "Proton Mail",
    "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail", "mandrill": "Mandrill (Mailchimp Transactional)",
    "mailjet": "Mailjet", "amazonses": "Amazon SES", "everlytickey1": "Everlytic", "everlytickey2": "Everlytic",
    "cm": "Campaign Monitor", "sig1": "iCloud Mail", "default": "generic (cPanel / self-hosted)",
    "dkim": "generic", "mail": "generic", "smtp": "generic", "mx": "generic",
}
_SEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62})$")


def parse_record(text: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in text.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip().lower()
            if k and k not in tags:
                tags[k] = "".join(v.split()) if k == "p" else v.strip()
    return tags


def is_dkim_record(tags: dict[str, str]) -> bool:
    return "p" in tags or tags.get("v", "").upper() == "DKIM1"


def analyze_key(p: str, k: str = "rsa") -> dict:
    """Describe the public key in the p= tag. Never raises."""
    if p == "":
        return {"revoked": True}
    try:
        raw = base64.b64decode(p + "=" * (-len(p) % 4), validate=True)
    except (binascii.Error, ValueError):
        return {"error": "p= is not valid base64"}
    if k == "ed25519":
        if len(raw) == 32:
            return {"type": "ed25519", "bits": 256}
        try:  # some publish a full SubjectPublicKeyInfo
            key = serialization.load_der_public_key(raw)
            if isinstance(key, ed25519.Ed25519PublicKey):
                return {"type": "ed25519", "bits": 256}
        except ValueError:
            pass
        return {"error": "p= is not a valid Ed25519 key"}
    try:
        key = serialization.load_der_public_key(raw)
    except ValueError:
        return {"error": "p= is not a valid public key (expected base64 of a DER SubjectPublicKeyInfo)"}
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "rsa", "bits": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"type": "ed25519", "bits": 256}
    return {"error": f"unsupported key type {type(key).__name__}"}


async def _fetch(r: Resolver, domain: str, selector: str) -> dict:
    name = f"{selector}._domainkey.{domain}"
    ans = await r.query(name, "TXT")
    out = {"selector": selector, "name": name, "found": False, "status": ans.status, "cname": ans.cname_chain[:3] or None,
           "hint": HINTS.get(selector)}
    if ans.failed:
        out["lookup_error"] = True
        return out
    for rec in ans.records:
        tags = parse_record(rec)
        if is_dkim_record(tags):
            out.update(found=True, record=rec, tags=tags, key=analyze_key(tags.get("p", ""), tags.get("k", "rsa").lower()))
            break
    return out


def _grade(res: CheckResult, item: dict) -> None:
    sel, name, tags, key = item["selector"], item["name"], item["tags"], item["key"]
    if key.get("revoked"):
        res.add("dkim_revoked", "warn", f"Selector {sel} is revoked (empty key)",
                "An empty p= means this key was deliberately retired. Mail signed with this selector fails DKIM.",
                [f"Make sure nothing still signs with selector \"{sel}\". If it should be active, publish the new public key from your provider."],
                selector=sel)
        return
    if "error" in key:
        res.add("dkim_key_invalid", "fail", f"Selector {sel}: the key cannot be read",
                f"{key['error']}. Receivers cannot verify signatures made with it, so DKIM fails.",
                ["Copy the full public key from your mail provider again; check it was not cut off or altered (no extra spaces, quotes or line breaks).",
                 "Long keys are split in several quoted strings; that is fine, but they must be joined exactly."], selector=sel)
        return
    if key["type"] == "rsa":
        bits = key["bits"]
        if bits < 1024:
            res.add("dkim_key_weak", "fail", f"Selector {sel}: {bits}-bit key is too weak",
                    f"A {bits}-bit RSA key can be cracked with modest resources, so someone could forge signed mail from your domain. "
                    "Major receivers may also reject it.",
                    ["In your mail provider's DKIM settings generate a new 2048-bit key.",
                     "Publish the new public key under a new selector name, switch signing to it, and delete the old record a week later."],
                    selector=sel, bits=bits)
        elif bits == 1024:
            res.add("dkim_key_1024", "warn", f"Selector {sel}: 1024-bit key (upgrade to 2048)",
                    "1024-bit keys still work and are accepted everywhere, but they are no longer considered strong. "
                    "2048 bits is the current recommendation.",
                    ["Generate a 2048-bit key at your mail provider and publish it under a new selector.",
                     "A 2048-bit key is longer than 255 characters, so the TXT value is split into several quoted strings; most DNS panels do this automatically."],
                    selector=sel, bits=bits)
        else:
            res.add("dkim_key_ok", "pass", f"Selector {sel}: {bits}-bit RSA key",
                    "The key size is strong enough." if bits >= 2048 else "The key is acceptable; 2048 bits is the usual choice.",
                    selector=sel, bits=bits)
    else:
        res.add("dkim_key_ok", "pass", f"Selector {sel}: Ed25519 key",
                "Ed25519 keys are small and strong. Some older receivers cannot verify them, so keep an RSA signature too.",
                selector=sel)
    if tags.get("v", "DKIM1").upper() != "DKIM1":
        res.add("dkim_bad_version", "warn", f"Selector {sel}: unexpected v={tags['v']}", "v must be DKIM1 when present.", ["Set v=DKIM1."], selector=sel)
    if "y" in tags.get("t", "").lower().split(":"):
        res.add("dkim_testing", "warn", f"Selector {sel} is in test mode (t=y)",
                "t=y tells receivers you are still testing, so they may ignore failures instead of treating them seriously.",
                ["Remove t=y once signing works."], selector=sel)
    h = [x.strip().lower() for x in tags.get("h", "").split(":") if x.strip()]
    if h and h == ["sha1"]:
        res.add("dkim_sha1_only", "warn", f"Selector {sel} only allows SHA-1",
                "SHA-1 is obsolete; receivers may stop accepting it.", ["Remove the h= tag or set h=sha256."], selector=sel)


async def check(domain: str, selector: str | None = None, resolver: Resolver | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    res = CheckResult("dkim", domain)
    t0 = time.perf_counter()
    if selector:
        selector = selector.strip().lower().rstrip(".")
        if not _SEL.match(selector):
            raise ValidationError("invalid DKIM selector (letters, digits, dot, dash, underscore)")
        item = await _fetch(r, domain, selector)
        res.timings_ms["lookup"] = round((time.perf_counter() - t0) * 1000, 1)
        res.data = {"mode": "selector", "selector": selector, "selectors": [_row(item)], "found_count": int(item["found"])}
        if item.get("lookup_error"):
            return error_result("dkim", domain, f"DNS lookup for {item['name']} failed ({item['status']}).")
        if not item["found"]:
            res.add("dkim_selector_missing", "fail", f"No DKIM key at {item['name']}",
                    "Receivers look up the public key at this exact name to verify your signature. Nothing is published there, "
                    "so mail signed with this selector fails DKIM.",
                    ["Check the selector name: it is the s= value inside the DKIM-Signature header of a real email from you.",
                     "Check the DNS record: its host/name must be exactly the name above (some DNS panels add your domain automatically; "
                     "do not type it twice).",
                     "If you just added it, wait for DNS to propagate (up to an hour) and retry."], name=item["name"])
            return res.finalize(f"No DKIM record for selector \"{selector}\".")
        _grade(res, item)
        res.data["record"] = item["record"]
        return res.finalize(_summary(res, [item]))

    sem = asyncio.Semaphore(PROBE_CONCURRENCY)

    async def one(s: str) -> dict:
        async with sem:
            return await _fetch(r, domain, s)

    items = await asyncio.gather(*(one(s) for s in PROBE_SELECTORS))
    res.timings_ms["probe"] = round((time.perf_counter() - t0) * 1000, 1)
    found = [i for i in items if i["found"]]
    res.data = {"mode": "probe", "selector": None, "selectors": [_row(i) for i in items], "found_count": len(found),
                "probed": len(items)}
    if not found:
        if all(i.get("lookup_error") for i in items):
            return error_result("dkim", domain, "DNS lookups for DKIM selectors failed.")
        res.add("dkim_none_found", "warn", "No DKIM key found under the common selector names",
                f"We tried {len(items)} common selector names. This does not prove DKIM is off: providers often use their own selector name "
                "and DNS cannot list them. If DKIM is really missing, mail is more likely to land in spam and DMARC cannot pass through DKIM.",
                ["Send an email from this domain to a Gmail address, open it, choose \"Show original\" and find the line starting with DKIM-Signature.",
                 "Copy the value after s= (the selector) and enter it in this checker.",
                 "If there is no DKIM-Signature line, turn on DKIM signing in your mail provider (Google Workspace, Microsoft 365, Zoho ... all have a DKIM page) "
                 "and publish the TXT/CNAME record they show you."])
        return res.finalize("No DKIM key found under common selector names (custom selectors cannot be guessed).")
    for i in found:
        _grade(res, i)
    return res.finalize(_summary(res, found))


def _row(i: dict) -> dict:
    key = i.get("key") or {}
    return {"selector": i["selector"], "name": i["name"], "found": i["found"], "hint": i.get("hint"),
            "key_type": key.get("type"), "bits": key.get("bits"), "revoked": bool(key.get("revoked")),
            "cname": i.get("cname"), "error": key.get("error")}


def _summary(res: CheckResult, found: list[dict]) -> str:
    n = len(found)
    sizes = [f"{i['key'].get('bits')}-bit {i['key'].get('type')}" for i in found if i["key"].get("type")]
    fails = [f for f in res.findings if f.status == "fail"]
    if fails:
        return f"DKIM key found but there is a problem: {fails[0].title}."
    base = f"{n} DKIM key{'s' if n != 1 else ''} found" + (f" ({', '.join(sizes)})" if sizes else "") + "."
    warns = [f for f in res.findings if f.status == "warn"]
    return base + (f" {len(warns)} to improve." if warns else "")
