"""Security-header grading and redirect-chain analysis for POST /http/headers (pure functions, no network I/O)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

HSTS_MIN = 15552000  # 180 days, the usual bar for a "good" HSTS max-age
MAX_VALUE = 512

# Response headers we hand back to the browser. Anything else (Set-Cookie, ...) is dropped.
SHOW = (
    "server", "x-powered-by", "x-aspnet-version", "content-type", "content-length", "cache-control", "date", "via", "alt-svc",
    "strict-transport-security", "content-security-policy", "content-security-policy-report-only", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "cross-origin-resource-policy", "x-xss-protection", "location",
)

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k in SHOW:
        if k in headers:
            out[k] = _CTRL.sub("", str(headers[k]))[:MAX_VALUE]
    return out


def clean_text(s: object, limit: int = 300) -> str:
    return _CTRL.sub("", str(s))[:limit]


def parse_hsts(value: str) -> dict:
    max_age = None
    for part in value.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip().lower() == "max-age":
            try:
                max_age = int(v.strip().strip('"'))
            except ValueError:
                max_age = None
    low = value.lower()
    return {"max_age": max_age, "include_subdomains": "includesubdomains" in low, "preload": bool(re.search(r"(^|;)\s*preload\s*($|;)", low))}


def parse_csp(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in value.split(";"):
        bits = part.strip().split(None, 1)
        if bits:
            out.setdefault(bits[0].lower(), bits[1] if len(bits) > 1 else "")
    return out


def grade_letter(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def grade_headers(headers: dict[str, str], https: bool) -> dict:
    """Score the six headers that matter (100 points). Each check: {id, label, points, max, status ok|warn|bad, value, note}.
    Served over plain HTTP the grade is capped at F: HSTS and most of the rest can be stripped in transit."""
    checks: list[dict] = []

    def add(cid, label, points, mx, status, value, note):
        checks.append({"id": cid, "label": label, "points": points, "max": mx, "status": status, "value": value, "note": note})

    # HSTS (25): 20 for max-age >= 180 days, +3 includeSubDomains, +2 preload
    v = headers.get("strict-transport-security")
    if not https:
        add("hsts", "Strict-Transport-Security", 0, 25, "bad", v, "The page is not served over HTTPS, so HSTS cannot apply.")
    elif v is None:
        add("hsts", "Strict-Transport-Security", 0, 25, "bad", None, "Missing. Browsers may still try plain HTTP first.")
    else:
        p = parse_hsts(v)
        if p["max_age"] is None:
            add("hsts", "Strict-Transport-Security", 0, 25, "bad", v, "No valid max-age, so browsers ignore the header.")
        elif p["max_age"] < HSTS_MIN:
            add("hsts", "Strict-Transport-Security", 8, 25, "warn", v, f"max-age {p['max_age']} is below {HSTS_MIN} seconds (180 days).")
        else:
            pts = 20 + (3 if p["include_subdomains"] else 0) + (2 if p["preload"] else 0)
            add("hsts", "Strict-Transport-Security", pts, 25, "ok" if p["include_subdomains"] else "warn", v,
                "Strong max-age." + ("" if p["include_subdomains"] else " includeSubDomains is missing.") + ("" if p["preload"] else " Not marked preload (optional)."))

    # CSP (25): 20 present (enforcing), +5 frame-ancestors
    v = headers.get("content-security-policy")
    ro = headers.get("content-security-policy-report-only")
    fa = False
    if v is not None:
        d = parse_csp(v)
        fa = "frame-ancestors" in d
        add("csp", "Content-Security-Policy", 20 + (5 if fa else 0), 25, "ok" if fa else "warn", v,
            "Present." + ("" if fa else " No frame-ancestors directive."))
    elif ro is not None:
        add("csp", "Content-Security-Policy", 5, 25, "warn", ro, "Only a Report-Only policy: browsers do not enforce it yet.")
    else:
        add("csp", "Content-Security-Policy", 0, 25, "bad", None, "Missing.")

    # X-Content-Type-Options (15)
    v = headers.get("x-content-type-options")
    if v is not None and v.strip().lower() == "nosniff":
        add("xcto", "X-Content-Type-Options", 15, 15, "ok", v, "nosniff set.")
    elif v is not None:
        add("xcto", "X-Content-Type-Options", 0, 15, "bad", v, "The only valid value is nosniff.")
    else:
        add("xcto", "X-Content-Type-Options", 0, 15, "bad", None, "Missing.")

    # Clickjacking (15): X-Frame-Options DENY/SAMEORIGIN, or CSP frame-ancestors
    v = headers.get("x-frame-options")
    vv = (v or "").strip().lower()
    if fa or vv in ("deny", "sameorigin"):
        add("frame", "X-Frame-Options / frame-ancestors", 15, 15, "ok", v or "frame-ancestors (CSP)", "Framing is restricted.")
    elif v is not None:
        add("frame", "X-Frame-Options / frame-ancestors", 5, 15, "warn", v, "ALLOW-FROM is obsolete and ignored by browsers; use DENY, SAMEORIGIN or CSP frame-ancestors.")
    else:
        add("frame", "X-Frame-Options / frame-ancestors", 0, 15, "bad", None, "Missing: other sites can put your pages in a frame.")

    # Referrer-Policy (10)
    v = headers.get("referrer-policy")
    if v is None:
        add("referrer", "Referrer-Policy", 0, 10, "bad", None, "Missing.")
    else:
        last = v.split(",")[-1].strip().lower()
        if last in ("unsafe-url", "no-referrer-when-downgrade", ""):
            add("referrer", "Referrer-Policy", 4, 10, "warn", v, "Sends the full URL to other sites. Prefer strict-origin-when-cross-origin.")
        else:
            add("referrer", "Referrer-Policy", 10, 10, "ok", v, "Set.")

    # Permissions-Policy (10)
    v = headers.get("permissions-policy")
    if v is None:
        add("permissions", "Permissions-Policy", 0, 10, "bad", None, "Missing.")
    else:
        add("permissions", "Permissions-Policy", 10, 10, "ok", v, "Set.")

    score = sum(c["points"] for c in checks)
    if not https:
        score = min(score, 49)
    return {"score": score, "grade": grade_letter(score), "checks": checks}


def version_leaks(headers: dict[str, str]) -> list[tuple[str, str]]:
    """Server / X-Powered-By / X-AspNet-Version values that reveal a software version."""
    out = []
    for k in ("server", "x-powered-by", "x-aspnet-version"):
        v = headers.get(k)
        if v and re.search(r"\d+\.\d+|/\d", v):
            out.append((k, v))
    return out


# ---------------------------------------------------------------- redirect chain
def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _apex(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def analyse_chain(hops: list[dict], *, start_https: bool, complete: bool, loop: bool, too_many: bool, blocked: str | None) -> dict:
    """Flags for a followed redirect chain. hops = [{url, status, location, ms[, error]}]."""
    reqs = [h for h in hops if h.get("status") is not None]
    redirects = [h for h in reqs if 300 <= h["status"] < 400 and h.get("location")]
    final_url = reqs[-1]["url"] if reqs else ""
    final_https = final_url.startswith("https://")
    temp = []
    for h in redirects:
        nxt = h.get("next") or ""
        if h["status"] in (302, 303, 307) and nxt:
            a, b = urlsplit(h["url"]), urlsplit(nxt)
            if a.scheme != b.scheme or (a.hostname or "").lower() != (b.hostname or "").lower():
                temp.append({"url": h["url"], "status": h["status"], "to": nxt})
    hosts = [_host(h["url"]) for h in reqs]
    has_www = any(x.startswith("www.") for x in hosts)
    has_bare = any(not x.startswith("www.") for x in hosts)
    mixed = has_www and has_bare and len({_apex(x) for x in hosts}) == 1
    start_http = bool(reqs) and reqs[0]["url"].startswith("http://")
    return {
        "no_https_redirect": bool(reqs) and start_http and complete and not final_https and not loop and not too_many,
        "loop": loop,
        "too_many_hops": too_many,
        "temporary_redirects": temp,
        "www_mix": mixed,
        "redirect_count": len(redirects),
        "long_chain": len(redirects) > 2,
        "blocked": blocked,
    }


# ---------------------------------------------------------------- fix snippets
def header_tabs(name: str, value: str, note: str = "") -> list[dict]:
    q = value
    ng = f'add_header {name} "{q}" always;'
    ap = f'Header always set {name} "{q}"'
    return [
        {"label": "nginx", "steps": ["Add this line inside the server { } block of your site, then run nginx -t and reload nginx." + note], "code": ng},
        {"label": "Apache (.htaccess)", "steps": ["Add this line to the .htaccess file in your web root (needs mod_headers, which most hosts enable)." + note], "code": ap},
        {"label": "LiteSpeed", "steps": ["LiteSpeed reads the same .htaccess directive: add the line below to the .htaccess file in your web root. On OpenLiteSpeed without .htaccess, add it under Virtual Hosts, Context, Header Operations in the WebAdmin console." + note], "code": ap},
    ]


def https_redirect_tabs() -> list[dict]:
    rw = "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
    return [
        {"label": "nginx", "steps": ["In the server block that listens on port 80, redirect everything to HTTPS with a permanent redirect."],
         "code": "server {\n    listen 80;\n    server_name example.com www.example.com;\n    return 301 https://$host$request_uri;\n}"},
        {"label": "Apache (.htaccess)", "steps": ["Add this to .htaccess in your web root (needs mod_rewrite). Behind a proxy or CDN that terminates TLS, test on %{HTTP:X-Forwarded-Proto} instead of %{HTTPS}."], "code": rw},
        {"label": "LiteSpeed", "steps": ["LiteSpeed understands the same rewrite rules in .htaccess."], "code": rw},
    ]


def permanent_redirect_tabs() -> list[dict]:
    return [
        {"label": "nginx", "steps": ["Use return 301 (permanent) rather than return 302 for redirects that never change."],
         "code": "return 301 https://example.com$request_uri;"},
        {"label": "Apache (.htaccess)", "steps": ["Add R=301 to the rewrite flags, or use RedirectPermanent."], "code": "RewriteRule ^ https://example.com%{REQUEST_URI} [L,R=301]"},
        {"label": "LiteSpeed", "steps": ["Same .htaccess rule as Apache; make sure the flag says R=301."], "code": "RewriteRule ^ https://example.com%{REQUEST_URI} [L,R=301]"},
    ]


HEADER_FIX = {
    "hsts": ("Strict-Transport-Security", "max-age=31536000; includeSubDomains", " Add preload only after every subdomain works over HTTPS."),
    "csp": ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'", " This starter policy blocks third-party scripts and images, so test with Content-Security-Policy-Report-Only first."),
    "xcto": ("X-Content-Type-Options", "nosniff", ""),
    "frame": ("X-Frame-Options", "SAMEORIGIN", ""),
    "referrer": ("Referrer-Policy", "strict-origin-when-cross-origin", ""),
    "permissions": ("Permissions-Policy", "camera=(), microphone=(), geolocation=()", ""),
}

_MEANING = {
    "hsts": "HSTS tells browsers to use HTTPS only for your site for a set time, which stops downgrade attacks and cookie theft on public Wi-Fi.",
    "csp": "A Content-Security-Policy limits where scripts, styles and frames may load from, which is the main defence against cross-site scripting.",
    "xcto": "nosniff stops browsers from guessing a file type, so an uploaded text file cannot be run as a script.",
    "frame": "Without it, another site can embed your pages in an invisible frame and trick visitors into clicking (clickjacking).",
    "referrer": "The Referrer-Policy decides how much of the page address is sent to other sites when a visitor follows a link.",
    "permissions": "Permissions-Policy switches off browser features (camera, microphone, location) the site does not use.",
}


def build_findings(*, hops: list[dict], flags: dict, grade: dict | None, headers: dict[str, str], final_status: int | None,
                   final_https: bool, tls_verified: bool, complete: bool) -> list[dict]:
    F: list[dict] = []

    def add(fid, status, title, meaning, fix=None, tabs=None, details=None):
        f = {"id": fid, "status": status, "title": title, "meaning": meaning}
        if fix:
            f["fix"] = fix
        if tabs:
            f["fix_tabs"] = tabs
        if details:
            f["details"] = details
        F.append(f)

    if flags.get("blocked"):
        add("redirect-blocked", "warn", "A redirect pointed somewhere we do not follow",
            "We only follow redirects to public web addresses on ports 80, 443, 8080 and 8443. The chain stopped before this target: " + clean_text(flags["blocked"], 200) + ".",
            fix=["If this is your own redirect, point it at a public https:// address.", "Redirects to private, local or non-web addresses are never followed by this tool."])
    if flags["loop"]:
        add("redirect-loop", "fail", "Redirect loop",
            "The chain came back to a URL it had already visited, so browsers show an error such as ERR_TOO_MANY_REDIRECTS.",
            fix=["Check for two rules that undo each other, for example a www to non-www rule and a CMS setting that does the opposite.",
                 "If you use Cloudflare, set SSL/TLS mode to Full (strict) so it does not bounce between HTTP and HTTPS."])
    if flags["too_many_hops"]:
        add("redirect-too-many", "fail", "Too many redirects (more than 8)",
            "The server was still redirecting after 8 hops, so the final page was never reached. Browsers give up after about 20 and search engines after fewer.",
            fix=["Collapse the chain so one redirect goes straight to the final URL."])
    if flags["no_https_redirect"]:
        add("no-https-redirect", "fail", "HTTP does not redirect to HTTPS",
            "Visitors who type your address without https:// stay on the unencrypted version of the site.",
            fix=["Redirect every http:// request to the https:// version with a permanent (301) redirect."], tabs=https_redirect_tabs())
    if flags["temporary_redirects"]:
        t = flags["temporary_redirects"]
        add("temporary-redirect", "warn", "Temporary redirect (" + "/".join(sorted({str(x["status"]) for x in t})) + ") used to switch HTTPS or www",
            "A scheme or host change that never reverts should be permanent. A 302 tells search engines to keep the old address in the index and browsers do not cache it.",
            fix=["Change the redirect status to 301 (or 308 to keep the request method)."], tabs=permanent_redirect_tabs(),
            details={"redirects": [f"{x['status']} {x['url']} -> {x['to']}" for x in t]})
    if flags["long_chain"] and not flags["loop"] and not flags["too_many_hops"]:
        add("long-chain", "warn", f"{flags['redirect_count']} redirects before the final page",
            "Every redirect costs a full round trip before the page can start loading. One or two hops is normal (http to https, then www).",
            fix=["Redirect straight to the final address: http://example.com should go to https://www.example.com in one step, not through https://example.com."])
    if flags["www_mix"]:
        add("www-mix", "info", "The chain uses both www and non-www",
            "Visitors pass through both versions of the host name. That is fine if it is deliberate, but pick one canonical host and redirect the other straight to it.")

    if final_status is not None and final_status >= 400:
        add("final-status", "warn", f"The final page returned HTTP {final_status}", "Visitors and crawlers see an error page at the end of this chain.",
            fix=["Open the final URL in a browser and check the server error log."])
    if complete and final_https and not tls_verified:
        add("tls-unverified", "warn", "The HTTPS certificate did not verify",
            "We could only read the headers by skipping certificate checks. Browsers would show a warning.",
            fix=["Run the TTFB & SSL checker for the certificate details."])

    if grade is not None:
        for c in grade["checks"]:
            name, val, note = HEADER_FIX[c["id"]]
            if c["status"] == "ok":
                add("hdr-" + c["id"], "pass", f"{c['label']} is set", c["note"], details={"value": c["value"]})
            else:
                # On an A grade a partly-set header is advice, not a warning, so the verdict agrees with the grade.
                st = "fail" if c["status"] == "bad" else "info" if grade["grade"].startswith("A") else "warn"
                if c["id"] == "hsts" and not final_https:
                    add("hdr-hsts", "fail", "Strict-Transport-Security cannot work over HTTP", _MEANING["hsts"],
                        fix=["Serve the site over HTTPS first, then add the header on the HTTPS responses."])
                    continue
                add("hdr-" + c["id"], st, f"{c['label']}: " + ("missing" if c["value"] is None else "needs work"),
                    _MEANING[c["id"]] + " " + c["note"],
                    fix=["Add the header to your HTTPS responses."], tabs=header_tabs(name, val, note),
                    details={"found": c["value"]} if c["value"] else None)
        for k, v in version_leaks(headers):
            add("leak-" + k, "info", f"{k.title()} header shows a software version: {clean_text(v, 80)}",
                "Version numbers help attackers pick known exploits for your exact software. Hiding them is a small hardening step, not a fix for an old version.",
                fix=["Update the software first. To hide the version: nginx server_tokens off; Apache ServerTokens Prod; PHP expose_php = Off."])
    return F


def overall_status(findings: list[dict]) -> str:
    s = {f["status"] for f in findings}
    return "fail" if "fail" in s else "warn" if "warn" in s else "pass"
