"""llms.txt (short index) and llms-full.txt (per-tool answers, inputs, outputs, curl) for AI assistants.

Built from the same content files and TOOLS list as the pages, so they never drift apart.
"""
from __future__ import annotations

from app import content
from app.core.config import (API_PREFIX, BASE_URL, CATEGORIES, EMBED_BASE_URL, RATE_LIMIT_PER_MIN, SITE_NAME, TOOLS,
                             TOOLS_PREFIX)

HUB_URL = f"{BASE_URL}{TOOLS_PREFIX}/"
SUMMARY = ("Free web tools from BookMyHost for checking email authentication (SPF, DKIM, DMARC), mail servers, "
           "blocklists, DNS, WHOIS/RDAP, IP networks (ASN, BGP, ping, traceroute), subnets, open ports and website "
           "TTFB and SSL certificates. No sign-up. BookMyHost provides cloud servers and VPS in India.")


def tool_url(slug: str) -> str:
    return f"{BASE_URL}{TOOLS_PREFIX}/{slug}"


def _by_category():
    for cat in CATEGORIES:
        items = [t for t in TOOLS if t["category"] == cat["key"]]
        if items:
            yield cat, items


def build_index() -> str:
    lines = [f"# {SITE_NAME}", "", f"> {SUMMARY}", "",
             "Each tool page has a short direct answer, a guide on how to read the result, FAQs and related tools. "
             "Results are produced live by the tool, not by this text.", ""]
    for cat, items in _by_category():
        lines += [f"## {cat['label']}", ""]
        lines += [f"- [{t['name']}]({tool_url(t['slug'])}): {t['short']}" for t in items]
        lines.append("")
    lines += [
        "## API and embedding", "",
        f"- [API documentation (Swagger UI)]({BASE_URL}{API_PREFIX}/docs): every tool has a JSON endpoint; "
        f"limit {RATE_LIMIT_PER_MIN} requests per minute per IP. Heavy endpoints need a Cloudflare Turnstile pass.",
        f"- [OpenAPI schema]({BASE_URL}{API_PREFIX}/openapi.json): machine-readable description of the endpoints.",
        f"- [Embed a tool]({HUB_URL}): each tool page has an iframe snippet; widgets load from {EMBED_BASE_URL}{TOOLS_PREFIX}/embed/<tool-slug> "
        f"with an optional resize script at {EMBED_BASE_URL}{TOOLS_PREFIX}/embed.js.",
        "",
        "## More", "",
        f"- [Toolbox home]({HUB_URL}): all tools in one place.",
        f"- [llms-full.txt]({BASE_URL}{TOOLS_PREFIX}/llms-full.txt): per tool, the direct answer, inputs, output meaning and an example API call.",
        f"- [Sitemap]({BASE_URL}{TOOLS_PREFIX}/sitemap.xml)",
        "",
    ]
    return "\n".join(lines)


def _access_note(t: dict, c: dict) -> str:
    if not c.get("curl"):
        return "No API: this tool runs entirely in the visitor's browser and nothing is uploaded."
    if t["heavy"]:
        return (f"This endpoint needs a short-lived pass in the X-Tools-Pass header. The pass is issued by POST {API_PREFIX}/pass "
                "after a Cloudflare Turnstile check that only a browser can complete, so programmatic use is limited. "
                f"Limits per IP and per target also apply ({RATE_LIMIT_PER_MIN} requests per minute for light endpoints, fewer for heavy ones).")
    return f"No pass needed. Limit: {RATE_LIMIT_PER_MIN} requests per minute per IP."


def build_full() -> str:
    lines = [f"# {SITE_NAME}: full reference", "", f"> {SUMMARY}", "",
             f"Home: {HUB_URL}  |  Short index: {BASE_URL}{TOOLS_PREFIX}/llms.txt  |  API docs: {BASE_URL}{API_PREFIX}/docs", ""]
    for cat, items in _by_category():
        lines += [f"# {cat['label']}", ""]
        for t in items:
            c = content.load(t["slug"])
            lines += [f"## {t['name']}", "", f"URL: {tool_url(t['slug'])}", "",
                      f"Direct answer: {c['answer']}", "",
                      f"Inputs: {c['inputs']}", "",
                      f"What the output means: {c['outputs']}", ""]
            if c.get("curl"):
                lines += ["Example API call:", "", "```bash", c["curl"], "```", ""]
            lines += [f"Access: {_access_note(t, c)}", ""]
    lines += ["# Embedding", "",
              f"Every tool can be embedded as an iframe:<iframe src=\"{EMBED_BASE_URL}{TOOLS_PREFIX}/embed/<tool-slug>\" "
              "width=\"100%\" height=\"420\" loading=\"lazy\"></iframe>. Options: theme=auto|light|dark, accent=#rrggbb, compact=1, q=<prefilled input>.", ""]
    return "\n".join(lines)
