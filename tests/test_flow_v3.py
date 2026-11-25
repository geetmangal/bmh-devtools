"""Toolbox GUI v3 slice C: form-first tool pages, ?q prefill, bmh:result and the Next steps block."""
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import TOOLS
from app.main import app

JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js"
SLUGS = [t["slug"] for t in TOOLS]


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.parametrize("slug", SLUGS)
async def test_form_comes_before_about_and_guide(client, slug):
    html = (await client.get(f"/tools/{slug}")).text
    h1 = html.index("<h1")
    form = html.index("<form", h1)  # the page's own tool form (the shell's omnibox form sits above the h1)
    assert h1 < form
    for marker in ('id="guide"', "About this tool", 'id="faq"', 'id="embed"'):
        if marker in html:
            assert form < html.index(marker), f"{slug}: form after {marker}"
    # the first section-level heading after the h1 is not an explanatory block placed ahead of the form
    assert "<h2" not in html[h1:form]


def test_result_event_is_dispatched_from_the_shared_runner():
    tool_js = (JS / "ui" / "tool.js").read_text()
    assert "bmh:result" in tool_js
    assert "bmh:result" in (JS / "ui" / "nextsteps.js").read_text()
    assert "nextsteps.js" in tool_js  # every tool page imports tool.js, so it gets the Next steps block


@pytest.mark.parametrize("path", sorted((JS / "tools").glob("*.js")), ids=lambda p: p.name)
def test_every_tool_goes_through_the_event_emitting_runner(path):
    text = path.read_text()
    assert "initTool(" in text or "domainTool(" in text, path.name
    if "domainTool(" in text:
        assert "bmh:result" in (JS / "ui" / "findings.js").read_text() or "initTool" in (JS / "ui" / "findings.js").read_text()


def test_findings_uses_the_shared_runner_and_prefills_q():
    f = (JS / "ui" / "findings.js").read_text()
    assert "initTool" in f and "qParam(p, 'domain')" in f


def test_nextsteps_exists_with_relative_imports_only():
    text = (JS / "ui" / "nextsteps.js").read_text()
    imports = re.findall(r"^\s*import\b[^'\"\n]*?['\"]([^'\"]+)['\"]", text, re.M)
    assert imports and all(i.startswith("./") or i.startswith("../") for i in imports)
    assert "innerHTML" not in text and "fetch(" not in text
    assert "spf-dmarc-generator" in text


def test_heavy_tools_do_not_autorun():
    t = (JS / "ui" / "tool.js").read_text()
    assert "heavy" in t and "focus(" in t
    for name in ("asn-lookup", "bgp-prefix-lookup", "looking-glass", "smtp-test", "port-checker"):
        assert "heavy: true" in (JS / "tools" / f"{name}.js").read_text().split("initTool(", 1)[1][:80], name


def test_header_analyzer_still_has_no_network_call():
    text = (JS / "tools" / "email-header-analyzer.js").read_text()
    assert "fetch(" not in text and "ctx.api" not in text and "XMLHttpRequest" not in text
