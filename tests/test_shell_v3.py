"""Toolbox GUI v3, slice A: compact header, breadcrumb + sibling rail, command palette, footer directory."""
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import CALCULATORS, TOOLS
from app.main import app

JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js"


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def _between(html: str, start: str, end: str) -> str:
    a = html.index(start)
    return html[a:html.index(end, a)]


async def test_tool_page_has_breadcrumb_and_sibling_rail_only(client):
    r = await client.get("/tools/spf-checker")
    html = r.text
    bc = _between(html, 'aria-label="Breadcrumb"', "</nav>")
    assert 'href="/tools/#cat-email"' in bc and 'aria-current="page"' in bc and "Email &amp; Deliverability" in bc
    assert "tabgroup" not in html
    rail = _between(html, 'class="tabrail sibrail', "</nav>")
    mine = {t["slug"] for t in TOOLS if t["category"] == "email"}
    linked = set(re.findall(r'href="/tools/([a-z0-9-]+)"', rail))
    assert linked and linked <= mine and len(linked) < len(TOOLS)
    assert re.search(r'href="/tools/spf-checker"[^>]*aria-current="page"', rail)
    assert 'data-tool-slug="spf-checker"' in html


async def test_hub_has_omnibox_tool_pages_do_not(client):
    hub = (await client.get("/tools/")).text
    assert 'id="cmdbar"' in hub and "<summary" in hub and "Shortcuts" in hub and 'aria-label="Breadcrumb"' not in hub
    for t in TOOLS[:6]:
        page = (await client.get(f"/tools/{t['slug']}")).text
        assert 'id="cmdbar"' not in page and 'id="cmd-input"' not in page


@pytest.mark.parametrize("path", ["/tools/", "/tools/dns-lookup"])
async def test_footer_directory_lists_every_tool_and_calculator(client, path):
    html = (await client.get(path)).text
    foot = _between(html, 'class="max-w-6xl mx-auto px-4 pt-8 footdir"', "</nav>")
    for t in TOOLS:
        assert f'href="/tools/{t["slug"]}"' in foot
    for c in CALCULATORS:
        assert f'href="{c["url"]}"' in foot


async def test_palette_dialog_and_triggers_present(client):
    html = (await client.get("/tools/dns-lookup")).text
    assert re.search(r'<dialog id="palette"[^>]*aria-label="Search tools"', html)
    assert html.count("data-palette-open") >= 2 and "Ctrl K" in html


def test_palette_and_recent_modules_exist_with_relative_imports_only():
    for name in ("palette.js", "recent.js"):
        src = (JS / "ui" / name).read_text(encoding="utf-8")
        for spec in re.findall(r"""from\s+['"]([^'"]+)['"]""", src) + re.findall(r"""import\(\s*['"]([^'"]+)['"]""", src):
            assert spec.startswith("./") or spec.startswith("../"), (name, spec)
    assert "bmh-recent" in (JS / "ui" / "recent.js").read_text(encoding="utf-8")
    shell = (JS / "shell.js").read_text(encoding="utf-8")
    assert "import('./ui/palette.js')" in shell and "pushRecent" in shell
