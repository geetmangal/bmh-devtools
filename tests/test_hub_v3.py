"""Hub page (gui-v3 slice B): quick starts, filter hooks, card search data, calculator links, hub.js imports."""
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import CATEGORIES, QUICK_STARTS, TOOLS
from app.main import app

SLUGS = {t["slug"] for t in TOOLS}
@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


HUB_JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "hub.js"


async def test_quick_start_links(client):
    t = (await client.get("/tools/")).text
    assert len(QUICK_STARTS) == 6
    for q in QUICK_STARTS:
        assert q["slug"] in SLUGS
        assert f'href="/tools/{q["slug"]}" class="card qs-card"' in t
    assert "Start with a problem" in t


async def test_filter_and_sections(client):
    t = (await client.get("/tools/")).text
    assert 'id="hub-filter"' in t and 'aria-label="Filter tools"' in t and 'aria-live="polite"' in t
    assert 'id="hub-recent"' in t
    for c in CATEGORIES:
        assert f'id="cat-{c["key"]}"' in t
    assert t.count("class=\"chip-cat\"") == 1 + len([c for c in CATEGORIES if c["key"] != "calc"])


async def test_every_tool_card_has_search_data_once(client):
    t = (await client.get("/tools/")).text
    cards = re.findall(r'<a href="(/tools/[^"]+)" class="card tool-card" data-cat="[a-z]+" data-search="([^"]+)"', t)
    assert sorted(h.rsplit("/", 1)[1] for h, _ in cards) == sorted(SLUGS)
    assert all(s.strip() for _, s in cards)
    assert "18% GST" in t  # calculator card copy still present


async def test_free_tools_urls_listed_once_each(client):
    t = (await client.get("/tools/")).text
    for path in ["/free-tools", "/free-tools/cloud-cost-gst-calculator",
                 "/free-tools/vps-sizing-calculator", "/free-tools/noida-latency-test"]:
        assert f'href="https://bookmyhost.com{path}"' in t
    assert "More free tools for India" not in t


def test_hub_js_relative_imports_only():
    src = HUB_JS.read_text(encoding="utf-8")
    specs = re.findall(r"""import\s[^;]*?from\s+['"]([^'"]+)['"]""", src)
    assert specs and all(s.startswith("./") or s.startswith("../") for s in specs)
    assert "innerHTML" not in src
