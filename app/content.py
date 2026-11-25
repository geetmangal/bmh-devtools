"""Long-form page content (direct answer, guide sections, FAQs, related tools) for the hub and every tool page.

The copy lives in app/data/content/<slug>.json (hub.json for /tools/). Templates, JSON-LD, llms.txt and
llms-full.txt are all rendered from the same data, so they can never disagree. Tokens @API@, @BASE@ and @RATE@ in
the text are replaced at load time.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from app.core.config import API_PREFIX, BASE_URL, RATE_LIMIT_PER_MIN

CONTENT_DIR = Path(__file__).resolve().parent / "data" / "content"
HUB = "hub"


def _fill(value):
    if isinstance(value, str):
        return value.replace("@BASE@", BASE_URL).replace("@API@", API_PREFIX).replace("@RATE@", str(RATE_LIMIT_PER_MIN))
    if isinstance(value, list):
        return [_fill(v) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v) for k, v in value.items()}
    return value


@lru_cache(maxsize=None)
def load(slug: str) -> dict:
    """Content for one tool slug (or 'hub'). Raises FileNotFoundError if the file is missing."""
    data = json.loads((CONTENT_DIR / f"{slug}.json").read_text(encoding="utf-8"))
    data = _fill(data)
    data["faq"] = [tuple(x) for x in data["faq"]]
    return data


def words(text: str) -> int:
    return len(text.split())


def guide_word_count(c: dict) -> int:
    """Words in the readable guide: direct answer plus every section heading and paragraph (FAQ not included)."""
    n = words(c["answer"])
    for s in c["sections"]:
        n += words(s["h"]) + sum(words(p) for p in s["p"])
    return n
