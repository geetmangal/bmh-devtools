"""Domain health aggregation, grading and streaming (no network)."""
import asyncio
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.mailcheck import health, mta_sts
from app.core.mailcheck.models import CheckResult
from app.core.mailcheck.resolver import FakeResolver

MX_IP = "142.250.27.27"
MX_PTR = "27.27.250.142.in-addr.arpa"


def key2048() -> str:
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


@pytest.fixture(scope="module")
def good_zone():
    return {
        "example.com/MX": ["1 aspmx.l.google.com"], "aspmx.l.google.com/A": [MX_IP],
        "example.com/TXT": ["v=spf1 include:_spf.google.com -all"], "_spf.google.com/TXT": ["v=spf1 ip4:35.190.247.0/24 ~all"],
        "_dmarc.example.com/TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        "google._domainkey.example.com/TXT": [f"v=DKIM1; k=rsa; p={key2048()}"],
        "_mta-sts.example.com/TXT": ["v=STSv1; id=1"], "_smtp._tls.example.com/TXT": ["v=TLSRPTv1; rua=mailto:t@example.com"],
        "example.com/SOA": ["ns1.example.net hostmaster.example.com 2026112501 7200 3600 1209600 3600"],
        "example.com/NS": ["ns1.example.net", "ns2.example.net"], "ns1.example.net/A": ["8.8.8.8"], "ns2.example.net/A": ["9.9.9.9"],
        "example.com/CAA": ['0 issue "letsencrypt.org"', '0 iodef "mailto:s@example.com"'],
        "example.com/DS": ["1 13 2 AB"], "example.com/DNSKEY": ["257 3 13 AA"], "example.com/A": ["93.184.216.34"],
    }


async def policy_ok(url):
    return mta_sts.PolicyResponse(200, "version: STSv1\nmode: enforce\nmx: aspmx.l.google.com\nmax_age: 604800\n", "text/plain")


def run_kwargs(zone, **extra):
    return dict(resolver=FakeResolver(zone, ad_names=["example.com"]), dnsbl_resolver=FakeResolver({}), policy_fetcher=policy_ok, **extra)


@pytest.fixture(autouse=True)
def smtp_off(monkeypatch):
    monkeypatch.delenv("BMH_TOOLS_SMTP_ENABLED", raising=False)
    monkeypatch.delenv("SPAMHAUS_DQS_KEY", raising=False)


def test_grade_boundaries():
    assert [health.grade_for(s) for s in (100, 90, 89, 80, 79, 70, 69, 60, 59, 0)] == list("AABBCCDDFF")
    assert abs(sum(health.AREA_WEIGHTS.values()) - 1) < 1e-9
    for comps in health.AREA_COMPONENTS.values():
        assert abs(sum(comps.values()) - 1) < 1e-9


async def test_well_configured_domain_gets_an_a(good_zone):
    out = await health.domain_health("example.com", **run_kwargs(good_zone))
    s = out["summary"]
    assert set(out["checks"]) == set(health.CHECK_NAMES)
    assert s["grade"] == "A" and s["score"] >= 90 and not s["capped_by"]
    assert [a["axis"] for a in s["radar"]] == ["Mail delivery", "Authentication", "Security", "DNS", "Reputation", "Configuration"]
    assert all(isinstance(a["score"], int) for a in s["radar"])
    assert out["checks"]["smtp"]["status"] == "info" and out["checks"]["smtp"]["data"]["applicable"] is False
    assert not any(f["status"] == "fail" for f in s["fixes"])
    assert s["checks"]["spf"]["status"] == "pass" and s["checks"]["dnsbl"]["status"] == "pass"


async def test_events_stream_then_summary(good_zone):
    events = [e async for e in health.iter_health("example.com", **run_kwargs(good_zone))]
    assert [e["type"] for e in events] == ["check"] * 10 + ["summary"]
    assert {e["name"] for e in events if e["type"] == "check"} == set(health.CHECK_NAMES)
    assert all(isinstance(e["result"]["findings"], list) and e["result"]["check"] == e["name"] for e in events[:-1])
    assert events[-1]["summary"]["domain"] == "example.com"


async def test_dnsbl_and_smtp_use_mx_ips_and_top_host(good_zone, monkeypatch):
    fake_bl = FakeResolver({})
    seen = {}

    async def fake_smtp(host, **kw):
        seen["host"] = host
        return CheckResult("smtp", host).finalize("fine")

    monkeypatch.setattr(health.smtpcheck, "check", fake_smtp)
    kw = run_kwargs(good_zone)
    kw["dnsbl_resolver"] = fake_bl
    out = await health.domain_health("example.com", **kw)
    assert seen["host"] == "aspmx.l.google.com"
    assert any(c[0] == f"27.27.250.142.b.barracudacentral.org" for c in fake_bl.calls)
    assert out["checks"]["dnsbl"]["data"]["target"] == MX_IP


async def test_mx_ips_capped_at_four(good_zone):
    zone = dict(good_zone)
    zone["example.com/MX"] = [f"{i} mx{i}.example.com" for i in range(1, 7)]
    for i in range(1, 7):
        zone[f"mx{i}.example.com/A"] = [f"8.8.{i}.1"]
    fake_bl = FakeResolver({})
    kw = run_kwargs(zone)
    kw["dnsbl_resolver"] = fake_bl
    out = await health.domain_health("example.com", **kw)
    assert len(out["checks"]["dnsbl"]["data"]["ips"]) == 4
    assert not any(c[0].startswith("1.6.8.8.b.") for c in fake_bl.calls)


async def test_bare_domain_is_capped_and_fix_list_sorted():
    zone = {"bare.com/A": ["93.184.216.34"], "bare.com/NS": ["ns1.example.net"], "ns1.example.net/A": ["8.8.8.8"],
            "bare.com/SOA": ["ns1.example.net h.bare.com 1 7200 3600 1209600 3600"]}
    out = await health.domain_health("bare.com", resolver=FakeResolver(zone), dnsbl_resolver=FakeResolver({}), policy_fetcher=policy_ok)
    s = out["summary"]
    assert s["grade"] in ("D", "F") and s["score"] <= 69 and s["capped_by"]
    reasons = {c["reason"] for c in s["capped_by"]}
    assert {"No SPF record", "No DMARC record"} <= reasons
    fixes = s["fixes"]
    statuses = [f["status"] for f in fixes]
    assert statuses == sorted(statuses, key=lambda x: x != "fail")  # all fails first
    assert fixes[0]["check"] == "spf" and fixes[0]["id"] == "spf_missing" and fixes[0]["fix"] and fixes[0]["fix_record"]
    assert {"spf_missing", "dmarc_missing"} <= {f["id"] for f in fixes}
    assert s["counts"]["fail"] >= 3


async def test_blocklisted_mx_ip_hurts_reputation(good_zone):
    kw = run_kwargs(good_zone)
    kw["dnsbl_resolver"] = FakeResolver({f"27.27.250.142.b.barracudacentral.org/A": ["127.0.0.2"], "27.27.250.142.bl.spamcop.net/A": ["127.0.0.2"],
                                         "27.27.250.142.psbl.surriel.com/A": ["127.0.0.2"]})
    out = await health.domain_health("example.com", **kw)
    rep = next(a for a in out["summary"]["areas"] if a["key"] == "reputation")
    assert rep["score"] <= 25 and out["checks"]["dnsbl"]["status"] == "fail"
    assert any(f["check"] == "dnsbl" and f["status"] == "fail" for f in out["summary"]["fixes"])
    assert out["summary"]["score"] < 100


async def test_null_mx_domain_skips_delivery_checks():
    zone = {"noreply.com/MX": ["0 ."], "noreply.com/TXT": ["v=spf1 -all"], "_dmarc.noreply.com/TXT": ["v=DMARC1; p=reject; rua=mailto:d@noreply.com"],
            "noreply.com/A": ["93.184.216.34"]}
    out = await health.domain_health("noreply.com", resolver=FakeResolver(zone), dnsbl_resolver=FakeResolver({}), policy_fetcher=policy_ok)
    areas = {a["key"]: a for a in out["summary"]["areas"]}
    assert areas["mail_delivery"]["score"] is None and areas["reputation"]["score"] is None
    assert out["summary"]["grade"] in ("A", "B", "C")
    assert out["checks"]["dnsbl"]["data"]["applicable"] is False


async def test_budget_timeout_and_crash_isolated(good_zone):
    async def slow():
        await asyncio.sleep(30)

    async def crash():
        raise RuntimeError("internal secret detail")

    out = await health.domain_health("example.com", overrides={"bimi": slow, "tlsrpt": crash}, budget=1.5, **run_kwargs(good_zone))
    assert out["checks"]["bimi"]["status"] == "error" and out["checks"]["tlsrpt"]["status"] == "error"
    assert "secret" not in out["checks"]["tlsrpt"]["summary"] and "RuntimeError" in out["checks"]["tlsrpt"]["summary"]
    assert out["checks"]["spf"]["status"] == "pass"
    assert out["summary"]["checks"]["bimi"]["status"] == "error"
    # errored checks are left out of scoring, not counted as zero
    cfg = next(a for a in out["summary"]["areas"] if a["key"] == "configuration")
    assert cfg["score"] is not None and cfg["score"] > 90


async def test_overall_budget_cancels_stragglers(good_zone):
    async def hang():
        await asyncio.sleep(60)

    t0 = asyncio.get_running_loop().time()
    events = [e async for e in health.iter_health("example.com", overrides={"dkim": hang}, budget=0.6, **run_kwargs(good_zone))]
    assert asyncio.get_running_loop().time() - t0 < 5
    dk = next(e for e in events if e["type"] == "check" and e["name"] == "dkim")
    assert dk["result"]["status"] == "error" and events[-1]["type"] == "summary"


async def test_invalid_domain_is_rejected():
    from app.core.validate import ValidationError
    with pytest.raises(ValidationError):
        async for _ in health.iter_health("127.0.0.1"):
            pass


def test_score_results_caps_and_missing_components():
    ok = CheckResult("spf", "x.com").finalize("ok")
    res = health.score_results("x.com", {"spf": ok})
    assert res["areas"][1]["score"] == 100 and res["areas"][0]["score"] is None and res["score"] == 100 and res["grade"] == "A"
    bad = CheckResult("spf", "x.com")
    bad.add("spf_plus_all", "fail", "t", "m", ["f"])
    bad.finalize("bad")
    res = health.score_results("x.com", {"spf": bad})
    assert res["score"] <= 79 and res["capped_by"][0]["cap"] == 79 and res["fixes"][0]["check"] == "spf"
