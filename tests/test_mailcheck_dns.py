"""BIMI, MTA-STS, TLS-RPT, DNS records and DNSBL checks (no network)."""
import asyncio
import json

import pytest

from app.core import dnsbl
from app.core.httpjson import FetchError
from app.core.mailcheck import bimi, dnsrec, mta_sts, tlsrpt
from app.core.mailcheck.resolver import FakeResolver
from app.core.validate import ValidationError


def ids(res):
    return {f.id for f in res.findings}


def status_of(res, fid):
    return next(f.status for f in res.findings if f.id == fid)


# ------------------------------------------------------------------ MTA-STS
POLICY = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mail.example.com\nmax_age: 604800\n"


def sts_zone(extra=None):
    z = {"_mta-sts.example.com/TXT": ["v=STSv1; id=20260101T000000"],
         "example.com/MX": ["10 mx1.example.com", "20 a.mail.example.com"]}
    z.update(extra or {})
    return z


def fetcher(text, ctype="text/plain; charset=utf-8"):
    calls = []

    async def f(url):
        calls.append(url)
        return mta_sts.PolicyResponse(200, text, ctype)

    f.calls = calls
    return f


def test_policy_parsing():
    p = mta_sts.parse_policy("version: STSv1\r\nmode: Enforce\r\nmx: A.example.com.\r\nmx: *.b.example.com\r\nmax_age: 86400\r\nfoo: bar\r\n\r\ngarbage")
    assert p["version"] == "STSv1" and p["mode"] == "enforce" and p["max_age"] == 86400
    assert p["mx"] == ["a.example.com", "*.b.example.com"] and p["unknown"] == ["foo"] and len(p["errors"]) == 1
    assert mta_sts.parse_policy("max_age: soon")["errors"]


@pytest.mark.parametrize("pattern,host,ok", [
    ("mx1.example.com", "MX1.example.com", True), ("*.example.com", "mx.example.com", True),
    ("*.example.com", "a.b.example.com", False), ("*.example.com", "example.com", False), ("mx1.example.com", "mx2.example.com", False)])
def test_mx_pattern_matching(pattern, host, ok):
    assert mta_sts.mx_matches(pattern, host) is ok


async def test_mta_sts_enforce_with_full_mx_coverage():
    f = fetcher(POLICY)
    res = await mta_sts.check("example.com", FakeResolver(sts_zone()), f)
    assert f.calls == ["https://mta-sts.example.com/.well-known/mta-sts.txt"]
    assert res.status == "pass" and res.data["policy"]["mode"] == "enforce" and res.data["id"] == "20260101T000000"
    assert [(c["host"], c["covered_by"]) for c in res.data["coverage"]] == [("mx1.example.com", "mx1.example.com"), ("a.mail.example.com", "*.mail.example.com")]


async def test_mta_sts_mx_not_covered_fails_in_enforce_warns_in_testing():
    pol = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n"
    res = await mta_sts.check("example.com", FakeResolver(sts_zone()), fetcher(pol))
    f = next(f for f in res.findings if f.id == "mta_sts_mx_mismatch")
    assert f.status == "fail" and f.details["missing"] == ["a.mail.example.com"] and "mx: a.mail.example.com" in f.fix_record
    res = await mta_sts.check("example.com", FakeResolver(sts_zone()), fetcher(pol.replace("enforce", "testing")))
    assert status_of(res, "mta_sts_mx_mismatch") == "warn" and status_of(res, "mta_sts_testing") == "warn"


async def test_mta_sts_policy_problems():
    bad = "version: STSv2\nmode: loud\nmx: mx1.example.com\n"
    res = await mta_sts.check("example.com", FakeResolver(sts_zone()), fetcher(bad, "text/html"))
    assert {"mta_sts_bad_version", "mta_sts_bad_mode", "mta_sts_no_max_age", "mta_sts_content_type"} <= ids(res)
    low = POLICY.replace("604800", "300")
    assert "mta_sts_max_age_low" in ids(await mta_sts.check("example.com", FakeResolver(sts_zone()), fetcher(low)))


async def test_mta_sts_missing_record_and_unreachable_policy_and_bad_id():
    res = await mta_sts.check("example.com", FakeResolver({"example.com/MX": ["10 mx1.example.com"]}), fetcher(POLICY))
    assert res.status == "info" and "mta_sts_missing" in ids(res) and 0 < res.score < 100

    async def boom(url):
        raise FetchError("could not connect over HTTPS")

    res = await mta_sts.check("example.com", FakeResolver(sts_zone()), boom)
    assert status_of(res, "mta_sts_policy_unreachable") == "fail"
    res = await mta_sts.check("example.com", FakeResolver(sts_zone({"_mta-sts.example.com/TXT": ["v=STSv1; id=bad id!"]})), fetcher(POLICY))
    assert "mta_sts_bad_id" in ids(res)


async def test_policy_fetcher_uses_ssrf_guard_without_network():
    for url in ("http://mta-sts.example.com/.well-known/mta-sts.txt", "https://127.0.0.1/.well-known/mta-sts.txt",
                "https://localhost/x", "https://user:pw@mta-sts.example.com/x", "https://169.254.169.254/latest"):
        with pytest.raises(FetchError):
            await mta_sts.fetch_policy_http(url)


# ------------------------------------------------------------------ TLS-RPT
async def test_tlsrpt():
    ok = await tlsrpt.check("example.com", FakeResolver({"_smtp._tls.example.com/TXT": ["v=TLSRPTv1; rua=mailto:t@example.com,https://r.example.net/x"]}))
    assert ok.status == "pass" and len(ok.data["rua"]) == 2
    miss = await tlsrpt.check("example.com", FakeResolver({"example.com/A": ["8.8.8.8"]}))
    assert miss.status == "info" and "tlsrpt_missing" in ids(miss) and next(iter(miss.findings)).fix_record.startswith("_smtp._tls.example.com.")
    bad = await tlsrpt.check("example.com", FakeResolver({"_smtp._tls.example.com/TXT": ["v=TLSRPTv1; rua=ftp://x"]}))
    assert "tlsrpt_bad_rua" in ids(bad) and bad.status == "fail"
    none = await tlsrpt.check("example.com", FakeResolver({"_smtp._tls.example.com/TXT": ["v=TLSRPTv1"]}))
    assert "tlsrpt_no_rua" in ids(none)


# ------------------------------------------------------------------ BIMI
async def test_bimi_record_and_dmarc_dependency():
    z = {"default._bimi.example.com/TXT": ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"],
         "_dmarc.example.com/TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]}
    ok = await bimi.check("example.com", FakeResolver(z))
    assert ok.status == "pass" and ok.data["logo"].endswith("logo.svg") and ok.data["dmarc_enforced"] is True
    z["_dmarc.example.com/TXT"] = ["v=DMARC1; p=none"]
    weak = await bimi.check("example.com", FakeResolver(z))
    assert status_of(weak, "bimi_needs_dmarc") == "warn"
    z["_dmarc.example.com/TXT"] = ["v=DMARC1; p=quarantine; pct=50"]
    assert "bimi_needs_dmarc" in ids(await bimi.check("example.com", FakeResolver(z)))


async def test_bimi_missing_and_bad_values():
    miss = await bimi.check("example.com", FakeResolver({"example.com/A": ["8.8.8.8"]}))
    assert miss.status == "info" and "bimi_missing" in ids(miss)
    bad = await bimi.check("example.com", FakeResolver({"default._bimi.example.com/TXT": ["v=BIMI1; l=http://example.com/logo.png; a=http://x/y.pem"]}))
    assert {"bimi_logo_not_https", "bimi_vmc_not_https"} <= ids(bad)
    png = await bimi.check("example.com", FakeResolver({"default._bimi.example.com/TXT": ["v=BIMI1; l=https://example.com/logo.png"]}))
    assert "bimi_logo_not_svg" in ids(png)


# ------------------------------------------------------------------ DNS records
SOA_OK = "ns1.example.net hostmaster.example.com 2026112501 7200 3600 1209600 3600"


def dns_zone(extra=None):
    z = {"example.com/SOA": [SOA_OK], "example.com/NS": ["ns1.example.net", "ns2.example.net"],
         "example.com/A": ["93.184.216.34"], "example.com/MX": ["10 mx.example.com"], "example.com/TXT": ["v=spf1 -all"],
         "ns1.example.net/A": ["8.8.8.8"], "ns2.example.net/A": ["9.9.9.9"]}
    z.update(extra or {})
    return z


async def test_dnsrec_collects_records_and_healthy_ns_soa():
    res = await dnsrec.check("example.com", FakeResolver(dns_zone()))
    assert res.data["records"]["A"] == ["93.184.216.34"] and res.data["records"]["MX"] == ["10 mx.example.com"]
    assert res.data["ns"]["count"] == 2 and "ns_ok" in ids(res) and "soa_ok" in ids(res)
    assert res.data["soa"]["serial_format"] == "date" and res.data["soa"]["serial"] == 2026112501
    assert res.status in ("pass", "warn") and res.data["scores"]["ns"] == 100


async def test_dnsrec_ns_problems():
    one = await dnsrec.check("example.com", FakeResolver(dns_zone({"example.com/NS": ["ns1.example.net"]})))
    assert status_of(one, "ns_single") == "fail"
    same = await dnsrec.check("example.com", FakeResolver(dns_zone({"ns2.example.net/A": ["8.8.8.9"]})))
    assert status_of(same, "ns_same_subnet") == "warn"
    lame = await dnsrec.check("example.com", FakeResolver(dns_zone({"example.com/SOA@9.9.9.9": "TIMEOUT"})))
    f = next(f for f in lame.findings if f.id == "ns_lame")
    assert f.status == "fail" and f.details["host"] == "ns2.example.net" and lame.data["scores"]["ns"] < 100
    noaddr = await dnsrec.check("example.com", FakeResolver(dns_zone({"ns2.example.net/A": "NXDOMAIN"})))
    assert "ns_no_address" in ids(noaddr)
    cn = await dnsrec.check("example.com", FakeResolver(dns_zone({"ns2.example.net/CNAME": ["ns9.example.net"], "ns2.example.net/A": ["9.9.9.9"]})))
    assert "ns_cname" in ids(cn)
    private = await dnsrec.check("example.com", FakeResolver(dns_zone({"ns2.example.net/A": ["10.0.0.5"]})))
    assert "ns_lame" not in ids(private)  # never probes a non-public address


async def test_dnsrec_soa_sanity():
    weird = "ns1.example.net h.example.com 5 100 9000 100 1"
    res = await dnsrec.check("example.com", FakeResolver(dns_zone({"example.com/SOA": [weird]})))
    f = next(f for f in res.findings if f.id == "soa_timers")
    assert f.status == "warn" and len(f.details["problems"]) >= 4 and res.data["soa"]["serial_format"] == "counter"
    assert dnsrec.serial_format(1764072000) == "unix-timestamp" and dnsrec.serial_format(2026112501) == "date"
    sub = await dnsrec.check("mail.example.com", FakeResolver({"mail.example.com/A": ["8.8.8.8"]}))
    assert "dns_not_apex" in ids(sub)


def test_caa_parsing():
    recs = dnsrec.parse_caa(['0 issue "letsencrypt.org"', '0 issuewild "digicert.com; account=1"', '0 iodef "mailto:s@example.com"', "128 weird x", "garbage"])
    assert recs[0]["ca"] == "letsencrypt.org" and recs[1]["ca"] == "digicert.com" and recs[1]["tag"] == "issuewild"
    assert recs[2]["tag"] == "iodef" and recs[2]["ca"] is None and recs[3]["flags"] == 128 and recs[4]["valid"] is False
    assert dnsrec.parse_caa(['0 issue ";"'])[0]["ca"] == ""


async def test_dnsrec_caa_findings():
    z = dns_zone({"example.com/CAA": ['0 issue "letsencrypt.org"', '0 issuewild ";"', '0 iodef "mailto:s@example.com"']})
    res = await dnsrec.check("example.com", FakeResolver(z))
    assert [c["domain"] for c in res.data["caa"]["allowed_cas"]] == ["letsencrypt.org"] and res.data["caa"]["allowed_cas"][0]["name"] == "Let's Encrypt"
    assert status_of(res, "caa_ok") == "pass" and "caa_no_iodef" not in ids(res)
    none = await dnsrec.check("example.com", FakeResolver(dns_zone()))
    assert status_of(none, "caa_missing") == "info" and none.data["scores"]["caa"] < 100
    crit = await dnsrec.check("example.com", FakeResolver(dns_zone({"example.com/CAA": ["128 futuretag x"]})))
    assert "caa_critical_unknown" in ids(crit)
    blocked = await dnsrec.check("example.com", FakeResolver(dns_zone({"example.com/CAA": ['0 issue ";"']})))
    assert "caa_no_issuance" in ids(blocked)


@pytest.mark.parametrize("ds,key,ad,state,fid", [
    (True, True, True, "signed", "dnssec_signed"), (True, True, False, "unverified", "dnssec_unverified"),
    (False, True, False, "partial", "dnssec_partial"), (True, False, False, "broken", "dnssec_broken"),
    (False, False, False, "unsigned", "dnssec_unsigned")])
async def test_dnssec_states(ds, key, ad, state, fid):
    z = dns_zone()
    if ds:
        z["example.com/DS"] = ["12345 13 2 ABCDEF"]
    if key:
        z["example.com/DNSKEY"] = ["257 3 13 AAAA"]
    res = await dnsrec.check("example.com", FakeResolver(z, ad_names=["example.com"] if ad else []))
    assert res.data["dnssec"]["state"] == state and fid in ids(res)
    if state == "broken":
        assert res.status == "fail" and res.data["scores"]["dnssec"] <= 65


async def test_dnssec_servfail_with_ds_is_broken():
    z = dns_zone({"example.com/DS": ["1 13 2 AB"], "example.com/DNSKEY": ["257 3 13 AA"]})
    fake = FakeResolver(z)
    orig = fake.query

    async def q(name, rtype, *, dnssec=False):
        r = await orig(name, rtype, dnssec=dnssec)
        if dnssec:
            r.status, r.records = "servfail", []
        return r

    fake.query = q
    assert (await dnsrec.check("example.com", fake)).data["dnssec"]["state"] == "broken"


async def test_dnsrec_nxdomain_and_cname_apex():
    assert (await dnsrec.check("nothing.example", FakeResolver({}))).status == "fail"
    res = await dnsrec.check("example.com", FakeResolver(dns_zone({"example.com/CNAME": ["other.example.net"]})))
    assert "dns_cname_apex" in ids(res)


# ------------------------------------------------------------------ DNSBL
def test_blocklist_data_file_is_sane():
    lists = dnsbl.load_lists()
    ip = [e for e in lists if e["type"] == "ip"]
    dom = [e for e in lists if e["type"] == "domain"]
    assert len(ip) >= 30 and len(dom) >= 6
    for e in lists:
        assert {"name", "zone", "type", "weight", "requires_key", "delist_url"} <= set(e) and e["weight"] in (1, 2, 3)
        assert e["delist_url"].startswith("https://") and e["zone"] == e["zone"].lower()
    assert len({e["zone"] for e in lists}) == len(lists)
    assert not any("sorbs" in e["zone"] for e in lists)
    assert {e["zone"] for e in lists if e["requires_key"]} == {"zen.spamhaus.org", "dbl.spamhaus.org"}
    assert all("dqs_zone" in e for e in lists if e["requires_key"])
    assert {e["zone"] for e in ip if e.get("ipv6")} >= {"zen.spamhaus.org"}
    assert {"b.barracudacentral.org", "bl.spamcop.net", "dnsbl-1.uceprotect.net", "psbl.surriel.com", "bl.mailspike.net", "all.s5h.net",
            "dyna.spamrats.com", "noptr.spamrats.com", "spam.spamrats.com", "dnsbl.justspam.org", "bl.nordspam.com"} <= {e["zone"] for e in ip}
    assert {"multi.surbl.org", "multi.uribl.com"} <= {e["zone"] for e in dom}
    json.dumps(list(lists))


def test_query_names_v4_and_v6():
    barracuda = next(e for e in dnsbl.load_lists() if e["zone"] == "b.barracudacentral.org")
    assert dnsbl.build_query(barracuda, "1.2.3.4") == "4.3.2.1.b.barracudacentral.org"
    v6 = dnsbl.reverse_ip("2001:4860:4860::8888")
    assert v6 == ".".join(reversed("20014860486000000000000000008888")) and v6.startswith("8.8.8.8.0.") and v6.endswith(".0.6.8.4.1.0.0.2")
    assert len(v6.split(".")) == 32
    zen = next(e for e in dnsbl.load_lists() if e["zone"] == "zen.spamhaus.org")
    assert dnsbl.build_query(zen, "1.2.3.4", "abcd1234efgh") == "4.3.2.1.abcd1234efgh.zen.dq.spamhaus.net"
    with pytest.raises(ValueError):
        dnsbl.build_query(zen, "1.2.3.4")
    surbl = next(e for e in dnsbl.load_lists() if e["zone"] == "multi.surbl.org")
    assert dnsbl.build_query(surbl, "Example.COM.") == "example.com.multi.surbl.org"


LISTS = [
    {"name": "TestBL", "zone": "bl.test", "type": "ip", "weight": 2, "requires_key": False, "ipv6": False, "delist_url": "https://bl.test/"},
    {"name": "TestBL6", "zone": "bl6.test", "type": "ip", "weight": 1, "requires_key": False, "ipv6": True, "delist_url": "https://bl6.test/"},
    {"name": "RefusingBL", "zone": "ref.test", "type": "domain", "weight": 3, "requires_key": False, "ipv6": False,
     "delist_url": "https://ref.test/", "refused_codes": ["127.0.0.1"]},
]


async def rows_for(target, zone, **kw):
    return {r["zone"]: r async for r in dnsbl.iter_check(target, FakeResolver(zone), lists=LISTS, **kw)}


async def test_listed_with_txt_reason():
    rows = await rows_for("1.2.3.4", {"4.3.2.1.bl.test/A": ["127.0.0.2"], "4.3.2.1.bl.test/TXT": ["Spam source, see bl.test/4.3.2.1"]})
    r = rows["bl.test"]
    assert r["status"] == "listed" and r["listed"] and r["code"] == "127.0.0.2" and "Spam source" in r["reason"] and r["delist_url"] == "https://bl.test/"
    assert rows["bl6.test"]["status"] == "clear" and "ref.test" not in rows


@pytest.mark.parametrize("answer", ["127.255.255.254", "127.255.255.252", "127.255.255.255", "10.0.0.1", "93.184.216.34"])
async def test_refused_or_non_loopback_answers_are_never_listed(answer):
    rows = await rows_for("1.2.3.4", {"4.3.2.1.bl.test/A": [answer]})
    assert rows["bl.test"]["status"] == "error" and rows["bl.test"]["listed"] is False and rows["bl.test"]["note"]
    res = dnsbl.summarize("1.2.3.4", "ip", list(rows.values()))
    assert res.data["counts"]["listed"] == 0 and not any(f.id.startswith("dnsbl_listed") for f in res.findings)
    assert "dnsbl_incomplete" in ids(res)


async def test_list_specific_refused_code_and_domain_lists():
    rows = await rows_for("example.com", {"example.com.ref.test/A": ["127.0.0.1"]})
    assert rows["ref.test"]["status"] == "error" and set(rows) == {"ref.test"}
    rows = await rows_for("example.com", {"example.com.ref.test/A": ["127.0.0.2"]})
    assert rows["ref.test"]["listed"]


async def test_ipv6_nibble_queries_and_unsupported_lists_skipped():
    v6 = "2001:4860:4860::8888"
    rows = await rows_for(v6, {f"{dnsbl.reverse_ip(v6)}.bl6.test/A": ["127.0.0.2"]})
    assert rows["bl6.test"]["status"] == "listed"
    assert rows["bl.test"]["status"] == "skipped" and "IPv6" in rows["bl.test"]["note"]


async def test_spamhaus_skipped_without_key_and_used_with_key(monkeypatch):
    monkeypatch.delenv("SPAMHAUS_DQS_KEY", raising=False)
    fake = FakeResolver({})
    rows = {r["zone"]: r async for r in dnsbl.iter_check("1.2.3.4", fake)}
    z = rows["zen.spamhaus.org"]
    assert z["status"] == "skipped" and "DQS" in z["note"] and not z["listed"]
    assert not any("spamhaus" in c[0] for c in fake.calls)
    res = await dnsbl.check("1.2.3.4", FakeResolver({}))
    assert "dnsbl_spamhaus_skipped" in ids(res) and res.status == "pass"
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "abcd1234efgh")
    fake = FakeResolver({"4.3.2.1.abcd1234efgh.zen.dq.spamhaus.net/A": ["127.0.0.4"]})
    rows = {r["zone"]: r async for r in dnsbl.iter_check("1.2.3.4", fake)}
    z = rows["zen.spamhaus.org"]
    assert z["status"] == "listed" and "XBL" in z["reason"] and "abcd1234efgh" not in json.dumps(z) and "<key>" in z["query"]
    assert ("4.3.2.1.abcd1234efgh.zen.dq.spamhaus.net", "A") in fake.calls


async def test_summary_scoring_and_findings():
    zone = {"4.3.2.1.bl.test/A": ["127.0.0.2"]}
    rows = [r async for r in dnsbl.iter_check("1.2.3.4", FakeResolver(zone), lists=LISTS[:2])]
    res = dnsbl.summarize("1.2.3.4", "ip", rows)
    assert res.status == "fail" and res.data["listed_weight"] == 2 and res.score == 70
    f = next(f for f in res.findings if f.id == "dnsbl_listed_bl_test")
    assert f.status == "fail" and len(f.fix) >= 3 and "https://bl.test/" in " ".join(f.fix)
    assert "1 of 2" in res.summary
    clean = dnsbl.summarize("1.2.3.4", "ip", [r async for r in dnsbl.iter_check("1.2.3.4", FakeResolver({}), lists=LISTS[:2])])
    assert clean.status == "pass" and clean.score == 100


async def test_pbl_listing_gets_specific_advice(monkeypatch):
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "abcd1234efgh")
    res = await dnsbl.check("1.2.3.4", FakeResolver({"4.3.2.1.abcd1234efgh.zen.dq.spamhaus.net/A": ["127.0.0.10"]}))
    f = next(f for f in res.findings if f.id == "dnsbl_listed_zen_spamhaus_org")
    assert "smarthost" in " ".join(f.fix) and "PBL" in f.meaning


async def test_private_and_invalid_targets_rejected():
    for bad in ("10.0.0.1", "127.0.0.1", "::1", "localhost", "a b"):
        with pytest.raises(ValidationError):
            async for _ in dnsbl.iter_check(bad, FakeResolver({})):
                pass


class Probe:
    """Resolver that records the peak number of concurrent queries."""

    def __init__(self, delay=0.01, hang=()):
        self.cur = self.peak = 0
        self.delay, self.hang = delay, hang

    async def query(self, name, rtype, *, dnssec=False):
        from app.core.mailcheck.resolver import DnsResult
        self.cur += 1
        self.peak = max(self.peak, self.cur)
        try:
            await asyncio.sleep(3600 if any(name.endswith(h) for h in self.hang) else self.delay)
        finally:
            self.cur -= 1
        return DnsResult(name, rtype, status="nxdomain")


async def test_concurrency_is_bounded_and_results_stream():
    p = Probe()
    n = 0
    async for _ in dnsbl.iter_check("1.2.3.4", p):
        n += 1
    assert n == len([e for e in dnsbl.load_lists() if e["type"] == "ip"]) and 10 <= p.peak <= 20


async def test_overall_timeout_marks_remaining_lists():
    p = Probe(hang=("bl.spamcop.net", "psbl.surriel.com"))
    rows = {r["zone"]: r async for r in dnsbl.iter_check("1.2.3.4", p, timeout=0.3)}
    assert rows["bl.spamcop.net"]["status"] == "timeout" and rows["psbl.surriel.com"]["status"] == "timeout"
    assert rows["dnsbl.dronebl.org"]["status"] == "clear"
    res = dnsbl.summarize("1.2.3.4", "ip", list(rows.values()))
    assert res.data["counts"]["timeout"] == 2


async def test_check_many_merges_ips():
    z = {"4.3.2.1.bl.test/A": ["127.0.0.2"]}
    res = await dnsbl.check_many(["1.2.3.4", "8.8.4.4"], FakeResolver(z), lists=LISTS[:1])
    assert res.status == "fail" and [i["ip"] for i in res.data["ips"]] == ["1.2.3.4", "8.8.4.4"]
    assert res.findings[0].title.endswith("(1.2.3.4)")
