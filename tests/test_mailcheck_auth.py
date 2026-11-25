"""SPF, DMARC, DKIM and MX checks against dict-backed fake resolvers (no network)."""
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.core.mailcheck import dkim, dmarc, models, mx, spf
from app.core.mailcheck.resolver import FakeResolver
from app.core.validate import ValidationError

FAKE_IP = "93.184.216.34"
PTR_FAKE_IP = "34.216.184.93.in-addr.arpa"


def ids(res):
    return {f.id for f in res.findings}


def status_of(res, fid):
    return next(f.status for f in res.findings if f.id == fid)


# ------------------------------------------------------------------ models
def test_result_shape_is_json_serialisable():
    import json
    r = models.CheckResult("x", "example.com")
    r.add("a", "warn", "T", "M", ["s1"], fix_record="rec", k=1)
    d = r.finalize("sum").to_dict()
    assert json.dumps(d)
    assert set(d) == {"check", "target", "status", "score", "summary", "findings", "data", "timings_ms"}
    assert d["status"] == "warn" and d["score"] == 88
    assert d["findings"][0]["fix_record"] == "rec" and d["findings"][0]["details"] == {"k": 1}


@pytest.mark.parametrize("bad", ["127.0.0.1", "8.8.8.8", "localhost", "a b.com", "-x.com", "single"])
def test_clean_domain_rejects(bad):
    with pytest.raises(ValidationError):
        models.clean_domain(bad)


# ------------------------------------------------------------------ SPF
def include_zone(n, last="~all"):
    zone = {"example.com/TXT": ["v=spf1 " + " ".join(f"include:i{i}.test" for i in range(n)) + f" {last}"]}
    for i in range(n):
        zone[f"i{i}.test/TXT"] = [f"v=spf1 ip4:8.8.{i}.1 -all"]
    return zone


async def test_spf_exactly_ten_lookups_passes():
    res = await spf.check("example.com", FakeResolver(include_zone(10)))
    assert res.data["lookups"] == 10
    assert res.status == "pass"
    assert "spf_too_many_lookups" not in ids(res)
    assert res.data["tree"]["lookups"] == 10


async def test_spf_eleven_lookups_fails_with_fix_steps():
    res = await spf.check("example.com", FakeResolver(include_zone(11)))
    assert res.data["lookups"] == 11 and res.status == "fail"
    f = next(f for f in res.findings if f.id == "spf_too_many_lookups")
    assert f.status == "fail" and len(f.fix) >= 3 and "PermError" in f.meaning


async def test_spf_tree_shape_and_per_node_counts():
    zone = {
        "example.com/TXT": ["v=spf1 include:a.test mx -all"],
        "a.test/TXT": ["v=spf1 include:b.test include:c.test ip4:8.8.8.8 -all"],
        "b.test/TXT": ["v=spf1 ip4:8.8.4.4 -all"],
        "c.test/TXT": ["v=spf1 a:host.test -all"],
        "host.test/A": ["8.8.8.9"],
        "example.com/MX": ["10 mail.example.com"], "mail.example.com/A": ["8.8.8.10"],
    }
    res = await spf.check("example.com", FakeResolver(zone))
    root = res.data["tree"]
    assert root["domain"] == "example.com" and root["kind"] == "root"
    assert [c["domain"] for c in root["children"]] == ["a.test"]
    a = root["children"][0]
    assert [c["domain"] for c in a["children"]] == ["b.test", "c.test"]
    assert root["own"] == 2 and a["own"] == 2 and a["children"][1]["own"] == 1
    assert a["lookups"] == 3 and root["lookups"] == 5 == res.data["lookups"]
    assert a["children"][0]["kind"] == "include"


async def test_spf_void_lookups():
    three = {"example.com/TXT": ["v=spf1 a:x1.test a:x2.test a:x3.test ~all"]}
    res = await spf.check("example.com", FakeResolver(three))
    assert res.data["void_lookups"] == 3 and status_of(res, "spf_void_lookups") == "fail"
    two = {"example.com/TXT": ["v=spf1 a:x1.test a:x2.test ~all"]}
    res = await spf.check("example.com", FakeResolver(two))
    assert res.data["void_lookups"] == 2 and status_of(res, "spf_void_at_limit") == "warn"
    assert "spf_void_lookups" not in ids(res)


async def test_spf_loop_detected():
    zone = {"example.com/TXT": ["v=spf1 include:a.test ~all"], "a.test/TXT": ["v=spf1 include:b.test -all"],
            "b.test/TXT": ["v=spf1 include:a.test -all"]}
    res = await spf.check("example.com", FakeResolver(zone))
    assert status_of(res, "spf_loop") == "fail" and res.status == "fail"


async def test_spf_two_records_fail_and_merged_fix():
    zone = {"example.com/TXT": ["v=spf1 ip4:8.8.8.8 include:a.test ~all", "v=spf1 ip4:8.8.8.8 ip4:9.9.9.9 -all", "unrelated"],
            "a.test/TXT": ["v=spf1 -all"]}
    res = await spf.check("example.com", FakeResolver(zone))
    f = next(f for f in res.findings if f.id == "spf_multiple")
    assert f.status == "fail"
    assert f.fix_record == "v=spf1 ip4:8.8.8.8 include:a.test ip4:9.9.9.9 ~all"
    assert res.data["records_found"] == 2 and res.status == "fail"


async def test_spf_plus_all_and_fix_record():
    res = await spf.check("example.com", FakeResolver({"example.com/TXT": ["v=spf1 ip4:8.8.8.8 +all"]}))
    f = next(f for f in res.findings if f.id == "spf_plus_all")
    assert f.status == "fail" and f.fix_record == "v=spf1 ip4:8.8.8.8 ~all"
    bare = await spf.check("example.com", FakeResolver({"example.com/TXT": ["v=spf1 all"]}))
    assert "spf_plus_all" in ids(bare)


async def test_spf_qualifier_advice():
    for rec, fid, st in [("v=spf1 ip4:8.8.8.8 ?all", "spf_neutral_all", "warn"), ("v=spf1 ip4:8.8.8.8", "spf_no_all", "warn"),
                         ("v=spf1 ip4:8.8.8.8 ~all", "spf_softfail", "pass"), ("v=spf1 ip4:8.8.8.8 -all", "spf_hardfail", "pass")]:
        res = await spf.check("example.com", FakeResolver({"example.com/TXT": [rec]}))
        assert status_of(res, fid) == st, rec


async def test_spf_redirect_is_followed_and_counted():
    zone = {"example.com/TXT": ["v=spf1 redirect=_spf.test"], "_spf.test/TXT": ["v=spf1 ip4:8.8.8.8 -all"]}
    res = await spf.check("example.com", FakeResolver(zone))
    assert res.data["lookups"] == 1 and res.data["all"] == "-"
    assert res.data["tree"]["children"][0]["kind"] == "redirect"
    assert "spf_no_all" not in ids(res) and res.status == "pass"


async def test_spf_redirect_ignored_when_all_present():
    zone = {"example.com/TXT": ["v=spf1 ip4:8.8.8.8 -all redirect=_spf.test"], "_spf.test/TXT": ["v=spf1 -all"]}
    res = await spf.check("example.com", FakeResolver(zone))
    assert status_of(res, "spf_redirect_ignored") == "warn" and res.data["lookups"] == 0


async def test_spf_include_of_missing_domain_or_without_spf():
    zone = {"example.com/TXT": ["v=spf1 include:gone.test include:nospf.test ~all"], "nospf.test/TXT": ["hello"]}
    res = await spf.check("example.com", FakeResolver(zone))
    assert {"spf_include_missing", "spf_include_no_record"} <= ids(res) and res.status == "fail"


async def test_spf_ptr_unknown_mechanism_and_bad_ip():
    res = await spf.check("example.com", FakeResolver({"example.com/TXT": ["v=spf1 ptr includes:x.test ip4:300.1.1.1 ~all"]}))
    assert {"spf_ptr", "spf_unknown_mechanism", "spf_bad_ip"} <= ids(res)
    assert res.data["lookups"] == 1


async def test_spf_mx_mechanism_host_limit_and_terms_after_all():
    hosts = [f"10 m{i}.example.com" for i in range(11)]
    zone = {"example.com/TXT": ["v=spf1 mx -all ip4:8.8.8.8"], "example.com/MX": hosts}
    for i in range(11):
        zone[f"m{i}.example.com/A"] = [f"8.8.8.{i + 1}"]
    res = await spf.check("example.com", FakeResolver(zone))
    assert status_of(res, "spf_mx_too_many_hosts") == "fail" and "spf_after_all" in ids(res)


async def test_spf_dedupe_fix_record_and_missing_suggests_provider():
    res = await spf.check("example.com", FakeResolver({"example.com/TXT": ["v=spf1 ip4:8.8.8.8 ip4:8.8.8.8 ~all"]}))
    f = next(f for f in res.findings if f.id == "spf_duplicates")
    assert f.fix_record == "v=spf1 ip4:8.8.8.8 ~all"
    zone = {"example.com/TXT": ["nothing"], "example.com/MX": ["1 aspmx.l.google.com"]}
    res = await spf.check("example.com", FakeResolver(zone))
    f = next(f for f in res.findings if f.id == "spf_missing")
    assert f.status == "fail" and f.fix_record == "v=spf1 include:_spf.google.com ~all"


async def test_spf_record_length_and_nxdomain_and_error():
    long = "v=spf1 " + " ".join(f"ip4:8.8.{i // 250}.{i % 250 + 1}" for i in range(40)) + " ~all"
    assert len(long) > 450
    res = await spf.check("example.com", FakeResolver({"example.com/TXT": [long]}))
    assert "spf_record_long" in ids(res)
    res = await spf.check("example.com", FakeResolver({"example.com/TXT": [("v=spf1 ip4:8.8.8.8 ", "x" * 300, " ~all")]}))
    assert "spf_string_too_long" in ids(res)
    assert (await spf.check("nope.example", FakeResolver({}))).status == "fail"
    assert (await spf.check("example.com", FakeResolver({"example.com/TXT": "TIMEOUT"}))).status == "error"


# ------------------------------------------------------------------ DMARC
def test_org_domain_heuristic():
    assert dmarc.org_domain("mail.example.com") == "example.com"
    assert dmarc.org_domain("a.b.example.co.uk") == "example.co.uk"
    assert dmarc.org_domain("example.co.in") == "example.co.in"
    assert dmarc.org_domain("example.com") == "example.com"


async def test_dmarc_parse_all_tags():
    rec = ("v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:r@example.com,mailto:r2@example.com!10m; "
           "ruf=mailto:f@example.com; adkim=s; aspf=r; fo=1:d; np=reject")
    res = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": [rec]}))
    d = res.data
    assert (d["policy"], d["sp"], d["pct"], d["np"], d["adkim"], d["aspf"], d["fo"]) == ("quarantine", "reject", 50, "reject", "s", "r", "1:d")
    assert d["rua"] == ["mailto:r@example.com", "mailto:r2@example.com!10m"] and d["ruf"] == ["mailto:f@example.com"]
    assert status_of(res, "dmarc_pct_partial") == "warn"
    assert d["flow"]["fail"]["policy"] == "quarantine"


async def test_dmarc_missing_has_starter_record():
    res = await dmarc.check("example.com", FakeResolver({"example.com/A": ["8.8.8.8"]}))
    f = next(f for f in res.findings if f.id == "dmarc_missing")
    assert f.status == "fail" and f.fix_record == "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
    assert res.status == "fail"


async def test_dmarc_p_none_gives_rollout_plan():
    rec = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
    res = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": [rec]}))
    f = next(f for f in res.findings if f.id == "dmarc_policy_none")
    assert f.status == "warn" and "pct=25" in f.fix_record and len(f.fix) == 4
    assert any("p=reject" in s for s in f.fix)


async def test_dmarc_enforced_is_pass():
    rec = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    res = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": [rec]}))
    assert res.status == "pass" and res.score == 100 and "enforced" in res.summary


async def test_dmarc_org_domain_fallback():
    zone = {"_dmarc.example.co.uk/TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.co.uk"], "mail.example.co.uk/A": ["8.8.8.8"]}
    res = await dmarc.check("mail.example.co.uk", FakeResolver(zone))
    assert res.data["inherited"] is True and res.data["found_at"] == "example.co.uk"
    assert "dmarc_inherited" in ids(res) and res.data["policy"] == "reject"


async def test_dmarc_external_rua_authorisation():
    rec = "v=DMARC1; p=reject; rua=mailto:x@vendor.net"
    bad = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": [rec], "vendor.net/A": ["8.8.8.8"]}))
    f = next(f for f in bad.findings if f.id == "dmarc_rua_unauthorised")
    assert f.status == "fail" and "example.com._report._dmarc.vendor.net" in f.meaning
    ok = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": [rec], "example.com._report._dmarc.vendor.net/TXT": ["v=DMARC1"]}))
    assert "dmarc_rua_unauthorised" not in ids(ok) and ok.data["rua_authorisation"][0]["authorised"] is True
    own = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=reject; rua=mailto:x@mail.example.com"]}))
    assert own.data["rua_authorisation"] == []  # same organisation: no authorisation needed


async def test_dmarc_invalid_and_multiple_and_weak_subdomain_policy():
    res = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=bogus"]}))
    assert "dmarc_bad_p" in ids(res)
    res = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]}))
    assert "dmarc_multiple" in ids(res)
    res = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com"]}))
    assert "dmarc_sp_weaker" in ids(res)
    res = await dmarc.check("example.com", FakeResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=reject"]}))
    assert "dmarc_no_rua" in ids(res)


# ------------------------------------------------------------------ DKIM
def rsa_p(bits: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


@pytest.fixture(scope="module")
def keys():
    return {1024: rsa_p(1024), 2048: rsa_p(2048)}


def test_dkim_key_size_computed_from_real_keys(keys):
    assert dkim.analyze_key(keys[1024]) == {"type": "rsa", "bits": 1024}
    assert dkim.analyze_key(keys[2048]) == {"type": "rsa", "bits": 2048}
    spaced = " ".join(keys[2048][i:i + 64] for i in range(0, len(keys[2048]), 64))
    assert dkim.parse_record(f"v=DKIM1; k=rsa; p={spaced}")["p"] == keys[2048]
    assert dkim.analyze_key("") == {"revoked": True}
    assert "error" in dkim.analyze_key("!!!not-base64")
    assert "error" in dkim.analyze_key(base64.b64encode(b"junk").decode())


async def test_dkim_selector_grades(keys):
    z = {f"s1024._domainkey.example.com/TXT": [f"v=DKIM1; k=rsa; p={keys[1024]}"],
         f"s2048._domainkey.example.com/TXT": [(f"v=DKIM1; k=rsa; p={keys[2048][:200]}", keys[2048][200:])]}
    r1024 = await dkim.check("example.com", "s1024", FakeResolver(z))
    assert status_of(r1024, "dkim_key_1024") == "warn" and r1024.status == "warn" and r1024.data["selectors"][0]["bits"] == 1024
    r2048 = await dkim.check("example.com", "s2048", FakeResolver(z))
    assert status_of(r2048, "dkim_key_ok") == "pass" and r2048.status == "pass" and r2048.data["selectors"][0]["bits"] == 2048


async def test_dkim_weak_revoked_missing_testing(keys, monkeypatch):
    monkeypatch.setattr(dkim, "analyze_key", lambda p, k="rsa": {"type": "rsa", "bits": 768})
    res = await dkim.check("example.com", "old", FakeResolver({"old._domainkey.example.com/TXT": [f"v=DKIM1; p={keys[1024]}"]}))
    assert status_of(res, "dkim_key_weak") == "fail"
    monkeypatch.undo()
    z = {"rev._domainkey.example.com/TXT": ["v=DKIM1; k=rsa; p="], "t._domainkey.example.com/TXT": [f"v=DKIM1; t=y:s; p={keys[2048]}"]}
    assert status_of(await dkim.check("example.com", "rev", FakeResolver(z)), "dkim_revoked") == "warn"
    assert "dkim_testing" in ids(await dkim.check("example.com", "t", FakeResolver(z)))
    miss = await dkim.check("example.com", "nope", FakeResolver({"example.com/A": ["8.8.8.8"]}))
    assert status_of(miss, "dkim_selector_missing") == "fail"
    with pytest.raises(ValidationError):
        await dkim.check("example.com", "bad selector!", FakeResolver({}))


async def test_dkim_ed25519_key():
    raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    z = {"e._domainkey.example.com/TXT": [f"v=DKIM1; k=ed25519; p={base64.b64encode(raw).decode()}"]}
    res = await dkim.check("example.com", "e", FakeResolver(z))
    assert res.data["selectors"][0]["key_type"] == "ed25519" and res.status == "pass"


async def test_dkim_probe_finds_common_selectors(keys):
    z = {"google._domainkey.example.com/TXT": [f"v=DKIM1; k=rsa; p={keys[2048]}"],
         "selector1._domainkey.example.com/CNAME": ["selector1-example-com._domainkey.tenant.onmicrosoft.com"],
         "selector1-example-com._domainkey.tenant.onmicrosoft.com/TXT": [f"v=DKIM1; k=rsa; p={keys[1024]}"],
         "example.com/A": ["8.8.8.8"]}
    fake = FakeResolver(z)
    res = await dkim.check("example.com", None, fake)
    grid = {s["selector"]: s for s in res.data["selectors"]}
    assert len(grid) == len(dkim.PROBE_SELECTORS) >= 25 and "sendgrid" not in grid
    assert grid["google"]["found"] and grid["google"]["bits"] == 2048 and grid["google"]["hint"] == "Google Workspace"
    assert grid["selector1"]["found"] and grid["selector1"]["bits"] == 1024 and grid["selector1"]["cname"]
    assert not grid["k1"]["found"] and res.data["found_count"] == 2
    assert {"google", "selector1", "s1", "fm3", "protonmail3", "everlytickey2", "sig1"} <= set(grid)


async def test_dkim_probe_none_found_is_helpful():
    res = await dkim.check("example.com", None, FakeResolver({"example.com/A": ["8.8.8.8"]}))
    f = next(f for f in res.findings if f.id == "dkim_none_found")
    assert f.status == "warn" and any("DKIM-Signature" in s for s in f.fix) and res.data["found_count"] == 0


# ------------------------------------------------------------------ MX
@pytest.mark.parametrize("host,expected", [
    ("aspmx.l.google.com", "Google Workspace"), ("alt1.aspmx.l.google.com", "Google Workspace"),
    ("example-com.mail.protection.outlook.com", "Microsoft 365"), ("mx.zoho.in", "Zoho Mail"),
    ("mail.protonmail.ch", "Proton Mail"), ("in1-smtp.messagingengine.com", "Fastmail"), ("mta5.am0.yahoodns.net", "Yahoo Mail"),
    ("inbound-smtp.us-east-1.amazonaws.com", "Amazon SES (inbound)"), ("us-smtp-inbound-1.mimecast.com", "Mimecast"),
    ("mx1.pphosted.com", "Proofpoint"), ("mx.ess.barracudanetworks.com", "Barracuda"), ("mail.example.com", "Self-hosted / cPanel"),
    ("mail.other.net", None)])
def test_provider_detection(host, expected):
    assert mx.detect_provider(host, "example.com") == expected


def mx_zone(extra=None):
    z = {"example.com/MX": ["20 mx2.example.com", "10 mx1.example.com"],
         "mx1.example.com/A": [FAKE_IP], "mx2.example.com/A": ["8.8.8.8"],
         f"{PTR_FAKE_IP}/PTR": ["mx1.example.com"], "8.8.8.8.in-addr.arpa/PTR": ["mx2.example.com"]}
    z.update(extra or {})
    return z


async def test_mx_ladder_sorted_with_fcrdns():
    res = await mx.check("example.com", FakeResolver(mx_zone()))
    ladder = res.data["ladder"]
    assert [(i["priority"], i["host"]) for i in ladder] == [(10, "mx1.example.com"), (20, "mx2.example.com")]
    a = ladder[0]["addresses"][0]
    assert a["ip"] == FAKE_IP and a["ptr"] == ["mx1.example.com"] and a["fcrdns"] is True and a["public"] is True
    assert ladder[1]["addresses"][0]["fcrdns"] is True  # PTR mx2 -> A 8.8.8.8 (set in zone via default A)
    assert res.data["mode"] == "mx" and res.data["provider"] == "Self-hosted / cPanel"
    assert mx.mx_addresses(res.data) == [FAKE_IP, "8.8.8.8"] and mx.top_mx_host(res.data) == "mx1.example.com"


async def test_mx_fcrdns_mismatch_and_missing_ptr():
    z = mx_zone({f"{PTR_FAKE_IP}/PTR": ["other.example.net"], "other.example.net/A": ["8.8.4.4"]})
    z.pop("8.8.8.8.in-addr.arpa/PTR")
    res = await mx.check("example.com", FakeResolver(z))
    assert {"mx_fcrdns_mismatch", "mx_no_ptr"} <= ids(res) and res.status == "warn"
    assert res.data["ladder"][0]["addresses"][0]["fcrdns"] is False


async def test_mx_provider_hosts_skip_ptr_noise_and_mixed_providers_warn():
    z = {"example.com/MX": ["1 aspmx.l.google.com", "5 example-com.mail.protection.outlook.com"],
         "aspmx.l.google.com/A": ["142.250.27.27"], "example-com.mail.protection.outlook.com/A": ["52.101.8.1"]}
    res = await mx.check("example.com", FakeResolver(z))
    assert "mx_no_ptr" not in ids(res) and status_of(res, "mx_mixed_providers") == "warn"
    assert res.data["providers"] == ["Google Workspace", "Microsoft 365"]


async def test_mx_null_mx():
    res = await mx.check("example.com", FakeResolver({"example.com/MX": ["0 ."]}))
    assert res.status == "info" and res.data["mode"] == "null" and res.data["applicable"] is False and "mx_null" in ids(res)
    mixed = await mx.check("example.com", FakeResolver({"example.com/MX": ["0 .", "10 mx1.example.com"], "mx1.example.com/A": ["8.8.8.8"]}))
    assert status_of(mixed, "mx_null_mixed") == "fail"


async def test_mx_no_mx_falls_back_to_a_record():
    res = await mx.check("example.com", FakeResolver({"example.com/A": ["8.8.8.8"]}))
    assert res.data["mode"] == "implicit" and status_of(res, "mx_implicit") == "warn"
    assert res.data["ladder"][0]["host"] == "example.com"
    none = await mx.check("example.com", FakeResolver({"example.com/TXT": ["x"]}))
    assert status_of(none, "mx_none") == "fail" and none.data["mode"] == "none"
    assert (await mx.check("gone.example", FakeResolver({}))).status == "fail"


async def test_mx_cname_ip_literal_private_and_unresolvable():
    z = {"example.com/MX": ["10 alias.example.com", "20 8.8.4.4", "30 priv.example.com", "40 ghost.example.com"],
         "alias.example.com/CNAME": ["real.example.net"], "real.example.net/A": ["8.8.8.8"],
         "priv.example.com/A": ["10.1.2.3"], "ghost.example.com/TXT": ["x"]}
    res = await mx.check("example.com", FakeResolver(z))
    assert {"mx_cname", "mx_ip_literal", "mx_private_ip", "mx_unresolvable"} <= ids(res)
    assert all(status_of(res, i) == "fail" for i in ("mx_cname", "mx_ip_literal", "mx_private_ip", "mx_unresolvable"))
    assert res.score <= 65 and next(f for f in res.findings if f.id == "mx_cname").fix_record.endswith("real.example.net.")


async def test_mx_lookup_error_is_error_result():
    assert (await mx.check("example.com", FakeResolver({"example.com/MX": "SERVFAIL"}))).status == "error"
