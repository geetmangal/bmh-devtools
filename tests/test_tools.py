import pytest
from httpx import ASGITransport, AsyncClient

from app.core.validate import ValidationError, is_public_ip, normalise_hostname, validate_ptr_target, validate_url
from app.main import app



@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------- subnet ----------------
async def test_subnet_calc_v4(client):
    r = await client.post("/api/v1/subnet/calc", json={"cidr": "10.0.0.0/22"})
    assert r.status_code == 200
    d = r.json()
    assert d["network"] == "10.0.0.0" and d["broadcast"] == "10.0.3.255"
    assert d["first_usable"] == "10.0.0.1" and d["last_usable"] == "10.0.3.254"
    assert d["usable_hosts"] == 1022 and d["total_addresses"] == 1024
    assert d["netmask"] == "255.255.252.0" and d["wildcard"] == "0.0.3.255"
    assert d["class"] == "A" and d["is_private"] is True and d["is_global"] is False
    assert d["reverse_dns_zone"] == "0.10.in-addr.arpa"
    assert d["netmask_binary"] == "11111111.11111111.11111100.00000000"


async def test_subnet_calc_v4_host_and_p2p(client):
    d = (await client.post("/api/v1/subnet/calc", json={"cidr": "192.168.1.77/31"})).json()
    assert d["usable_hosts"] == 2 and d["first_usable"] == "192.168.1.76" and d["last_usable"] == "192.168.1.77"
    d = (await client.post("/api/v1/subnet/calc", json={"cidr": "8.8.8.8"})).json()
    assert d["prefix"] == 32 and d["usable_hosts"] == 1 and d["is_global"] is True


async def test_subnet_calc_v6(client):
    d = (await client.post("/api/v1/subnet/calc", json={"cidr": "2401:db00:abcd::1/48"})).json()
    assert d["version"] == 6 and d["network"] == "2401:db00:abcd::" and d["broadcast"] is None
    assert d["total_addresses"] == str(2 ** 80) and d["usable_hosts"] == str(2 ** 80 - 1)
    assert d["reverse_dns_zone"] == "d.c.b.a.0.0.b.d.1.0.4.2.ip6.arpa"
    assert d["exploded"] == "2401:db00:abcd:0000:0000:0000:0000:0001"
    assert d["is_global"] is True


async def test_subnet_calc_invalid(client):
    r = await client.post("/api/v1/subnet/calc", json={"cidr": "300.1.1.1/24"})
    assert r.status_code == 422


async def test_subnet_split(client):
    d = (await client.post("/api/v1/subnet/split", json={"cidr": "10.0.0.0/22", "new_prefix": 24})).json()
    assert d["count"] == 4 and [s["cidr"] for s in d["subnets"]] == ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    d = (await client.post("/api/v1/subnet/split", json={"cidr": "2001:db8::/32", "new_prefix": 34})).json()
    assert d["count"] == 4 and d["subnets"][1]["cidr"] == "2001:db8:4000::/34"
    r = await client.post("/api/v1/subnet/split", json={"cidr": "10.0.0.0/8", "new_prefix": 24})
    assert r.status_code == 422  # 65536 > cap
    r = await client.post("/api/v1/subnet/split", json={"cidr": "10.0.0.0/24", "new_prefix": 24})
    assert r.status_code == 422


async def test_subnet_summarise(client):
    d = (await client.post("/api/v1/subnet/summarise",
                           json={"cidrs": ["192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/23"]})).json()
    assert d["collapsed"] == ["192.168.0.0/22"] and d["single_supernet"] == "192.168.0.0/22"
    d = (await client.post("/api/v1/subnet/summarise", json={"cidrs": ["10.0.0.0/24", "10.0.5.0/24"]})).json()
    assert d["single_supernet"] == "10.0.0.0/21"


# ---------------- validation ----------------
@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "172.16.0.1", "192.168.0.1",
                                "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "224.0.0.1"])
def test_private_ips_rejected(ip):
    assert is_public_ip(ip) is False
    with pytest.raises(ValidationError):
        validate_url(f"http://{ip}/")


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "160.22.108.2"])
def test_public_ips_accepted(ip):
    assert is_public_ip(ip) is True


def test_validate_url():
    assert validate_url("bookmyhost.com") == ("https", "bookmyhost.com", 443, "/")
    assert validate_url("http://Example.COM:8080/a?b=1") == ("http", "example.com", 8080, "/a?b=1")
    for bad in ["ftp://example.com", "http://localhost/", "http://foo.internal/", "https://example.com:22/",
                "http://user:pw@example.com/", "http://[::1]/", "http://127.1/"]:
        with pytest.raises(ValidationError):
            validate_url(bad)


def test_hostname():
    assert normalise_hostname("Bücher.example.") == "xn--bcher-kva.example"
    for bad in ["-bad.com", "a..b", "a" * 64 + ".com", "ex ample.com", ""]:
        with pytest.raises(ValidationError):
            normalise_hostname(bad)


def test_ptr_target():
    assert validate_ptr_target("8.8.4.4") == "4.4.8.8.in-addr.arpa"
    with pytest.raises(ValidationError):
        validate_ptr_target("10.0.0.1")
    with pytest.raises(ValidationError):
        validate_ptr_target("example.com")


async def test_http_check_rejects_private(client):
    for u in ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://10.0.0.1/", "http://localhost:8080/"]:
        r = await client.post("/api/v1/http/check", json={"url": u})
        assert r.status_code == 422, u


async def test_dns_rejects_bad_name(client):
    r = await client.post("/api/v1/dns/propagation", json={"name": "bad host", "type": "A"})
    assert r.status_code == 422
    r = await client.post("/api/v1/dns/propagation", json={"name": "10.0.0.1", "type": "PTR"})
    assert r.status_code == 422
    r = await client.post("/api/v1/dns/propagation", json={"name": "example.com", "type": "HINFO"})
    assert r.status_code == 422


# ---------------- pages ----------------
async def test_pages_and_meta(client):
    for path in ["/tools/", "/tools/dns-propagation-checker", "/tools/subnet-calculator", "/tools/ttfb-ssl-checker"]:
        r = await client.get(path)
        assert r.status_code == 200, path
        assert "<h1" in r.text and 'rel="canonical"' in r.text and "FAQPage" in r.text
        assert "https://bookmyhost.com" in r.text
        assert "X-Robots-Tag" not in r.headers
    r = await client.get("/tools/sitemap.xml")
    assert r.status_code == 200 and r.text.count("<loc>") == 4
    r = await client.get("/robots.txt")
    assert "Sitemap:" in r.text
    r = await client.get("/healthz")
    assert r.json() == {"status": "ok"}
    r = await client.post("/api/v1/subnet/calc", json={"cidr": "10.0.0.0/24"})
    assert r.headers.get("x-robots-tag") == "noindex"


async def test_rate_limit(client):
    from app.core import ratelimit
    bucket = ratelimit.TokenBucket(2)
    assert bucket.allow("k") and bucket.allow("k") and not bucket.allow("k")
    hdr = {"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}
    codes = [(await client.post("/api/v1/subnet/calc", json={"cidr": "10.0.0.0/24"}, headers=hdr)).status_code for _ in range(32)]
    assert 429 in codes


# ---------------- network ----------------
@pytest.mark.network
async def test_dns_propagation_live(client):
    r = await client.post("/api/v1/dns/propagation", json={"name": "example.com", "type": "A"})
    assert r.status_code == 200
    d = r.json()
    assert d["summary"]["total"] == len(d["resolvers"]) >= 16
    assert any(x["status"] == "ok" and x["answers"] for x in d["resolvers"])


@pytest.mark.network
async def test_http_check_live(client):
    r = await client.post("/api/v1/http/check", json={"url": "https://example.com"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] in (200, 301, 302) and d["ssl"]["certificate"]["hostname_matches"] is True
    assert d["timing"]["ttfb_ms"]["min"] > 0 and d["timing_first_sample"]["tls_ms"] > 0
