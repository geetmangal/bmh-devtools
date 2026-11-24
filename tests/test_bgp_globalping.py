"""Globalping client: locations, target safety, normalisation, polling/streaming (offline)."""
import pytest

from app.core import globalping as gp
from app.core.httpjson import FetchError
from app.core.target import TargetError
from tests.test_bgp_fixtures import clean_bgp_state  # noqa: F401


class Post:
    def __init__(self, status=202, doc=None):
        self.status, self.doc, self.calls = status, doc if doc is not None else {"id": "abc123XYZ789", "probesCount": 4}, []

    async def __call__(self, url, body, headers, timeout=10.0):
        self.calls.append((url, body, headers))
        return self.status, self.doc


async def resolver_ok(host, *a, **k):
    return ["93.184.216.34"]


async def resolver_private(host, *a, **k):
    raise TargetError(f"{host} resolves to a non-public address (10.0.0.5); refusing", 422)


def probe_doc(city="Mumbai", cc="IN", asn=9498, network="Bharti Airtel", status="finished", result=None):
    return {"probe": {"continent": "AS", "region": "Southern Asia", "country": cc, "state": None, "city": city, "asn": asn,
                      "longitude": 72.88, "latitude": 19.07, "network": network, "tags": [], "resolvers": []},
            "result": result if result is not None else {"status": status}}


PING_OK = {"status": "finished", "rawOutput": "PING ...", "resolvedAddress": "1.1.1.1", "resolvedHostname": "1.1.1.1",
           "timings": [{"ttl": 59, "rtt": 11.2}], "stats": {"min": 10.5, "max": 14.1, "avg": 11.9, "total": 3, "rcv": 3, "drop": 0, "loss": 0}}


# --- locations -----------------------------------------------------------------------------
def test_preset_india_four_cities_one_probe_each():
    locs = gp.build_locations("India", 4)
    assert [(l["city"], l["limit"]) for l in locs] == [("Mumbai", 1), ("Delhi", 1), ("Bengaluru", 1), ("Chennai", 1)]
    assert all(l["country"] == "IN" for l in locs)


def test_limit_is_clamped_and_split_across_locations():
    assert sum(l["limit"] for l in gp.build_locations("India", 99)) == 10
    assert [l["limit"] for l in gp.build_locations("India", 6)] == [2, 2, 1, 1]
    assert len(gp.build_locations("India", 2)) == 2                         # fewer probes than cities: first two
    assert gp.build_locations("Asia", 3) == [{"continent": "AS", "limit": 3}]
    assert gp.build_locations("europe", 0) == [{"continent": "EU", "limit": 1}]
    assert gp.build_locations("North America", 2) == [{"continent": "NA", "limit": 2}]
    assert len(gp.build_locations("World", 6)) == 6 and gp.build_locations(None, 3)[0] == {"continent": "NA", "limit": 1}


def test_explicit_locations():
    assert gp.build_locations("Frankfurt, DE", 1) == [{"city": "Frankfurt", "country": "DE", "limit": 1}]
    assert gp.build_locations(["IN", "AS13335"], 2) == [{"country": "IN", "limit": 1}, {"asn": 13335, "limit": 1}]
    assert gp.build_locations("IN,DE", 2) == [{"country": "IN", "limit": 1}, {"country": "DE", "limit": 1}]
    assert gp.build_locations([{"city": "Tokyo", "evil": "x"}], 1) == [{"city": "Tokyo", "limit": 1}]
    for bad in ("Mumbai; rm -rf", "x" * 80, [{}]):
        with pytest.raises(gp.GlobalpingError):
            gp.build_locations(bad, 1)


# --- create_measurement: safety + request body -----------------------------------------------
@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "160.22.109.1",
                                    "::1", "fd00::1", "localhost", "printer.local"])
async def test_private_targets_rejected_before_any_request(target):
    post = Post()
    with pytest.raises(gp.GlobalpingError) as ei:
        await gp.create_measurement("ping", target, "India", 2, post=post, resolve=resolver_ok)
    assert ei.value.status == 422 and post.calls == []


async def test_hostname_resolving_to_private_space_rejected():
    post = Post()
    with pytest.raises(gp.GlobalpingError, match="non-public"):
        await gp.create_measurement("traceroute", "internal.example.com", "India", 2, post=post, resolve=resolver_private)
    assert post.calls == []


async def test_dns_type_does_not_need_public_resolution_of_the_name():
    post = Post()
    await gp.create_measurement("dns", "internal.example.com", "India", 2, {"query_type": "mx"}, post=post, resolve=resolver_private)
    assert post.calls[0][1]["measurementOptions"] == {"query": {"type": "MX"}}


async def test_private_resolver_option_rejected():
    with pytest.raises(gp.GlobalpingError):
        await gp.create_measurement("dns", "example.com", "India", 1, {"resolver": "10.0.0.53"}, post=Post(), resolve=resolver_ok)


async def test_create_ping_body_and_result():
    post = Post()
    r = await gp.create_measurement("ping", "1.1.1.1", "India", 4, {"packets": 3, "junk": 1}, post=post, resolve=resolver_ok)
    assert r == {"id": "abc123XYZ789", "probes_count": 4, "type": "ping", "target": "1.1.1.1"}
    url, body, headers = post.calls[0]
    assert url == "https://api.globalping.io/v1/measurements"
    assert body["type"] == "ping" and body["target"] == "1.1.1.1" and body["measurementOptions"] == {"packets": 3}
    assert [l["city"] for l in body["locations"]] == ["Mumbai", "Delhi", "Bengaluru", "Chennai"]
    assert "limit" not in body and headers == {}


async def test_http_options_whitelisted():
    post = Post()
    await gp.create_measurement("http", "example.com", "World", 2, {"method": "get", "path": "/health", "protocol": "https", "port": 443,
                                                                      "host": "evil.internal", "headers": {"X": "y"}}, post=post, resolve=resolver_ok)
    assert post.calls[0][1]["measurementOptions"] == {"request": {"method": "GET", "path": "/health"}, "protocol": "HTTPS", "port": 443}
    for opts in ({"path": "/a b"}, {"path": "nohead"}, {"port": 22}, {"method": "POST"}):
        with pytest.raises(gp.GlobalpingError):
            await gp.create_measurement("http", "example.com", "India", 1, opts, post=post, resolve=resolver_ok)


async def test_bad_type_and_token_header(monkeypatch):
    with pytest.raises(gp.GlobalpingError):
        await gp.create_measurement("curl", "1.1.1.1", "India", 1, post=Post(), resolve=resolver_ok)
    monkeypatch.setenv("GLOBALPING_TOKEN", "tok")
    post = Post()
    await gp.create_measurement("ping", "1.1.1.1", "India", 1, post=post, resolve=resolver_ok)
    assert post.calls[0][2] == {"Authorization": "Bearer tok"}


@pytest.mark.parametrize("status", [429, 402])
async def test_credit_exhaustion_gives_clear_message(status):
    with pytest.raises(gp.GlobalpingError) as ei:
        await gp.create_measurement("ping", "1.1.1.1", "India", 1, post=Post(status, {"error": {"type": "too_many_requests"}}), resolve=resolver_ok)
    assert ei.value.status == 429 and ei.value.code == "rate_limited" and "credits" in str(ei.value)


async def test_validation_error_from_api_surfaces_message():
    post = Post(422, {"error": {"type": "no_probes_found", "message": "No suitable probes found"}})
    with pytest.raises(gp.GlobalpingError, match="No suitable probes") as ei:
        await gp.create_measurement("ping", "1.1.1.1", "Atlantis", 1, post=post, resolve=resolver_ok)
    assert ei.value.status == 422


# --- normalisation -----------------------------------------------------------------------------
def test_normalise_ping():
    n = gp.normalise_result("ping", probe_doc(result=PING_OK))
    assert n["probe"] == {"city": "Mumbai", "country": "IN", "asn": 9498, "network": "Bharti Airtel", "lat": 19.07, "lon": 72.88,
                          "continent": "AS", "state": None}
    assert n["stats"] == {"min": 10.5, "avg": 11.9, "max": 14.1, "loss": 0.0} and n["hops"] == [] and n["status"] == "finished"


def test_normalise_ping_all_lost():
    n = gp.normalise_result("ping", probe_doc(result={"status": "finished", "stats": {"min": None, "avg": None, "max": None, "total": 3, "rcv": 0, "drop": 3, "loss": 100}}))
    assert n["stats"] == {"min": None, "avg": None, "max": None, "loss": 100.0}


def test_normalise_traceroute_hops_compatible_with_parse_traceroute_shape():
    res = {"status": "finished", "resolvedAddress": "1.1.1.1", "hops": [
        {"resolvedAddress": "192.168.0.1", "resolvedHostname": "gw", "timings": [{"rtt": 1.0}, {"rtt": 3.0}]},
        {"resolvedAddress": None, "resolvedHostname": None, "timings": []},
        {"resolvedAddress": "1.1.1.1", "resolvedHostname": "one.one.one.one", "timings": [{"rtt": 18.0}, {"rtt": 20.0}]}]}
    n = gp.normalise_result("traceroute", probe_doc(result=res))
    assert [(h["hop"], h["ip"], h["rtt_ms"]) for h in n["hops"]] == [(1, "192.168.0.1", 2.0), (2, None, None), (3, "1.1.1.1", 19.0)]
    assert n["stats"]["avg"] == 19.0 and n["stats"]["loss"] == 0.0 and n["detail"]["reached"] is True
    res["hops"].pop()
    assert gp.normalise_result("traceroute", probe_doc(result=res))["stats"]["loss"] == 100.0


def test_normalise_mtr_dns_http():
    mtr = {"status": "finished", "resolvedAddress": "1.1.1.1", "hops": [
        {"resolvedAddress": "1.1.1.1", "resolvedHostname": "x", "asn": [13335], "stats": {"min": 9, "avg": 10, "max": 12, "loss": 5, "total": 20}}]}
    n = gp.normalise_result("mtr", probe_doc(result=mtr))
    assert n["hops"][0]["asn"] == [13335] and n["stats"] == {"min": 9.0, "avg": 10.0, "max": 12.0, "loss": 5.0}
    dns = {"status": "finished", "answers": [{"name": "example.com", "type": "A", "ttl": 60, "class": "IN", "value": "93.184.216.34"}],
           "timings": {"total": 22}, "resolver": "8.8.8.8", "statusCodeName": "NOERROR"}
    n = gp.normalise_result("dns", probe_doc(result=dns))
    assert n["detail"]["answers"][0]["value"] == "93.184.216.34" and n["stats"]["avg"] == 22.0
    http = {"status": "finished", "statusCode": 200, "statusCodeName": "OK", "headers": {"server": "cloudflare", "set-cookie": "secret"},
            "rawBody": "<html>", "timings": {"total": 120, "dns": 5}, "tls": {"protocol": "TLSv1.3", "issuer": {"O": "Let's Encrypt"}}}
    n = gp.normalise_result("http", probe_doc(result=http))
    assert n["detail"]["status_code"] == 200 and "set-cookie" not in n["detail"]["headers"] and n["detail"]["tls"]["issuer"] == "Let's Encrypt"


async def test_get_measurement_validates_id_and_maps_429():
    async def get_429(*a, **k):
        raise FetchError("upstream returned HTTP 429")

    with pytest.raises(gp.GlobalpingError):
        await gp.get_measurement("../etc", get=get_429)
    with pytest.raises(gp.GlobalpingError) as ei:
        await gp.get_measurement("abc123XYZ789", get=get_429)
    assert ei.value.code == "rate_limited"


# --- polling / streaming -------------------------------------------------------------------------
class Poller:
    """GET stub that returns a scripted sequence of measurement documents (last one repeats)."""

    def __init__(self, docs):
        self.docs, self.n = docs, 0

    async def __call__(self, url, params=None, timeout=10.0, headers=None):
        d = self.docs[min(self.n, len(self.docs) - 1)]
        self.n += 1
        return d


def measurement(status, *probes):
    return {"id": "abc123XYZ789", "type": "ping", "status": status, "target": "1.1.1.1", "probesCount": len(probes), "results": list(probes)}


class FakeTime:
    def __init__(self):
        self.t, self.sleeps = 100.0, []

    def clock(self):
        return self.t

    async def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


async def collect(**kw):
    return [e async for e in gp.run("ping", "1.1.1.1", "India", 2, post=Post(), resolve=resolver_ok, **kw)]


async def test_run_streams_partial_probes_until_finished():
    mum = probe_doc("Mumbai", result=PING_OK)
    delhi_pending = probe_doc("Delhi", status="in-progress")
    delhi_done = probe_doc("Delhi", result={**PING_OK, "stats": {**PING_OK["stats"], "avg": 30.0}})
    t = FakeTime()
    get = Poller([measurement("in-progress", mum, delhi_pending), measurement("in-progress", mum, delhi_pending),
                  measurement("finished", mum, delhi_done)])
    events = await collect(get=get, sleep=t.sleep, clock=t.clock)
    kinds = [e["event"] for e in events]
    assert kinds == ["created", "probe", "probe", "done"]
    assert events[1]["probe"]["probe"]["city"] == "Mumbai" and events[1]["index"] == 0       # first probe streamed early
    assert events[2]["probe"]["probe"]["city"] == "Delhi" and events[2]["probe"]["stats"]["avg"] == 30.0
    assert events[3]["finished"] and len(events[3]["probes"]) == 2
    assert len(t.sleeps) == 2 and get.n == 3


async def test_run_times_out_after_budget_with_partial_data():
    mum = probe_doc("Mumbai", result=PING_OK)
    stuck = probe_doc("Delhi", status="in-progress")
    t = FakeTime()
    events = await collect(get=Poller([measurement("in-progress", mum, stuck)]), sleep=t.sleep, clock=t.clock, budget=25.0, interval=1.0)
    assert [e["event"] for e in events] == ["created", "probe", "timeout"]
    assert events[-1]["pending"] == 1 and len(events[-1]["probes"]) == 2 and not events[-1]["finished"]
    assert 24.9 <= sum(t.sleeps) <= 25.1                      # polled for ~the whole budget, then gave up


async def test_run_reports_creation_and_poll_errors_as_events():
    events = [e async for e in gp.run("ping", "10.0.0.1", "India", 1, post=Post(), resolve=resolver_ok)]
    assert [e["event"] for e in events] == ["error"] and events[0]["status"] == 422

    events = [e async for e in gp.run("ping", "1.1.1.1", "India", 1, post=Post(429, {}), resolve=resolver_ok)]
    assert events[0]["event"] == "error" and events[0]["code"] == "rate_limited"

    async def broken(*a, **k):
        raise FetchError("upstream returned HTTP 429")

    events = await collect(get=broken, sleep=FakeTime().sleep)
    assert [e["event"] for e in events] == ["created", "error"] and "credits" in events[1]["message"]


async def test_run_collect_summary():
    mum = probe_doc("Mumbai", result=PING_OK)
    t = FakeTime()
    res = await gp.run_collect("ping", "1.1.1.1", "India", 1, post=Post(), get=Poller([measurement("finished", mum)]),
                               resolve=resolver_ok, sleep=t.sleep, clock=t.clock)
    assert res["status"] == "finished" and res["probes"][0]["stats"]["avg"] == 11.9 and not res["timed_out"] and res["error"] is None
