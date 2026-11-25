"""ip:port nameserver parsing for the unbound sidecar."""
import dns.nameserver
import pytest

from app.core.mailcheck.resolver import DnsResolver, parse_nameserver


def test_plain_ip_stays_string():
    assert parse_nameserver("9.9.9.9") == "9.9.9.9"
    assert parse_nameserver("2001:db8::1") == "2001:db8::1"


def test_ipv4_with_port():
    ns = parse_nameserver("127.0.0.1:5335")
    assert isinstance(ns, dns.nameserver.Do53Nameserver)
    assert ns.address == "127.0.0.1" and ns.port == 5335


def test_ipv6_bracket_with_port():
    ns = parse_nameserver("[::1]:5335")
    assert ns.address == "::1" and ns.port == 5335


@pytest.mark.parametrize("bad", ["nope", "1.2.3.4:0", "1.2.3.4:70000", "[::1]:x"])
def test_garbage_rejected(bad):
    with pytest.raises(ValueError):
        parse_nameserver(bad)


def test_resolver_builds_with_port():
    r = DnsResolver(nameservers=["127.0.0.1:5335"])._make()
    assert r.nameservers[0].port == 5335
