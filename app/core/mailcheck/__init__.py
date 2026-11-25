"""Pure-Python email / DNS check engine (MX, SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, DNS records,
DNSBL, SMTP probe, domain health). No web framework code here: the API layer calls these modules.

Every check returns a ``models.CheckResult`` (``.to_dict()`` is JSON-serialisable). All DNS goes through
the injectable resolver in ``resolver.py``; tests use ``FakeResolver``."""
