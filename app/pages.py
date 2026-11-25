"""Form labels, intro and about text for the email, DNS and BGP tools.

One generic template (templates/tool_generic.html) renders all of these; each tool has its own JS module
(static/js/tools/<slug>.js). Titles, meta descriptions, guides, FAQs and related links live in app/data/content/<slug>.json.
"""
from app.core.config import API_PREFIX as API

FORM_DOMAIN = {"input": "domain", "label": "Domain name", "placeholder": "example.com", "button": "Check"}

PAGES: dict[str, dict] = {
    "domain-health": {
        **FORM_DOMAIN, "button": "Run health check", "mono_extra": "dkim_selector",
        "h1": "Domain Health Report",
        "intro": "Enter a domain to run all the email and DNS checks at once: mail servers (MX), SPF, DKIM, DMARC, BIMI, MTA-STS, TLS reporting, nameservers, DNSSEC and blocklists. You get an A to F grade, a six-axis chart and a fix list ordered by importance.",
        "about": ["A domain that cannot send or receive mail reliably usually has one of a handful of problems: a missing or broken SPF record, no DMARC policy, mail servers without reverse DNS, a single nameserver, or an address listed on a blocklist. This report checks them together so you can see which one matters most.",
                  f"The same data is available from the JSON API: POST {API}/health/domain with {{\"domain\": \"example.com\"}} streams one line per check and a final graded summary."],
    },
    "mx-lookup": {
        **FORM_DOMAIN, "button": "Look up MX",
        "h1": "MX Lookup",
        "intro": "Find the mail servers that receive email for a domain, in the order senders try them. For each server you see its IP addresses and whether the reverse DNS matches (FCrDNS), plus the mail provider we recognise from the host name.",
        "about": [f"This tool queries public DNS only. API: POST {API}/mail/mx with {{\"domain\": \"example.com\"}}."],
    },
    "spf-checker": {
        **FORM_DOMAIN, "button": "Check SPF",
        "h1": "SPF Record Checker",
        "intro": "SPF is a DNS record that lists the servers allowed to send email for your domain. This checker reads it, follows every include, counts the DNS lookups against the limit of 10 and shows exactly where the record is too permissive or broken.",
        "about": [f"This tool queries public DNS only. API: POST {API}/mail/spf with {{\"domain\": \"example.com\"}}."],
    },
    "dmarc-checker": {
        **FORM_DOMAIN, "button": "Check DMARC",
        "h1": "DMARC Record Checker",
        "intro": "DMARC tells receivers what to do with mail that claims to be from your domain but fails SPF and DKIM alignment, and where to send reports. This checker explains your current policy, how alignment works and what to change next.",
        "about": [f"This tool queries public DNS only. API: POST {API}/mail/dmarc with {{\"domain\": \"example.com\"}}."],
    },
    "dkim-checker": {
        **FORM_DOMAIN, "button": "Check DKIM", "selector": True,
        "h1": "DKIM Record Checker",
        "intro": "DKIM adds a signature to outgoing email that receivers verify with a public key published in DNS under a selector name. Enter your domain and, if you know it, the selector; without one we try the most common selector names.",
        "about": [f"This tool queries public DNS only. API: POST {API}/mail/dkim with {{\"domain\": \"example.com\", \"selector\": \"google\"}}; leave the selector out to probe common names."],
    },
    "blacklist-check": {
        "input": "target", "label": "IP address or domain", "placeholder": "8.8.8.8 or example.com", "button": "Check blocklists",
        "h1": "Email Blacklist Check",
        "intro": "Mail servers use public DNS blocklists to decide whether to accept mail from an IP address or a domain. Enter either one to see, live, which lists know it, what they say and where to ask for removal.",
        "about": [f"Only public IP addresses and plain domain names can be checked. API: POST {API}/dnsbl/check with {{\"target\": \"8.8.8.8\"}}; the answer streams as one JSON line per list."],
    },
    "smtp-test": {
        "input": "host", "label": "Mail server host name", "placeholder": "mail.example.com", "button": "Test SMTP", "port": True,
        "h1": "SMTP Server Test",
        "intro": "Connects to a public mail server the way another mail server would: reads the greeting, says EHLO, tries STARTTLS and reports the TLS version, cipher and certificate. It never sends a message.",
        "about": [f"Only public mail servers can be tested. API: POST {API}/smtp/check with {{\"host\": \"mail.example.com\", \"port\": 25}}."],
    },
    "email-header-analyzer": {
        "input": "headers", "textarea": True, "label": "Paste the full email headers", "placeholder": "Received: from mail.example.com ...\nAuthentication-Results: ...\nFrom: ...", "button": "Analyze headers",
        "h1": "Email Header Analyzer",
        "intro": "Paste the raw headers of a message to see the servers it passed through and how long each hop took, whether SPF, DKIM and DMARC passed, and what the spam filters said. The analysis runs in your browser: your headers are never sent to our server.",
        "about": ["Header analysis is only a guide: any server can add false Received lines below the one added by your own mail server, so trust the topmost hops that belong to servers you know."],
    },
    "dns-lookup": {
        **FORM_DOMAIN, "button": "Look up DNS",
        "h1": "DNS Lookup",
        "intro": "See every common DNS record of a domain with its TTL, check that each nameserver answers and sits on a separate network, review the SOA timers and CAA policy, and see whether DNSSEC is signed and validating.",
        "about": [f"This tool queries public DNS only. API: POST {API}/mail/dns with {{\"domain\": \"example.com\"}}."],
    },
    "asn-lookup": {
        "input": "asn", "label": "AS number", "placeholder": "AS13335 or 13335", "button": "Look up AS",
        "h1": "ASN Lookup",
        "intro": "Look up any autonomous system number to see who runs it, which prefixes it announces, how many are protected by RPKI, which networks sit upstream and downstream of it on a graph, and where it connects (internet exchanges and facilities from PeeringDB).",
        "about": [f"API: GET {API}/asn/13335."],
    },
    "bgp-prefix-lookup": {
        "input": "prefix", "label": "IP prefix or address", "placeholder": "1.1.1.0/24 or 1.1.1.1", "button": "Look up prefix",
        "h1": "BGP Prefix Lookup",
        "intro": "Enter an IP prefix or a single address to see which AS originates it, whether RPKI validates the announcement, how widely it is visible around the world, how the origin changed over the last 30 days and the AS paths collectors use to reach it.",
        "about": [f"API: GET {API}/prefix/1.1.1.0/24."],
    },
}
