# BookMyHost Dev Tools

Free, fast, single-purpose developer web tools built by the [BookMyHost](https://bookmyhost.com) engineering team (Blazing Bullet Pvt Ltd). Each tool has its own crawlable page with explainer copy, FAQ (JSON-LD `FAQPage` + `SoftwareApplication`), an embeddable link snippet, and a JSON API with OpenAPI docs.

| Tool | Page | API |
|---|---|---|
| DNS Propagation Checker (18 resolvers, India-labelled, authoritative compare) | `/tools/dns-propagation-checker` | `POST /api/v1/dns/propagation` |
| IPv4 / IPv6 Subnet Calculator (client-side, split, supernet) | `/tools/subnet-calculator` | `POST /api/v1/subnet/{calc,split,summarise}` |
| TTFB & SSL Checker (DNS/TCP/TLS/TTFB waterfall, cert inspection) | `/tools/ttfb-ssl-checker` | `POST /api/v1/http/check` |

Also: `/tools/` index, `/tools/sitemap.xml`, `/robots.txt`, `/healthz`, `/api/v1/docs`.

## Why

Developers link to tools they use. These are the three checks we run most often ourselves when migrating customers to our Indian cloud servers, so we publish them as a public utility and a natural backlink magnet. No sign-up, no ads, no tracking.

## Stack

FastAPI (async) + Jinja2 server-rendered pages (SEO, work without JS for the copy) + vanilla JS + Tailwind CDN (no build step). `dnspython` async for resolver fan-out, raw `asyncio` sockets + `ssl` for true per-phase timing, `cryptography` for certificate parsing, `ipaddress` for subnets.

## Run locally

```bash
make venv          # python3 -m venv .venv && pip install -r requirements.txt
make run           # uvicorn on http://127.0.0.1:8765 (reload)
make test          # non-network tests
make test-network  # tests that hit example.com
```

Open http://127.0.0.1:8765/tools/ .

## Deploy

```bash
docker compose up -d --build        # listens on 127.0.0.1:8765, non-root, read-only FS
```

Then include `deploy/nginx-tools.conf` inside the `server {}` block of bookmyhost.com (adds `/tools/`, `/api/v1/`, `/healthz` proxies with `X-Forwarded-For`; add the `limit_req_zone` line to `http {}`). Make sure the site's `/robots.txt` lists `Sitemap: https://bookmyhost.com/tools/sitemap.xml` and does not disallow `/tools/`.

Environment variables: `BMH_TOOLS_BASE_URL` (default `https://bookmyhost.com`), `BMH_TOOLS_PREFIX` (`/tools`), `BMH_TOOLS_CORS` (comma list), `BMH_TOOLS_RATE_PER_MIN` (30), `BMH_TOOLS_DNS_TIMEOUT` (2.0 s), `BMH_TOOLS_HTTP_TIMEOUT` (10 s).

## API examples

```bash
curl -s -X POST https://bookmyhost.com/api/v1/dns/propagation \
  -H 'Content-Type: application/json' -d '{"name":"bookmyhost.com","type":"A"}'

curl -s -X POST https://bookmyhost.com/api/v1/subnet/calc \
  -H 'Content-Type: application/json' -d '{"cidr":"10.0.0.0/22"}'

curl -s -X POST https://bookmyhost.com/api/v1/subnet/split \
  -H 'Content-Type: application/json' -d '{"cidr":"10.0.0.0/22","new_prefix":24}'

curl -s -X POST https://bookmyhost.com/api/v1/subnet/summarise \
  -H 'Content-Type: application/json' -d '{"cidrs":["192.168.0.0/24","192.168.1.0/24"]}'

curl -s -X POST https://bookmyhost.com/api/v1/http/check \
  -H 'Content-Type: application/json' -d '{"url":"https://bookmyhost.com"}'
```

Responses are JSON; errors use `{"detail": "..."}` with 422 (validation), 400 (target unreachable), 429 (rate limit).

## Security / abuse controls

- Strict hostname validation (IDNA, label regex), URL scheme http/https only, ports 80/443/8080/8443 only.
- SSRF guard: private, loopback, link-local (incl. 169.254.169.254), CGNAT, multicast, reserved and IPv4-mapped addresses are refused, both for literal IPs and after DNS resolution, and on every redirect hop (max 5). PTR lookups accept public IPs only.
- Per-IP token bucket (30/min, first `X-Forwarded-For` hop), 2 s per-resolver DNS timeout, 10 s HTTP phase timeouts, 1 MiB response cap, no keep-alive.
- CORS allowlist for bookmyhost.com origins; `X-Robots-Tag: noindex` on `/api/*` only (tool pages are indexable).

## Licence

MIT. Copyright (c) 2026 Blazing Bullet Pvt Ltd.
