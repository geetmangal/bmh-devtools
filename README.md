# BookMyHost Dev Tools

Free, fast, single-purpose developer web tools built by the [BookMyHost](https://bookmyhost.com) engineering team (Blazing Bullet Pvt Ltd). Each tool has its own crawlable page with explainer copy, FAQ (JSON-LD `FAQPage` + `SoftwareApplication`), an embeddable link snippet, and a JSON API with OpenAPI docs.

| Tool | Page | API |
|---|---|---|
| DNS Propagation Checker (18 resolvers, India-labelled, authoritative compare) | `/tools/dns-propagation-checker` | `POST /tools/api/v1/dns/propagation` |
| IPv4 / IPv6 Subnet Calculator (client-side, split, supernet) | `/tools/subnet-calculator` | `POST /tools/api/v1/subnet/{calc,split,summarise}` |
| TTFB & SSL Checker (DNS/TCP/TLS/TTFB waterfall, cert inspection) | `/tools/ttfb-ssl-checker` | `POST /tools/api/v1/http/check` |

Also: `/tools/` index, `/tools/sitemap.xml`, `/tools/healthz`, `/tools/api/v1/docs`, `/tools/api/v1/openapi.json`. Everything lives under `/tools/` (static files under `/tools/static/`), so the host site's own `/api/...` routes are never touched.

## Why

Developers link to tools they use. These are the three checks we run most often ourselves when migrating customers to our Indian cloud servers, so we publish them as a public utility and a natural backlink magnet. No sign-up, no ads, no tracking.

## Stack

FastAPI (async) + Jinja2 server-rendered pages (SEO, work without JS for the copy) + vanilla JS + self-hosted Tailwind (official standalone CLI v3.4.17, SHA-256 pinned; minified `app/static/css/tools.css` is built by `make css` locally and by the Dockerfile `css` stage, never loaded from a CDN). `dnspython` async for resolver fan-out, raw `asyncio` sockets + `ssl` for true per-phase timing, `cryptography` for certificate parsing, `ipaddress` for subnets.

## Run locally

```bash
make venv          # python3 -m venv .venv && pip install -r requirements.txt
make css           # download the pinned Tailwind CLI and build the minified CSS
make run           # uvicorn on http://127.0.0.1:8765 (reload)
make test          # non-network tests
make test-network  # tests that hit example.com
```

Open http://127.0.0.1:8765/tools/ .

## Deploy (production: bookmyhost.com/tools/)

Production runs on the panel VM 160.22.109.2 as docker container `bmh-devtools` (compose project in `/opt/bmh-devtools`):

```bash
docker compose up -d --build   # 127.0.0.1:8765 only, restart always, 256 MiB, read-only FS, non-root, cap_drop ALL, logs to journald
```

nginx (files in `deploy/nginx/`):

- `conf.d-bmh-tools-ratelimit.conf` -> `/etc/nginx/conf.d/bmh-tools-ratelimit.conf` (`limit_req_zone` API 30 r/min burst 10, pages 5 r/s).
- `snippets-bmh-tools.conf` + `snippets-bmh-tools-proxy.conf` -> `/etc/nginx/snippets/`, included in the Cloudflare-proxied 443 server block of `sites-available/bmh-wildcard` before `bmh-panel-locations.conf`. Client IP = `CF-Connecting-IP` via the vhost's `set_real_ip_from` Cloudflare ranges; nginx passes it as `X-Real-IP` (the app ignores `X-Forwarded-For`). Reseller hosts `*.bookmyhost.com` get 404 on `/tools/`.

The storefront `robots.txt` should list `Sitemap: https://bookmyhost.com/tools/sitemap.xml` and `Disallow: /tools/api/`.

Environment variables: `BMH_TOOLS_BASE_URL` (default `https://bookmyhost.com`), `BMH_TOOLS_PREFIX` (`/tools`), `BMH_TOOLS_CORS` (comma list), `BMH_TOOLS_RATE_PER_MIN` (30), `BMH_TOOLS_DNS_TIMEOUT` (2.0 s), `BMH_TOOLS_HTTP_TIMEOUT` (10 s), `BMH_TOOLS_MAX_DNS` (6) / `BMH_TOOLS_MAX_HTTP` (4) concurrent checks, `BMH_TOOLS_QUEUE_WAIT` (5 s, then 503), `BMH_TOOLS_BLOCK_NETS` (extra SSRF block list; default the host network's gateway 160.22.109.1, host 160.22.109.2 and CloudStack virtual router 160.22.109.9).

## API examples

```bash
curl -s -X POST https://bookmyhost.com/tools/api/v1/dns/propagation \
  -H 'Content-Type: application/json' -d '{"name":"bookmyhost.com","type":"A"}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/subnet/calc \
  -H 'Content-Type: application/json' -d '{"cidr":"10.0.0.0/22"}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/subnet/split \
  -H 'Content-Type: application/json' -d '{"cidr":"10.0.0.0/22","new_prefix":24}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/subnet/summarise \
  -H 'Content-Type: application/json' -d '{"cidrs":["192.168.0.0/24","192.168.1.0/24"]}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/http/check \
  -H 'Content-Type: application/json' -d '{"url":"https://bookmyhost.com"}'
```

Responses are JSON; errors use `{"detail": "..."}` with 422 (validation or internal target), 400 (target unreachable or resolves/redirects to an internal address), 429 (rate limit), 503 (checker busy).

## Security / abuse controls

- Strict hostname validation (IDNA, label regex), URL scheme http/https only, ports 80/443/8080/8443 only, no single-label or numeric/hex host forms.
- SSRF guard: loopback, 10/8, 172.16/12, 192.168/16, 100.64/10, link-local (incl. 169.254.169.254), multicast, reserved, ULA, NAT64/6to4/Teredo and IPv4-mapped forms, plus `BMH_TOOLS_BLOCK_NETS` (gateway, host, virtual router) are refused for literal IPs, for names where ANY resolved address is internal, and on every redirect hop (max 5). The validated IP is pinned: sockets connect to that literal, so DNS rebinding cannot switch the target. The DNS checker skips authoritative servers with internal addresses. PTR lookups accept public IPs only.
- Rate limits: nginx `limit_req` (authoritative) plus a per-IP token bucket in the app (30/min, keyed on `X-Real-IP`). Concurrency caps per check type (503 when saturated), 2 s per-resolver DNS timeout, 10 s HTTP phase timeouts, 1 MiB response cap, no keep-alive.
- Strict CSP: `script-src 'self' 'nonce-...'` (per response), no inline handlers, `default-src 'none'`, `frame-ancestors 'none'`; API responses `Cache-Control: no-store` + `X-Robots-Tag: noindex`; static files `public, max-age=2592000, immutable` behind `?v=<hash>` URLs.
- Logs (stdout -> journald) carry method, path without query string, status and duration only.
- CORS allowlist for bookmyhost.com origins; tool pages are indexable with canonical `https://bookmyhost.com/tools/...` URLs.

## Licence

MIT. Copyright (c) 2026 Blazing Bullet Pvt Ltd.
