# BookMyHost Dev Tools

Free, fast, single-purpose developer web tools built by the [BookMyHost](https://bookmyhost.com) engineering team (Blazing Bullet Pvt Ltd). Each tool has its own crawlable page with explainer copy, FAQ (JSON-LD `FAQPage` + `SoftwareApplication`), an embeddable link snippet, and a JSON API with OpenAPI docs.

| Tool | Page | API |
|---|---|---|
| DNS Propagation Checker (18 resolvers, India-labelled, authoritative compare) | `/tools/dns-propagation-checker` | `POST /tools/api/v1/dns/propagation` |
| IPv4 / IPv6 Subnet Calculator (client-side, split, supernet) | `/tools/subnet-calculator` | `POST /tools/api/v1/subnet/{calc,split,summarise}` |
| TTFB & SSL Checker (DNS/TCP/TLS/TTFB waterfall, cert inspection) | `/tools/ttfb-ssl-checker` | `POST /tools/api/v1/http/check` |
| Looking Glass (ping, traceroute, BGP; from Noida AS152523) | `/tools/looking-glass` | `POST /tools/api/v1/lg/{run,bgp}` |
| WHOIS / RDAP lookup (domains + IPs) | `/tools/whois-lookup` | `POST /tools/api/v1/whois/lookup` |
| Reverse DNS (PTR) + FCrDNS check | `/tools/reverse-dns-lookup` | `POST /tools/api/v1/rdns/lookup` |
| Open Port Checker (visitor's own IP only) | `/tools/port-checker` | `POST /tools/api/v1/ports/check`, `GET /tools/api/v1/ports/myip` |

Also: `/tools/` index, `/tools/sitemap.xml`, `/tools/healthz`, `/tools/api/v1/docs`, `/tools/api/v1/openapi.json`. Everything lives under `/tools/` (static files under `/tools/static/`), so the host site's own `/api/...` routes are never touched.

## Why

Developers link to tools they use. These are the checks we run most often ourselves when migrating customers to our Indian cloud servers, so we publish them as a public utility and a natural backlink magnet. No sign-up, no ads, no tracking.

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

## Network tools (looking glass, WHOIS/RDAP, rDNS, port checker): runbook

Added in 1.2.0. Same app, same container; nothing else to install on the host except one sysctl.

**Container packages:** `iputils-ping` and `traceroute` (added to the Dockerfile runtime stage; `libcap2-bin` is used only to strip the file capability from `ping`). No `mtr`. **NET_RAW is NOT required** and must not be added: the container stays non-root, `cap_drop: ALL`, `no-new-privileges`.

**Host prerequisite (one time, on the devtools host, which shares its network namespace with the container):** ping runs through unprivileged ICMP sockets, so the container user (gid 10001) must be inside the host sysctl range:

```bash
sysctl net.ipv4.ping_group_range                 # must cover 10001, e.g. "0 2147483647"
echo 'net.ipv4.ping_group_range = 0 2147483647' > /etc/sysctl.d/90-ping-group.conf && sysctl --system   # if not
```

traceroute uses its default UDP mode (kernel IP_RECVERR), no raw socket. If ping is not permitted the API still answers; `output` shows the ping error and `reachable` is false. Verify after deploy: `curl -s -X POST https://bookmyhost.com/tools/api/v1/lg/run -H 'Content-Type: application/json' -d '{"target":"1.1.1.1","tool":"ping"}'`.

**Security model.** Looking glass: fixed command set (`ping -c 4`, `traceroute -m 30`), argv lists via `create_subprocess_exec` (no shell), the target is a single validated public IP literal (hostnames are resolved first, every address must be public, the command gets the pinned IP), the whole command is killed after 12 s (ping) / 40 s (traceroute), output capped at 16 KiB. Refused: private, loopback, link-local, CGNAT, multicast, reserved, IPv4-mapped/NAT64/6to4 forms and `BMH_TOOLS_BLOCK_NETS` (our gateway, host and virtual router). Limits: 6 runs/min per IP (burst 3), one run per IP at a time, 3 concurrent runs globally (503 beyond), plus nginx zone `bmh_tools_net`. BGP data comes from RIPEstat (`stat.ripe.net`); our routers are never queried. WHOIS/RDAP: IANA bootstrap (cached 24 h), https only, re-validated redirects, registrant/admin/tech personal data never returned, classic port-43 WHOIS only for a TLD with no RDAP service. Port checker: the target is always the client IP from `X-Real-IP` (set by nginx from the Cloudflare-verified address); the request model has no target field and unknown fields, query parameters and other headers are ignored; non-public visitor addresses are refused; 3 s timeout, 8 checks/min per IP.

**Residual risk.** RDAP/RIPEstat requests resolve the upstream hostname twice (guard, then httpx); the upstream names come from IANA bootstrap data, responses are size-capped and never reflected unparsed. The port checker trusts nginx's `X-Real-IP`: keep the app bound to 127.0.0.1.

**Env vars (new):** `BMH_TOOLS_LG_RATE_PER_MIN` (6), `BMH_TOOLS_LG_BURST` (3), `BMH_TOOLS_MAX_LG` (3), `BMH_TOOLS_NET_RATE_PER_MIN` (20, WHOIS + rDNS), `BMH_TOOLS_PORT_RATE_PER_MIN` (8), `BMH_TOOLS_MAX_NET` (6), `BMH_TOOLS_RIPESTAT_URL`, `BMH_TOOLS_RDAP_BOOTSTRAP`, `BMH_TOOLS_RDAP_TIMEOUT`, `BMH_TOOLS_RIPESTAT_TIMEOUT`, `BMH_TOOLS_RDNS_GUIDE_PUBLISHED` (0; set to 1 only when `/blog/rdns-ptr-record-vps` is live, which switches on the guide link on the rDNS page and in the API).

**Deploy (from local main, never from GitHub):**

1. nginx: back up, then install `deploy/nginx/conf.d-bmh-tools-ratelimit.conf` and `snippets-bmh-tools.conf` (new zone `bmh_tools_net` and the two `location ^~ /tools/api/v1/{lg,ports}/` blocks), `nginx -t && systemctl reload nginx`.
2. Host sysctl as above.
3. `docker tag bmh-devtools:latest bmh-devtools:prev`, `git archive` the release into `/opt/bmh-devtools`, then `docker compose up -d --build` (the image build needs outbound apt; compose already uses `network: host`).
4. Smoke: `/tools/healthz`, the four pages, `sitemap.xml` (8 URLs), the ping call above, `/tools/api/v1/ports/myip`.

**Rollback:** `docker tag bmh-devtools:prev bmh-devtools:latest && docker compose up -d --no-build`, or `git archive` the previous release (335f3ee) into `/opt/bmh-devtools` and `docker compose up -d --build`. Restore the backed-up nginx files and reload. The sysctl is harmless and may stay. No data or schema is involved (all state is in memory).

## Toolbox shell, Turnstile and embeds
- **Shell**: every page renders `shell.html` (command bar, category tab rail, Beginner/Expert toggle, light/dark theme). Tool
  scripts are ES modules in `app/static/js/tools/<slug>.js` built on the results kit in `app/static/js/ui/` (verdict, cards,
  gauges, timeline, tree, tiles, waterfall, radar, address bar, glossary, streaming, share, Turnstile). Glossary text is
  `app/data/glossary.json`.
- **Turnstile** (heavy tools: `heavy: True` in `app/core/config.py`): set `TURNSTILE_SITEKEY`, `TURNSTILE_SECRET` and
  `TOOLS_PASS_SECRET` (all three, from the environment / compose `.env`; Cloudflare's published test keys work in dev).
  The page exchanges a Turnstile token at `POST /tools/api/v1/pass` for a 15 minute HMAC pass bound to the client /24 (/48 for
  IPv6) and the User-Agent, sent as `X-Tools-Pass`. Without a pass heavy endpoints answer `403 {"error":"pass_required"}`;
  if Cloudflare is unreachable `/pass` answers 503 so they fail closed. `TURNSTILE_BYPASS_IPS` (CIDRs) skips the check.
  With any of the three unset the check is a no-op and a warning is logged at startup.
- **Embeds**: `/tools/embed/<slug>?theme=light|dark|auto&accent=%23hex&q=&compact=1` is the only path that may be framed
  (`frame-ancestors *`, no `X-Frame-Options`); everything else stays `DENY`. `/tools/embed.js` resizes iframes marked
  `data-bmh-tool` from `{type:'bmh-tools:resize', height}` messages (origin checked). Embed API calls carry `X-Tools-Embed`
  and use their own 12/min bucket per IP + embedding host; embedding hostnames (no IPs) are logged once an hour.

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

curl -s -X POST https://bookmyhost.com/tools/api/v1/lg/run \
  -H 'Content-Type: application/json' -d '{"target":"1.1.1.1","tool":"traceroute"}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/lg/bgp \
  -H 'Content-Type: application/json' -d '{"target":"8.8.8.8"}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/whois/lookup \
  -H 'Content-Type: application/json' -d '{"query":"bookmyhost.com"}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/rdns/lookup \
  -H 'Content-Type: application/json' -d '{"ip":"8.8.8.8"}'

curl -s -X POST https://bookmyhost.com/tools/api/v1/ports/check \
  -H 'Content-Type: application/json' -d '{"port":443}'   # tests the caller's own IP only

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
