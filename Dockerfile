# ---- stage 1: build the minified Tailwind CSS with the official standalone CLI (no CDN at runtime) ----
FROM debian:bookworm-slim AS css
ARG TAILWIND_VERSION=v3.4.17
ARG TAILWIND_SHA256=7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl >/dev/null \
 && curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64" \
 && echo "${TAILWIND_SHA256}  /usr/local/bin/tailwindcss" | sha256sum -c - \
 && chmod +x /usr/local/bin/tailwindcss
WORKDIR /build
COPY tailwind.config.js ./
COPY assets ./assets
COPY app/templates ./app/templates
COPY app/static/js ./app/static/js
RUN tailwindcss -c tailwind.config.js -i assets/tools.css -o /build/tools.css --minify

# ---- stage 2: runtime ----
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY --from=css /build/tools.css ./app/static/css/tools.css

RUN useradd --system --uid 10001 --no-create-home tools && chown -R root:root /srv && chmod -R a+rX /srv
USER tools

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/tools/healthz', timeout=2).status==200 else 1)"
# One worker: the in-app token bucket and concurrency gates are per process (nginx limit_req is authoritative).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765", "--workers", "1", "--no-access-log", "--no-server-header", "--timeout-keep-alive", "5", "--limit-concurrency", "100"]
