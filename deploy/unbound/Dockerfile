# Local recursive resolver for the toolbox. Many DNSBLs (Spamhaus, Barracuda, ...) refuse queries that
# arrive via big public resolvers (8.8.8.8 / 1.1.1.1), so DNSBL and mail checks resolve through this.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends unbound dns-root-data ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/unbound && chown unbound:unbound /var/lib/unbound
COPY unbound.conf /etc/unbound/unbound.conf
RUN unbound-checkconf /etc/unbound/unbound.conf
USER unbound
CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
