"""SPF check (RFC 7208): fetch, parse, expand include/redirect recursively, count DNS lookups.

Counting rules implemented (RFC 7208 4.6.4):
  * Terms that cause DNS queries: include, a, mx, ptr, exists, and the redirect modifier. Max 10 in total
    for the whole evaluation (nested includes count). The first TXT lookup of the domain itself is free.
  * "Void" lookups (query answered NXDOMAIN or empty): max 2.
  * One mx mechanism may name at most 10 MX hosts.
  * `redirect=` is ignored by receivers when the record also has an `all` mechanism, so we neither count nor
    follow it in that case (and warn).
Macros (%{...}) cannot be evaluated without a real message, so such terms are counted but not followed."""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass

from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.mx import detect_provider, parse_mx
from app.core.mailcheck.resolver import Resolver, get_default_resolver

LOOKUP_LIMIT = 10
VOID_LIMIT = 2
MX_HOST_LIMIT = 10
MAX_DEPTH = 10
MAX_QUERIES = 80  # hard bound on DNS queries per check
MECHS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
DNS_MECHS = {"include", "a", "mx", "ptr", "exists"}

PROVIDER_INCLUDES = {
    "Google Workspace": "include:_spf.google.com",
    "Microsoft 365": "include:spf.protection.outlook.com",
    "Proton Mail": "include:_spf.protonmail.ch",
    "Fastmail": "include:spf.messagingengine.com",
    "Amazon SES (inbound)": "include:amazonses.com",
    "Zoho Mail": "include:zohomail.com",  # Zoho's SPF guide: one include for every data centre (checked 2026-11-25)
}


@dataclass
class Term:
    raw: str
    kind: str            # mech | mod
    name: str            # lower-case mechanism / modifier name
    qual: str = "+"
    arg: str | None = None   # mechanism: text after the name (":x", "/24", ":x/24"); modifier: the value


_MOD = re.compile(r"^([A-Za-z][A-Za-z0-9._-]*)=(.*)$")


def parse_term(tok: str) -> Term:
    m = _MOD.match(tok)
    if m:
        return Term(tok, "mod", m.group(1).lower(), arg=m.group(2))
    qual = "+"
    rest = tok
    if rest and rest[0] in "+-~?":
        qual, rest = rest[0], rest[1:]
    name = re.split(r"[:/]", rest, maxsplit=1)[0].lower()
    arg = rest[len(name):] or None
    return Term(tok, "mech", name, qual, arg)


def is_spf(text: str) -> bool:
    t = text.strip().lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def _domain_arg(term: Term, default: str) -> tuple[str, bool]:
    """(domain, has_macro) for a/mx/include/exists style args: ':domain[/cidr]' or '/cidr'."""
    if not term.arg or term.arg.startswith("/"):
        return default, False
    d = term.arg[1:].split("/", 1)[0]
    return d.rstrip(".").lower(), "%" in d


class _Ctx:
    def __init__(self, resolver: Resolver) -> None:
        self.r = resolver
        self.lookups = 0
        self.void = 0
        self.queries = 0
        self.max_depth = 0
        self.memo: dict[str, tuple[str, list[str]]] = {}
        self.truncated = False
        self.issues: list[dict] = []   # {"id","status","title","meaning","fix","details"}

    def issue(self, id: str, status: str, title: str, meaning: str, fix: list[str] | None = None,
              fix_record: str | None = None, **details) -> None:
        self.issues.append({"id": id, "status": status, "title": title, "meaning": meaning,
                            "fix": fix or [], "fix_record": fix_record, "details": details})

    async def q(self, name: str, rtype: str):
        self.queries += 1
        return await self.r.query(name, rtype)

    async def spf_txt(self, domain: str) -> tuple[str, list[str]]:
        """('ok'|'nxdomain'|'none'|'multiple'|'error', [spf records])."""
        if domain in self.memo:
            return self.memo[domain]
        ans = await self.q(domain, "TXT")
        if ans.status == "nxdomain":
            out = ("nxdomain", [])
        elif ans.failed:
            out = ("error", [])
        else:
            recs = [t for t in ans.records if is_spf(t)]
            out = ("ok", recs) if len(recs) == 1 else ("multiple" if recs else "none", recs)
        self.memo[domain] = out
        return out

    def add_void(self, what: str) -> None:
        self.void += 1


async def _expand(ctx: _Ctx, domain: str, record: str, depth: int, path: tuple[str, ...], kind: str, via: str = "") -> dict:
    ctx.max_depth = max(ctx.max_depth, depth)
    node: dict = {"domain": domain, "kind": kind, "via": via, "record": record, "own": 0, "lookups": 0,
                  "all": None, "children": [], "terms": [], "error": None}
    tokens = record.split()[1:]
    seen_all = False
    redirect: Term | None = None
    for tok in tokens:
        t = parse_term(tok)
        if t.kind == "mod":
            if t.name == "redirect":
                if redirect is None:
                    redirect = t
                else:
                    ctx.issue("spf_duplicate_redirect", "fail", "More than one redirect= in a record",
                              "A record may have only one redirect= modifier; receivers treat two as an error.",
                              ["Remove the extra redirect= term."], record=domain)
            elif t.name != "exp":
                ctx.issue("spf_unknown_modifier", "info", f"Unknown modifier {t.name}=",
                          "Receivers ignore modifiers they do not know, so this term does nothing.",
                          ["Remove it if it is not needed."], term=tok, record=domain)
            continue
        if t.name not in MECHS:
            ctx.issue("spf_unknown_mechanism", "fail", f"Unknown SPF term \"{tok}\"",
                      "This word is not part of SPF (allowed: all, include, a, mx, ip4, ip6, exists, ptr). Receivers treat the whole "
                      "record as broken (PermError), so SPF fails for all your mail. Typos like \"includes:\" or \"ip:\" are common.",
                      [f"Fix or delete \"{tok}\" in the record for {domain}."], term=tok, record=domain)
            continue
        if seen_all:
            ctx.issue("spf_after_all", "warn", f"\"{tok}\" comes after \"all\"",
                      "Everything after the \"all\" term is ignored by receivers, so this has no effect.",
                      ["Move it before the \"all\" term, or delete it."], term=tok, record=domain)
            continue
        node["terms"].append({"term": tok, "type": t.name, "qualifier": t.qual})
        if t.name == "all":
            seen_all = True
            node["all"] = t.qual
            if t.arg:
                ctx.issue("spf_unknown_mechanism", "fail", f"Unknown SPF term \"{tok}\"",
                          "\"all\" takes no value.", [f"Change it to a plain -all or ~all."], term=tok, record=domain)
        elif t.name in ("ip4", "ip6"):
            _check_ip(ctx, t, domain)
        elif t.name == "include":
            ctx.lookups += 1
            node["own"] += 1
            target, macro = _domain_arg(t, "")
            if not target:
                ctx.issue("spf_bad_term", "fail", "include: without a domain",
                          "An include must name the domain to include, like include:_spf.google.com.",
                          ["Add the domain after include: or remove the term."], term=tok, record=domain)
                continue
            if macro:
                ctx.issue("spf_macro", "info", "A term uses SPF macros",
                          "Macros such as %{i} are expanded per message, so we cannot follow this term. It is still counted as a lookup.",
                          term=tok, record=domain)
                continue
            child = await _follow(ctx, target, depth, path, "include", f"{t.qual}{t.name}:{target}", domain)
            node["children"].append(child)
        elif t.name in ("a", "mx"):
            ctx.lookups += 1
            node["own"] += 1
            target, macro = _domain_arg(t, domain)
            if macro:
                ctx.issue("spf_macro", "info", "A term uses SPF macros",
                          "Macros cannot be expanded here, so this term is counted but not followed.", term=tok, record=domain)
            elif ctx.queries < MAX_QUERIES:
                await _dns_term(ctx, t.name, target, node, tok)
        elif t.name == "exists":
            ctx.lookups += 1
            node["own"] += 1
            target, macro = _domain_arg(t, "")
            if target and not macro and ctx.queries < MAX_QUERIES:
                ans = await ctx.q(target, "A")
                if not ans.ok:
                    ctx.add_void(tok)
                    node["terms"][-1]["void"] = True
        elif t.name == "ptr":
            ctx.lookups += 1
            node["own"] += 1
            ctx.issue("spf_ptr", "warn", "The ptr mechanism is used",
                      "ptr is officially deprecated (RFC 7208): it is slow, puts load on DNS and many receivers ignore it. "
                      "It also uses up one of your 10 lookups.",
                      ["Delete ptr and list the real sending servers with ip4:, ip6: or include: instead."], term=tok, record=domain)
    if redirect is not None:
        if seen_all:
            ctx.issue("spf_redirect_ignored", "warn", "redirect= is ignored because the record also has \"all\"",
                      "When a record contains an \"all\" term, receivers skip the redirect= modifier. The redirect does nothing.",
                      ["Remove redirect= (if you want the other domain's rules), or remove the \"all\" term (to follow the redirect)."],
                      record=domain)
        else:
            ctx.lookups += 1
            node["own"] += 1
            target = (redirect.arg or "").rstrip(".").lower()
            if not target or "%" in target:
                if target:
                    ctx.issue("spf_macro", "info", "A term uses SPF macros", "redirect target contains macros; not followed.",
                              term=redirect.raw, record=domain)
            else:
                child = await _follow(ctx, target, depth, path, "redirect", f"redirect={target}", domain)
                node["children"].append(child)
                node["all"] = child.get("all")
                node["terms"].append({"term": redirect.raw, "type": "redirect", "qualifier": ""})
    node["lookups"] = node["own"] + sum(c["lookups"] for c in node["children"])
    return node


def _check_ip(ctx: _Ctx, t: Term, domain: str) -> None:
    val = (t.arg or "")[1:] if (t.arg or "").startswith(":") else ""
    try:
        net = ipaddress.ip_network(val, strict=False)
        if (t.name == "ip4") != (net.version == 4):
            raise ValueError("family")
    except ValueError:
        ctx.issue("spf_bad_ip", "fail", f"Invalid address in \"{t.raw}\"",
                  "ip4: needs an IPv4 address or range (like ip4:203.0.113.0/24) and ip6: an IPv6 one. A bad value makes the whole record "
                  "invalid (PermError).", [f"Correct or remove \"{t.raw}\"."], term=t.raw, record=domain)
        return
    if net.prefixlen == 0 and t.qual == "+":
        ctx.issue("spf_open_ip", "fail", "An ip range allows the entire internet",
                  f"\"{t.raw}\" authorises every address on the internet to send as your domain, which defeats SPF.",
                  ["Replace it with the real server addresses."], term=t.raw, record=domain)


async def _dns_term(ctx: _Ctx, kind: str, target: str, node: dict, tok: str) -> None:
    if kind == "a":
        a = await ctx.q(target, "A")
        aaaa = await ctx.q(target, "AAAA")
        if not (a.ok or aaaa.ok):
            ctx.add_void(tok)
            node["terms"][-1]["void"] = True
        return
    mx = await ctx.q(target, "MX")
    hosts = [p[1] for p in (parse_mx(x) for x in mx.records) if p and p[1] != "."]
    if not hosts:
        ctx.add_void(tok)
        node["terms"][-1]["void"] = True
        return
    node["terms"][-1]["mx_hosts"] = len(hosts)
    if len(hosts) > MX_HOST_LIMIT:
        ctx.issue("spf_mx_too_many_hosts", "fail", f"\"{tok}\" expands to {len(hosts)} mail servers",
                  f"A single mx term may expand to at most {MX_HOST_LIMIT} servers. {target} has {len(hosts)}, so receivers "
                  "give a PermError and SPF fails.",
                  [f"Replace \"{tok}\" with the actual IP addresses (ip4:/ip6:) of the servers that send your mail."],
                  term=tok, hosts=len(hosts))
    for h in hosts[:MX_HOST_LIMIT]:
        if ctx.queries >= MAX_QUERIES:
            ctx.truncated = True
            break
        a = await ctx.q(h, "A")
        aaaa = await ctx.q(h, "AAAA")
        if not (a.ok or aaaa.ok):
            ctx.add_void(f"{tok} -> {h}")


async def _follow(ctx: _Ctx, target: str, depth: int, path: tuple[str, ...], kind: str, via: str, parent: str) -> dict:
    stub = {"domain": target, "kind": kind, "via": via, "record": None, "own": 0, "lookups": 0, "all": None,
            "children": [], "terms": [], "error": None}
    if target in path or target == parent:
        stub["error"] = "loop"
        ctx.issue("spf_loop", "fail", f"SPF loop: {parent} includes {target}, which leads back to itself",
                  "The records point at each other in a circle. Receivers detect this and give up with an error, so SPF fails for your mail.",
                  [f"Remove the include/redirect to {target} from the record of {parent} (or whichever record closes the circle)."],
                  chain=list(path) + [target])
        return stub
    if depth + 1 > MAX_DEPTH:
        stub["error"] = "too_deep"
        ctx.issue("spf_too_deep", "fail", "SPF includes are nested too deeply",
                  f"More than {MAX_DEPTH} levels of include/redirect. Receivers stop at 10 lookups anyway, so this record cannot work.",
                  ["Flatten the chain: list the final IP ranges or fewer includes directly in your record."], depth=depth + 1)
        return stub
    if ctx.queries >= MAX_QUERIES:
        ctx.truncated = True
        stub["error"] = "truncated"
        return stub
    status, recs = await ctx.spf_txt(target)
    if status == "ok":
        child = await _expand(ctx, target, recs[0], depth + 1, path + (target,), kind, via)
        return child
    word = "include" if kind == "include" else "redirect"
    if status == "nxdomain":
        ctx.add_void(via)
        stub["error"] = "nxdomain"
        ctx.issue("spf_include_missing", "fail", f"{word} target {target} does not exist",
                  f"The record says to look at {target}, but that domain does not exist. Receivers return a PermError, "
                  "so SPF fails for all mail from your domain.",
                  [f"Fix the spelling of {target} (check your provider's current instructions), or remove the {word}."],
                  target=target, via=parent)
    elif status == "none":
        stub["error"] = "no_spf"
        ctx.issue("spf_include_no_record", "fail", f"{target} has no SPF record",
                  f"Your record includes {target}, but {target} does not publish an SPF record. A {word} to a domain without SPF "
                  "is a PermError, so SPF fails for all mail from your domain.",
                  [f"Remove the {word}:{target} term, or ask that service for the correct include value."], target=target, via=parent)
    elif status == "multiple":
        stub["error"] = "multiple"
        ctx.issue("spf_include_multiple", "fail", f"{target} publishes more than one SPF record",
                  f"{target} has two SPF records, which is an error (PermError) and breaks your own record too.",
                  [f"Ask the owner of {target} to merge their SPF records, or stop including it."], target=target)
    else:
        stub["error"] = "dns_error"
        ctx.issue("spf_include_dns_error", "warn", f"Could not look up {target}",
                  "The DNS lookup timed out or failed, so this part of the record could not be checked.",
                  ["Run the check again."], target=target)
    return stub


def build_clean_record(records: list[str]) -> str:
    """Merge/dedupe one or more SPF records into one valid record (used for fix_record)."""
    seen: list[str] = []
    seen_lower: set[str] = set()
    redirect: str | None = None
    all_quals: list[str] = []
    for rec in records:
        had_all = False
        for tok in rec.split()[1:]:
            t = parse_term(tok)
            if t.kind == "mod":
                if t.name == "redirect" and redirect is None:
                    redirect = tok
                elif t.name == "exp" and tok.lower() not in seen_lower:
                    pass
                continue
            if had_all or t.name not in MECHS or t.name == "ptr":
                continue
            if t.name == "all":
                had_all = True
                all_quals.append(t.qual)
                continue
            if tok.lower().lstrip("+") not in seen_lower:
                seen_lower.add(tok.lower().lstrip("+"))
                seen.append(tok if tok[0] in "+-~?" else tok)
        if not had_all:
            all_quals.append("")
    body = " ".join(seen)
    if redirect and not any(q for q in all_quals):
        tail = redirect
    else:
        strict = bool(all_quals) and all(q == "-" for q in all_quals)
        tail = "-all" if strict else "~all"
    return " ".join(x for x in ["v=spf1", body, tail] if x)


def _provider_suggestion(mx_records: list[str], domain: str) -> str:
    for rec in mx_records:
        p = parse_mx(rec)
        if not p:
            continue
        prov = detect_provider(p[1], domain)
        if prov in PROVIDER_INCLUDES:
            return f"v=spf1 {PROVIDER_INCLUDES[prov]} ~all"
    return "v=spf1 mx ~all"


async def check(domain: str, resolver: Resolver | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    res = CheckResult("spf", domain)
    ctx = _Ctx(r)
    t0 = time.perf_counter()
    ans = await r.query(domain, "TXT")
    res.timings_ms["txt"] = round((time.perf_counter() - t0) * 1000, 1)
    if ans.status == "nxdomain":
        res.add("spf_domain_missing", "fail", "This domain does not exist", f"{domain} has no DNS records.",
                ["Check the spelling of the domain."])
        res.data = {"record": None, "records_found": 0}
        return res.finalize("Domain does not exist.")
    if ans.failed:
        return error_result("spf", domain, f"DNS lookup for TXT records failed ({ans.status}).")
    pairs = [(t, ans.txt_strings[i] if i < len(ans.txt_strings) else [t]) for i, t in enumerate(ans.records) if is_spf(t)]
    data: dict = {"record": None, "records_found": len(pairs), "lookups": 0, "limit": LOOKUP_LIMIT, "void_lookups": 0,
                  "void_limit": VOID_LIMIT, "all": None, "tree": None, "terms": []}

    if not pairs:
        mx = await r.query(domain, "MX")
        suggestion = _provider_suggestion(mx.records, domain)
        res.add("spf_missing", "fail", "No SPF record found",
                "SPF is a list of the servers allowed to send email for your domain. Without it, Gmail, Yahoo and Microsoft are "
                "more likely to treat your mail as spam (and since 2024 Gmail/Yahoo require it from bulk senders).",
                [f"Add a TXT record at the root of {domain} (host \"@\") with the value below.",
                 "Add an include: for every other service that sends mail as you (newsletter tool, CRM, website forms). "
                 "Your provider shows the exact include text.",
                 "Keep exactly one SPF record per domain."],
                fix_record=suggestion)
        res.data = data
        return res.finalize("No SPF record published.")

    records = [p[0] for p in pairs]
    if len(pairs) > 1:
        merged = build_clean_record(records)
        res.add("spf_multiple", "fail", f"{len(pairs)} SPF records found (only one is allowed)",
                "A domain must publish exactly one SPF record. With two or more, receivers return a PermError and ignore SPF "
                "entirely, so your mail can fail authentication even though each record alone looks fine.",
                ["Delete all SPF TXT records except one.", "Copy the servers from the removed records into the one you keep.",
                 "The merged record below combines them (check that every sender is still listed; lookups are limited to 10)."],
                fix_record=merged, records=records)
    record, strings = pairs[0]
    data["record"] = record
    data["strings"] = len(strings)

    # ---- record length ----
    if any(len(s) > 255 for s in strings):
        res.add("spf_string_too_long", "fail", "A single text string in the record is longer than 255 characters",
                "DNS limits each quoted string inside a TXT record to 255 characters. Longer values are rejected or cut, which breaks "
                "the record.",
                ["Split the value into several quoted strings of up to 255 characters; most DNS panels do this automatically."])
    if len(record) > 450:
        res.add("spf_record_long", "warn", f"The record is long ({len(record)} characters)",
                "Records over about 450 characters may not fit into a standard 512-byte DNS answer, so some receivers fail to read them. "
                "They also usually mean too many includes.",
                ["Remove services you no longer use.", "Replace includes of big providers with only the ranges you need."])
    elif len(strings) > 1:
        res.add("spf_multi_string", "info", "The record is stored as several text strings",
                "That is allowed: receivers join the strings without adding spaces. Make sure each break is not in the middle of a word.")

    # ---- expand ----
    t0 = time.perf_counter()
    root = await _expand(ctx, domain, record, 0, (domain,), "root")
    res.timings_ms["expand"] = round((time.perf_counter() - t0) * 1000, 1)
    total = root["lookups"]
    data.update({"lookups": total, "void_lookups": ctx.void, "tree": root, "all": root["all"], "terms": root["terms"],
                 "max_depth": ctx.max_depth, "truncated": ctx.truncated})
    seen_ids: set[tuple] = set()
    for i in ctx.issues:
        key = (i["id"], i["details"].get("term"), i["details"].get("target"), i["details"].get("record"))
        if key in seen_ids:
            continue
        seen_ids.add(key)
        res.add(i["id"], i["status"], i["title"], i["meaning"], i["fix"], i["fix_record"], **i["details"])

    # ---- limits ----
    if total > LOOKUP_LIMIT:
        res.add("spf_too_many_lookups", "fail", f"Too many DNS lookups ({total} of {LOOKUP_LIMIT} allowed)",
                f"SPF allows at most {LOOKUP_LIMIT} lookups (include, a, mx, ptr, exists, redirect), counting those inside the "
                "included records. Over the limit, receivers return a PermError and SPF fails for ALL your mail, even from correct servers.",
                ["Open the lookup tree and remove includes for services you no longer use.",
                 "Replace a/mx terms with the servers' ip4:/ip6: addresses.",
                 "Use a sub-domain for each bulk sender (for example news.example.com) so each gets its own 10 lookups.",
                 "As a last resort use SPF flattening, but remember flattened IPs go stale when the provider changes them."],
                lookups=total, limit=LOOKUP_LIMIT)
    elif total >= LOOKUP_LIMIT - 1:
        res.add("spf_lookups_near_limit", "info", f"{total} of {LOOKUP_LIMIT} lookups used",
                "You are right at the limit. Adding one more service will break SPF.", ["Plan to trim unused includes before adding new ones."],
                lookups=total)
    if ctx.void > VOID_LIMIT:
        res.add("spf_void_lookups", "fail", f"Too many empty lookups ({ctx.void}, maximum {VOID_LIMIT})",
                "Terms that point at names with no records count as void lookups. More than 2 gives a PermError at strict receivers.",
                ["Remove the a:/mx:/include: terms whose domain no longer has records (they are marked in the tree)."], void=ctx.void)
    elif ctx.void == VOID_LIMIT:
        res.add("spf_void_at_limit", "warn", f"{ctx.void} empty lookups (the limit is {VOID_LIMIT})",
                "Terms pointing at names without records are at the limit. One more breaks SPF at strict receivers.",
                ["Remove terms whose domain has no records."], void=ctx.void)
    if ctx.truncated:
        res.add("spf_truncated", "info", "Analysis stopped early", "The record chain is so large we stopped following it.")

    # ---- included records that allow everyone ----
    def walk(n: dict, top: bool = True) -> None:
        for c in n["children"]:
            if c["kind"] == "include" and c["all"] == "+" :
                res.add("spf_include_pass_all", "fail", f"The included record of {c['domain']} ends in +all",
                        f"Anything that matches the include of {c['domain']} is accepted, and a +all there matches every sender.",
                        [f"Stop including {c['domain']} or ask its owner to fix it."], target=c["domain"])
            walk(c, False)
    walk(root)

    # ---- the all mechanism ----
    all_q = root["all"]
    cleaned = build_clean_record(records) if records else None
    changed_all = False
    if all_q == "+":
        changed_all = True
        res.add("spf_plus_all", "fail", "The record ends with +all (anyone may send as you)",
                "+all (or a bare \"all\") means every server in the world is allowed to send mail as your domain. "
                "It makes SPF useless and is a common reason domains get spoofed.",
                ["Replace +all with ~all (softfail) now; move to -all once you are sure every sender is listed."],
                fix_record=cleaned)
    elif all_q == "?":
        res.add("spf_neutral_all", "warn", "The record ends with ?all (no opinion)",
                "?all tells receivers not to judge mail from other servers, which gives no protection against spoofing.",
                ["Change ?all to ~all, and later to -all."], fix_record=cleaned)
    elif all_q == "~":
        res.add("spf_softfail", "pass", "Soft-fail policy (~all)",
                "Mail from servers you did not list is marked suspicious but usually still delivered. This is a safe choice and works "
                "well together with DMARC.",
                ["Optional: switch to -all once you have confirmed every legitimate sender is listed (DMARC reports help)."])
    elif all_q == "-":
        res.add("spf_hardfail", "pass", "Strict policy (-all)",
                "Mail from servers you did not list should be rejected. This is the strongest setting.",
                ["Keep every new sending service added to the record, or its mail will be rejected."])
    elif root["all"] is None and not any(t["type"] == "redirect" for t in root["terms"]):
        res.add("spf_no_all", "warn", "The record has no \"all\" ending",
                "Without -all or ~all, servers you did not list are neither allowed nor refused, so SPF does not protect your domain.",
                ["Add ~all at the end of the record (or -all if you are sure about your senders)."], fix_record=cleaned)
    elif root["all"] is None:
        res.add("spf_redirect_no_all", "warn", "The redirected record has no \"all\" ending",
                "The record redirects to another domain whose record has no -all/~all, so there is no policy for unlisted servers.",
                ["Ask the owner of the redirect target to end it with ~all or -all."])

    # ---- duplicates / cleanup ----
    toks = [t["term"].lower().lstrip("+") for t in root["terms"] if t["type"] != "redirect"]
    dups = sorted({x for x in toks if toks.count(x) > 1})
    if dups:
        res.add("spf_duplicates", "warn", "The same term appears more than once",
                f"Repeated: {', '.join(dups)}. Duplicates waste DNS lookups and can push you over the limit of 10.",
                ["Keep each term once."], fix_record=cleaned, terms=dups)

    if not any(f.status in ("fail", "warn") for f in res.findings) :
        pass
    res.data = data
    return res.finalize(_summary(res, total, root["all"], len(pairs)))


def _summary(res: CheckResult, total: int, all_q: str | None, n_records: int) -> str:
    if res.has("spf_multiple"):
        return "Several SPF records are published, so SPF is broken: keep only one."
    pol = {"-": "strict (-all)", "~": "soft-fail (~all)", "?": "neutral (?all)", "+": "open (+all)"}.get(all_q or "", "no all-policy")
    fails = [f for f in res.findings if f.status == "fail"]
    if fails:
        return f"SPF record found but has {len(fails)} error(s): {fails[0].title}."
    warns = [f for f in res.findings if f.status == "warn"]
    base = f"Valid SPF record, {total} of {LOOKUP_LIMIT} DNS lookups used, {pol}."
    return base + (f" {len(warns)} improvement(s) suggested." if warns else "")
