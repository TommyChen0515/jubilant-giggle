#!/usr/bin/env python3
"""
Build Surge rulesets from HaGeZi Ultimate + blackmatrix7 + mickeu + 217heidai,
then subtract everything already covered by Sukka's ad-block rulesets.

Published outputs (repo root):
  hagezi_ultimate.list                     Surge DOMAIN-SET
  adblock_merged.list                      Surge RULE-SET  (HaGeZi + b + c + d)
  adblock_sukka_complement.list            Surge RULE-SET  (merged - Sukka),
                                           containing only types eligible for
                                           pre-matching
  adblock_sukka_complement_extra.list      Surge RULE-SET  (URL-REGEX / USER-AGENT /
                                           PROCESS-NAME / PROTOCOL - NOT eligible
                                           for pre-matching, kept separate)
  adblock_sukka_complement_mitm.sgmodule   Surge module, [MITM] %APPEND% hostnames
                                           for the URL-REGEX rules above

Two user-controlled inputs shape the result:

  exclusions.list (EXCLUDE_FILE)   user allowlist; a host listed there is never
                                   blocked by any generated output. DOT-prefixed
                                   (.host) also unblocks its subdomains.
  DEDUPE_FILES                     extra rule files whose content is subtracted
                                   from the complement as well, so the same host
                                   is not published twice when several sets are
                                   loaded in Surge at once.

Standard library only. Every file is validated against Surge's documented
rule-set syntax before anything is written; any validation failure aborts the
run and leaves previously published files untouched.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import sys
from datetime import datetime, timezone

# --------------------------------------------------------------------- outputs
CACHE = "cache"
OUT_HAGEZI = "hagezi_ultimate.list"
OUT_MERGED = "adblock_merged.list"
OUT_COMPLEMENT = "adblock_sukka_complement.list"
OUT_COMPLEMENT_EXTRA = "adblock_sukka_complement_extra.list"
OUT_MODULE = "adblock_sukka_complement_mitm.sgmodule"

# ------------------------------------------------- user-controlled adjustments
# Hosts that must never be blocked, even when an upstream list contains them.
OUT_EXCLUDE = os.environ.get("EXCLUDE_FILE", "exclusions.list")
# Extra rule files whose content is subtracted from the complement, so rules that
# would be loaded twice (e.g. our own DOMAIN-SET in the Surge profile) are dropped.
DEDUPE_FILES = [p.strip() for p in
                os.environ.get("DEDUPE_FILES", "Adblock_Supplement.list").split(",")
                if p.strip()]


# ----------------------------------------------------------------------- gates
HAGEZI_MAX_UNUSUAL = 1000
SUKKA_MIN_DOMAINS = 150000
MERGED_MIN_RULES = 150000
COMPLEMENT_MIN_RULES = 40000
MODULE_MAX_HOSTS = 5000

HAGEZI_VERSION = (os.environ.get("HAGEZI_VERSION") or "unknown").strip() or "unknown"
HAGEZI_SRC_NAME = (os.environ.get("HAGEZI_SRC_NAME") or "-").strip() or "-"
HAGEZI_SRC_URL = (os.environ.get("HAGEZI_SRC_URL") or "-").strip() or "-"
RAW_BASE = os.environ.get("RAW_BASE", "").rstrip("/")
NOW = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")

# --------------------------------------------------------------------- regexes
LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$")
STRICT_2PLUS = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")
RULE_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)[ \t]*,(.*)$")

# Never copied verbatim: they reference other sets / carry their own policy.
REF_TYPES = {"DOMAIN-SET", "RULE-SET", "FINAL", "LOGIC"}

DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6"}
LOGICAL_TYPES = {"AND", "OR", "NOT"}
HTTP_TYPES = {"URL-REGEX", "USER-AGENT"}

# Types we are willing to publish at all. Anything else is dropped + counted,
# never silently mis-ordered.
EMIT_TYPES = DOMAIN_TYPES | IP_TYPES | LOGICAL_TYPES | HTTP_TYPES | {
    "PROCESS-NAME", "PROTOCOL", "DEST-PORT", "SRC-PORT", "SRC-IP",
}

# Types Surge accepts in the pre-matching phase (per REJECT policy docs).
# URL-REGEX / USER-AGENT / PROCESS-NAME / PROTOCOL are absent on purpose.
PREMATCH_TYPES = (DOMAIN_TYPES | IP_TYPES | LOGICAL_TYPES
                  | {"DEST-PORT", "SRC-PORT", "SRC-IP"})

# Per-line flags Surge allows inside a rule-set file.
ALLOWED_LINE_FLAGS = {"extended-matching", "no-resolve"}

stats: dict[str, dict[str, int]] = {}


def st(key: str) -> dict[str, int]:
    return stats.setdefault(key, {"lines": 0, "unusual": 0, "ips": 0,
                                  "skipped": 0, "flags": 0})


def die(msg: str) -> None:
    print(f"::error::{msg}", flush=True)
    sys.exit(1)


def warn(msg: str) -> None:
    print(f"::warning::{msg}", flush=True)


def gh_output(**kv) -> None:
    path = os.environ.get("GITHUB_OUTPUT", "")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            for k, v in kv.items():
                f.write(f"{k}={v}\n")


def gh_summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(md + "\n")


# ---------------------------------------------------------------- value helpers
def as_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def ip_net(ip):
    return ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}", strict=False)


def canon_host(value: str):
    v = value.strip().lower().rstrip(".")
    if not v or v.startswith(".") or any(c in v for c in " \t,\\'\"#%*?()[]"):
        return None
    return v if all(LABEL.match(lbl) for lbl in v.split(".")) else None


def canon_wildcard(value: str):
    v = value.strip().lower()
    if not v or "," in v or not re.fullmatch(r"[\x21-\x7e]+", v):
        return None
    return v


def new_rules() -> dict:
    return {"suffix": set(), "exact": set(), "kw": set(),
            "wc": set(), "ips": set(), "other": set()}


def iter_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\r\n")


def split_value_extra(raw: str):
    raw = raw.strip()
    if raw.startswith("("):
        return raw, ""
    i = raw.find(",")
    if i < 0:
        return raw, ""
    return raw[:i].strip(), raw[i + 1:].strip()


# ---------------------------------------------------------------------- parsing
def parse_rule(key: str, line: str, r: dict) -> None:
    m = RULE_LINE.match(line)
    if not m:
        st(key)["unusual"] += 1
        return
    rtype = m.group(1).upper()
    rest = m.group(2).strip()

    # URL-REGEX has no policy column here and the pattern may contain commas.
    if rtype == "URL-REGEX":
        v = rest
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1]
        if v:
            r["other"].add((rtype, v, ""))
        else:
            st(key)["unusual"] += 1
        return

    value, extra = split_value_extra(rest)

    if rtype in ("DOMAIN", "DOMAIN-SUFFIX"):
        if extra:
            # per-line extended-matching / no-resolve: valid, not modelled per entry
            st(key)["flags"] += 1
        ip = as_ip(value.strip().lstrip("."))
        if ip is not None:
            r["ips"].add(ip_net(ip))
            st(key)["ips"] += 1
            return
        d = canon_host(value.strip().lstrip("."))
        if d:
            (r["exact"] if rtype == "DOMAIN" else r["suffix"]).add(d)
        else:
            st(key)["unusual"] += 1
    elif rtype == "DOMAIN-KEYWORD":
        v = value.strip()
        if v:
            r["kw"].add(v)
        else:
            st(key)["unusual"] += 1
    elif rtype == "DOMAIN-WILDCARD":
        v = canon_wildcard(value)
        if v:
            r["wc"].add(v)
        else:
            st(key)["unusual"] += 1
    elif rtype in IP_TYPES:
        try:
            net = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            st(key)["unusual"] += 1
            return
        r["ips"].add(net)
        st(key)["ips"] += 1
    elif rtype in REF_TYPES:
        st(key)["skipped"] += 1
    elif rtype in EMIT_TYPES:
        v = value.strip()
        if v:
            r["other"].add((rtype, v, extra))
        else:
            st(key)["unusual"] += 1
    else:
        st(key)["unusual"] += 1
    st(key)["lines"] += 1


def parse_ruleset_file(path: str, key: str, r: dict) -> None:
    for line in iter_lines(path):
        s = line.strip()
        if not s or s[0] in "#;/!" or s.startswith("["):
            continue
        parse_rule(key, s, r)


def parse_domain_file(path: str, key: str, r: dict, bare_as_suffix: bool) -> None:
    """DOMAIN-SET syntax: '.d' / '+.d' / '*.d' = d + subdomains, bare 'd' = exact."""
    for line in iter_lines(path):
        s = line.strip()
        if not s or s[0] in "#;/!":
            continue
        s = s.split()[0]
        suffix = bare_as_suffix
        while s[:2] in ("+.", "*."):
            s, suffix = s[2:], True
        if s.startswith("."):
            s, suffix = s[1:], True
        if not s:
            st(key)["unusual"] += 1
            continue
        ip = as_ip(s)
        if ip is not None:
            r["ips"].add(ip_net(ip))
            st(key)["ips"] += 1
            st(key)["lines"] += 1
            continue
        d = canon_host(s)
        if not d:
            st(key)["unusual"] += 1
            continue
        st(key)["lines"] += 1
        (r["suffix"] if suffix else r["exact"]).add(d)


# ------------------------------------------------------------------ set algebra
def merge_rules(dst: dict, *srcs: dict) -> None:
    for s in srcs:
        for k in ("suffix", "exact", "kw", "wc", "ips", "other"):
            dst[k] |= s[k]


def parent_in(d: str, sset: set, include_self: bool = False) -> bool:
    if include_self and d in sset:
        return True
    parts = d.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in sset:
            return True
    return False


def collapse(r: dict) -> None:
    sf = {s for s in r["suffix"] if not parent_in(s, r["suffix"])}
    r["suffix"] = sf
    r["exact"] = {e for e in r["exact"] if e not in sf and not parent_in(e, sf)}
    ips = r["ips"]
    r["ips"] = {n for n in ips
                if not any(m != n and m.version == n.version and n.subnet_of(m)
                           for m in ips)}


def total_rules(r: dict) -> int:
    return (len(r["exact"]) + len(r["suffix"]) + len(r["kw"])
            + len(r["wc"]) + len(r["ips"]) + len(r["other"]))


# ------------------------------------------------------- exclusions (allowlist)
def wildcard_hits(pattern: str, hosts: set[str]) -> bool:
    """True when a DOMAIN-WILDCARD pattern can still match one of the hosts."""
    rx = re.compile(fnmatch.translate(pattern), re.I)
    return any(rx.match(h) for h in hosts)


def load_exclusion_file(path: str) -> dict:
    """User allowlist in DOMAIN-SET syntax.

    '.d' / '+.d' / '*.d' unblocks d and every subdomain of d.
    A bare 'd' unblocks exactly that host.
    """
    ex = new_rules()
    if not os.path.isfile(path):
        warn(f"{path} not found - no exclusions applied")
        return ex
    parse_domain_file(path, "exclusions", ex, False)
    ex["exact"] -= ex["suffix"]
    print(f"{path}: {len(ex['suffix'])} host(s) with subdomains and "
          f"{len(ex['exact'])} exact host(s) unblocked")
    return ex


def blocking_hit(host: str, r: dict) -> bool:
    """Does any rule in r block this host? (used to spot typos in the allowlist)"""
    if host in r["suffix"] or host in r["exact"] or parent_in(host, r["suffix"]):
        return True
    if any(k.lower() in host for k in r["kw"]):
        return True
    return any(wildcard_hits(w, {host}) for w in r["wc"])


def unblock(r: dict, ex: dict) -> set[str]:
    """Remove every rule in r that would still cover an excluded host.

    Returns the excluded hosts that were actually blocked by r, so the caller can
    warn about allowlist entries that match nothing (typo or already dropped
    upstream) instead of letting them rot unnoticed.
    """
    suf, exact = ex["suffix"], ex["exact"]
    hosts = suf | exact
    present = {h for h in hosts if blocking_hit(h, r)}
    r["suffix"] = {s for s in r["suffix"] if s not in suf and not parent_in(s, suf)}
    r["exact"] = {e for e in r["exact"]
                  if e not in suf and e not in exact and not parent_in(e, suf)}
    r["wc"] = {w for w in r["wc"] if not wildcard_hits(w, hosts)}
    # A keyword cannot be excepted, so it has to go as a whole; say so loudly.
    killed = sorted(k for k in r["kw"] if any(k.lower() in h for h in hosts))
    if killed:
        warn("unblocking an excluded host also drops DOMAIN-KEYWORD rule(s): "
             + ", ".join(killed[:10]))
        r["kw"] -= set(killed)
    return present


# ----------------------------------------------------------- rule-set coverage
RE_TAIL = re.compile(r"(?:\.\*)?\$*$")


def canon_regex(v: str) -> str:
    """Same pattern written two ways must compare equal: \\/ vs /, \\. vs ., case."""
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v.replace("\\/", "/").replace("\\.", ".").lower()


def regex_already_covered(ours: str, prior: set[str]) -> bool:
    """True when a prior pattern matches at least everything ours matches."""
    o = canon_regex(ours)
    if o in prior:
        return True
    # ours ends in ".*$" -> the same pattern without that tail matches a superset
    trimmed = RE_TAIL.sub("", o)
    return trimmed != o and trimmed in prior


class Coverage:
    """Union of rule sets: answers 'would this set already block domain X?'."""

    def __init__(self, *sets: dict) -> None:
        self.suffix: set[str] = set()
        self.exact: set[str] = set()
        self.kw: set[str] = set()
        self.wc: set[str] = set()
        self.other: set[tuple] = set()
        self.ips: list = []
        for s in sets:
            self.suffix |= s["suffix"]
            self.exact |= s["exact"]
            self.kw |= s["kw"]
            self.wc |= s["wc"]
            self.other |= s["other"]
            self.ips.extend(s["ips"])
        self.wc_rx = [(w, re.compile(fnmatch.translate(w), re.I)) for w in self.wc]
        self.other_norm = {canon_regex(v) for (_t, v, _e) in self.other}

    def covers_other(self, rule: tuple) -> bool:
        rtype, value, _extra = rule
        if rule in self.other:
            return True
        if rtype == "URL-REGEX":
            return regex_already_covered(value, self.other_norm)
        return False

    def covers_domain(self, d: str, is_suffix: bool) -> bool:
        if parent_in(d, self.suffix, include_self=True):
            return True
        if not is_suffix and d in self.exact:
            return True
        if any(k.lower() in d for k in self.kw):
            return True
        if not is_suffix and any(rx.match(d) for _w, rx in self.wc_rx):
            return True
        return False

    def covers_keyword(self, k: str) -> bool:
        return k in self.kw or any(pk in k for pk in self.kw)

    def covers_wildcard(self, w: str) -> bool:
        if w in self.wc:
            return True
        return w.startswith("*.") and parent_in(w[2:], self.suffix, include_self=True)

    def covers_ip(self, n) -> bool:
        return any(m.version == n.version and n.subnet_of(m) for m in self.ips)


def subtract(src: dict, cov: Coverage) -> dict:
    out = new_rules()
    out["suffix"] = {s for s in src["suffix"] if not cov.covers_domain(s, True)}
    out["exact"] = {e for e in src["exact"] if not cov.covers_domain(e, False)}
    out["kw"] = {k for k in src["kw"] if not cov.covers_keyword(k)}
    out["wc"] = {w for w in src["wc"] if not cov.covers_wildcard(w)}
    out["ips"] = {n for n in src["ips"] if not cov.covers_ip(n)}
    out["other"] = {o for o in src["other"] if not cov.covers_other(o)}
    return out


def parse_any_file(path: str, key: str, r: dict) -> None:
    """Parse a RULE-SET or a DOMAIN-SET by looking at its first real line."""
    ruleset = False
    for line in iter_lines(path):
        s = line.strip()
        if not s or s[0] in "#;/!" or s.startswith("["):
            continue
        m = RULE_LINE.match(s)
        ruleset = bool(m and m.group(1).upper() in (EMIT_TYPES | REF_TYPES))
        break
    if ruleset:
        parse_ruleset_file(path, key, r)
    else:
        parse_domain_file(path, key, r, False)


def rules_matching_host(host: str, body: list[str]) -> list[str]:
    """Post-build guard: which rendered rules would still block this host?"""
    hits: list[str] = []
    for line in body:
        m = RULE_LINE.match(line)
        if not m:
            continue
        rtype = m.group(1).upper()
        value = m.group(2).split(",")[0].strip().strip('"')
        if rtype == "DOMAIN" and value == host:
            hits.append(line)
        elif rtype == "DOMAIN-SUFFIX" and (host == value or host.endswith("." + value)):
            hits.append(line)
        elif rtype == "DOMAIN-KEYWORD" and value and value.lower() in host:
            hits.append(line)
        elif rtype == "DOMAIN-WILDCARD" and wildcard_hits(value, {host}):
            hits.append(line)
        elif rtype in LOGICAL_TYPES and host in m.group(2):
            hits.append(line)
    return hits


# -------------------------------------------------------------------- rendering
def quote_value(v: str) -> str:
    return f'"{v}"' if "," in v else v


def render_rules(r: dict) -> list[str]:
    out = [f"DOMAIN,{d}" for d in sorted(r["exact"])]
    out += [f"DOMAIN-SUFFIX,{d}" for d in sorted(r["suffix"])]
    out += [f"DOMAIN-KEYWORD,{k}" for k in sorted(r["kw"])]
    out += [f"DOMAIN-WILDCARD,{w}" for w in sorted(r["wc"])]

    logical = sorted((t, v) for (t, v, _e) in r["other"] if t in LOGICAL_TYPES)
    passthru = sorted((t, v, e) for (t, v, e) in r["other"]
                      if t not in LOGICAL_TYPES and t != "URL-REGEX")
    out += [f"{t},{v}" for t, v in logical]
    out += [f"{t},{quote_value(v)}" + (f",{e}" if e else "") for t, v, e in passthru]

    # URL-REGEX last: it is the most expensive type and must not sit before
    # anything that forces a DNS lookup.
    out += [f"URL-REGEX,{quote_value(v)}"
            for (t, v, _e) in sorted(r["other"]) if t == "URL-REGEX"]

    for n in sorted(r["ips"], key=lambda x: (x.version, int(x.network_address), x.prefixlen)):
        out.append(("IP-CIDR," if n.version == 4 else "IP-CIDR6,") + f"{n},no-resolve")
    return out


def counts(r: dict) -> list[tuple[str, int]]:
    c = []
    for name, key in (("DOMAIN", "exact"), ("DOMAIN-SUFFIX", "suffix"),
                      ("DOMAIN-KEYWORD", "kw"), ("DOMAIN-WILDCARD", "wc")):
        if r[key]:
            c.append((name, len(r[key])))
    other: dict[str, int] = {}
    for t, _v, _e in r["other"]:
        other[t] = other.get(t, 0) + 1
    for t in sorted(other):
        c.append((t, other[t]))
    v4 = sum(1 for x in r["ips"] if x.version == 4)
    v6 = len(r["ips"]) - v4
    if v4:
        c.append(("IP-CIDR (no-resolve)", v4))
    if v6:
        c.append(("IP-CIDR6 (no-resolve)", v6))
    return c


def counts_str(r: dict) -> str:
    return ", ".join(f"{t}: {n}" for t, n in counts(r))


# ------------------------------------------------------------------- validation
def validate_rules_body(body: list[str], name: str) -> None:
    errors: list[str] = []
    for lineno, line in enumerate(body, 1):
        if not line or line.startswith("#"):
            continue
        m = RULE_LINE.match(line)
        if not m:
            errors.append(f"{name}:{lineno}: not a rule line: {line[:80]!r}")
            continue
        rtype, rest = m.group(1).upper(), m.group(2)
        if rtype not in EMIT_TYPES:
            errors.append(f"{name}:{lineno}: rule type {rtype} not allowed")
            continue
        if rtype in IP_TYPES:
            parts = rest.split(",")
            if len(parts) != 2 or parts[1].strip() != "no-resolve":
                errors.append(f"{name}:{lineno}: IP rule must be '<net>,no-resolve': {line!r}")
        elif rtype in DOMAIN_TYPES:
            parts = rest.split(",")
            if not parts[0].strip():
                errors.append(f"{name}:{lineno}: empty value: {line!r}")
            for flag in parts[1:]:
                if flag.strip() not in ALLOWED_LINE_FLAGS:
                    errors.append(f"{name}:{lineno}: stray column {flag!r}: {line!r}")
        elif rtype == "URL-REGEX":
            if not rest.strip():
                errors.append(f"{name}:{lineno}: empty URL-REGEX: {line!r}")
            elif "," in rest and not (rest.startswith('"') and rest.endswith('"')):
                errors.append(f"{name}:{lineno}: URL-REGEX with comma must be quoted: {line!r}")
    if errors:
        for e in errors[:20]:
            print(f"::error::{e}", flush=True)
        die(f"{name}: {len(errors)} format problem(s) - nothing written")


def validate_domain_set(body: list[str], name: str) -> None:
    bad = [ln for ln in body if not STRICT_2PLUS.match(ln.lstrip("."))]
    if bad:
        for ln in bad[:20]:
            print(f"::error::{name}: invalid DOMAIN-SET entry: {ln!r}", flush=True)
        die(f"{name}: {len(bad)} invalid entries - nothing written")


# ------------------------------------------------------------------ MITM module
TOK_ESC = re.compile(r"[A-Za-z0-9_-]+(?:\\\.[A-Za-z0-9_-]+)+")
TOK_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+")

# Extensions that are never TLDs, so a token ending in them is a file, not a host.
# Deliberately excludes .zip / .mov / .sh etc. which are real TLDs.
BAD_TLDS = {
    "js", "mjs", "css", "png", "jpg", "jpeg", "gif", "webp", "svg", "ico",
    "json", "xml", "html", "htm", "php", "asp", "aspx", "jsp", "txt", "csv",
    "mp4", "m3u8", "woff", "woff2", "ttf", "eot", "map", "gz", "apk", "ipa",
    "bin", "dat", "swf", "webmanifest",
}
MITM_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$")

# Second-level public suffixes: a two-label token that IS one of these is not a
# host but a fragment of a longer pattern, and MITM-ing it would intercept an
# entire national namespace (e.g. *.com.cn = every Chinese company site).
PUBLIC_SUFFIX = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "com.tw", "com.mo", "co.jp", "co.kr", "com.sg", "com.au",
    "co.nz", "com.br", "com.ru", "co.uk", "org.uk", "ac.uk", "com.my",
    "co.id", "in.th", "com.vn", "co.th", "com.ph", "co.in", "com.mx",
}


def mitm_hostnames(regex_values: list[str]) -> set[str]:
    found: set[str] = set()
    for v in regex_values:
        for rx in (TOK_ESC, TOK_PLAIN):
            for m in rx.finditer(v):
                found.add(m.group(0).replace("\\.", "."))
    hosts: set[str] = set()
    for tok in found:
        labels = tok.lower().strip(".").split(".")
        if len(labels) < 2 or any(not lbl for lbl in labels):
            continue
        if labels[-1] in BAD_TLDS or len(labels[-1]) < 2:
            continue
        if ".".join(labels) in PUBLIC_SUFFIX:
            continue
        if all(lbl.isdigit() for lbl in labels):
            continue
        if not all(LABEL.match(lbl) for lbl in labels):
            continue
        base = ".".join(labels)
        hosts.add(base)
        hosts.add("*." + base)
    if len(hosts) > MODULE_MAX_HOSTS:
        warn(f"{len(hosts)} MITM hostnames derived; keeping the first {MODULE_MAX_HOSTS}")
        hosts = set(sorted(hosts)[:MODULE_MAX_HOSTS])
    bad = [h for h in hosts if not MITM_HOST_RE.match(h)]
    if bad:
        warn(f"dropping {len(bad)} malformed MITM hostnames")
        hosts -= set(bad)
    return hosts


def write_module(urlregex_values: list[str]) -> tuple[str, set[str]]:
    if not urlregex_values:
        if os.path.exists(OUT_MODULE):
            os.remove(OUT_MODULE)
            print(f"no URL-REGEX rules left - removed stale {OUT_MODULE}")
            return "deleted", set()
        return "absent", set()

    hosts = mitm_hostnames(urlregex_values)
    if not hosts:
        warn("URL-REGEX rules present but no literal hostname could be derived - "
             "those rules only match plain HTTP until hostnames are added manually")
        if os.path.exists(OUT_MODULE):
            os.remove(OUT_MODULE)
            return "deleted", set()
        return "absent", set()

    content = "\n".join([
        "#!name=AdBlock Complement (Sukka) - URL-REGEX MITM",
        f"#!desc=Appends {len(hosts)} MITM hostname entries derived from the "
        f"{len(urlregex_values)} URL-REGEX rules in {OUT_COMPLEMENT_EXTRA}, so those "
        "rules can also match HTTPS. Requires a generated and trusted MITM CA "
        "certificate (Surge -> MitM -> Generate CA). Without the certificate this "
        "module does nothing, and certificate-pinning apps may fail to connect.",
        "#!category=Ad Blocking",
        "",
        "[MITM]",
        "hostname = %APPEND% " + ", ".join(sorted(hosts)),
        "",
    ])

    old_hosts = None
    if os.path.isfile(OUT_MODULE):
        try:
            with open(OUT_MODULE, "r", encoding="utf-8", errors="replace") as f:
                m = re.search(r"^hostname\s*=\s*%APPEND%\s*(.*)$", f.read(), re.M)
            if m:
                old_hosts = {h.strip() for h in m.group(1).split(",") if h.strip()}
        except OSError:
            old_hosts = None

    if old_hosts is not None and old_hosts == hosts:
        print(f"{OUT_MODULE}: hostname list unchanged - keeping existing file")
        return "unchanged", hosts

    with open(OUT_MODULE, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print(f"{OUT_MODULE}: written ({len(hosts)} hostnames)")
    return "written", hosts


# --------------------------------------------------------------------------- io
def strip_body(path: str):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [ln.rstrip("\n") for ln in f if ln.strip() and not ln.startswith("#")]


HDR_TIME = re.compile(r"^#\s*Last modified\s*:", re.I)


def read_header(path: str) -> list[str]:
    """Leading comment lines of a previously written file (empty when absent)."""
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.rstrip("\r\n")
            if not s.startswith("#"):
                break
            out.append(s)
    return out


def write_if_changed(path: str, header: list[str], body: list[str]) -> bool:
    old = strip_body(path)
    if old is not None and old == body:
        # Compare the header too, ignoring the timestamp, so corrected header
        # text still reaches the published file without a commit every run.
        old_hdr = [h for h in read_header(path) if not HDR_TIME.match(h)]
        new_hdr = [h for h in header if not HDR_TIME.match(h)]
        if old_hdr == new_hdr:
            print(f"{path}: unchanged - keeping existing file")
            return False
        print(f"{path}: header updated ({len(body)} rules unchanged)")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header) + "\n")
        if body:
            f.write("\n".join(body) + "\n")
    os.replace(tmp, path)
    print(f"{path}: written ({len(body)} rules)")
    return True


def remove_if_empty(path: str, body: list[str]) -> None:
    if not body and os.path.exists(path):
        os.remove(path)
        print(f"{path}: no rules left - removed")


def version_key(v: str):
    return tuple((1, int(p)) if p.isdigit() else (0, p.lower())
                 for p in re.split(r"[._\-+ ]+", v))


# ------------------------------------------------------------------------- main
def main() -> None:
    required = ["hagezi.txt", "blackmatrix.list", "mickeu.list", "heidai.txt",
                "sukka_ds_reject.conf", "sukka_ds_extra.conf", "sukka_nonip_reject.conf",
                "sukka_nonip_urlregex.conf", "sukka_nonip_nodrop.conf",
                "sukka_nonip_drop.conf", "sukka_ip_reject.conf"]
    missing = [f for f in required if not os.path.isfile(os.path.join(CACHE, f))]
    if missing:
        die(f"missing downloaded file(s): {', '.join(missing)}")

    old_ver = ""
    if os.path.isfile(OUT_HAGEZI):
        with open(OUT_HAGEZI, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"^#\s*Upstream version:\s*(.*)$", line, re.I)
                if m:
                    old_ver = m.group(1).strip()
                    break
    if (old_ver and HAGEZI_VERSION != "unknown" and old_ver != HAGEZI_VERSION
            and version_key(old_ver) > version_key(HAGEZI_VERSION)):
        print(f"fetched HaGeZi {HAGEZI_VERSION} is older than published {old_ver}; "
              f"keeping all current files.")
        gh_output(changed="false", version=HAGEZI_VERSION, merged_count=0, complement_count=0)
        return

    # ---- parse ---------------------------------------------------------
    hagezi = new_rules()
    parse_domain_file(f"{CACHE}/hagezi.txt", "hagezi-ultimate", hagezi, True)

    bm = new_rules()
    parse_ruleset_file(f"{CACHE}/blackmatrix.list", "blackmatrix7_Advertising_All", bm)

    mk = new_rules()
    parse_ruleset_file(f"{CACHE}/mickeu.list", "mickeu_Advertising_Supplement", mk)

    hd = new_rules()
    # 217heidai publishes a genuine DOMAIN-SET: bare entries are exact matches.
    parse_domain_file(f"{CACHE}/heidai.txt", "217heidai_adblocksurge", hd, False)

    sukka = new_rules()
    parse_domain_file(f"{CACHE}/sukka_ds_reject.conf", "sukka/reject_(domainset)", sukka, False)
    parse_domain_file(f"{CACHE}/sukka_ds_extra.conf", "sukka/reject_extra", sukka, False)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_reject.conf", "sukka/reject_(non_ip)", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_urlregex.conf", "sukka/reject-url-regex", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_nodrop.conf", "sukka/reject-no-drop", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_drop.conf", "sukka/reject-drop", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_ip_reject.conf", "sukka/reject_(ip)", sukka)

    # ---- sanity --------------------------------------------------------
    hst = st("hagezi-ultimate")
    strict_bad = sum(1 for d in (hagezi["suffix"] | hagezi["exact"])
                     if not STRICT_2PLUS.match(d))
    if hst["unusual"] + strict_bad > HAGEZI_MAX_UNUSUAL:
        die(f"HaGeZi list looks malformed ({hst['unusual'] + strict_bad} unusual "
            f"entries) - aborting")
    if len(sukka["suffix"]) + len(sukka["exact"]) < SUKKA_MIN_DOMAINS:
        die("Sukka rulesets look truncated - aborting")

    # ---- user adjustments ----------------------------------------------
    excluded = load_exclusion_file(OUT_EXCLUDE)
    priors: list[dict] = []
    prior_info: list[tuple[str, int]] = []
    for path in DEDUPE_FILES:
        if not os.path.isfile(path):
            print(f"dedupe source {path} not found - skipped")
            continue
        extra = new_rules()
        parse_any_file(path, f"dedupe:{os.path.basename(path)}", extra)
        priors.append(extra)
        prior_info.append((path, total_rules(extra)))
        print(f"dedupe source {path}: {total_rules(extra)} rule(s) "
              "subtracted from the complement")

    # ---- merged = HaGeZi + b + c + d -----------------------------------
    merged = new_rules()
    merge_rules(merged, hagezi, bm, mk, hd)
    if excluded["suffix"] or excluded["exact"]:
        before = total_rules(merged)
        present = unblock(merged, excluded)
        print(f"exclusions removed {before - total_rules(merged)} merged rule(s)")
        unused = sorted((excluded["suffix"] | excluded["exact"]) - present)
        if unused:
            warn(f"{len(unused)} allowlist host(s) match nothing in the upstream "
                 "lists (typo, or the upstream already dropped them): "
                 + ", ".join(unused[:10]))
    collapse(merged)

    # ---- complement = merged - (Sukka + local sets) --------------------
    cov = Coverage(sukka, *priors)
    comp = subtract(merged, cov)

    # Split out the types Surge cannot use in the pre-matching phase.
    comp_extra = new_rules()
    comp_extra["other"] = {o for o in comp["other"] if o[0] not in PREMATCH_TYPES}
    comp["other"] = {o for o in comp["other"] if o[0] in PREMATCH_TYPES}

    # ---- size gates ----------------------------------------------------
    if total_rules(merged) < MERGED_MIN_RULES:
        die(f"merged ruleset only has {total_rules(merged)} rules "
            f"(expected >= {MERGED_MIN_RULES}) - aborting")
    comp_total = total_rules(comp) + total_rules(comp_extra)
    if comp_total < COMPLEMENT_MIN_RULES:
        die(f"complement only has {comp_total} rules "
            f"(expected >= {COMPLEMENT_MIN_RULES}) - subtraction may be wrong - aborting")
    leftover = ([s for s in comp["suffix"] if cov.covers_domain(s, True)]
                + [e for e in comp["exact"] if cov.covers_domain(e, False)])
    if leftover:
        die(f"subtraction incomplete: {len(leftover)} rules still duplicate a "
            "prior set (Sukka or DEDUPE_FILES) - aborting")

    # ---- render + validate before touching anything --------------------
    hagezi_body = sorted("." + d for d in (hagezi["suffix"] | hagezi["exact"]))
    merged_body = render_rules(merged)
    comp_body = render_rules(comp)
    comp_extra_body = render_rules(comp_extra)

    validate_domain_set(hagezi_body, OUT_HAGEZI)
    validate_rules_body(merged_body, OUT_MERGED)
    validate_rules_body(comp_body, OUT_COMPLEMENT)
    validate_rules_body(comp_extra_body, OUT_COMPLEMENT_EXTRA)

    # ---- exclusion guard: an excluded host must not survive in any output
    still_blocked: list[str] = []
    for host in sorted(excluded["suffix"] | excluded["exact"]):
        hit = (rules_matching_host(host, comp_body)
               or rules_matching_host(host, comp_extra_body)
               or rules_matching_host(host, merged_body))
        if hit:
            still_blocked.append(f"{host} <- {hit[0]}")
    if still_blocked:
        for s in still_blocked[:20]:
            print(f"::error::excluded host still blocked: {s}", flush=True)
        die(f"{len(still_blocked)} excluded host(s) would still be blocked "
            "(an ancestor DOMAIN-SUFFIX, a DOMAIN-KEYWORD or a logical upstream "
            "rule covers them, or the profile still loads " + OUT_HAGEZI +
            ") - nothing written")
    if excluded["suffix"] or excluded["exact"]:
        print(f"exclusion guard: {len(excluded['suffix'] | excluded['exact'])} "
              "host(s) verified free of blocking rules")

    # ---- write ---------------------------------------------------------
    ch_h = write_if_changed(OUT_HAGEZI, [
        "# Title: HaGeZi's Ultimate DNS Blocklist (Surge DOMAIN-SET)",
        f"# Source: {HAGEZI_SRC_NAME}",
        f"# Source URL: {HAGEZI_SRC_URL}",
        f"# Upstream version: {HAGEZI_VERSION}",
        f"# Last modified: {NOW}",
        "# Syntax: Surge DOMAIN-SET",
        f"# Number of entries: {len(hagezi_body)}",
        "#",
    ], hagezi_body)

    ch_m = write_if_changed(OUT_MERGED, [
        "# Title: Merged Ad-Block Ruleset for Surge (RULE-SET)",
        "# Description: HaGeZi Ultimate + blackmatrix7 Advertising_All",
        "#              + mickeu Advertising_Supplement + 217heidai adblocksurge,",
        "#              merged, normalized and de-duplicated.",
        f"# Last modified: {NOW}",
        "# Syntax: Surge RULE-SET (one rule per line, no trailing policy)",
        (f"# Usage: RULE-SET,{RAW_BASE}/{OUT_MERGED},REJECT" if RAW_BASE
         else "# Usage: point a RULE-SET rule at the raw URL of this file"),
        "# Notes: IP rules carry no-resolve; URL-REGEX rules only match plain HTTP",
        "#        or MITM-decrypted HTTPS requests.",
        f"# Entries: {counts_str(merged)}",
        f"# Number of entries: {len(merged_body)}",
        "#",
    ], merged_body)

    comp_header = [
        "# Title: Ad-Block complement to Sukka's rulesets - main set (Surge RULE-SET)",
        "# Description: (HaGeZi Ultimate + blackmatrix7 Advertising_All + mickeu",
        "#              Advertising_Supplement + 217heidai adblocksurge) minus every rule",
        "#              already covered by Sukka's reject / reject_extra / reject-url-regex",
        "#              / reject-no-drop / reject-drop / ip reject rulesets.",
        f"# Last modified: {NOW}",
        "# Usage: place AFTER all of Sukka's ad-block rulesets:",
        (f"#   RULE-SET,{RAW_BASE}/{OUT_COMPLEMENT},REJECT" if RAW_BASE
         else f"#   RULE-SET,<raw URL of {OUT_COMPLEMENT}>,REJECT"),
        "# All entries here are domain/IP/logical/port rules, so this set may also",
        "# carry the pre-matching flag (REJECT-family policy required).",
        f"# Companion file (URL-REGEX etc., cannot use pre-matching): {OUT_COMPLEMENT_EXTRA}",
    ]
    if prior_info:
        comp_header.append("# Dedupe sources also subtracted: "
                           + ", ".join(p for p, _n in prior_info))
    if excluded["suffix"] or excluded["exact"]:
        comp_header.append(f"# Exclusions applied ({OUT_EXCLUDE}): "
                           f"{len(excluded['suffix'] | excluded['exact'])} host(s) unblocked")
    comp_header += [f"# Entries: {counts_str(comp)}",
                    f"# Number of entries: {len(comp_body)}",
                    "#"]
    ch_c = write_if_changed(OUT_COMPLEMENT, comp_header, comp_body)

    ch_x = False
    if comp_extra_body:
        ch_x = write_if_changed(OUT_COMPLEMENT_EXTRA, [
            "# Title: Ad-Block complement to Sukka - extra rules (Surge RULE-SET)",
            "# Description: URL-REGEX / USER-AGENT / PROCESS-NAME / PROTOCOL rules.",
            "#              Surge does not allow these types in the pre-matching phase,",
            "#              so they are kept in a separate set.",
            f"# Last modified: {NOW}",
            (f"# Usage: RULE-SET,{RAW_BASE}/{OUT_COMPLEMENT_EXTRA},REJECT" if RAW_BASE
             else f"# Usage: RULE-SET,<raw URL of {OUT_COMPLEMENT_EXTRA}>,REJECT"),
            f"# MITM hostnames for the URL-REGEX rules: {OUT_MODULE}",
            f"# Entries: {counts_str(comp_extra)}",
            f"# Number of entries: {len(comp_extra_body)}",
            "#",
        ], comp_extra_body)
    else:
        remove_if_empty(OUT_COMPLEMENT_EXTRA, comp_extra_body)
        if os.path.exists(OUT_COMPLEMENT_EXTRA):
            os.remove(OUT_COMPLEMENT_EXTRA)
            ch_x = True
            print(f"{OUT_COMPLEMENT_EXTRA}: no rules - removed")

    urlregex = sorted(v for (t, v, _e) in comp_extra["other"] if t == "URL-REGEX")
    module_state, module_hosts = write_module(urlregex)

    changed = ch_h or ch_m or ch_c or ch_x or module_state in ("written", "deleted")
    gh_output(changed=str(changed).lower(),
              version=HAGEZI_VERSION,
              merged_count=len(merged_body),
              complement_count=comp_total)

    # ---- report --------------------------------------------------------
    md = ["### Surge ad-block ruleset build",
          f"*HaGeZi upstream version: {HAGEZI_VERSION} · source: {HAGEZI_SRC_NAME}*", "",
          "| Output | Format | Entries | Updated |",
          "| --- | --- | --- | --- |",
          f"| `{OUT_HAGEZI}` | DOMAIN-SET | {len(hagezi_body)} | {ch_h} |",
          f"| `{OUT_MERGED}` | RULE-SET | {len(merged_body)} | {ch_m} |",
          f"| `{OUT_COMPLEMENT}` | RULE-SET | {len(comp_body)} | {ch_c} |",
          f"| `{OUT_COMPLEMENT_EXTRA}` | RULE-SET | {len(comp_extra_body)} | {ch_x} |",
          f"| `{OUT_MODULE}` | module | {len(module_hosts)} hostnames | {module_state} |",
          "", "#### Merged -> complement (rules already covered by Sukka removed)",
          "| Rule type | Merged | Complement | Removed |", "| --- | --- | --- | --- |"]
    mc = dict(counts(merged))
    cc = dict(counts(comp))
    for t in sorted(set(mc) | set(cc)):
        md.append(f"| {t} | {mc.get(t, 0)} | {cc.get(t, 0)} | {mc.get(t, 0) - cc.get(t, 0)} |")
    extra_total = total_rules(comp_extra)
    md.append(f"| **total** | **{total_rules(merged)}** | **{comp_total}** | "
              f"**{total_rules(merged) - comp_total}** |")
    md += ["", "#### Upstream parse stats",
           "| Source | rules | IP literals | unusual | skipped refs | line flags |",
           "| --- | --- | --- | --- | --- | --- |"]
    for k in sorted(stats):
        s = stats[k]
        md.append(f"| {k} | {s['lines']} | {s['ips']} | {s['unusual']} | "
                  f"{s['skipped']} | {s['flags']} |")
    if excluded["suffix"] or excluded["exact"]:
        md += ["", "#### Exclusions (`" + OUT_EXCLUDE + "`)",
               f"* {len(excluded['suffix'])} host(s) unblocked including subdomains, "
               f"{len(excluded['exact'])} exact host(s); verified absent from "
               f"`{OUT_COMPLEMENT}`, `{OUT_COMPLEMENT_EXTRA}` and `{OUT_MERGED}`.",
               "* `" + OUT_HAGEZI + "` stays a byte-faithful upstream mirror, so it still "
               "contains them - do not load it as a rule-set if you need exclusions."]
    if priors:
        md += ["", "#### Dedupe sources subtracted from the complement",
               "| Source | rules |", "| --- | --- |"]
        for path, n in prior_info:
            md.append(f"| `{path}` | {n} |")
    if urlregex:
        md += ["", f"URL-REGEX in extra set: **{len(urlregex)}**, "
                   f"MITM hostnames derived: **{len(module_hosts)}**"]
    if extra_total:
        md += ["", f"Extra set total: **{extra_total}** rules"]
    gh_summary("\n".join(md))
    print("build finished")


if __name__ == "__main__":
    main()
