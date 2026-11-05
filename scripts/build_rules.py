#!/usr/bin/env python3
"""
Build Surge rulesets from HaGeZi Ultimate + blackmatrix7 + mickeu + 217heidai,
and subtract everything already covered by Sukka's ad-block rulesets.

Outputs (all written to the repo root):
  hagezi_ultimate.list                    Surge DOMAIN-SET
  adblock_merged.list                     Surge RULE-SET  (HaGeZi + b + c + d)
  adblock_sukka_complement.list           Surge RULE-SET  (merged - Sukka)
  adblock_sukka_complement_mitm.sgmodule  Surge module    ([MITM] %APPEND% hostnames)

Only the Python standard library is used. Every file is validated against
Surge's documented syntax before anything is written; any validation failure
aborts the run with the previously published files left untouched.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import sys
from datetime import datetime, timezone

# --------------------------------------------------------------------------- paths
CACHE = "cache"
OUT_HAGEZI = "hagezi_ultimate.list"
OUT_MERGED = "adblock_merged.list"
OUT_COMPLEMENT = "adblock_sukka_complement.list"
OUT_MODULE = "adblock_sukka_complement_mitm.sgmodule"

# --------------------------------------------------------------------------- gates
HAGEZI_MAX_UNUSUAL = 1000       # tolerance copied from the original workflow
SUKKA_MIN_DOMAINS = 150000      # reject(~148k) + reject_extra(~81k) today
MERGED_MIN_RULES = 150000       # guards against a silently broken parser
COMPLEMENT_MIN_RULES = 40000    # guards against over-aggressive subtraction
MODULE_MAX_HOSTS = 5000

HAGEZI_VERSION = (os.environ.get("HAGEZI_VERSION") or "unknown").strip() or "unknown"
HAGEZI_SRC_NAME = (os.environ.get("HAGEZI_SRC_NAME") or "-").strip() or "-"
HAGEZI_SRC_URL = (os.environ.get("HAGEZI_SRC_URL") or "-").strip() or "-"
RAW_BASE = os.environ.get("RAW_BASE", "").rstrip("/")
NOW = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")

# --------------------------------------------------------------------------- regexes
LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$")
STRICT_2PLUS = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")
RULE_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)[ \t]*,(.*)$")

# Rule types that must never be copied verbatim into a published file.
REF_TYPES = {"DOMAIN-SET", "RULE-SET", "FINAL", "LOGIC"}

# Everything this script is allowed to emit. Anything else is dropped + counted.
EMIT_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "URL-REGEX",
    "AND", "OR", "NOT",
    "USER-AGENT", "PROCESS-NAME", "PROTOCOL", "DEST-PORT", "SRC-PORT", "SRC-IP",
}

stats: dict[str, dict[str, int]] = {}


def st(key: str) -> dict[str, int]:
    return stats.setdefault(key, {"lines": 0, "unusual": 0, "ips": 0, "skipped": 0})


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


# --------------------------------------------------------------------------- helpers
def as_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def ip_net(ip):
    return ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}", strict=False)


def canon_host(value: str):
    """Lower-case hostname, or None if it is not a plain domain."""
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
    if raw.startswith("("):          # logical rule: keep the whole expression
        return raw, ""
    i = raw.find(",")
    if i < 0:
        return raw, ""
    return raw[:i].strip(), raw[i + 1:].strip()


# --------------------------------------------------------------------------- parsing
def parse_rule(key: str, line: str, r: dict) -> None:
    m = RULE_LINE.match(line)
    if not m:
        st(key)["unusual"] += 1
        return
    st(key)["lines"] += 1
    rtype = m.group(1).upper()
    rest = m.group(2).strip()

    # URL-REGEX has no policy column in a rule-set file, and the pattern may
    # legitimately contain commas -> take the whole remainder as the value.
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
        ip = as_ip(value.strip().lstrip("."))
        if ip is not None:                      # IP literal -> real IP rule
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
    elif rtype in ("IP-CIDR", "IP-CIDR6"):
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
        st(key)["unusual"] += 1                  # unknown type -> never published


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


# --------------------------------------------------------------------------- set algebra
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
    """Drop entries already covered by a broader entry of the same list."""
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


# --------------------------------------------------------------------------- rendering
def quote_value(v: str) -> str:
    return f'"{v}"' if "," in v else v


def render_rules(r: dict) -> list[str]:
    out = [f"DOMAIN,{d}" for d in sorted(r["exact"])]
    out += [f"DOMAIN-SUFFIX,{d}" for d in sorted(r["suffix"])]
    out += [f"DOMAIN-KEYWORD,{k}" for k in sorted(r["kw"])]
    out += [f"DOMAIN-WILDCARD,{w}" for w in sorted(r["wc"])]

    logical = sorted((t, v) for (t, v, _e) in r["other"] if t in ("AND", "OR", "NOT"))
    passthru = sorted((t, v, e) for (t, v, e) in r["other"]
                      if t not in ("AND", "OR", "NOT", "URL-REGEX"))
    out += [f"{t},{v}" for t, v in logical]
    out += [f"{t},{quote_value(v)}" + (f",{e}" if e else "") for t, v, e in passthru]

    # URL-REGEX before IP rules: no rule then forces a DNS lookup to be reached.
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


# --------------------------------------------------------------------------- validation
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
        if rtype in ("IP-CIDR", "IP-CIDR6"):
            if not rest.endswith(",no-resolve") or rest.count(",") != 1:
                errors.append(f"{name}:{lineno}: IP rule must be '<net>,no-resolve': {line!r}")
        elif rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"):
            if "," in rest:
                errors.append(f"{name}:{lineno}: stray policy column: {line!r}")
            if not rest.strip():
                errors.append(f"{name}:{lineno}: empty value: {line!r}")
        elif rtype == "URL-REGEX":
            if not rest.strip():
                errors.append(f"{name}:{lineno}: empty URL-REGEX: {line!r}")
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


# --------------------------------------------------------------------------- MITM module
TOK_ESC = re.compile(r"[A-Za-z0-9_-]+(?:\\\.[A-Za-z0-9_-]+)+")
TOK_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+")
# Tokens ending in a file extension are not hostnames (e.g. "foo.js" in a path).
BAD_TLDS = {
    "js", "mjs", "css", "png", "jpg", "jpeg", "gif", "webp", "svg", "ico",
    "json", "xml", "html", "htm", "php", "asp", "aspx", "jsp", "txt", "csv",
    "mp4", "m3u8", "ts", "woff", "woff2", "ttf", "eot", "map", "gz", "zip",
    "apk", "ipa", "bin", "dat", "swf", "webmanifest",
}

MITM_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$")


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
        if all(lbl.isdigit() for lbl in labels):        # IPv4 literal, not a hostname
            continue
        if not all(LABEL.match(lbl) for lbl in labels):
            continue
        base = ".".join(labels)
        hosts.add(base)
        hosts.add("*." + base)                          # cover subdomains too
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
             "those rules will only match plain HTTP until you add hostnames manually")
        if os.path.exists(OUT_MODULE):
            os.remove(OUT_MODULE)
            return "deleted", set()
        return "absent", set()

    content = "\n".join([
        "#!name=AdBlock Complement (Sukka) - URL-REGEX MITM",
        f"#!desc=Appends {len(hosts)} MITM hostname entries derived from the "
        f"{len(urlregex_values)} URL-REGEX rules in adblock_sukka_complement.list, so those "
        "rules can also match HTTPS requests. Install this module next to that RULE-SET, "
        "and generate + trust a MITM CA certificate in Surge first "
        "(Settings -> MitM -> Generate CA). Without the certificate the module does nothing.",
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


def write_if_changed(path: str, header: list[str], body: list[str]) -> bool:
    old = strip_body(path)
    if old is not None and old == body:
        print(f"{path}: rule body unchanged - keeping existing file")
        return False
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header) + "\n")
        if body:
            f.write("\n".join(body) + "\n")
    os.replace(tmp, path)
    print(f"{path}: written ({len(body)} rules)")
    return True


def version_key(v: str):
    return tuple((1, int(p)) if p.isdigit() else (0, p.lower())
                 for p in re.split(r"[._\-+ ]+", v))


# --------------------------------------------------------------------------- main
def main() -> None:
    required = ["hagezi.txt", "blackmatrix.list", "mickeu.list", "heidai.txt",
                "sukka_ds_reject.conf", "sukka_ds_extra.conf", "sukka_nonip_reject.conf",
                "sukka_nonip_urlregex.conf", "sukka_nonip_nodrop.conf",
                "sukka_nonip_drop.conf", "sukka_ip_reject.conf"]
    missing = [f for f in required if not os.path.isfile(os.path.join(CACHE, f))]
    if missing:
        die(f"missing downloaded file(s): {', '.join(missing)}")

    # 0) never downgrade: a fallback mirror may be older than what is published
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

    # 1) parse every upstream list
    hagezi = new_rules()
    parse_domain_file(f"{CACHE}/hagezi.txt", "hagezi-ultimate", hagezi, True)

    bm = new_rules()
    parse_ruleset_file(f"{CACHE}/blackmatrix.list", "blackmatrix7_Advertising_All", bm)

    mk = new_rules()
    parse_ruleset_file(f"{CACHE}/mickeu.list", "mickeu_Advertising_Supplement", mk)

    hd = new_rules()
    # 217heidai ships a genuine DOMAIN-SET: bare entries are exact matches.
    parse_domain_file(f"{CACHE}/heidai.txt", "217heidai_adblocksurge", hd, False)

    sukka = new_rules()
    parse_domain_file(f"{CACHE}/sukka_ds_reject.conf", "sukka/reject_(domainset)", sukka, False)
    parse_domain_file(f"{CACHE}/sukka_ds_extra.conf", "sukka/reject_extra", sukka, False)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_reject.conf", "sukka/reject_(non_ip)", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_urlregex.conf", "sukka/reject-url-regex", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_nodrop.conf", "sukka/reject-no-drop", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_nonip_drop.conf", "sukka/reject-drop", sukka)
    parse_ruleset_file(f"{CACHE}/sukka_ip_reject.conf", "sukka/reject_(ip)", sukka)

    # 2) sanity gates before building anything
    hst = st("hagezi-ultimate")
    strict_bad = sum(1 for d in (hagezi["suffix"] | hagezi["exact"])
                     if not STRICT_2PLUS.match(d))
    if hst["unusual"] + strict_bad > HAGEZI_MAX_UNUSUAL:
        die(f"HaGeZi list looks malformed ({hst['unusual'] + strict_bad} unusual "
            f"entries) - aborting")
    if len(sukka["suffix"]) + len(sukka["exact"]) < SUKKA_MIN_DOMAINS:
        die("Sukka rulesets look truncated - aborting")

    # 3) merged = HaGeZi + (b) + (c) + (d), de-duplicated
    merged = new_rules()
    merge_rules(merged, hagezi, bm, mk, hd)
    collapse(merged)

    # 4) complement = merged - everything Sukka already covers
    kw = list(sukka["kw"])
    wc_rx = [(w, re.compile(fnmatch.translate(w))) for w in sukka["wc"]]
    s_suf, s_ex, s_ips = sukka["suffix"], sukka["exact"], list(sukka["ips"])

    def covered_by_sukka(d: str, is_suffix: bool) -> bool:
        if parent_in(d, s_suf, include_self=True):      # suffix covers d + subdomains
            return True
        if not is_suffix and d in s_ex:                 # exact host already blocked
            return True
        for k in kw:                                    # keyword in d => d and subs covered
            if k in d:
                return True
        if not is_suffix:                               # wildcard matches the host itself
            for _w, rx in wc_rx:
                if rx.fullmatch(d):
                    return True
        return False

    comp = new_rules()
    comp["suffix"] = {s for s in merged["suffix"] if not covered_by_sukka(s, True)}
    comp["exact"] = {e for e in merged["exact"] if not covered_by_sukka(e, False)}
    comp["kw"] = {k for k in merged["kw"] if not any(sk == k or sk in k for sk in kw)}
    comp["wc"] = merged["wc"] - sukka["wc"]
    comp["ips"] = {n for n in merged["ips"]
                   if not any(m.version == n.version and n.subnet_of(m) for m in s_ips)}
    comp["other"] = {o for o in merged["other"] if o not in sukka["other"]}

    # 5) size gates
    if total_rules(merged) < MERGED_MIN_RULES:
        die(f"merged ruleset only has {total_rules(merged)} rules "
            f"(expected >= {MERGED_MIN_RULES}) - aborting")
    if total_rules(comp) < COMPLEMENT_MIN_RULES:
        die(f"complement only has {total_rules(comp)} rules "
            f"(expected >= {COMPLEMENT_MIN_RULES}) - subtract logic may be wrong - aborting")
    leftover = (comp["suffix"] & s_suf) | (comp["exact"] & s_ex)
    if leftover:
        die(f"subtraction incomplete: {len(leftover)} rules still duplicate Sukka entries")

    # 6) build bodies + validate BEFORE touching any published file
    hagezi_body = sorted("." + d for d in (hagezi["suffix"] | hagezi["exact"]))
    merged_body = render_rules(merged)
    comp_body = render_rules(comp)

    validate_domain_set(hagezi_body, OUT_HAGEZI)
    validate_rules_body(merged_body, OUT_MERGED)
    validate_rules_body(comp_body, OUT_COMPLEMENT)

    # 7) write
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
        "#        or MITM-decrypted HTTPS requests and are listed before IP rules.",
        f"# Entries: {counts_str(merged)}",
        f"# Number of entries: {len(merged_body)}",
        "#",
    ], merged_body)

    ch_c = write_if_changed(OUT_COMPLEMENT, [
        "# Title: Ad-Block complement to Sukka's rulesets (Surge RULE-SET)",
        "# Description: (HaGeZi Ultimate + blackmatrix7 Advertising_All + mickeu",
        "#              Advertising_Supplement + 217heidai adblocksurge) minus every rule",
        "#              already covered by Sukka's reject / reject_extra / reject-url-regex",
        "#              / reject-no-drop / reject-drop / ip reject rulesets.",
        f"# Last modified: {NOW}",
        "# Usage: put this line AFTER all of Sukka's ad-block rulesets:",
        (f"#   RULE-SET,{RAW_BASE}/{OUT_COMPLEMENT},REJECT" if RAW_BASE
         else "#   RULE-SET,<raw URL of this file>,REJECT"),
        "# The MITM hostnames for the URL-REGEX rules below live in",
        f"# {OUT_MODULE} - install that module to enable them on HTTPS.",
        f"# Entries: {counts_str(comp)}",
        f"# Number of entries: {len(comp_body)}",
        "#",
    ], comp_body)

    urlregex = sorted(v for (t, v, _e) in comp["other"] if t == "URL-REGEX")
    module_state, module_hosts = write_module(urlregex)

    # 8) report
    changed = ch_h or ch_m or ch_c or module_state in ("written", "deleted")
    gh_output(changed=str(changed).lower(),
              version=HAGEZI_VERSION,
              merged_count=len(merged_body),
              complement_count=len(comp_body))

    md = ["### Surge ad-block ruleset build",
          f"*HaGeZi upstream version: {HAGEZI_VERSION} · source: {HAGEZI_SRC_NAME}*", "",
          "| Output | Format | Entries | Updated |",
          "| --- | --- | --- | --- |",
          f"| `{OUT_HAGEZI}` | DOMAIN-SET | {len(hagezi_body)} | {ch_h} |",
          f"| `{OUT_MERGED}` | RULE-SET | {len(merged_body)} | {ch_m} |",
          f"| `{OUT_COMPLEMENT}` | RULE-SET | {len(comp_body)} | {ch_c} |",
          f"| `{OUT_MODULE}` | module | {len(module_hosts)} MITM hostnames | {module_state} |",
          "", "#### Merged -> complement (rules already covered by Sukka removed)",
          "| Rule type | Merged | Complement | Removed |", "| --- | --- | --- | --- |"]
    mc, cc = dict(counts(merged)), dict(counts(comp))
    for t in sorted(set(mc) | set(cc)):
        md.append(f"| {t} | {mc.get(t, 0)} | {cc.get(t, 0)} | {mc.get(t, 0) - cc.get(t, 0)} |")
    md.append(f"| **total** | **{total_rules(merged)}** | **{total_rules(comp)}** | "
              f"**{total_rules(merged) - total_rules(comp)}** |")
    md += ["", "#### Upstream parse stats",
           "| Source | rules | IP literals | unusual | skipped refs |",
           "| --- | --- | --- | --- | --- |"]
    for k in sorted(stats):
        s = stats[k]
        md.append(f"| {k} | {s['lines']} | {s['ips']} | {s['unusual']} | {s['skipped']} |")
    if urlregex:
        md += ["", f"URL-REGEX rules in complement: **{len(urlregex)}** "
                   f"(MITM hostnames derived: **{len(module_hosts)}**)"]
    gh_summary("\n".join(md))
    print("build finished")


if __name__ == "__main__":
    main()
