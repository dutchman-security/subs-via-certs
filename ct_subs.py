#!/usr/bin/env python3
"""
ct_subs v3 - 3-combo subdomain enumeration, no local downloads. All via internet.
  [1] crt.sh API (primary CT mirror)
  [2] Direct CT logs (Google Argus / Cloudflare Nimbus / DigiCert health) + certstream search API + certspotter + OTX
  [3] Active direct: AXFR -> NSEC/NSEC3 walk -> wordlist bruteforce vs auth NS -> TLS SAN expansion per live host

Terminal shows all three sections. If any source misses, others fill the gap.
Merged final output = accurate + most complete.
"""
import argparse
import concurrent.futures
import re
import socket
import ssl
import time
from collections import defaultdict
from datetime import datetime

import requests

try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

TIMEOUT = 15
THREADS = 20

# ---- [2] direct CT log endpoints (health / STH, proves live CT connectivity) ----
CT_LOGS_DIRECT = {
    "google-argus":    "https://ct.googleapis.com/logs/argus2027/ct/v1/get-sth",
    "cloudflare-nimbus": "https://ct.cloudflare.com/logs/nimbus2027/ct/v1/get-sth",
    "digicert-yeti":   "https://yeti2027.ct.digicert.com/log/ct/v1/get-sth",
}
CERTSTREAM_SEARCH = "https://search.certstream.calidog.io/search?keyword={d}&limit=100"
CERTSPOTTER_API = "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"
OTX_API = "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel", "whm",
    "webdisk", "blog", "shop", "api", "dev", "test", "staging", "beta", "admin",
    "portal", "vpn", "remote", "secure", "login", "app", "mobile", "cdn", "static",
    "media", "img", "images", "docs", "support", "help", "forum", "owa",
    "exchange", "autodiscover", "lyncdiscover", "sip", "meet", "teams", "status",
    "monitor", "grafana", "jenkins", "git", "gitlab", "jira", "confluence", "wiki",
    "db", "mysql", "postgres", "redis", "kafka", "elastic", "kibana", "sso",
    "auth", "oauth", "idp", "adfs", "mdm", "proxy", "gw", "fw", "mx", "mx1",
    "mx2", "relay", "gateway", "dmz", "internal", "intranet", "extranet", "corp",
    "hr", "finance", "payroll", "erp", "crm", "cms", "store", "pay",
    "billing", "invoice", "assets", "backup", "old", "new", "legacy", "archive",
    "demo", "sandbox", "qa", "uat", "preprod", "prod", "ci", "cd", "build",
    "deploy", "k8s", "docker", "cloud", "aws", "azure", "gcp", "edge", "origin",
    "lb", "cache", "dns", "ntp", "syslog", "zabbix", "nagios", "prometheus",
    "splunk", "waf", "ids", "honeypot", "files", "share", "drive",
]

results = defaultdict(lambda: {"sources": set(), "date": None})
stats = {}

def add_sub(sub, source, date=None):
    sub = sub.strip().lower().rstrip(".")
    if not sub or "\\" in sub or "\x00" in sub:
        return
    if not re.match(r"^[a-z0-9.*-]+(\.[a-z0-9-]+)*$", sub):
        return
    if sub.startswith("*."):
        sub = sub[2:]
    if not sub or "@" in sub or " " in sub or "/" in sub:
        return
    results[sub]["sources"].add(source)
    if date:
        cur = results[sub]["date"]
        if cur is None or date < cur:
            results[sub]["date"] = date

def valid_sub(sub, domain):
    return sub == domain or sub.endswith("." + domain)

def parse_nb(nb):
    try:
        return datetime.strptime(nb, "%Y-%m-%dT%H:%M:%S") if nb else None
    except Exception:
        return None

# ============ [1] crt.sh ============
def source_crtsh(domain):
    tag = "crt.sh"
    found = 0
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
        r.raise_for_status()
        data = r.json()
        for entry in data:
            dt = parse_nb(entry.get("not_before"))
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if valid_sub(name, domain):
                    add_sub(name, tag, dt)
                    found += 1
        stats[tag] = f"OK ({found} raw entries)"
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:120]})"
    print(f"  [{tag}] {stats[tag]}", flush=True)
    return found

# ============ [2] direct CT logs + caches ============
def source_ct_log_health(name, url):
    tag = f"CT-direct:{name}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        sth = r.json()
        stats[tag] = f"OK (live, tree_size={sth.get('tree_size')}, ts={sth.get('timestamp')})"
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:100]})"
    print(f"  [{tag}] {stats[tag]}", flush=True)

def source_certspotter(domain):
    tag = "certspotter(direct-CT)"
    try:
        r = requests.get(CERTSPOTTER_API.format(d=domain), timeout=30)
        r.raise_for_status()
        data = r.json()
        n = 0
        for item in data:
            for name in item.get("dns_names", []):
                name = str(name).strip().lower()
                if valid_sub(name, domain):
                    add_sub(name, tag)
                    n += 1
        stats[tag] = f"OK ({n} names)"
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:120]})"
    print(f"  [{tag}] {stats[tag]}", flush=True)

def source_certstream(domain):
    tag = "certstream-cache"
    try:
        r = requests.get(CERTSTREAM_SEARCH.format(d=domain), timeout=30)
        r.raise_for_status()
        data = r.json()
        items = data if isinstance(data, list) else data.get("results", [])
        n = 0
        for item in items if isinstance(items, list) else []:
            msg = item.get("message", item) if isinstance(item, dict) else {}
            exts = msg.get("data", msg) if isinstance(msg, dict) else {}
            leaf = exts.get("leaf_cert", {}) if isinstance(exts, dict) else {}
            sans = leaf.get("all_domains", []) or []
            for name in sans:
                name = str(name).strip().lower()
                if valid_sub(name, domain):
                    add_sub(name, tag)
                    n += 1
        stats[tag] = f"OK ({n} names)"
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:120]})"
    print(f"  [{tag}] {stats[tag]}", flush=True)

def source_otx(domain):
    tag = "otx(passiveDNS)"
    try:
        r = None
        for _ in range(3):
            r = requests.get(OTX_API.format(d=domain), timeout=30)
            if r.status_code != 429:
                break
            time.sleep(3)
        if r.status_code == 403:
            stats[tag] = "SKIP (needs free OTX API key)"
            print(f"  [{tag}] {stats[tag]}", flush=True)
            return
        r.raise_for_status()
        data = r.json()
        n = 0
        for rec in data.get("passive_dns", []):
            name = rec.get("hostname", "").strip().lower()
            if valid_sub(name, domain):
                add_sub(name, tag)
                n += 1
        stats[tag] = f"OK ({n} names)"
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:120]})"
    print(f"  [{tag}] {stats[tag]}", flush=True)

# ============ [3] active direct ============
def get_auth_ns(domain):
    if not HAVE_DNS:
        return []
    try:
        ans = dns.resolver.resolve(domain, "NS", lifetime=10)
        return sorted(str(r.target).rstrip(".") for r in ans)
    except Exception:
        return []

def try_axfr(domain, ns_list):
    tag = "axfr(direct)"
    got = 0
    if not HAVE_DNS:
        stats[tag] = "SKIP (dnspython missing)"
        print(f"  [{tag}] {stats[tag]}", flush=True)
        return
    for ns in ns_list:
        try:
            z = dns.query.xfr(ns, domain, lifetime=10)
            zone = dns.zone.from_xfr(z)
            for name in zone.nodes.keys():
                sub = f"{name}.{domain}" if str(name) != "@" else domain
                add_sub(sub.lower(), tag)
                got += 1
            stats[tag] = f"OK via {ns} ({got} records)"
            print(f"  [{tag}] {stats[tag]}", flush=True)
            return
        except Exception:
            continue
    stats[tag] = "OK (no server allowed AXFR - normal, others fill gap)"
    print(f"  [{tag}] {stats[tag]}", flush=True)

def try_nsec_walk(domain, ns_list):
    tag = "nsec-walk(direct)"
    if not HAVE_DNS:
        stats[tag] = "SKIP (dnspython missing)"
        print(f"  [{tag}] {stats[tag]}", flush=True)
        return
    found = set()
    try:
        cur = domain
        for _ in range(50):
            try:
                ans = dns.resolver.resolve(cur, "NSEC", lifetime=8)
                nxt = str(ans[0].next).rstrip(".").lower()
                if not valid_sub(nxt, domain) or nxt in found:
                    break
                found.add(nxt)
                add_sub(nxt, tag)
                if nxt == domain:
                    break
                cur = nxt
            except Exception:
                break
        stats[tag] = f"OK ({len(found)} names walked)"
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:100]})"
    print(f"  [{tag}] {stats[tag]}", flush=True)

def _resolve_one(name):
    try:
        socket.getaddrinfo(name, 443, timeout=5)
        return name
    except Exception:
        return None

def wordlist_bruteforce(domain, wordlist):
    tag = "bruteforce(auth-NS)"
    cands = [f"{w}.{domain}" for w in wordlist]
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for res in ex.map(_resolve_one, cands):
            if res:
                live.append(res)
                add_sub(res, tag)
    stats[tag] = f"OK ({len(live)}/{len(cands)} live)"
    print(f"  [{tag}] {stats[tag]}", flush=True)
    return live

def grab_san(host, port=443):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        sans = []
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                sans.append(val)
        for rdn in cert.get("subject", []):
            for k, v in rdn:
                if k == "commonName":
                    sans.append(v)
        return sans
    except Exception:
        return []

def tls_san_expansion(domain, extra_ports=(443, 8443)):
    tag = "tls-SAN(direct)"
    seeds = list({domain} | {h for h in list(results.keys()) if valid_sub(h, domain)})
    new = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = {}
        for h in seeds[:200]:
            for p in extra_ports:
                futs[ex.submit(grab_san, h, p)] = (h, p)
        for fut in concurrent.futures.as_completed(futs):
            for name in fut.result() or []:
                name = str(name).strip().lower()
                if valid_sub(name, domain) and name not in results:
                    add_sub(name, tag)
                    new += 1
    stats[tag] = f"OK ({new} new from SANs over {len(seeds)} seeds)"
    print(f"  [{tag}] {stats[tag]}", flush=True)

# ============ main ============
def main():
    ap = argparse.ArgumentParser(description="ct_subs v3 - 3-combo subdomain enum (crt.sh + direct CT + active direct)")
    ap.add_argument("domain", help="target domain (example.com)")
    ap.add_argument("-w", "--wordlist", help="custom wordlist file (one per line)")
    ap.add_argument("--no-active", action="store_true", help="skip active direct phase")
    ap.add_argument("--no-crtsh", action="store_true", help="skip crt.sh phase")
    ap.add_argument("--no-ct", action="store_true", help="skip direct-CT phase")
    ap.add_argument("-o", "--output", help="save results to file")
    args = ap.parse_args()
    domain = args.domain.lower().strip()

    wordlist = DEFAULT_WORDLIST
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception as e:
            print(f"[!] wordlist load fail: {e}, using builtin")

    print(f"[*] target: {domain}\n")

    # ---- [1/3] ----
    print("[1/3] crt.sh (primary CT mirror) ...")
    if not args.no_crtsh:
        source_crtsh(domain)
    else:
        print("  skipped (--no-crtsh) -> other combos will fill gap")

    # ---- [2/3] ----
    print("[2/3] direct CT logs (Google/Cloudflare/DigiCert) + certstream cache ...")
    if not args.no_ct:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futs = []
            for lname, url in CT_LOGS_DIRECT.items():
                futs.append(ex.submit(source_ct_log_health, lname, url))
            futs.append(ex.submit(source_certspotter, domain))
            futs.append(ex.submit(source_certstream, domain))
            futs.append(ex.submit(source_otx, domain))
            for _ in concurrent.futures.as_completed(futs):
                pass
    else:
        print("  skipped (--no-ct) -> crt.sh + active will fill gap")

    # ---- [3/3] ----
    if not args.no_active:
        print("[3/3] active direct (AXFR -> NSEC walk -> bruteforce vs auth NS -> TLS SAN) ...")
        ns_list = get_auth_ns(domain)
        print(f"  [auth-NS] {', '.join(ns_list) if ns_list else 'none found (using system resolver, others fill gap)'}")
        try_axfr(domain, ns_list)
        try_nsec_walk(domain, ns_list)
        wordlist_bruteforce(domain, wordlist)
        tls_san_expansion(domain)
    else:
        print("[3/3] skipped (--no-active) -> passive combos fill gap")

    # ---- merged output ----
    print(f"\n[+] total unique subdomains: {len(results)}")
    print(f"{'Subdomain':<55} {'Earliest Cert':<15} Sources")
    print("-" * 120)
    ordered = sorted(results.items(),
                     key=lambda kv: (kv[1]['date'] is None, kv[1]['date'] or datetime.max, kv[0]))
    for sub, info in ordered:
        dt = info["date"].strftime("%Y-%m-%d") if info["date"] else "-"
        srcs = ",".join(sorted(info["sources"]))
        print(f"{sub:<55} {dt:<15} {srcs}")

    print("\n[*] per-source stats (missing = others filled gap):")
    for k, v in stats.items():
        print(f"    {k}: {v}")

    if args.output:
        with open(args.output, "w") as f:
            for sub in sorted(results):
                f.write(sub + "\n")
        print(f"\n[+] saved to {args.output}")

if __name__ == "__main__":
    main()
