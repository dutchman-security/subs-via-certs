#!/usr/bin/env python3
"""
SUBS-VIA-CERTS v3 - 3-combo subdomain enumeration via Certificate Transparency
No local downloads. All internet-based. Three phases that fill each other's gaps.
"""
import argparse
import concurrent.futures
import re
import socket
import ssl
import sys
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

# ─── colors ───
class C:
    R = '\033[91m'      # red
    G = '\033[92m'      # green
    Y = '\033[93m'      # yellow
    B = '\033[94m'      # blue
    M = '\033[95m'      # magenta
    C = '\033[96m'      # cyan
    W = '\033[97m'      # white
    D = '\033[90m'      # dim
    BD = '\033[1m'      # bold
    UL = '\033[4m'      # underline
    X = '\033[0m'       # reset

def c(text, color): return f"{color}{text}{C.X}"
def ok(t): return c(f"  [✓] {t}", C.G)
def fail(t): return c(f"  [✗] {t}", C.R)
def warn(t): return c(f"  [!] {t}", C.Y)
def info(t): return c(f"  [*] {t}", C.C)
def dim(t): return c(t, C.D)
def bold(t): return c(t, C.BD)
def mag(t): return c(t, C.M)

# ─── compact banner ───
BANNER = f"""
{C.M}{C.BD}╔══════════════════════════════════════════════════════════════╗
║  {C.W}{C.BD}SUBS-VIA-CERTS{C.X}{C.M}{C.BD}  v3.0  •  3-phase CT subdomain enum  ║
║  {C.D}crt.sh  +  direct CT logs  +  active recon{C.M}{C.BD}           ║
║  {C.D}no local DB  •  no downloads  •  gap-filling by design{C.M}{C.BD}  ║
║  {C.D}developed by Dutchman Security{C.M}{C.BD}                        ║
╚══════════════════════════════════════════════════════════════╝{C.X}
"""

# ─── CT endpoints ───
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

# ═══════════════════════════════════════════════════════════════
# PHASE 1 — crt.sh
# ═══════════════════════════════════════════════════════════════
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
        print(ok(f"{tag}: {found} entries"))
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:100]})"
        print(fail(f"{tag}: {str(e)[:100]}"))
    return found

# ═══════════════════════════════════════════════════════════════
# PHASE 2 — direct CT logs + caches
# ═══════════════════════════════════════════════════════════════
def source_ct_log_health(name, url):
    tag = f"CT-direct:{name}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        sth = r.json()
        stats[tag] = f"OK (live, tree_size={sth.get('tree_size')}, ts={sth.get('timestamp')})"
        print(ok(f"{tag}: live (tree={sth.get('tree_size'):,})"))
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:80]})"
        print(fail(f"{tag}: {str(e)[:80]}"))

def source_certspotter(domain):
    tag = "certspotter"
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
        print(ok(f"{tag}: {n} names"))
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:100]})"
        print(fail(f"{tag}: {str(e)[:100]}"))

def source_certstream(domain):
    tag = "certstream"
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
        print(ok(f"{tag}: {n} names"))
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:100]})"
        print(fail(f"{tag}: {str(e)[:100]}"))

def source_otx(domain):
    tag = "otx"
    try:
        r = None
        for _ in range(3):
            r = requests.get(OTX_API.format(d=domain), timeout=30)
            if r.status_code != 429:
                break
            time.sleep(3)
        if r.status_code == 403:
            stats[tag] = "SKIP (needs OTX API key)"
            print(warn(f"{tag}: needs free API key"))
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
        print(ok(f"{tag}: {n} names"))
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:100]})"
        print(fail(f"{tag}: {str(e)[:100]}"))

# ═══════════════════════════════════════════════════════════════
# PHASE 3 — active direct
# ═══════════════════════════════════════════════════════════════
def get_auth_ns(domain):
    if not HAVE_DNS:
        return []
    try:
        ans = dns.resolver.resolve(domain, "NS", lifetime=10)
        return sorted(str(r.target).rstrip(".") for r in ans)
    except Exception:
        return []

def try_axfr(domain, ns_list):
    tag = "axfr"
    got = 0
    if not HAVE_DNS:
        stats[tag] = "SKIP (dnspython missing)"
        print(warn(f"{tag}: dnspython not installed"))
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
            print(ok(f"{tag}: {got} records via {ns}"))
            return
        except Exception:
            continue
    stats[tag] = "OK (no AXFR allowed - normal)"
    print(info(f"{tag}: no server allowed AXFR (others fill gap)"))

def try_nsec_walk(domain, ns_list):
    tag = "nsec-walk"
    if not HAVE_DNS:
        stats[tag] = "SKIP (dnspython missing)"
        print(warn(f"{tag}: dnspython not installed"))
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
        print(ok(f"{tag}: {len(found)} names"))
    except Exception as e:
        stats[tag] = f"FAIL ({str(e)[:80]})"
        print(fail(f"{tag}: {str(e)[:80]}"))

def _resolve_one(name):
    try:
        socket.getaddrinfo(name, 443, timeout=5)
        return name
    except Exception:
        return None

def wordlist_bruteforce(domain, wordlist):
    tag = "bruteforce"
    cands = [f"{w}.{domain}" for w in wordlist]
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for res in ex.map(_resolve_one, cands):
            if res:
                live.append(res)
                add_sub(res, tag)
    stats[tag] = f"OK ({len(live)}/{len(cands)} live)"
    print(ok(f"{tag}: {len(live)}/{len(cands)} live"))

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
    tag = "tls-SAN"
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
    print(ok(f"{tag}: {new} new from {len(seeds)} seeds"))

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def print_phase_header(num, total, title):
    bar = "█" * num + "░" * (total - num)
    print(f"\n{C.BD}{C.B}[{num}/{total}]{C.X} {C.W}{title}{C.X}  {C.D}{bar}{C.X}")

def print_target(domain):
    print(f"\n{C.BD}{C.C}▶ TARGET{C.X}  {C.W}{domain}{C.X}")

def print_ns(ns_list):
    if ns_list:
        print(f"{C.BD}{C.C}▶ AUTH NS{C.X}  {C.W}{', '.join(ns_list)}{C.X}")
    else:
        print(f"{C.BD}{C.C}▶ AUTH NS{C.X}  {C.Y}none found (system resolver){C.X}")

def print_summary(domain, output_file=None):
    total = len(results)
    print(f"\n{C.BD}{C.G}═══ RESULTS ═══{C.X}")
    print(f"{C.BD}{C.W}Total unique subdomains: {C.G}{total}{C.X}")
    print(f"{C.D}{'─' * 110}{C.X}")
    print(f"{C.BD}{C.W}{'Subdomain':<55} {'Earliest Cert':<15} Sources{C.X}")
    print(f"{C.D}{'─' * 110}{C.X}")

    ordered = sorted(results.items(),
                     key=lambda kv: (kv[1]['date'] is None, kv[1]['date'] or datetime.max, kv[0]))
    for sub, info in ordered:
        dt = info["date"].strftime("%Y-%m-%d") if info["date"] else c("-", C.D)
        srcs = ",".join(sorted(info["sources"]))
        src_colored = []
        for s in sorted(info["sources"]):
            if "crt.sh" in s: src_colored.append(c(s, C.C))
            elif "certspotter" in s: src_colored.append(c(s, C.M))
            elif "certstream" in s: src_colored.append(c(s, C.B))
            elif "otx" in s: src_colored.append(c(s, C.Y))
            elif "axfr" in s: src_colored.append(c(s, C.G))
            elif "nsec" in s: src_colored.append(c(s, C.G))
            elif "brute" in s: src_colored.append(c(s, C.R))
            elif "tls" in s: src_colored.append(c(s, C.M))
            elif "CT-direct" in s: src_colored.append(c(s, C.B))
            else: src_colored.append(s)
        print(f"{C.W}{sub:<55}{C.X} {dt:<15} {', '.join(src_colored)}")

    print(f"\n{C.BD}{C.C}═══ PER-SOURCE STATS ═══{C.X}  {C.D}(missing = others filled gap){C.X}")
    for k, v in stats.items():
        if "OK" in v:
            print(f"  {c('✓', C.G)} {c(k, C.W)}: {c(v, C.G)}")
        elif "SKIP" in v:
            print(f"  {c('⊘', C.Y)} {c(k, C.W)}: {c(v, C.Y)}")
        else:
            print(f"  {c('✗', C.R)} {c(k, C.W)}: {c(v, C.R)}")

    if output_file:
        with open(output_file, "w") as f:
            for sub in sorted(results):
                f.write(sub + "\n")
        print(f"\n{c('✓', C.G)} {c('Saved:', C.W)} {C.G}{output_file}{C.X} ({total} subdomains)")

def main():
    print(BANNER)

    ap = argparse.ArgumentParser(
        description="SUBS-VIA-CERTS v3 - 3-phase CT subdomain enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.D}examples:{C.X}
  python3 ct_subs.py target.com                    # full 3-phase
  python3 ct_subs.py target.com --no-active        # passive only
  python3 ct_subs.py target.com -w wordlist.txt    # custom wordlist
  python3 ct_subs.py target.com -o subs.txt        # save to file
        """
    )
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
            print(info(f"loaded custom wordlist: {len(wordlist)} entries"))
        except Exception as e:
            print(warn(f"wordlist load failed: {e}, using builtin ({len(DEFAULT_WORDLIST)} entries)"))

    print_target(domain)

    # ═══ PHASE 1 ═══
    print_phase_header(1, 3, "crt.sh (primary CT mirror)")
    if not args.no_crtsh:
        source_crtsh(domain)
    else:
        print(warn("skipped (--no-crtsh) → other phases fill gap"))

    # ═══ PHASE 2 ═══
    print_phase_header(2, 3, "direct CT logs + caches (certspotter, certstream, OTX)")
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
        print(warn("skipped (--no-ct) → crt.sh + active fill gap"))

    # ═══ PHASE 3 ═══
    if not args.no_active:
        print_phase_header(3, 3, "active direct (AXFR → NSEC → bruteforce → TLS SAN)")
        ns_list = get_auth_ns(domain)
        print_ns(ns_list)
        try_axfr(domain, ns_list)
        try_nsec_walk(domain, ns_list)
        wordlist_bruteforce(domain, wordlist)
        tls_san_expansion(domain)
    else:
        print_phase_header(3, 3, "active direct")
        print(warn("skipped (--no-active) → passive phases fill gap"))

    # ═══ RESULTS ═══
    print_summary(domain, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{warn('interrupted by user')}")
        sys.exit(130)
