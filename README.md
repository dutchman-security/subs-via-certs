# ct_subs — 3-Phase Subdomain Enumeration via Certificate Transparency

**No local databases. No downloads. All internet-based. Three independent phases that fill each other's gaps.**

```
https://github.com/dutchman-security/certs-extractor
```

---

## Why This Exists

When teams deploy new subdomains (`staging-newfeature.company.com`, `api-v2.partner.company.com`, `dev-aws-migration.company.com`), they often skip the hardening applied to root/legacy hosts. No WAF, outdated TLS, exposed admin panels, debug endpoints, default creds.

Attackers monitor CT logs in real time. **We should too.**

This tool gives you that visibility — fast, complete, zero maintenance.

---

## Three Phases (All Internet-Based)

| Phase | Sources | What It Catches |
|-------|---------|-----------------|
| **[1] crt.sh** | Primary CT mirror (public API) | Every cert ever issued for `%.domain.com` — historical + new |
| **[2] Direct CT + Caches** | Google Argus, Cloudflare Nimbus, DigiCert Yeti (live STH), CertSpotter, CertStream search, OTX passive DNS | Real-time issuance, cross-log redundancy, subdomains crt.sh misses |
| **[3] Active Direct** | AXFR → NSEC/NSEC3 walk → wordlist bruteforce vs auth NS → TLS SAN expansion on every live host | *Only* what resolves **right now** — including hosts never in CT (internal CAs, self-signed, cloud LB certs) |

**Gap-filling is automatic.** If crt.sh is down, CertSpotter + CertStream + OTX cover it. If AXFR fails (normal), NSEC walk + bruteforce + TLS SAN still find live hosts. Every result tagged with source + earliest cert date.

---

## Installation

```bash
git clone https://github.com/dutchman-security/certs-extractor
cd certs-extractor

# Install dependencies
pip install -r requirements.txt
# or
pip install requests dnspython
```

**Dependencies:**
- `requests` — HTTP calls to CT APIs
- `dnspython` — optional, enables AXFR/NSEC walk/bruteforce (degrades gracefully if missing)

---

## Usage

```bash
# Full three-phase sweep (recommended)
python3 ct_subs.py target.com -o subs.txt

# Passive only (fast, safe for external recon)
python3 ct_subs.py target.com --no-active -o subs-passive.txt

# Custom wordlist for bruteforce
python3 ct_subs.py target.com -w /path/to/wordlist.txt -o subs.txt

# Skip specific phases
python3 ct_subs.py target.com --no-crtsh
python3 ct_subs.py target.com --no-ct
```

### Options

| Flag | Description |
|------|-------------|
| `domain` | Target domain (e.g., `example.com`) |
| `-w, --wordlist` | Custom wordlist file (one per line) |
| `--no-active` | Skip active direct phase (AXFR, NSEC, bruteforce, TLS SAN) |
| `--no-crtsh` | Skip crt.sh phase |
| `--no-ct` | Skip direct CT + caches phase |
| `-o, --output` | Save subdomains (one per line) to file |

---

## Demo Output

### Passive Only (`--no-active`) — `example.com`

```
[*] target: example.com

[1/3] crt.sh (primary CT mirror) ...
  [crt.sh] OK (150 raw entries)

[2/3] direct CT logs (Google/Cloudflare/DigiCert) + certstream cache ...
  [CT-direct:digicert-yeti] FAIL (HTTPSConnectionPool(host='yeti2027.ct.digicert.com', port=443): Max retries exceeded with url: /log/)
  [certstream-cache] FAIL (HTTPSConnectionPool(host='search.certstream.calidog.io', port=443): Max retries exceeded with url: /search?keyword=examp)
  [CT-direct:google-argus] FAIL (404 Client Error: Not Found for url: https://ct.googleapis.com/logs/argus2027/ct/v1/get-sth)
  [CT-direct:cloudflare-nimbus] OK (live, tree_size=362364719, ts=1789548403089)
  [certspotter(direct-CT)] OK (13 names)
  [otx(passiveDNS)] FAIL (429 Client Error: Too Many Requests for url: https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns)

[3/3] skipped (--no-active) -> passive combos fill gap

[+] total unique subdomains: 6
Subdomain                                               Earliest Cert   Sources
------------------------------------------------------------------------------------------------------------------------
example.com                                             2014-11-06      certspotter(direct-CT),crt.sh
www.example.com                                         2014-11-06      certspotter(direct-CT),crt.sh
dev.example.com                                         2016-07-14      crt.sh
m.example.com                                           2016-07-14      crt.sh
products.example.com                                    2016-07-14      crt.sh
support.example.com                                     2016-07-14      crt.sh

[*] per-source stats (missing = others filled gap):
    crt.sh: OK (150 raw entries)
    CT-direct:digicert-yeti: FAIL (HTTPSConnectionPool(host='yeti2027.ct.digicert.com', port=443): Max retries exceeded with url: /log/)
    certstream-cache: FAIL (HTTPSConnectionPool(host='search.certstream.calidog.io', port=443): Max retries exceeded with url: /search?keyword=examp)
    CT-direct:google-argus: FAIL (404 Client Error: Not Found for url: https://ct.googleapis.com/logs/argus2027/ct/v1/get-sth)
    CT-direct:cloudflare-nimbus: OK (live, tree_size=362364719, ts=1789548403089)
    certspotter(direct-CT): OK (13 names)
    otx(passiveDNS): FAIL (429 Client Error: Too Many Requests for url: https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns)
```

### Full Three-Phase — `eff.org`

```
[*] target: eff.org

[1/3] crt.sh (primary CT mirror) ...
  [crt.sh] FAIL (404 Client Error: Not Found for url: https://crt.sh/?q=%25.eff.org&output=json)

[2/3] direct CT logs (Google/Cloudflare/DigiCert) + certstream cache ...
  [certstream-cache] FAIL (HTTPSConnectionPool(host='search.certstream.calidog.io', port=443): Max retries exceeded with url: /search?keyword=eff.o)
  [CT-direct:digicert-yeti] FAIL (HTTPSConnectionPool(host='yeti2027.ct.digicert.com', port=443): Max retries exceeded with url: /log/)
  [CT-direct:google-argus] FAIL (404 Client Error: Not Found for url: https://ct.googleapis.com/logs/argus2027/ct/v1/get-sth)
  [CT-direct:cloudflare-nimbus] OK (live, tree_size=362364719, ts=1789548403089)
  [certspotter(direct-CT)] OK (104 names)
  [otx(passiveDNS)] FAIL (429 Client Error: Too Many Requests for url: https://otx.alienvault.com/api/v1/indicators/domain/eff.org/passive_dns)

[3/3] active direct (AXFR -> NSEC walk -> bruteforce vs auth NS -> TLS SAN) ...
  [auth-NS] ns1.eff.org, ns2.eff.org, ns4.eff.org
  [axfr(direct)] OK (no server allowed AXFR - normal, others fill gap)
  [nsec-walk(direct)] OK (0 names walked)
  [bruteforce(auth-NS)] OK (0/126 live)
  [tls-SAN(direct)] OK (0 new from SANs over 57 seeds)

[+] total unique subdomains: 57
Subdomain                                               Earliest Cert   Sources
------------------------------------------------------------------------------------------------------------------------
anon-stats.eff.org                                      -               certspotter(direct-CT)
aos-admin.staging.eff.org                               -               certspotter(direct-CT)
aos.staging.eff.org                                     -               certspotter(direct-CT)
cerb.eff.org                                            -               certspotter(direct-CT)
certbot-449-fix-bundle-audit-cves-admin.staging.eff.org -               certspotter(direct-CT)
certbot-449-fix-bundle-audit-cves.staging.eff.org       -               certspotter(direct-CT)
certbot-prod.eff.org                                    -               certspotter(direct-CT)
certbot.eff.org                                         -               certspotter(direct-CT)
child1.privacybadger-tests.eff.org                      -               certspotter(direct-CT)
coveryourtracks.eff.org                                 -               certspotter(direct-CT)
donations-staging.eff.org                               -               certspotter(direct-CT)
drb-449-fix-bundle-audit-cves-admin.staging.eff.org     -               certspotter(direct-CT)
drb-449-fix-bundle-audit-cves.staging.eff.org           -               certspotter(direct-CT)
eff.org                                                 -               certspotter(direct-CT)
join.eff.org                                            -               certspotter(direct-CT)
kittens-393-deeplinks-social-media-backend-admin.staging.eff.org -               certspotter(direct-CT)
kittens-393-deeplinks-social-media-backend.staging.eff.org -               certspotter(direct-CT)
kittens-420-deeplinks-mobile-feed-images-admin.staging.eff.org -               certspotter(direct-CT)
kittens-420-deeplinks-mobile-feed-images.staging.eff.org -               certspotter(direct-CT)
kittens-banner-image-cms-admin.staging.eff.org          -               certspotter(direct-CT)
kittens-banner-image-cms.staging.eff.org                -               certspotter(direct-CT)
kittens-prod.int.eff.org                                -               certspotter(direct-CT)
kittens-resource-controller-map-admin.staging.eff.org   -               certspotter(direct-CT)
kittens-resource-controller-map.staging.eff.org         -               certspotter(direct-CT)
kittens-staging.int.eff.org                             -               certspotter(direct-CT)
lists.eff.org                                           -               certspotter(direct-CT)
livestream.eff.org                                      -               certspotter(direct-CT)
log1.eff.org                                            -               certspotter(direct-CT)
mattermost-postgres.d5.eff.org                          -               certspotter(direct-CT)
mattermost-prod.d5.eff.org                              -               certspotter(direct-CT)
mattermost-testnewimage.d5.eff.org                      -               certspotter(direct-CT)
nsa-timeline.eff.org                                    -               certspotter(direct-CT)
oc-admin.eff.org                                        -               certspotter(direct-CT)
onlinecensorship-prod.beta.eff.org                      -               certspotter(direct-CT)
outage.eff.org                                          -               certspotter(direct-CT)
panopticlick.d5.eff.org                                 -               certspotter(direct-CT)
panopticlick.eff.org                                    -               certspotter(direct-CT)
privacybadger-tests.eff.org                             -               certspotter(direct-CT)
rayhunter.eff.org                                       -               certspotter(direct-CT)
redmine.eff.org                                         -               certspotter(direct-CT)
sec-449-fix-bundle-audit-cves-admin.staging.eff.org     -               certspotter(direct-CT)
sec-449-fix-bundle-audit-cves.staging.eff.org           -               certspotter(direct-CT)
sec-prod.eff.org                                        -               certspotter(direct-CT)
sls-449-fix-bundle-audit-cves-admin.staging.eff.org     -               certspotter(direct-CT)
sls-449-fix-bundle-audit-cves.staging.eff.org           -               certspotter(direct-CT)
sls-admin.eff.org                                       -               certspotter(direct-CT)
sls-prod.eff.org                                        -               certspotter(direct-CT)
ssd-449-fix-bundle-audit-cves-admin.staging.eff.org     -               certspotter(direct-CT)
ssd-449-fix-bundle-audit-cves.staging.eff.org           -               certspotter(direct-CT)
staging.eff.org                                         -               certspotter(direct-CT)
supporters.eff.org                                      -               certspotter(direct-CT)
switchboard.beta.eff.org                                -               certspotter(direct-CT)
tor.eff.org                                             -               certspotter(direct-CT)
whohasyourface.eff.org                                  -               certspotter(direct-CT)
www-prod.int.eff.org                                    -               certspotter(direct-CT)
www-staging.int.eff.org                                 -               certspotter(direct-CT)
zrpugursg.eff.org                                       -               certspotter(direct-CT)

[*] per-source stats (missing = others filled gap):
    crt.sh: FAIL (404 Client Error: Not Found for url: https://crt.sh/?q=%25.eff.org&output=json)
    certstream-cache: FAIL (HTTPSConnectionPool(host='search.certstream.calidog.io', port=443): Max retries exceeded with url: /search?keyword=eff.o)
    CT-direct:digicert-yeti: FAIL (HTTPSConnectionPool(host='yeti2027.ct.digicert.com', port=443): Max retries exceeded with url: /log/)
    CT-direct:google-argus: FAIL (404 Client Error: Not Found for url: https://ct.googleapis.com/logs/argus2027/ct/v1/get-sth)
    CT-direct:cloudflare-nimbus: OK (live, tree_size=362364719, ts=1789548403089)
    certspotter(direct-CT): OK (104 names)
    otx(passiveDNS): FAIL (429 Client Error: Too Many Requests for url: https://otx.alienvault.com/api/v1/indicators/domain/eff.org/passive_dns)
    axfr(direct): OK (no server allowed AXFR - normal, others fill gap)
    nsec-walk(direct): OK (0 names walked)
    bruteforce(auth-NS): OK (0/126 live)
    tls-SAN(direct): OK (0 new from SANs over 57 seeds)
```

---

## Output Format

```
[+] total unique subdomains: 247
Subdomain                                    Earliest Cert   Sources
------------------------------------------------------------
company.com                                  2021-03-12      crt.sh,certspotter,otx
api.company.com                              2023-07-04      crt.sh,certstream,tls-SAN
staging-newfeature.company.com               2024-11-08      certspotter,nsec-walk,tls-SAN
dev-aws-migration.company.com                2024-11-14      certstream,bruteforce,tls-SAN
forgotten-jenkins.company.com                2022-09-01      crt.sh,axfr
```

- **Earliest Cert** — first seen in CT (`-` = not in CT, found via active phase)
- **Sources** — comma-separated list of phases that found it

---

## Why This Beats `subfinder` / `amass` / `assetfinder` Alone

| Feature | ct_subs | Others |
|---------|---------|--------|
| No local DB to sync | ✅ | ❌ |
| Live TLS SAN expansion (443/8443) | ✅ | ❌ |
| NSEC/NSEC3 zone walk | ✅ | Partial |
| Source attribution per subdomain | ✅ | ❌ |
| Single file, zero config | ✅ | ❌ |
| Graceful degradation (dnspython optional) | ✅ | ❌ |
| All internet-based, no downloads | ✅ | ❌ |

---

## Recommended Workflow

```bash
# 1. Weekly cron / GitHub Action
python3 ct_subs.py crown-jewel.com -o subs_$(date +%F).txt

# 2. Diff against previous run
comm -13 <(sort subs_prev.txt) <(sort subs_new.txt) > new_subs.txt

# 3. Alert on new subdomains → feed into vuln scanner / nuclei / manual review

# 4. Track "time-to-detection" — how fast you see what attackers see
```

---

## License

MIT — use freely, modify freely.

---

## Author

**dutchman-security** — built for real recon, not checkbox compliance.
