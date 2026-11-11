# DFCS Bootcamp — Day 5: Web Application Pentesting & Recon

**Student:** Muhammad Zain Nasir
**Program:** Digital Forensics & Cyber Security Bootcamp — PSEB-CYBER-ISB-02
**Trainer:** Waseem Abbas Khan
**Repo folder:** `s09-web-recon`

This assignment covers four tasks from the Day 5 handout: a scope document, a
Google dork report, subdomain reconciliation, and a comparison of ZAP and
Burp Suite against a local vulnerable target.

---

## Task 1 — Scope Document and Rules of Engagement (25%)

**Scenario:** A hypothetical web application penetration test of `*.intel.com`.

### 1.1 Engagement Overview

This document defines the scope and rules of engagement for a web
application penetration test of `*.intel.com`, conducted under written
authorization from the client. The engagement is **grey-box**: testers are
supplied with two sets of test credentials, one per user role, so that
authenticated functionality is reached rather than only the public login
page.

### 1.2 In Scope

- `*.intel.com` — all subdomains, current and newly discovered during the
  engagement window
- IP range: `198.51.100.0/24` *(placeholder — replaced with the client's
  published range in a real engagement)*
- All REST and internal APIs reachable under the above domains

### 1.3 Explicitly Out of Scope

- `career.intel.com` — third-party-hosted recruiting platform, excluded by
  name at the client's request
- Any third-party service or CDN endpoint merely pointed at the `intel.com`
  zone (e.g. a vendor's shared infrastructure), unless separately authorized
- Physical security and social engineering (see §1.5)

### 1.4 Break-Glass Clause

Because `*.intel.com` is a wildcard scope, it may include subdomains unknown
to the client at contract signing, or created during the test window.
Before testing any newly discovered host not already confirmed in scope:

1. The tester contacts the named Engagement Point of Contact (§1.7).
2. Written authorization (email is sufficient) is received and logged
   **before** active testing begins on that host.
3. The authorization is appended to the engagement log and included in the
   final report.

### 1.5 Prohibited Techniques

- No denial-of-service testing or any technique likely to degrade
  production availability
- No social engineering (phishing, pretexting, physical intrusion) unless
  separately scoped and authorized in writing
- No destructive actions — no deleting, encrypting, or corrupting data,
  under any circumstance
- No testing outside the agreed testing window without prior written
  authorization

### 1.6 Access Granted

- Two test accounts, one per application role (standard user,
  administrator), provisioned before testing begins
- VPN access to any internal-only staging environments in scope
- Jump-server details (hostname, port, credentials) where applicable
- **Box classification:** Grey-box

### 1.7 Testing Window and Emergency Contact

| Field | Value |
|---|---|
| Testing dates | [Start date] – [End date] |
| Testing hours | Business hours only, [time zone], to limit production impact |
| Engagement Point of Contact | [Name], [Direct phone], [Email] — authorizes break-glass requests and receives critical-finding notifications |
| Emergency stop procedure | Any tester who believes testing caused unintended impact halts all activity immediately, notifies the Point of Contact by phone, and documents the incident within one hour |

### 1.8 Rules of Engagement

- Written authorization, signed by an authorized client representative,
  is obtained before the first packet is sent.
- Testers test only what is listed in §1.2, subject to the break-glass
  clause (§1.4) for wildcard discoveries.
- **Data minimization:** if customer or personal data is encountered (e.g.
  via SQL injection or an exposed file), testers access and document the
  minimum necessary to prove impact — one record, one file — and never
  bulk-copy or exfiltrate a data store.
- **No destructive actions** are permitted at any point, authorized or not,
  without separate written sign-off naming the specific action.
- **Stop on critical finding:** any Critical-severity finding (e.g.
  unauthenticated remote code execution, full database compromise) is
  reported to the Point of Contact within 24 hours, rather than held for
  the final report.
- **Prompt reporting:** findings are delivered in the final report within
  [X] business days of testing completion.
- **Data destruction:** any test data, credentials, or copies of client
  data obtained during testing are destroyed within 30 days of report
  delivery, with written confirmation sent to the client.

---

## Task 2 — Google Dork Report (25%)

**Target:** `vulnweb.com` — a deliberately vulnerable demonstration site
published by Acunetix for security training.

> All queries below were run passively against Google's existing index. No
> page was opened, logged into, tested, or exploited. `vulnweb.com` is
> intentionally vulnerable, so the exposures below are expected; they are
> documented here, with remediation, exactly as they would be for a real
> client engagement.

### 2.1 Dork Table

| # | Dork | What it found | Why it matters | Fix |
|---|---|---|---|---|
| 1 | `site:vulnweb.com -www` | Subdomains `rest`, `testasp`, `testaspnet` indexed, with deep paths (`/about`, `/showthread`, `/Comments`) | Maps hosts and pages without sending a single packet to the target; matches the subdomain enumeration in Task 3 | `noindex` on non-public hosts, Search Console removal requests, authentication/VPN in front of staging and test hosts |
| 2 | `site:vulnweb.com` | The `rest` listing's own snippet discloses: Ubuntu 18, Apache, PHP 7.1, MySQL, supported auth types (JWT, Basic, OAuth2) | Technology and version disclosure narrows an attacker's research to known CVEs; PHP 7.1 is end-of-life | Remove stack details from page descriptions/metadata; `ServerTokens Prod`; `expose_php = Off`; upgrade unsupported software |
| 3 | `site:vulnweb.com inurl:admin` | `https://testphp.vulnweb.com/admin/` indexed | An administrative interface should never be discoverable via search | Restrict by IP/VPN, require MFA, `noindex`, never link it publicly |
| 4 | `site:vulnweb.com inurl:login` | Login pages indexed on `testphp`, `testasp` (acuforum), `testaspnet` (acublog) | Each page is a ready-made target for credential attacks | `noindex`, rate limiting, account lockout, MFA |
| 5 | `site:vulnweb.com filetype:php` | `signup.php` and `listproducts.php` on `testphp` indexed | Exposes dynamic script entry points; parameterized scripts like `listproducts.php` are classic injection candidates | Parameterized queries, input validation, clean URLs instead of raw script names, WAF |
| 6 | `site:vulnweb.com intitle:"index of"` | Exact phrase: no match. Fallback (unquoted) surfaced `testphp.vulnweb.com/pictures/` as a candidate directory path (unverified — not opened) | A bare directory path is a candidate for directory listing | `Options -Indexes` in Apache; add an index file; store uploads outside the web root |

**Negative results (also evidence):**

- `site:vulnweb.com intext:"sql syntax"` — **no matches.** No database error
  messages are currently indexed.
- `site:vulnweb.com ext:sql OR ext:bak OR ext:log` — **no matches.** No
  backup, dump, or log files are currently indexed.

### 2.2 Screenshots

![site:vulnweb.com](images/task2-dork01-site-vulnweb.png)
*Dork 1: `site:vulnweb.com`*

![site:vulnweb.com -www](images/task2-dork02-site-minus-www.png)
*Dork 2: `site:vulnweb.com -www`*

![site:vulnweb.com inurl:admin](images/task2-dork03-inurl-admin.png)
*Dork 3: `site:vulnweb.com inurl:admin`*

![site:vulnweb.com intitle:"index of"](images/task2-dork04-intitle-index-of.png)
*Dork 4: `site:vulnweb.com intitle:"index of"`*

![site:vulnweb.com filetype:php](images/task2-dork05-filetype-php.png)
*Dork 5: `site:vulnweb.com filetype:php`*

![site:vulnweb.com intext:"sql syntax" (no results)](images/task2-dork06-intext-sql-syntax-noresult.png)
*Dork 6: `site:vulnweb.com intext:"sql syntax"` — no results*

![site:vulnweb.com inurl:login](images/task2-dork07-inurl-login.png)
*Dork 7: `site:vulnweb.com inurl:login`*

![site:vulnweb.com ext:sql OR ext:bak OR ext:log (no results)](images/task2-dork08-ext-sql-bak-log-noresult.png)
*Dork 8: `site:vulnweb.com ext:sql OR ext:bak OR ext:log` — no results*

---

## Task 3 — Subdomain Reconciliation (25%)

**Target:** `vulnweb.com`. Enumeration performed passively with three
independent tools from Kali.

### 3.1 Tool Setup

Initial tool check found `subfinder`, `assetfinder`, `sublist3r`, and
`zaproxy` missing; `amass`, `theHarvester`, and `burpsuite` were already
present. All were installed via `apt`, and `httpx-toolkit` (ProjectDiscovery)
was confirmed separately from Kali's conflicting Python `httpx` package.

![initial `which` check](images/task3-01-initial-tool-check.png)
*initial `which` check*

![tools installed, `httpx-toolkit -version`, Java confirmed](images/task3-02-httpx-toolkit-verify.png)
*tools installed, `httpx-toolkit -version`, Java confirmed*

![repo pulled, `s09-web-recon/` folder created](images/task3-03-git-repo-sync.png)
*repo pulled, `s09-web-recon/` folder created*


### 3.2 Running the Three Tools

```bash
subfinder -d vulnweb.com -all -silent | sort -u > subfinder.txt
assetfinder -subs-only vulnweb.com | sort -u > assetfinder.txt
amass enum -passive -d vulnweb.com 2>&1 | tee amass_raw.txt
amass subs -d vulnweb.com -names | sort -u > amass.txt
```

Notes from the run:

- `assetfinder` on this Kali build takes a single-dash flag (`-subs-only`),
  not the double-dash form shown in some documentation.
- `amass` v5.1.3 no longer supports `-o` to write results directly; its
  console output is progress bars only, and the actual hostnames had to be
  recovered afterwards with `amass subs -d vulnweb.com -names`.
- `sublist3r` was attempted as a possible third/fourth tool but crashed
  with `TypeError: cannot pickle '_thread.lock' object` on Python 3.14 —
  a known incompatibility of the older codebase, not a configuration
  error. It was dropped in favor of `amass`.

![](images/task3-04-subfinder-assetfinder-amass-start.png)

![](images/task3-05-amass-libpostal-download.png)

![](images/task3-06-amass-run-complete.png)

![](images/task3-07-assetfinder-amass-fixed-commands.png)

![subfinder 99 / assetfinder 7 / amass(raw) 0](images/task3-08-wordcount-results.png)
*subfinder 99 / assetfinder 7 / amass(raw) 0*

![`amass subs` recovers 7 real hostnames](images/task3-09-amass-subs-recovered.png)
*`amass subs` recovers 7 real hostnames*

![](images/task3-10-sublist3r-typo-attempt.png)

![](images/task3-11-sublist3r-crash.png)


### 3.3 Results Summary

| Tool | Hostnames found |
|---|---|
| subfinder | 99 |
| assetfinder | 7 |
| amass | 7 |
| **Union (deduplicated)** | **100** |

```bash
cat subfinder.txt assetfinder.txt amass.txt | sort -u > all_subs.txt
comm -23 subfinder.txt   <(cat assetfinder.txt amass.txt | sort -u)   # only subfinder: 92
comm -23 assetfinder.txt <(cat subfinder.txt amass.txt | sort -u)     # only assetfinder: 0
comm -23 amass.txt       <(cat subfinder.txt assetfinder.txt | sort -u)  # only amass: 0
comm -12 subfinder.txt assetfinder.txt | comm -12 - amass.txt         # all three: 5
```

| Comparison | Count |
|---|---|
| Found by all three tools | 5 (`rest`, `testaspnet`, `testhtml5`, `testphp`, `www`) |
| Unique to subfinder | 92 |
| Unique to assetfinder | 0 |
| Unique to amass | 0 |

![](images/task3-12-comm-comparison-merge.png)


Neither assetfinder nor amass found anything subfinder missed — but both
found the **bare apex domain `vulnweb.com`**, which subfinder's own output
did not include (`grep -c "^vulnweb.com$" subfinder.txt` → `0`).

### 3.4 Resolving the List

```bash
httpx-toolkit -l all_subs.txt -ip -td -sc -title -rl 5 -threads 5 -silent > live.txt
httpx-toolkit -l core.txt -ip -td -sc -title -timeout 15 -retries 2 -ports 80,443,8080 -silent | tee live_core.txt
while read h; do echo "$h,$(dig +short "$h" | head -n1)"; done < all_subs.txt > resolved.csv
```

![](images/task3-13-httpx-live-hosts.png)

![](images/task3-14-live-core-dig-check.png)

![](images/task3-15-dns-resolution-check.png)

![](images/task3-16-resolved-hosts-list.png)

![](images/task3-17-curl-testphp-timeout-confirmed.png)


| Stage | Count |
|---|---|
| Combined unique names | 100 |
| Resolve in DNS | 8 |
| Respond over HTTP (200) | 3 (`rest`, `testasp`, `testaspnet`) |

Of the 8 resolving names, 4 (`testhtml5`, `testphp`, `vulnweb.com`, `www`)
share one IP (`44.228.249.3`) and all returned a connection timeout
(`curl` exit code 28) rather than a response — one shared server issue, not
four separate findings. `localhost.vulnweb.com` resolves to the loopback
address `127.0.0.1`, a DNS misconfiguration worth noting even though it
cannot be tested directly. A control check with a name that cannot exist
(`thisdoesnotexist12345.compute.vulnweb.com`) returned nothing, ruling out
a wildcard DNS record as the explanation for the many cloud-style names.

### 3.5 Conclusion

> Subfinder returned 99 names, 92 of them found by no other tool, because it
> draws on certificate transparency logs and passive DNS datasets, which
> include many historical or machine-generated names (such as
> auto-scaling cloud load-balancer hostnames). Assetfinder and amass each
> returned 7 names that overlapped almost completely with each other and
> with subfinder's core results. Only 5 names were found by all three
> tools. Neither assetfinder nor amass found a name that subfinder had
> missed, but both found the bare domain `vulnweb.com`, which subfinder
> did not report — a concrete example of a simpler tool catching
> something a larger one missed. After DNS resolution, only 8 of the 100
> combined names resolved, and only 3 responded as live web servers. This
> demonstrates why the union of several tools is larger than any single
> tool, and why resolution is mandatory before a subdomain list is used:
> most passive-source results are historical noise rather than live
> infrastructure.

---

## Task 4 — Scanner Comparison: ZAP vs Burp Suite (25%)

**Target:** Metasploitable 2 (`192.168.206.130`) running DVWA, Security
Level: Low. Attacking machine: Kali (`192.168.206.128`), same virtual
network, isolated from the internet during testing.

![](images/task4-01-metasploitable-vm-network-settings.png)

![](images/task4-02-metasploitable-ifconfig.png)

![](images/task4-03-kali-ping-curl-metasploitable.png)

![](images/task4-04-dvwa-security-low.png)


### 4.1 OWASP ZAP

**Method:** Manual Explore (browsing every DVWA vulnerability page through
ZAP's proxy to populate the site tree), followed by a full Active Scan.

![](images/task4-05-zap-manual-explore-sites-tree.png)

![](images/task4-06-zap-sites-tree-expanded.png)

![](images/task4-07-zap-sites-tree-full.png)

![scan complete, 2,769 requests sent](images/task4-08-zap-active-scan-100pct.png)
*scan complete, 2,769 requests sent*


**Alerts — 19 distinct findings, 279 instances:**

| Risk | Count | Key findings |
|---|---|---|
| High | 3 | Path Traversal (`fi` page); Remote Code Execution — CVE-2012-1823 (13 endpoints); Source Code Disclosure — CVE-2012-1823 (13 endpoints) |
| Medium | 7 | Absence of Anti-CSRF Tokens; CSP Header Not Set; Directory Browsing; HTTP Only Site; Missing Anti-clickjacking Header; Parameter Tampering; XSLT Injection |
| Low | 5 | Cookie No HttpOnly Flag; Cookie without SameSite Attribute; Server Leaks "X-Powered-By"; Server Leaks Version via "Server" header; X-Content-Type-Options Missing |
| Informational | 4 | Authentication Request Identified; Cookie Poisoning; Session Management Response Identified; User Agent Fuzzer |

![](images/task4-09-zap-alerts-high-risk.png)

![](images/task4-10-zap-alerts-medium-risk.png)

![](images/task4-11-zap-alerts-low-risk.png)

![](images/task4-12-zap-alerts-informational.png)

![](images/task4-13-zap-generate-report-dialog.png)

![`zap_report.html`, Traditional HTML Report](images/task4-14-zap-report-summary.png)
*`zap_report.html`, Traditional HTML Report*


The two High-risk CVE-2012-1823 alerts (RCE and Source Code Disclosure)
share one root cause — an old PHP-CGI argument-injection flaw on
Metasploitable's outdated PHP — appearing across 13 URLs each because the
same vulnerable request pattern applies to every page, not 26 independent
bugs. The ZAP report's own Insights table notes that **48% of all
responses during the scan were 3xx redirects**, which explains both the
scan's long duration and why path/RCE-style findings dominated: ZAP's
crawl followed redirects extensively but did not submit the SQL Injection
or XSS forms with attacker-chosen values during the automated phase.

### 4.2 Burp Suite Community Edition

**Method:** Proxy + manual browsing (Community's automated Crawl and Audit
is disabled), followed by manual exploitation in Repeater.

![](images/task4-15-kali-restart-burpsuite-launch.png)

![](images/task4-16-burp-proxy-listener-8080.png)

![](images/task4-17-burp-browser-dvwa-login.png)

![](images/task4-18-burp-dvwa-security-low-set.png)

![](images/task4-19-burp-command-exec-manual-ping.png)

![](images/task4-20-burp-http-history-populated-1.png)

![](images/task4-21-burp-http-history-populated-2.png)

![](images/task4-22-burp-http-history-populated-3.png)

![](images/task4-23-burp-http-history-populated-4.png)

![](images/task4-24-burp-http-history-populated-5.png)


47 requests were captured in HTTP history after manually visiting and
submitting every DVWA vulnerability page (Brute Force, Command Execution,
SQL Injection, SQL Injection Blind, XSS reflected, XSS stored, Upload,
CSRF, File Inclusion).

**Manual exploitation in Repeater:**

**SQL Injection** — `GET /dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit`
returned all 5 users (admin, Gordon Brown, Hack Me, Pablo Picasso, Bob
Smith) instead of the single record for `id=1`, confirming the `id`
parameter is concatenated directly into a SQL query with no sanitization.

![](images/task4-25-repeater-sqli-request.png)


**OS Command Injection** — `POST /dvwa/vulnerabilities/exec/` with body
`ip=127.0.0.1 && whoami` returned the normal ping output followed by an
extra line, `www-data` — the result of the injected `whoami` command,
confirming the `ip` field is passed straight into a shell command.

![first attempt, empty response (debugging)](images/task4-26-repeater-exec-attempt1.png)
*first attempt, empty response (debugging)*

![corrected request (fixed `Content-Length` mismatch and the parameter name case, `submit` not `Submit`)](images/task4-27-repeater-exec-request-body.png)
*corrected request (fixed `Content-Length` mismatch and the parameter name case, `submit` not `Submit`)*

![confirmed: `www-data` in the response](images/task4-28-repeater-command-injection-confirmed.png)
*confirmed: `www-data` in the response*


### 4.3 Comparison

| | ZAP (Active Scan) | Burp Community (manual) |
|---|---|---|
| Found automatically | Path Traversal, RCE (CVE-2012-1823), Source Code Disclosure, CSRF/CSP/clickjacking gaps, cookie flags, header leaks | None — Community's scanner is disabled |
| Found by manual follow-up | — | SQL Injection, OS Command Injection |
| Missed | SQL Injection, OS Command Injection (not triggered during automated crawl) | Path Traversal, RCE, header/config issues (no automated scanner to find them) |

> ZAP's Active Scan, run after a Manual Explore pass, found 3 High-risk
> issues, 7 Medium, and 5 Low, without manual input beyond the initial
> browse. It did not report SQL Injection or OS Command Injection — both
> known to exist in DVWA — most likely because its automated crawl did not
> submit the vulnerable forms with attacker-controlled input. Burp
> Community has no automated active scanner at all, so none of ZAP's
> findings were reproduced automatically; instead, each candidate request
> was sent to Repeater and tested by hand. Changing the `sqli` page's `id`
> parameter to `1' OR '1'='1` returned all five user records, confirming
> SQL injection, and changing the `exec` page's `ip` parameter to
> `127.0.0.1 && whoami` caused the server to execute and return an
> injected command, confirming OS command injection. This shows that
> automated scanning and manual testing find different, complementary
> classes of vulnerability: a crawler-based scanner is efficient at
> path-, file-, and header-level issues it encounters while spidering,
> while an analyst working by hand through Repeater can confirm
> injection flaws that depend on submitting specific attacker-chosen
> values the automated crawl never tried. Building the manual Command
> Execution request also surfaced a practical lesson in HTTP mechanics: a
> one-byte `Content-Length` mismatch after editing the request body
> silently truncated it, and DVWA's form field is the lowercase `submit`
> rather than `Submit` — both had to be corrected before the injection
> would process, illustrating the lower-level precision manual testing in
> Burp requires compared to a GUI-driven scan.

---

## Repository Contents

```
s09-web-recon/
├── README.md                 (this file)
├── images/                   (53 screenshots, see references above)
├── subfinder.txt             (99 hostnames)
├── assetfinder.txt           (7 hostnames)
├── amass.txt                 (7 hostnames)
├── all_subs.txt              (100 deduplicated hostnames)
├── resolved.csv              (DNS resolution results)
├── live.txt / live_core.txt  (httpx-toolkit live-host results)
└── zap_report.html           (ZAP Traditional HTML Report)
```

> **Note:** the `.txt`/`.csv`/`.html` evidence files above were generated
> on the Kali VM during the lab session. Copy them from
> `/home/kali/Desktop/dfcs-bootcamp/s09-web-recon/` into this folder
> before committing, alongside this `README.md` and the `images/` folder.

