# Task 1, Part C — Remediation (10 Marks)

**Shared root cause:** both vulnerabilities come from the same underlying mistake — user-controlled input reaching a powerful interpreter (the filesystem's `include()`, or the SQL engine) with no validation and no separation between "code/structure" and "data." In the LFI case, `$_GET['page']` was passed directly into `include()`, letting an attacker redefine *which code* runs. In the SQLi case, `$_GET['id']` was concatenated directly into a SQL string, letting an attacker redefine *what the query itself does*, not just what value it searches for.

## Comparison table

| | File Inclusion | SQL Injection |
|---|---|---|
| **Root cause** | User input passed directly to `include()`/`require()` | User input concatenated directly into a SQL string |
| **Primary fix** | Never let user input choose a filename/path. Use a hardcoded **allowlist** mapping short keys (e.g. `page=file1`) to actual filenames server-side; only `include()` the mapped value. | Use **parameterized queries / prepared statements** (mysqli/PDO bound parameters) so user input is always treated as data, never as SQL syntax. |
| **Secondary hardening** | Disable `allow_url_fopen`/`allow_url_include` (blocks RFI); run the web process with minimal filesystem read access (chroot/jail); treat traversal-sequence stripping as defense-in-depth only. | Enforce least-privilege DB accounts (no `FILE`, `DROP`, or cross-schema rights for the web app's DB user); disable verbose SQL errors in production. |
| **What doesn't fully fix it** | Blocklisting strings like `../` or `.php` — trivially bypassed (encoding, null bytes, wrappers like `php://filter`). | Manual escaping (`addslashes()`) — easy to miss edge cases (encoding tricks, numeric/unquoted contexts, as seen with our own `id` parameter). |
| **Role of a WAF** | Catches obvious `../../../etc/passwd` patterns but is bypassed by encoding or log-poisoning (as demonstrated in Part A). | Catches common payloads (`UNION SELECT`, `' OR 1=1`) but bypassed by encoding, comments, or alternate syntax. |

A WAF is **defense-in-depth only, never the fix**. It filters known-bad patterns in front of the vulnerable code but doesn't change the code itself; new payload variations or misconfigurations slip through. The real fix (allowlisting / parameterization) must happen in the application logic.

## Why an allowlist beats a blocklist, in both cases

A blocklist tries to enumerate every *bad* input — but attackers only need one variation the defender didn't think of (different encoding, null byte, case change, a wrapper like `php://filter/convert.base64-encode/resource=`). The set of "bad" inputs is effectively infinite. An **allowlist** instead enumerates the small, finite set of *good*, expected inputs (exact filenames for LFI; parameter placeholders for SQLi) and rejects everything else by default. This flips the security model from "block what I can think of" to "only allow what I explicitly expect" — strictly stronger, since it doesn't depend on the defender's imagination keeping pace with the attacker's creativity.
