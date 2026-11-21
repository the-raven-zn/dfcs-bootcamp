# s10 — File Inclusion and SQL Injection

**Student:** Muhammad Zain Nasir  
**Program:** DFCS Bootcamp – PSEBCYBERISB02  
**Repository:** https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s10-file-inclusion-and-sqli

## Contents

| File | Description |
|------|-------------|
| `Part-A-LFI-to-RCE.md` | LFI to RCE chain: path disclosure → log poisoning → reverse shell (20 Marks) |
| `Part-B-Manual-SQLi.md` | Manual UNION-based SQL injection, full credential dump — no sqlmap (20 Marks) |
| `Part-C-Remediation.md` | Fix for file inclusion and SQL injection; allowlist vs blocklist (10 Marks) |
| `screenshots/` | Evidence screenshots (1a-xx = LFI/RCE, 1b-xx = SQLi) |

## Screenshot Index

| File | Description |
|------|-------------|
| 1a-01-lfi-etc-passwd.png | LFI confirmed — /etc/passwd read |
| 1a-02-reverse-shell-connect.png | Reverse shell received on nc listener |
| 1a-03-reverse-shell-id-pwd.png | id and pwd inside the shell |
| 1a-04-path-disclosure-warnings.png | PHP error revealing installation path |
| 1b-01-sqli-baseline-id1.png | Baseline response for id=1 |
| 1b-02-sqli-single-quote-error.png | SQL syntax error confirming injection |
| 1b-03-orderby-2-ok.png | ORDER BY 2 — OK (2 columns confirmed) |
| 1b-04-orderby-3-error.png | ORDER BY 3 — column count error |
| 1b-05-union-select-1-2.png | UNION SELECT confirming injectable columns |
| 1b-06-db-version-enum.png | Database name and version extraction |
| 1b-07-groupconcat-tables.png | Table enumeration with group_concat() |
| 1b-08-column-enum.png | Column enumeration from information_schema |
| 1b-09-final-creds-dump.png | Full credential dump with MD5 hashes |
