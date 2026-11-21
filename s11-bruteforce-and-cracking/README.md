# s11 — Brute Force and Cracking

**Student:** Muhammad Zain Nasir  
**Program:** DFCS Bootcamp – PSEBCYBERISB02  
**Repository:** https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s11-bruteforce-and-cracking

## Contents

| File | Description |
|------|-------------|
| `Part-A-BruteForce.md` | DVWA Intruder attacks at Low / Medium / High security (15 Marks) |
| `Part-B-Steganography.md` | steghide embed, detect, stegcracker passphrase crack, extract (15 Marks) |
| `Part-C-ArchiveCracking.md` | zip2john + john — $pkzip$ hash format and protection analysis (10 Marks) |
| `Part-D-CVE.md` | CVE-2011-2523 reproduction report — vsftpd 2.3.4 backdoor (10 Marks) |
| `screenshots/` | Evidence screenshots (2a-xx = brute force, 2b-xx = stego, 2c-xx = zip, 2d-xx = CVE) |

## Screenshot Index

| File | Description |
|------|-------------|
| 2a-01-low-intruder-results-success.png | Low — Intruder results, password cracked |
| 2a-03-medium-intruder-results-success.png | Medium — Intruder results, password cracked |
| 2a-04-medium-cookie-header-positions.png | Medium — Positions tab with valid security=medium cookie |
| 2a-05-high-intruder-positions-with-token.png | High — static CSRF token in Intruder request |
| 2a-06-high-intruder-results-all-blocked.png | High — all 302 rejections |
| 2a-07-high-csrf-token-incorrect-messages.png | High — CSRF token incorrect messages |
| 2b-01-carrier-jpg-properties.png | Carrier JPEG file properties |
| 2b-02-steghide-install.png | steghide installation |
| 2b-03-baseline-capacity-check.png | steghide info on clean carrier |
| 2b-04-embed-and-filesize-diff.png | Embed complete; file size comparison |
| 2b-05-stego-info-and-stegcracker-install.png | Detection attempt without passphrase + stegcracker install |
| 2b-06-stegcracker-success.png | Passphrase cracked: AssignmentSecret123 |
| 2b-07-extracted-content-verified.png | Recovered payload matches original |
| 2c-01-zip-creation.png | Password-protected ZIP creation |
| 2c-02-zip2john-hash-and-john-crack.png | zip2john hash extraction and john crack |
| 2d-01-metasploitable2-ifconfig.png | Metasploitable2 ifconfig |
| 2d-02-kali-ip-a.png | Kali ip a |
| 2d-03-kali-ping-metasploitable-success.png | Kali → Metasploitable2 ping (reachable) |
| 2d-04-host-ping-metasploitable-via-vmnet.png | Host ping via VMnet |
| 2d-05-metasploitable-ping-internet-usage-error.png | Metasploitable internet ping — usage error |
| 2d-06-host-ipconfig-separate-subnet.png | Host on separate 192.168.132.0/24 subnet |
| 2d-07-metasploitable-ping-internet-unreachable.png | Metasploitable → internet: unreachable |
| 2d-08-nmap-vsftpd-234-confirmed.png | Nmap confirms vsftpd 2.3.4 |
| 2d-09-msf-search-vsftpd-use-module.png | Metasploit search and use |
| 2d-10-msf-show-options.png | Metasploit show options |
| 2d-11-msf-payload-list.png | Payload selection |
| 2d-12-msf-exploit-shell-opened.png | Shell session opened |
| 2d-13-root-shell-id-whoami.png | id and whoami — root confirmed |
| 2d-14-root-shell-uname-hostname.png | uname -a and hostname |
