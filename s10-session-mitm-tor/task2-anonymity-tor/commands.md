# Task 2 — Anonymity and the Dark Web: Commands Log

> **Redaction note:** per the assignment instruction *"No real IP exposed in a shared document,"* the real public IP address and precise location fields (city, region, coordinates, postal code) captured during Step 1 have been replaced with `[REDACTED]` in both this file and the corresponding screenshots. Tor exit-node IPs (which are not personally identifying) are shown unredacted, as is the private lab IP range used in Step 3's leak test and `scanme.nmap.org`'s public IP (an intentionally public nmap test target).

## 1. Your IP

- Command 1: `curl -s https://api.ipify.org` → `[REDACTED - real IP]`
- Command 2: `curl -s https://ipinfo.io/json` →
  ```json
  {
    "ip": "[REDACTED - real IP]",
    "city": "[REDACTED]",
    "region": "[REDACTED]",
    "country": "PK",
    "loc": "[REDACTED]",
    "org": "AS24499 Telenor Pakistan",
    "postal": "[REDACTED]",
    "timezone": "Asia/Karachi"
  }
  ```
- Command 3: browserleaks.com/ip — confirms the same public IP (`[REDACTED - real IP]`), and additionally reports: ISP/Organization (Telenor Pakistan), usage type (Cellular), a geolocation map, full WHOIS (including named technical/abuse contacts at the ISP), browser TCP/IP fingerprint (reports host OS as Windows, link type "Probably IPsec or other VPN", MTU 1400, 20 hops — notable since the underlying VM is Linux, suggesting some NAT/VPN layer between the VM and the public internet is altering the visible fingerprint), TLS/JA3/JA4 fingerprints, and a direct **Tor Relay check** confirming this IP is not a known Tor exit/relay node.

**Difference between the three, in one sentence:** `ipify` returns only the bare IP address with nothing else; `ipinfo.io/json` returns the same IP plus geolocation, ISP/organization, and timezone metadata; `browserleaks.com` goes further still, adding WHOIS ownership/abuse-contact details, a Tor-relay-status check, and client-side fingerprinting (TCP/IP, TLS, HTTP headers) that the plain IP lookups don't attempt at all.

- Evidence: `images/1_ipify_result.png`, `images/1_ipinfo_json_result.png`, `images/1_browserleaks_ip_top.png`, `images/1_browserleaks_fingerprint.png`, `images/1_browserleaks_tor_relay_check.png`, `images/1_browserleaks_whois.png`, `images/1_browserleaks_whois_cont.png`

## 2. Tor service

- Install (not present by default on this Kali image): `sudo apt update && sudo apt install tor -y`
- Start: `sudo service tor start`
- Confirm listening: `sudo ss -tlnp | grep 9050` → `LISTEN 0 4096 127.0.0.1:9050`
- Fetch IP directly (no Tor): `curl -s https://api.ipify.org` → `[REDACTED - real IP]`
- Fetch IP through Tor: `curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org` → `192.42.116.59`
- Why they differ: the direct request leaves Kali's NIC straight out to the internet, so the destination server sees the real originating IP, assigned by the local ISP (Telenor Pakistan). The Tor request instead gets wrapped in several layers of encryption and relayed through at least three hops of the Tor network (guard → middle → exit relay) before reaching the destination; the server only ever sees the IP address of the final **exit relay** (`192.42.116.59`, a known Tor node in a completely different network/region), never the client's real address — this is the core anonymity property Tor provides.
- Evidence: `images/2_tor_installed_started_listening.png`, `images/2_direct_vs_tor_ip.png`

## 3. Tor leak

- Install: `sudo apt install proxychains4 -y`
- curl through proxychains:
  ```
  proxychains4 curl -s https://api.ipify.org
  [proxychains] Strict chain ... 127.0.0.1:9050 ... api.ipify.org:443 ... OK
  104.244.72.115
  ```
  → correctly tunneled: explicit "Strict chain ... OK" trace shown, and the returned IP is a *different* Tor exit than Step 2's (`104.244.72.115` vs `192.42.116.59`), confirming a genuinely new, independent circuit.

- `nmap -sS` through proxychains: `sudo proxychains4 nmap -sS -p 80,443 scanme.nmap.org` → reported port 80 open in 0.038s, **no "Strict chain ... OK" trace line printed at all** (only generic DLL-preload messages). Confirmed via `sudo tcpdump -i eth0 -nn host 45.33.32.156` running in parallel: real ICMP/SYN/RST packets observed flowing directly between Kali's real interface (`192.168.153.128`) and the real target (`45.33.32.156`) — a genuine leak.

- `nmap -sT` through proxychains: `proxychains4 nmap -sT -p 80,443 scanme.nmap.org` → also **no "Strict chain ... OK" trace line**, and the parallel tcpdump capture (14 packets) again showed direct, real TCP handshake traffic (SYN/SYN-ACK/RST with standard OS TCP options — MSS, SACK, timestamps, window scaling) between Kali's real IP and `45.33.32.156`, identical in character to the `-sS` leak.

- **What actually happened (contrary to the textbook expectation that only `-sS` leaks):** both `-sS` and `-sT` leaked real traffic under proxychains in this environment, while only the plain `curl` request was verifiably tunneled. `proxychains` works by intercepting the standard `connect()` libc call via `LD_PRELOAD`; `nmap`'s internal scan engine manages its own sockets — non-blocking I/O and custom timing/event-loop code for ordinary scans, and fully raw packet crafting for `-sS` — in ways that bypass this simple hook in both modes, not just the raw-socket case. The absence of any `Strict chain ... OK` line for *either* nmap command (versus its clear presence for `curl`) was the first warning sign, and the tcpdump capture confirmed it directly on the wire as ground truth.
- Evidence: `images/3_tcpdump_syn_scan_leak_proof.png`, `images/3_nmap_sS_through_proxychains.png`, `images/3_nmap_sT_through_proxychains.png`, `images/3_tcpdump_sT_also_leaked.png`
## 4. Onion service

- Web server: `sudo apt install apache2 -y && sudo systemctl start apache2`, test page: `<h1>My Onion Service - DFCS Assignment 8</h1>` written to `/var/www/html/index.html`
- Local curl test: `curl -s http://127.0.0.1` → `<h1>My Onion Service - DFCS Assignment 8</h1>` (confirms the local service itself, independent of Tor)
- Hidden service config, appended to `/etc/tor/torrc`:
  ```
  HiddenServiceDir /var/lib/tor/my_site/
  HiddenServicePort 80 127.0.0.1:80
  ```
- Applied with: `sudo service tor restart`
- Generated address: `sudo cat /var/lib/tor/my_site/hostname` → `d4q6iwsgdhemr5ee6pjoii76zqcqriua6oes6eipqqp2ijutdgdukead.onion`
- Hostname length check: the address portion (excluding `.onion`) is **exactly 56 characters** (`d4q6iwsgdhemr5ee6pjoii76zqcqriua6oes6eipqqp2ijutdgdukead`), confirmed via Python `len()` — matches the expected length for a v3 onion service address.
- Tor Browser load: installed via `sudo apt install torbrowser-launcher -y && torbrowser-launcher`. First connection attempt failed (`CONNECTREFUSED`) — root cause was the system `tor` service (hosting the hidden service) and Tor Browser's own bundled Tor instance briefly conflicting on first launch; `sudo service tor stop` then `sudo service tor start` (restarting the system service cleanly) resolved it, and loading the address in Tor Browser then succeeded: full `.onion` URL in the address bar, Tor's onion/padlock security indicator, and the page content rendered correctly.
- Evidence: `images/4_torrc_hidden_service_config.png`, `images/4_apache_install_local_curl.png`, `images/4_onion_hostname_generated.png`, `images/4_onion_site_loaded_tor_browser.png`
## 5. Verify-config

- As root: `sudo tor --verify-config` →
  ```
  [warn] /var/lib/tor/my_site/ is not owned by this user (root, 0) but by debian-tor (121).
  Perhaps you are running Tor as the wrong user?
  [warn] Failed to parse/validate config: Failed to configure rendezvous options. See logs for details.
  [err] Reading config failed--see warnings above.
  ```
- As debian-tor: `sudo -u debian-tor tor --verify-config` →
  ```
  Configuration was valid
  ```
- Why root fails and debian-tor succeeds: Tor hardens hidden service directories by requiring that they be owned by exactly the user the daemon actually runs as in production (`debian-tor`), not by root. This directory holds the hidden service's private key, so Tor refuses to trust its contents unless the ownership precisely matches the expected runtime user — root privileges do not satisfy this check, since root is not the identity Tor expects here; being able to read/write the files at the OS level is irrelevant to Tor's own explicit "does this belong to the right user" validation. The trap is the common assumption that root can do anything a lower-privileged user can — here, running `--verify-config` as root actively fails a check that the correct, lower-privileged user passes immediately, because the test is about identity match, not permission level.
- Evidence: `images/5_verify_config_root_vs_debian_tor.png`
