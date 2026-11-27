# Task 1 — Session Interception Report: Commands Log

## A. Capture and filter

### A.1 — Capture
- Capture filter used: `host 192.168.206.130`
- Reason: captures every frame to and from the victim regardless of port/protocol, in a single raw file that can be re-filtered multiple ways for the exercises below (narrower filters like `tcp port 80` would have excluded ARP/ICMP traffic needed elsewhere in the assignment).
- Traffic generated: Firefox browsing to DVWA (192.168.206.130), login (admin/password), logout/login cycle, and visits to all vulnerability pages (Brute Force, Command Execution, CSRF, File Inclusion, SQL Injection, SQL Injection Blind, Upload, XSS reflected, XSS stored) to generate sufficient volume.
- Frame count: **1013** (verified both in Wireshark status bar and independently by parsing the .pcapng Enhanced Packet Block count)
- Evidence: `images/A1_capture_1013_frames.png`, `captures/session_capture.pcapng`

### A.2 — Display filters and frame counts
- Traffic to and from target: `ip.addr == 192.168.206.130` → **1009 / 1013 (99.6%)**. Note: not 100% — the 4 unmatched frames are ARP frames from the capture, which have no IP layer and so cannot match an `ip.addr` filter even though they involve the target's MAC.
- Traffic from target only: `ip.src == 192.168.206.130` → **442 / 1013 (43.6%)**, roughly half the to/from total, as expected for one direction of a bidirectional exchange.
- HTTP requests only: `http.request` → **116 / 1013 (11.5%)** — only client-to-server requests, excluding HTTP responses, TCP handshakes/ACKs, and keep-alives.
- Evidence: `images/A2_filter_to_and_from_target.png`, `images/A2_filter_from_target_only.png`, `images/A2_filter_http_requests.png`

### A.3 — Range-filter trap
- Wrong form: `ip.addr >= 192.168.206.129 && ip.addr <= 192.168.206.129` → **1009 / 1013 (99.6%)**
- Correct form: `ip.addr == 192.168.206.129` → **0 / 1013 (0.0%)**
- Why the wrong one over-matches: `ip.addr` matches a packet if *either* its source or its destination satisfies the condition — the two halves of the expression (`>=129` and `<=129`) are each evaluated independently against src/dst, not jointly against one single address. A packet with `src=192.168.206.128, dst=192.168.206.130` passes `ip.addr >= .129` because `.130` (the dst) satisfies it, and separately passes `ip.addr <= .129` because `.128` (the src) satisfies it — so the AND of the two conditions is true even though no single field in the packet equals, or is bounded by, `.129` at all. The filter was written intending "match the single host .129," but because no host named .129 exists in this capture, the correct form (`ip.addr == 192.168.206.129`) correctly returns 0, while the broken range form matches almost the entire capture (1009/1013) by accident.
- Evidence: `images/A3_range_trap_wrong_form.png`, `images/A3_range_trap_correct_form.png`

## B. What the attacker sees

### B.1 — Credential extraction
- Command:
  ```
  tshark -r session_capture.pcapng -Y "http.request.method == POST && http.request.uri == \"/dvwa/login.php\"" -T fields -e frame.number -e urlencoded-form.key -e urlencoded-form.value
  ```
- Output:
  ```
  20   username,password,Login   admin,password,Login
  303  username,password,Login   admin,password,Login
  ```
- Two login POSTs captured (frame 20: initial login, frame 303: the deliberate relogin), both showing the credentials `admin` / `password` in cleartext, since DVWA serves this form over plain HTTP with no transport encryption.
- Note: an earlier attempt extracting `http.file_data` directly returned raw hex (e.g. `757365726e616d653d61646d696e...`), which decodes via `bytes.fromhex(...).decode()` to the same `username=admin&password=password&Login=Login` — confirming the result two ways. The `urlencoded-form.key`/`.value` fields are preferred for the report since they give directly readable output without a manual decode step.
- Evidence: `images/B1_tshark_credential_extraction.png`

### B.2 — Session cookie extraction + curl reuse
- Session cookie extraction command:
  ```
  tshark -r session_capture.pcapng -Y "http.cookie" -T fields -e frame.number -e http.cookie | head -5
  ```
- Output: `security=high; PHPSESSID=[REDACTED - live session cookie]` (consistent across frames 6, 10, 20, 23, 28 — same session throughout the whole browsing sequence)
- curl reuse command (no login performed — cookie alone):
  ```
  curl -s -i --cookie "security=high; PHPSESSID=[REDACTED - live session cookie]" http://192.168.206.130/dvwa/index.php | head -30
  ```
- Result: `HTTP/1.1 200 OK`, full DVWA dashboard HTML returned (`<title>Damn Vulnerable Web App (DVWA) v1.0.7 :: Welcome</title>`), proving the sniffed cookie alone is sufficient to impersonate the authenticated admin session — no credentials submitted.
- Negative control: an earlier attempt using the literal placeholder text instead of the real session ID correctly returned `302 Found` → redirected to `login.php` with a fresh `Set-Cookie`, confirming the server does reject an invalid/unknown session and that the success above is specifically due to the valid stolen value, not a server misconfiguration that accepts any cookie.
- Evidence: `images/B2_cookie_extraction.png`, `images/B2_curl_cookie_reuse_success.png`

### B.3 — Cookie flag assessment
- Command: `curl -s -i http://192.168.206.130/dvwa/index.php | grep -i "set-cookie"`
- Observed headers:
  ```
  Set-Cookie: PHPSESSID=[REDACTED - live session cookie]; path=/
  Set-Cookie: security=high
  ```
- Flags present: none (only `path=/` on the session cookie; the `security` cookie has no attributes at all)
- Flags missing and the attack each one enables:

  | Missing flag | Attack enabled |
  |---|---|
  | **HttpOnly** | Without it, client-side JavaScript (`document.cookie`) can read the session cookie. Combined with a reflected/stored XSS vulnerability (both present on this same DVWA instance), an attacker can inject a script that exfiltrates the victim's session cookie to an attacker-controlled server — turning a one-off XSS bug into full session takeover. |
  | **Secure** | Without it, the browser will send the cookie over plain HTTP as well as HTTPS. This is precisely what made Parts B.1/B.2 of this exercise possible: because the cookie wasn't marked Secure (and the whole app runs over HTTP anyway), it travelled across the network in cleartext, where it was captured with Wireshark and replayed with curl. |
  | **SameSite** | Without it (default `None`/unset in older browsers, or inconsistently enforced), the cookie is attached automatically to cross-site requests, enabling Cross-Site Request Forgery — a malicious page on another site can trigger state-changing requests (e.g. changing DVWA security level, submitting forms) using the victim's authenticated session without their knowledge. This matches the separate "Absence of Anti-CSRF Tokens" finding against the same application. |

- Evidence: `images/B3_set_cookie_flags.png`
- Note: the live session cookie values captured during this exercise have been redacted from this file and the corresponding screenshots (B2, B3), per the assignment's instruction not to include any live session cookie in the submission.

## C. Man in the middle

### C.1 — ARP poisoning, proof via victim's ARP table
- ip_forward confirmed OFF before starting: `cat /proc/sys/net/ipv4/ip_forward` → `0`
- ARP poisoning command (Kali, impersonating the gateway to the victim):
  ```
  sudo arpspoof -i eth0 -t 192.168.206.130 192.168.206.2
  ```
- Victim's ARP table BEFORE (not explicitly captured as a separate screenshot — flushed instead): `sudo ip -s -s neigh flush all` was used to force a clean re-learn, then `ping 192.168.206.2` was started to force a fresh ARP request/reply exchange under poisoning conditions.
- Victim's ARP table AFTER (via `arp -n`, over SSH):
  ```
  Address          HWtype  HWaddress           Flags Mask   Iface
  192.168.206.1    ether   00:50:56:C0:00:01   C            eth0
  192.168.206.2    ether   00:0C:29:0A:43:6D   C            eth0   <- poisoned
  192.168.206.128  ether   00:0C:29:0A:43:6D   C            eth0   <- real Kali MAC
  ```
  The gateway (`.2`) now shows the **identical MAC address** as Kali (`.128`) itself (`00:0C:29:0A:43:6D`) — proof the victim has been tricked into believing Kali is the router.
- Evidence: `images/C1a_arpspoof_running_on_kali.png`, `images/C1a_victim_arp_table_poisoned.png`

### C.2 — Why ip_forward is required, and what the victim observes when it is off
- With `ip_forward=0` (default) and poisoning active, the victim's ping to the real gateway produced:
  ```
  PING 192.168.206.2 (192.168.206.2) 56(84) bytes of data.
  From 192.168.206.130 icmp_seq=1 Destination Host Unreachable
  From 192.168.206.130 icmp_seq=2 Destination Host Unreachable
  ...
  ```
- Explanation: ARP poisoning only redirects traffic at Layer 2 — it makes the victim send gateway-bound packets to Kali's MAC address instead of the real router's. If Kali's kernel does not forward IP packets between interfaces (`ip_forward=0`), those packets arrive at Kali and go nowhere: Kali is not routing them onward to the real gateway, and is not the gateway itself, so the packet is simply dropped. The victim's own kernel reports this as "Destination Host Unreachable" (its own NIC immediately learns there's no route back) — in effect, poisoning without forwarding turns a stealthy interception attack into a trivially detectable denial-of-service, since legitimate traffic silently stops reaching the internet/gateway. Enabling forwarding is therefore required to keep the attack both (a) functional (victim still has connectivity) and (b) covert (no obvious outage that would prompt investigation).
- Evidence: `images/C1a_victim_ping_unreachable_forwarding_off.png`

### C.3 — Enabling forwarding and final interception proof
- Command: `sudo sysctl -w net.ipv4.ip_forward=1` → confirmed `net.ipv4.ip_forward = 1`
- Troubleshooting note (included for completeness/honesty): the lab's `route add default gw 192.168.206.2` was a dead address — `.2` never answers ARP at all (confirmed `(incomplete)` in Kali's own ARP table, and Kali itself cannot reach `.2` even with no poisoning active). The real responsive host-only network device is `192.168.206.1` (VMware's own host-only adapter), so the attack was re-targeted: `sudo arpspoof -i eth0 -t 192.168.206.130 192.168.206.1`.
- Even after retargeting to `.1` and enabling forwarding, victim pings to `.1` still show 100% packet loss — but this was confirmed to be because `.1` itself does not answer ICMP Echo at all (verified by pinging `.1` directly from Kali with poisoning completely stopped: still 100% loss, 3/3). This is unrelated to whether the MITM is working.
- Final proof of interception (independent of whether `.1` replies): `sudo tcpdump -i eth0 -nn icmp` on Kali, while the victim ran `ping -c 5 192.168.206.1`, captured:
  ```
  20:32:58 IP 192.168.206.130 > 192.168.206.1: ICMP echo request, id 29718, seq 1
  20:32:59 IP 192.168.206.130 > 192.168.206.1: ICMP echo request, id 29718, seq 2
  20:33:00 IP 192.168.206.130 > 192.168.206.1: ICMP echo request, id 29718, seq 3
  20:33:03 IP 192.168.206.130 > 192.168.206.1: ICMP echo request, id 29718, seq 4
  20:33:03 IP 192.168.206.128 > 192.168.206.130: ICMP redirect 192.168.206.1 to host 192.168.206.1
  20:33:03 IP 192.168.206.130 > 192.168.206.1: ICMP echo request, id 29718, seq 5
  ```
  These are packets addressed (at the IP layer) from the victim to the gateway, yet they physically arrived on **Kali's own interface** — direct proof that Layer-2 interception is working, regardless of whether the final destination answers.
- Incidental finding worth noting in the report: Kali's own kernel issued an `ICMP redirect` back to the victim ("talk to 192.168.206.1 directly, don't route through me") after noticing the destination is on the same subnet it just forwarded to. This is a real weakness of naive ARP-poisoning MITM — a victim OS that honors ICMP redirects can partially self-heal around the attacker's position mid-attack, which is one reason real MITM tooling (e.g. ettercap, bettercap) typically also suppresses or filters outgoing ICMP redirects on the attacker host.
- Evidence: `images/C1b_kali_direct_ping_fails_no_mitm.png`, `images/C1c_arpspoof_restarted_target_gateway1.png`, `images/C1c_tcpdump_listening.png`, `images/C1c_victim_ping_to_gateway1.png`, `images/C1c_victim_ping_stats_100pct_loss.png`, `images/C1c_tcpdump_intercepted_icmp_proof.png`

### C.4 — Three client controls, in deployment order
1. **Dynamic ARP Inspection (DAI) / Port Security on the office switch** — deployed first because it stops the attack at its root: a managed switch validates ARP replies against a trusted binding table (DHCP snooping database or static bindings) and simply drops forged ARP packets before they ever reach other hosts. Stops: all ARP-based MITM on that segment, trivially and with no client-side changes needed. Does not stop: any attack that doesn't rely on ARP spoofing (e.g. a rogue DHCP server, a compromised switch port with a legitimate MAC, or an attacker who is the actual default gateway).
2. **Enforce HTTPS/TLS end-to-end for the application (HSTS + redirect HTTP→HTTPS)** — deployed second because even if an attacker still achieves a MITM position (e.g. on an unmanaged guest network DAI doesn't cover), TLS makes the intercepted traffic unreadable and the session cookie unreplayable without also defeating certificate validation. Stops: credential/cookie sniffing in cleartext (exactly what happened in Parts B.1/B.2 of this report), and (with the `Secure` cookie flag added) stops the cookie being sent over any downgraded HTTP connection at all. Does not stop: an attacker who can also perform a TLS-stripping or rogue-CA attack, or application-layer issues unrelated to transport encryption (e.g. XSS, CSRF — see B.3).
3. **Set HttpOnly, Secure and SameSite on the session cookie at the application layer** — deployed third/last because it's a defense-in-depth layer that specifically narrows the blast radius if the first two controls are ever bypassed or misconfigured. Stops: JavaScript-based cookie theft via XSS (HttpOnly), the cookie ever being sent over a plaintext channel (Secure), and the cookie being attached to forged cross-site requests (SameSite). Does not stop: an attacker already holding a valid MITM position who also controls a valid certificate, nor does it protect data in requests that legitimately need cross-site cookie delivery if SameSite is set too loosely.
