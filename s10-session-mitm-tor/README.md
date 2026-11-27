# s10-session-mitm-tor

Atomcamp DFCS Bootcamp — Assignment 8

## Contents
- `report.md` / `report.pdf` — final combined write-up for both tasks (start here)
- `task1-session-interception/` — Session Interception Report (capture/filter, credential+cookie extraction, ARP-poisoning MITM)
  - GitHub folder link: https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s10-session-mitm-tor/task1-session-interception
- `task2-anonymity-tor/` — Anonymity and the Dark Web (public IP checks, Tor service, proxychains leak test, onion service, tor --verify-config)
  - GitHub folder link: https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s10-session-mitm-tor/task2-anonymity-tor

## Lab environment
- Attacker: Kali Linux (host-only network for Task 1, NAT/internet-connected for Task 2)
- Victim (Task 1 only): Metasploitable 2 (192.168.206.130), DVWA running, host-only network
- All capture and exploitation performed in an isolated VM lab segment; no production or internet-facing systems involved in Task 1.

## Privacy / redaction notes
- Task 1: live session cookie values redacted from text and screenshots per assignment instruction.
- Task 2: real public IP address and precise location fields (city, region, coordinates, postal code) redacted from text and screenshots per assignment instruction. Tor exit-node IPs and the public `scanme.nmap.org` test target are not personally identifying and are left unredacted.
