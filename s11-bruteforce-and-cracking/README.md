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


<img width="954" height="375" alt="2d-14-root-shell-uname-hostname" src="https://github.com/user-attachments/assets/168c1a0f-905f-47a1-a5ea-0808168461c5" />
<img width="951" height="304" alt="2d-13-root-shell-id-whoami" src="https://github.com/user-attachments/assets/5e3631db-9121-461b-9902-5a6d6f2df8b1" />
<img width="958" height="257" alt="2d-12-msf-exploit-shell-opened" src="https://github.com/user-attachments/assets/97bd83bb-a52f-425d-958f-fe756a7dbdd1" />
<img width="948" height="706" alt="2d-11-msf-payload-list" src="https://github.com/user-attachments/assets/ecc7313d-7010-4d9d-8004-6aa087146f54" />
<img width="955" height="872" alt="2d-10-msf-show-options" src="https://github.com/user-attachments/assets/ce0ef570-7f8d-4a56-a68c-56a817cd9dce" />
<img width="956" height="775" alt="2d-09-msf-search-vsftpd-use-module" src="https://github.com/user-attachments/assets/e3a2a778-5db4-4d29-a9a8-aebdb1625e89" />
<img width="805" height="284" alt="2d-08-nmap-vsftpd-234-confirmed" src="https://github.com/user-attachments/assets/ec147141-3192-435e-8922-b1b11fcf716b" />
<img width="523" height="80" alt="2d-07-metasploitable-ping-internet-unreachable" src="https://github.com/user-attachments/assets/60462c9b-d520-4e59-bcce-88c33319af88" />
<img width="668" height="814" alt="2d-06-host-ipconfig-separate-subnet" src="https://github.com/user-attachments/assets/ecc3d492-d940-4de7-88b0-f0288bf438b9" />
<img width="711" height="106" alt="2d-05-metasploitable-ping-internet-usage-error" src="https://github.com/user-attachments/assets/3f0e2e43-80eb-470a-8a9f-4892f8004e6f" />
<img width="817" height="630" alt="2d-04-host-ping-metasploitable-via-vmnet" src="https://github.com/user-attachments/assets/5676cfff-a937-46d3-a760-89cd60f3ee86" />
<img width="583" height="290" alt="2d-03-kali-ping-metasploitable-success" src="https://github.com/user-attachments/assets/0733f3a2-62b1-4d33-b325-2701d4bebda8" />
<img width="859" height="332" alt="2d-02-kali-ip-a" src="https://github.com/user-attachments/assets/b85169e9-03f3-487a-84c1-434661ebedd3" />
<img width="807" height="545" alt="2d-01-metasploitable2-ifconfig" src="https://github.com/user-attachments/assets/80073a0a-8ca1-40cd-b22c-6bafcc6a76b1" />
<img width="952" height="794" alt="2c-02-zip2john-hash-and-john-crack" src="https://github.com/user-attachments/assets/fac364d2-2049-445c-a3c1-719a856a4c2f" />
<img width="719" height="169" alt="2c-01-zip-creation" src="https://github.com/user-attachments/assets/ebf607fc-1b8e-42f5-a686-666b8cda3909" />
<img width="548" height="134" alt="2b-07-extracted-content-verified" src="https://github.com/user-attachments/assets/f7e19e4b-73b7-41f3-9128-8a29d8d32737" />
<img width="959" height="876" alt="2b-06-stegcracker-success" src="https://github.com/user-attachments/assets/40400ca0-6828-4a0a-8cd8-1fb6a268af8a" />
<img width="797" height="520" alt="2b-05-stego-info-and-stegcracker-install" src="https://github.com/user-attachments/assets/61e80881-14ec-43a8-8374-441de47d6e83" />
<img width="948" height="244" alt="2b-04-embed-and-filesize-diff" src="https://github.com/user-attachments/assets/80348bef-985f-4388-808e-b8ef4ae5a752" />
<img width="887" height="273" alt="2b-03-baseline-capacity-check" src="https://github.com/user-attachments/assets/cc3d2847-f31c-43f8-83a8-2aeb1e910ab9" />
<img width="886" height="804" alt="2b-02-steghide-install" src="https://github.com/user-attachments/assets/1c666be3-b7bf-4301-bcab-4f296d00ab54" />
<img width="621" height="553" alt="2b-01-carrier-jpg-properties" src="https://github.com/user-attachments/assets/89a61c70-5c9e-444f-8f6c-0138c5ed4245" />
<img width="940" height="792" alt="2a-07-high-csrf-token-incorrect-messages" src="https://github.com/user-attachments/assets/99090677-e989-41a8-97f8-c155007b64b2" />
<img width="964" height="668" alt="2a-06-high-intruder-results-all-blocked" src="https://github.com/user-attachments/assets/7d49798f-4dc3-4535-a260-b5d2329bc94b" />
<img width="954" height="897" alt="2a-05-high-intruder-positions-with-token" src="https://github.com/user-attachments/assets/726d4372-1a02-40b8-a365-08fa278dadf9" />
<img width="952" height="893" alt="2a-04-medium-cookie-header-positions" src="https://github.com/user-attachments/assets/1cadeeb2-a31d-40d4-9a9a-c3f8d581ec84" />
<img width="957" height="785" alt="2a-03-medium-intruder-results-success" src="https://github.com/user-attachments/assets/de9b3367-5807-448e-b301-cc8675da9471" />
<img width="963" height="833" alt="2a-01-low-intruder-results-success" src="https://github.com/user-attachments/assets/58b4b2d8-8b86-4273-bf36-c6d83d4ebdae" />

