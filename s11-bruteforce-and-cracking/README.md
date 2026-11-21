# s11 — Brute Force, Steganography, Archive Cracking & CVE Exploitation

## 👤 Author Information

| Field | Details | 
| ----- | ----- | 
| **Student Name** | Muhammad Zain Nasir | 
| **Program** | DFCS Bootcamp (PSEBCYBERISB02) | 
| **Repository URL** | [dfcs-bootcamp / s11-bruteforce-and-cracking](https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s11-bruteforce-and-cracking) | 
| **Assessment Focus** | Credential Brute-Forcing, Steganographic Analysis, Offline Hash Cracking & Vulnerability Reproduction | 

## 📌 Executive Summary

This repository documents hands-on security evaluations spanning four critical domains of cybersecurity: automated web application credential brute-forcing, steganography payload embedding and extraction, offline ZIP archive password cracking, and vulnerability reproduction of **CVE-2011-2523** (vsftpd 2.3.4 backdoor execution). 

### Key Technical Takeaways

1. **Web Brute Force Defenses (DVWA):** Analyzing HTTP request behavior across **Low**, **Medium**, and **High** security settings in DVWA. Exploring how session cookies (`security=medium`) and anti-CSRF tokens block straightforward automated attacks (e.g., Burp Suite Intruder) without macro-based token updating.

2. **Steganography Analysis (`steghide` & `stegcracker`):** Hiding secret payloads within JPEG image carrier files, evaluating file capacity and size shifts, and recovering passphrases using dictionary-based cracking tools.

3. **Archive Hash Extraction & Offline Cracking:** Extracting `$pkzip$` hashes from encrypted ZIP archives via `zip2john` and cracking them offline with `john` (John the Ripper) using wordlists (`rockyou.txt`).

4. **Vulnerability Reproduction (CVE-2011-2523):** Setting up isolated virtual network subnets ($192.168.132.0/24$), verifying target reachability, and exploiting the malicious backdoor inside vsftpd 2.3.4 to spawn an unauthenticated root shell (`uid=0`).

---

## 📁 Repository Structure

```
s11-bruteforce-and-cracking/
├── Part-A-BruteForce.md      # DVWA HTTP Intruder attacks across Low/Medium/High levels (15 Marks)
├── Part-B-Steganography.md   # Steghide embedding, stegcracker passphrase recovery (15 Marks)
├── Part-C-ArchiveCracking.md # zip2john hash extraction & John the Ripper cracking (10 Marks)
├── Part-D-CVE.md             # CVE-2011-2523 vsftpd 2.3.4 backdoor exploitation (10 Marks)
├── README.md                 # Master project documentation & evidence index (This file)
└── screenshots/              # Comprehensive proof-of-concept visual evidence
```

| File / Directory | Weightage | Core Focus & Description | 
| ----- | ----- | ----- | 
| `Part-A-BruteForce.md` | **15 Marks** | Web authentication attacks: Burp Suite Intruder setup, session cookie handling, and anti-CSRF token defense mechanisms. | 
| `Part-B-Steganography.md` | **15 Marks** | Covert data hiding: Embedding secret data into JPEG carriers via `steghide` and dictionary attacks via `stegcracker`. | 
| `Part-C-ArchiveCracking.md` | **10 Marks** | Offline hash cracking: Exporting `$pkzip$` structure via `zip2john` and recovering plaintexts with `john`. | 
| `Part-D-CVE.md` | **10 Marks** | Vulnerability reproduction report: Network isolation setup, service enumeration (`vsftpd 2.3.4`), Metasploit module execution, and root privilege verification. | 
| `screenshots/` | — | Repository media asset folder containing raw proof-of-concept images. | 

---

## 🛡️ Technical Overview & Attack Methodologies

### 1. Part A: DVWA Brute Force Attacks

* **Low Security:** No rate-limiting or CSRF tokens exist. A single dictionary attack using Burp Suite Intruder immediately identifies valid credentials based on response length and status code.
* **Medium Security:** Introduces explicit session cookie constraints (`security=medium`) and slight execution delays, but requests remain vulnerable to dictionary attacks when the session cookie is included in headers.
* **High Security:** Employs dynamic anti-CSRF tokens (`user_token`) generated per request. Standard Intruder attacks fail (returning `HTTP 302` or "CSRF token incorrect" errors) unless Burp Pitchfork/Grep-Extract macros update the `user_token` dynamically for each iteration.

### 2. Part B: Steganography Data Embedding & Extraction

* **Embedding Payload:** Hiding sensitive text payloads into cover JPEG images using `steghide embed -cf carrier.jpg -ef payload.txt`.
* **Capacity & Metadata Analysis:** Observing structural integrity and file size deltas without altering visible image quality.
* **Passphrase Recovery:** Utilizing `stegcracker` coupled with `rockyou.txt` to brute-force passphrase protection (`AssignmentSecret123`) and extract the original payload.

### 3. Part C: Encrypted Archive Password Cracking

* **Hash Extraction:** Converting encrypted ZIP metadata into a formatted hash string using `zip2john sample.zip > zip.hash`. The resulting hash follows the `$pkzip$` standard.
* **Hash Cracking:** Processing `zip.hash` with `john --wordlist=rockyou.txt zip.hash` to recover archive credentials offline without triggering application locking mechanisms.

### 4. Part D: CVE-2011-2523 (vsftpd 2.3.4 Backdoor) Reproduction

* **Network Isolation:** Configuring host and guest virtual machines (Kali Linux & Metasploitable2) on isolated subnets ($192.168.132.0/24$) without direct internet routing.
* **Reconnaissance:** Scanning port $21$ using `nmap -sV` to confirm the target is running `vsftpd 2.3.4`.
* **Exploitation:** Executing `exploit/unix/ftp/vsftpd_234_backdoor` in Metasploit Framework. Sending a username containing `:)` triggers a command shell listener on port $6200$, yielding an unauthenticated `root` shell (`uid=0(root)`).

---

## 📷 Screenshot Evidence Index

The table below catalogs all visual proof of concept assets for evaluation.

| Screenshot File | Visual Preview | Phase / Objective | Technical Description & Explanation | 
| ----- | ----- | ----- | ----- | 
| `2a-01-low-intruder-results-success.png` | <img width="280" alt="2a-01-low-intruder-results-success" src="https://github.com/user-attachments/assets/58b4b2d8-8b86-4273-bf36-c6d83d4ebdae" /> | **Low Security Brute Force** | Successful Burp Intruder attack on DVWA Low security, highlighting the unique HTTP response length for valid credentials. | 
| `2a-03-medium-intruder-results-success.png` | <img width="280" alt="2a-03-medium-intruder-results-success" src="https://github.com/user-attachments/assets/de9b3367-5807-448e-b301-cc8675da9471" /> | **Medium Security Brute Force** | Intruder results window showing successful password identification under Medium security settings. | 
| `2a-04-medium-cookie-header-positions.png` | <img width="280" alt="2a-04-medium-cookie-header-positions" src="https://github.com/user-attachments/assets/1cadeeb2-a31d-40d4-9a9a-c3f8d581ec84" /> | **Medium Position Setup** | Configuring payload positions in Burp Intruder while maintaining `security=medium` within the `Cookie` header. | 
| `2a-05-high-intruder-positions-with-token.png` | <img width="280" alt="2a-05-high-intruder-positions-with-token" src="https://github.com/user-attachments/assets/726d4372-1a02-40b8-a365-08fa278dadf9" /> | **High CSRF Token Positions** | Positioning attack vectors on DVWA High, showing the static `user_token` field in the request body. | 
| `2a-06-high-intruder-results-all-blocked.png` | <img width="280" alt="2a-06-high-intruder-results-all-blocked" src="https://github.com/user-attachments/assets/7d49798f-4dc3-4535-a260-b5d2329bc94b" /> | **CSRF Defense In Action** | Intruder result grid demonstrating total request rejection (`302 Redirection`) due to static/unhandled CSRF tokens. | 
| `2a-07-high-csrf-token-incorrect-messages.png` | <img width="280" alt="2a-07-high-csrf-token-incorrect-messages" src="https://github.com/user-attachments/assets/99090677-e989-41a8-97f8-c155007b64b2" /> | **CSRF Rejection Error** | Response preview showing explicit "CSRF token is incorrect" error messages generated by DVWA High. | 
| `2b-01-carrier-jpg-properties.png` | <img width="280" alt="2b-01-carrier-jpg-properties" src="https://github.com/user-attachments/assets/89a61c70-5c9e-444f-8f6c-0138c5ed4245" /> | **Carrier Image Check** | Inspecting properties and metadata of the initial cover image (`carrier.jpg`) before steganographic embedding. | 
| `2b-02-steghide-install.png` | <img width="280" alt="2b-02-steghide-install" src="https://github.com/user-attachments/assets/1c666be3-b7bf-4301-bcab-4f296d00ab54" /> | **Steghide Setup** | Installing `steghide` utility via `apt-get` package manager on the Linux host machine. | 
| `2b-03-baseline-capacity-check.png` | <img width="280" alt="2b-03-baseline-capacity-check" src="https://github.com/user-attachments/assets/cc3d2847-f31c-43f8-83a8-2aeb1e910ab9" /> | **Carrier Capacity Analysis** | Executing `steghide info` to analyze the maximum steganographic data embedding capacity of the cover file. | 
| `2b-04-embed-and-filesize-diff.png` | <img width="280" alt="2b-04-embed-and-filesize-diff" src="https://github.com/user-attachments/assets/80348bef-985f-4388-808e-b8ef4ae5a752" /> | **Payload Embedding** | Embedding text file into carrier JPG; comparing pre-embedding vs post-embedding file sizes. | 
| `2b-05-stego-info-and-stegcracker-install.png` | <img width="280" alt="2b-05-stego-info-and-stegcracker-install" src="https://github.com/user-attachments/assets/61e80881-14ec-43a8-8374-441de47d6e83" /> | **Stegcracker Preparation** | Attempting detection without passphrase and setting up `stegcracker` dictionary cracking environment. | 
| `2b-06-stegcracker-success.png` | <img width="280" alt="2b-06-stegcracker-success" src="https://github.com/user-attachments/assets/40400ca0-6828-4a0a-8cd8-1fb6a268af8a" /> | **Steganography Passphrase Cracked** | `stegcracker` successfully cracking the stego-file passphrase (`AssignmentSecret123`) using `rockyou.txt`. | 
| `2b-07-extracted-content-verified.png` | <img width="280" alt="2b-07-extracted-content-verified" src="https://github.com/user-attachments/assets/f7e19e4b-73b7-41f3-9128-8a29d8d32737" /> | **Payload Integrity Check** | Verifying extracted content against original plaintext file to confirm data integrity. | 
| `2c-01-zip-creation.png` | <img width="280" alt="2c-01-zip-creation" src="https://github.com/user-attachments/assets/ebf607fc-1b8e-42f5-a686-666b8cda3909" /> | **Protected Archive Creation** | Creating a password-encrypted ZIP file via terminal command line for cracking analysis. | 
| `2c-02-zip2john-hash-and-john-crack.png` | <img width="280" alt="2c-02-zip2john-hash-and-john-crack" src="https://github.com/user-attachments/assets/fac364d2-2049-445c-a3c1-719a856a4c2f" /> | **ZIP Hash Extraction & Crack** | Extracting `$pkzip$` hash format using `zip2john` and cracking the password using John the Ripper. | 
| `2d-01-metasploitable2-ifconfig.png` | <img width="280" alt="2d-01-metasploitable2-ifconfig" src="https://github.com/user-attachments/assets/80073a0a-8ca1-40cd-b22c-6bafcc6a76b1" /> | **Metasploitable2 IP Verification** | Displaying target network parameters (`ifconfig`) on Metasploitable2 machine. | 
| `2d-02-kali-ip-a.png` | <img width="280" alt="2d-02-kali-ip-a" src="https://github.com/user-attachments/assets/b85169e9-03f3-487a-84c1-434661ebedd3" /> | **Kali Linux IP Configuration** | Displaying attacker IP address (`ip a`) on Kali Linux instance. | 
| `2d-03-kali-ping-metasploitable-success.png` | <img width="280" alt="2d-03-kali-ping-metasploitable-success" src="https://github.com/user-attachments/assets/0733f3a2-62b1-4d33-b325-2701d4bebda8" /> | **Attacker $\rightarrow$ Target Ping** | ICMP reachability verification between Kali attacker host and Metasploitable2 target VM. | 
| `2d-04-host-ping-metasploitable-via-vmnet.png` | <img width="280" alt="2d-04-host-ping-metasploitable-via-vmnet" src="https://github.com/user-attachments/assets/5676cfff-a937-46d3-a760-89cd60f3ee86" /> | **Host Network Routing** | Validating connectivity between physical host operating system and VMnet interface. | 
| `2d-05-metasploitable-ping-internet-usage-error.png` | <img width="280" alt="2d-05-metasploitable-ping-internet-usage-error" src="https://github.com/user-attachments/assets/3f0e2e43-80eb-470a-8a9f-4892f8004e6f" /> | **Network Syntax Check** | Command syntax verification during egress internet connectivity testing on target VM. | 
| `2d-06-host-ipconfig-separate-subnet.png` | <img width="280" alt="2d-06-host-ipconfig-separate-subnet" src="https://github.com/user-attachments/assets/ecc3d492-d940-4de7-88b0-f0288bf438b9" /> | **Host Subnet Isolation** | Confirming host network interface resides on a separate $192.168.132.0/24$ subnet. | 
| `2d-07-metasploitable-ping-internet-unreachable.png` | <img width="280" alt="2d-07-metasploitable-ping-internet-unreachable" src="https://github.com/user-attachments/assets/60462c9b-d520-4e59-bcce-88c33319af88" /> | **Air-Gapped Lab Isolation** | Proving Metasploitable2 cannot reach external internet endpoints, ensuring isolated lab safety. | 
| `2d-08-nmap-vsftpd-234-confirmed.png` | <img width="280" alt="2d-08-nmap-vsftpd-234-confirmed" src="https://github.com/user-attachments/assets/ec147141-3192-435e-8922-b1b11fcf716b" /> | **Service Version Enum** | `nmap -sV` output confirming target port 21 runs vulnerable `vsftpd 2.3.4` service. | 
| `2d-09-msf-search-vsftpd-use-module.png` | <img width="280" alt="2d-09-msf-search-vsftpd-use-module" src="https://github.com/user-attachments/assets/e3a2a778-5db4-4d29-a9a8-aebdb1625e89" /> | **Metasploit Module Selection** | Searching Metasploit framework for `vsftpd` and selecting `exploit/unix/ftp/vsftpd_234_backdoor`. | 
| `2d-10-msf-show-options.png` | <img width="280" alt="2d-10-msf-show-options" src="https://github.com/user-attachments/assets/ce0ef570-7f8d-4a56-a68c-56a817cd9dce" /> | **Exploit Module Options** | Configuring module parameters (`RHOSTS`, `RPORT`) prior to exploit execution. | 
| `2d-11-msf-payload-list.png` | <img width="280" alt="2d-11-msf-payload-list" src="https://github.com/user-attachments/assets/ecc7313d-7010-4d9d-8004-6aa087146f54" /> | **Payload Options Analysis** | Reviewing available shell payload modules for the vsftpd backdoor exploit. | 
| `2d-12-msf-exploit-shell-opened.png` | <img width="280" alt="2d-12-msf-exploit-shell-opened" src="https://github.com/user-attachments/assets/97bd83bb-a52f-425d-958f-fe756a7dbdd1" /> | **Command Shell Opened** | Triggering backdoor trigger signature (`:)`) and opening command shell session on target port 6200. | 
| `2d-13-root-shell-id-whoami.png` | <img width="280" alt="2d-13-root-shell-id-whoami" src="https://github.com/user-attachments/assets/5e3631db-9121-461b-9902-5a6d6f2df8b1" /> | **Root Identity Verification** | Executing `id` and `whoami` commands inside spawned shell, verifying `uid=0(root)` privileges. | 
| `2d-14-root-shell-uname-hostname.png` | <img width="280" alt="2d-14-root-shell-uname-hostname" src="https://github.com/user-attachments/assets/168c1a0f-905f-47a1-a5ea-0808168461c5" /> | **Target Machine Fingerprint** | Executing `uname -a` and `hostname` to confirm complete system compromise of target host. | 

---

## 🛠️ Verification & Replication Instructions

To reproduce or evaluate these assessment findings:

1. **Part A (DVWA Brute Force):** Refer to `Part-A-BruteForce.md` for Burp Intruder configurations and token bypass requirements.
2. **Part B (Steganography):** Refer to `Part-B-Steganography.md` for exact `steghide` parameters and `stegcracker` command flags.
3. **Part C (Archive Cracking):** Follow steps in `Part-C-ArchiveCracking.md` to extract `$pkzip$` hashes and run John the Ripper.
4. **Part D (CVE-2011-2523):** Review `Part-D-CVE.md` for Metasploit parameters and isolated lab network topology setup.