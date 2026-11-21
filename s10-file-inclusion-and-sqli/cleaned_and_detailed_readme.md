# s10 — Local File Inclusion (LFI) to RCE & Manual SQL Injection (SQLi)

[![Security Assessment](https://img.shields.io/badge/Assessment-DFCS_Bootcamp-blue.svg)](https://github.com/the-raven-zn/dfcs-bootcamp)
[![Module](https://img.shields.io/badge/Module-S10_File_Inclusion_%26_SQLi-red.svg)](#)
[![Status](https://img.shields.io/badge/Status-Completed-success.svg)](#)

---

## 👤 Author Information

| Field | Details |
| :--- | :--- |
| **Student Name** | Muhammad Zain Nasir |
| **Program** | DFCS Bootcamp (PSEBCYBERISB02) |
| **Repository URL** | [dfcs-bootcamp / s10-file-inclusion-and-sqli](https://github.com/the-raven-zn/dfcs-bootcamp/tree/main/s10-file-inclusion-and-sqli) |
| **Assessment Focus** | Web Application Vulnerability Exploitation, Privilege Escalation & Secure Code Remediation |

---

## 📌 Executive Summary

This repository documents the practical exploitation and remediation of two critical web application vulnerabilities: **Local File Inclusion (LFI) leading to Remote Code Execution (RCE)** and **Manual UNION-based SQL Injection (SQLi)**. All lab tasks were performed manually without relying on automated scanners such as `sqlmap` to ensure a fundamental understanding of underlying application flaw mechanics.

### Key Technical Takeaways
1. **LFI to RCE Chain:** Escalating a read-only Local File Inclusion flaw into full system compromise using path disclosure warnings, Apache log poisoning, and reverse shell execution.
2. **Manual UNION SQLi:** Determining query structure using `ORDER BY` techniques, finding injectable columns, enumerating database schemas via MySQL `information_schema`, and dumping user password hashes.
3. **Remediation & Secure Coding:** Replacing dangerous dynamic file inclusions with strict allowlists and refactoring vulnerable SQL queries with parameterized statements (PDO).

---

## 📁 Repository Structure

```text
s10-file-inclusion-and-sqli/
├── Part-A-LFI-to-RCE.md     # Detailed write-up for LFI to RCE attack path (20 Marks)
├── Part-B-Manual-SQLi.md    # Step-by-step manual SQL injection & data extraction (20 Marks)
├── Part-C-Remediation.md   # Secure code implementation & allowlist vs blocklist analysis (10 Marks)
├── README.md                # Project documentation & visual index (This file)
└── screenshots/             # Proof of concept evidence screenshots
```

| File / Directory | Weightage | Core Focus & Description |
| :--- | :---: | :--- |
| `Part-A-LFI-to-RCE.md` | **20 Marks** | Full LFI-to-RCE attack chain: PHP error path disclosure $\rightarrow$ log file poisoning via User-Agent header $\rightarrow$ reverse shell listener connection. |
| `Part-B-Manual-SQLi.md` | **20 Marks** | Manual UNION-based SQL injection without automated tools: column identification, database enumeration, credential dump. |
| `Part-C-Remediation.md` | **10 Marks** | Source code remediation: fixing dynamic includes (`in_array()` allowlisting) and implementing PDO prepared statements. |
| `screenshots/` | — | Evidence directory containing raw image assets for visual proof of exploitation. |

---

## 🛡️ Technical Overview & Attack Methodologies

### 1. Part A: LFI to Remote Code Execution (RCE) Chain
- **Step 1 — Vulnerability Identification:** The application accepts unvalidated user input in file paths (e.g., `?page=...`), allowing directory traversal (`../../etc/passwd`).
- **Step 2 — Information Disclosure:** Inducing PHP runtime errors reveals the absolute file system path (Path Disclosure), exposing log paths such as `/var/log/apache2/access.log`.
- **Step 3 — Log Poisoning:** Web server access logs log incoming requests, including the `User-Agent` HTTP header. By injecting PHP payload `<?php system($_GET['cmd']); ?>` into the header, the PHP command is written directly into the log file.
- **Step 4 — Execution & Reverse Shell:** Including the poisoned access log file executes the payload. A Netcat listener (`nc -lvnp <port>`) catches the incoming connection, providing an interactive system shell.

### 2. Part B: Manual UNION-Based SQL Injection (SQLi)
- **Step 1 — Input Sanitization Check:** Submitting a single quote `'` breaks the SQL query syntax, causing a MySQL error that confirms an injection vector.
- **Step 2 — Column Count Determination:** Incremental `ORDER BY N` queries test the number of columns returned by the original query until an error occurs (confirming $N=2$ columns).
- **Step 3 — Data Payload Placement:** A `UNION SELECT 1, 2` query matches the column output structure and reveals which column position renders in the UI.
- **Step 4 — Schema Enumeration:** Querying `information_schema.tables` and `information_schema.columns` via `group_concat()` extracts table names (`users`) and column names (`username`, `password`).
- **Step 5 — Data Exfiltration:** Dumping credential hashes directly from the database table.

### 3. Part C: Remediation & Secure Development
- **File Inclusion Fix:** Replace dynamic user-controlled paths with a strict static **allowlist** array check using `in_array()`. Blocklists are insufficient as bypasses (e.g., URL encoding, double encoding) frequently succeed.
- **SQL Injection Fix:** Abandon raw string concatenation. Utilize **Parameterized Queries / Prepared Statements** (PDO or MySQLi with bound parameters), decoupling query structure from user input.

---

## 📷 Screenshot Evidence Index

The following table indexes all visual evidence demonstrating successful exploitation and credential extraction.

| Screenshot File | Visual Preview | Phase / Objective | Technical Description & Explanation |
| :--- | :---: | :--- | :--- |
| `1a-01-lfi-etc-passwd.png` | <img src="https://github.com/user-attachments/assets/8b3e409a-944f-43c7-ab7a-bbeb26086313" width="280" alt="LFI /etc/passwd" /> | **LFI Confirmation** | Demonstrates successful directory traversal by retrieving the server's `/etc/passwd` file via unvalidated parameter input. |
| `1a-02-reverse-shell-connect.png` | <img src="https://github.com/user-attachments/assets/501dff84-4358-4721-a6d8-4773a5f01399" width="280" alt="Reverse Shell Connection" /> | **RCE Execution** | Displays the incoming reverse connection established on the Netcat listener (`nc -lvnp`) after triggering the log payload. |
| `1a-03-reverse-shell-id-pwd.png` | <img src="https://github.com/user-attachments/assets/08930bb8-6e47-46e3-95d6-5cff10581832" width="280" alt="Shell Identity Check" /> | **Shell Interaction** | Validates execution context within the compromised system by executing system commands `id` (user identity) and `pwd` (working directory). |
| `1a-04-path-disclosure-warnings.png` | <img src="https://github.com/user-attachments/assets/6d3ea8f4-8e30-4a01-b586-9494648cc440" width="280" alt="Path Disclosure Error" /> | **Information Gathering** | Discloses the absolute web root file path through PHP runtime warning messages, assisting in log location discovery. |
| `1b-01-sqli-baseline-id1.png` | <img src="https://github.com/user-attachments/assets/e6cc7e8e-9178-4e4d-9c35-912464141740" width="280" alt="SQLi Baseline" /> | **Baseline Setup** | Captures the legitimate application behavior when querying `id=1` under standard operating conditions. |
| `1b-02-sqli-single-quote-error.png` | <img src="https://github.com/user-attachments/assets/a51987b9-8889-4a4b-8f27-c1600c0296c9" width="280" alt="SQL Syntax Error" /> | **Vulnerability Verification** | Triggers an unhandled database syntax error by injecting a single quote (`'`), confirming the SQL parameter is unescaped. |
| `1b-03-orderby-2-ok.png` | <img src="https://github.com/user-attachments/assets/b999d902-2b08-40b2-8ff5-90a1ce7c1afa" width="280" alt="ORDER BY 2 Success" /> | **Column Count Test** | Confirms the query contains at least 2 columns using `ORDER BY 2`, which executes without throwing an error. |
| `1b-04-orderby-3-error.png` | <img src="https://github.com/user-attachments/assets/3f785652-4282-4014-a158-8176c068ce6a" width="280" alt="ORDER BY 3 Error" /> | **Column Limit Test** | Triggers a column index error using `ORDER BY 3`, proving that the original query projects exactly 2 columns. |
| `1b-05-union-select-1-2.png` | <img src="https://github.com/user-attachments/assets/2137e679-fea7-4c65-ba33-84d00d062a71" width="280" alt="UNION SELECT Output" /> | **Injectable Position Test** | Uses `UNION SELECT 1, 2` to determine which database fields render on the screen for payload reflection. |
| `1b-06-db-version-enum.png` | <img src="https://github.com/user-attachments/assets/87ab8587-8ce9-462e-a3f4-805c178520ec" width="280" alt="Database Version Enum" /> | **System Fingerprinting** | Extracts the active database name (`database()`) and backend server version (`version()`) into the output fields. |
| `1b-07-groupconcat-tables.png` | <img src="https://github.com/user-attachments/assets/ac58c138-6afb-48fd-801c-af410a121863" width="280" alt="Table Enumeration" /> | **Schema Discovery** | Uses `group_concat(table_name)` against `information_schema.tables` to aggregate and list all database tables. |
| `1b-08-column-enum.png` | <img src="https://github.com/user-attachments/assets/9c5bda1e-216e-44e5-9d3c-4a46b2f2beb4" width="280" alt="Column Enumeration" /> | **Target Column Enum** | Enumerates specific column names from the target table via `information_schema.columns`. |
| `1b-09-final-creds-dump.png` | <img src="https://github.com/user-attachments/assets/4301f660-2cec-414c-9d5d-78e79eff66fb" width="280" alt="Credentials Dump" /> | **Data Exfiltration** | Successfully dumps sensitive user credentials including usernames and MD5 password hashes from the database. |

---

## 🛠️ Verification & Replication Instructions

To review or verify the submission findings locally:
1. **LFI to RCE:** Consult `Part-A-LFI-to-RCE.md` for exact log poisoning payloads and Netcat commands.
2. **Manual SQLi:** Follow `Part-B-Manual-SQLi.md` for raw HTTP request strings and UNION payload constructions.
3. **Remediation Snippets:** Refer to `Part-C-Remediation.md` for secure PHP code replacements.