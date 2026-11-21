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
| 1a-01-lfi-etc-passwd.png <img width="961" height="925" alt="1a-01-lfi-etc-passwd" src="https://github.com/user-attachments/assets/8b3e409a-944f-43c7-ab7a-bbeb26086313" />
 | LFI confirmed — /etc/passwd read |
| 1a-02-reverse-shell-connect.png <img width="687" height="141" alt="1a-02-reverse-shell-connect" src="https://github.com/user-attachments/assets/501dff84-4358-4721-a6d8-4773a5f01399" />
| Reverse shell received on nc listener <img width="698" height="247" alt="1a-03-reverse-shell-id-pwd" src="https://github.com/user-attachments/assets/08930bb8-6e47-46e3-95d6-5cff10581832" />
|
| 1a-03-reverse-shell-id-pwd.png | id and pwd inside the shell <img width="698" height="247" alt="1a-03-reverse-shell-id-pwd" src="https://github.com/user-attachments/assets/e630697d-c89d-412a-8c78-21ec9c21c46d" />
|
| 1a-04-path-disclosure-warnings.png <img width="957" height="340" alt="1a-04-path-disclosure-warnings" src="https://github.com/user-attachments/assets/6d3ea8f4-8e30-4a01-b586-9494648cc440" />
| PHP error revealing installation path |
| 1b-01-sqli-baseline-id1.png <img width="949" height="933" alt="1b-01-sqli-baseline-id1" src="https://github.com/user-attachments/assets/e6cc7e8e-9178-4e4d-9c35-912464141740" />
| Baseline response for id=1 |
| 1b-02-sqli-single-quote-error.png <img width="956" height="280" alt="1b-02-sqli-single-quote-error" src="https://github.com/user-attachments/assets/a51987b9-8889-4a4b-8f27-c1600c0296c9" />
| SQL syntax error confirming injection |
| 1b-03-orderby-2-ok.png <img width="961" height="1018" alt="1b-03-orderby-2-ok" src="https://github.com/user-attachments/assets/b999d902-2b08-40b2-8ff5-90a1ce7c1afa" />
| ORDER BY 2 — OK (2 columns confirmed) |
| 1b-04-orderby-3-error.png<img width="954" height="434" alt="1b-04-orderby-3-error" src="https://github.com/user-attachments/assets/3f785652-4282-4014-a158-8176c068ce6a" />
 | ORDER BY 3 — column count error |
| 1b-05-union-select-1-2.png<img width="964" height="888" alt="1b-05-union-select-1-2" src="https://github.com/user-attachments/assets/2137e679-fea7-4c65-ba33-84d00d062a71" />
 | UNION SELECT confirming injectable columns |
| 1b-06-db-version-enum.png<img width="960" height="939" alt="1b-06-db-version-enum" src="https://github.com/user-attachments/assets/87ab8587-8ce9-462e-a3f4-805c178520ec" />
 | Database name and version extraction |
| 1b-07-groupconcat-tables.png <img width="955" height="913" alt="1b-07-groupconcat-tables" src="https://github.com/user-attachments/assets/ac58c138-6afb-48fd-801c-af410a121863" />
 | Table enumeration with group_concat() |
| 1b-08-column-enum.png <img width="958" height="861" alt="1b-08-column-enum" src="https://github.com/user-attachments/assets/9c5bda1e-216e-44e5-9d3c-4a46b2f2beb4" />
| Column enumeration from information_schema |
| 1b-09-final-creds-dump.png <img width="951" height="925" alt="1b-09-final-creds-dump" src="https://github.com/user-attachments/assets/4301f660-2cec-414c-9d5d-78e79eff66fb" />
| Full credential dump with MD5 hashes |
