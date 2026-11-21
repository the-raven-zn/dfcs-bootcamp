# Task 2, Part C — Archive Cracking

**Environment:** Kali VM, local filesystem only. Tools: `zip`, `zip2john` (part of the John the Ripper suite), `john`.

---

## 1. Creating the password-protected archive

```
$ zip -e /home/kali/Desktop/protected_archive.zip /home/kali/Desktop/secret.txt
Enter password:
Verify password:
  adding: home/kali/Desktop/secret.txt (stored 0%)
```

The `-e` flag tells `zip` to encrypt the archive, prompting interactively for a password (set here to `pass`, chosen deliberately weak for demonstration). The payload file was `secret.txt` from Part B.

Screenshot: `2c-01-zip-creation.png`.

---

## 2. Extracting the hash with zip2john

```
$ zip2john /home/kali/Desktop/protected_archive.zip > /home/kali/Desktop/archive_hash.txt
$ cat /home/kali/Desktop/archive_hash.txt
ver 1.0 efh 5455 efh 7875 protected_archive.zip/home/kali/Desktop/secret.txt PKZIP Encr: 2b chk, TS_chk, cmplen=75, decmplen=63, crc=14E1B5AE ts=7D5B cs=7d5b type=0
protected_archive.zip/home/kali/Desktop/secret.txt:$pkzip$1*2*2*0*4b*3f*14e1b5ae*0*56*0*4b*7d5b*d327b2d478f9a11eb889ea75e07cad48c229d4c64f3f0d08d793fa045def690a94f19cc24af72d083fbdebdd8d86f27f96cf3de697d70d77b4ab746bac446922b75e4a8526c2d66277041*$/pkzip$:/home/kali/Desktop/secret.txt:protected_archive.zip::/home/kali/Desktop/protected_archive.zip
```

**Key finding — the hash format is `$pkzip$`.** This identifies the archive as using the **traditional PKZIP / "ZipCrypto" stream cipher**, which is the legacy encryption scheme built into the original ZIP specification (distinct from the modern, much stronger **AES-256 ZIP encryption**, which `zip2john` would instead report as a `$zip2$` hash).

Screenshot: `2c-02-zip2john-hash-and-john-crack.png` (top portion).

---

## 3. Cracking with John the Ripper

A small wordlist including the real password among decoys:
```
$ cat << 'EOF' > /home/kali/Desktop/zip_wordlist.txt
123456
letmein
password
pass
qwerty
admin
dvwa2026
EOF
```

Crack run:
```
$ john --wordlist=/home/kali/Desktop/zip_wordlist.txt /home/kali/Desktop/archive_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Note: Passwords longer than 21 [worst case UTF-8] to 63 [ASCII] rejected
Press 'q' or Ctrl-C to abort, almost any other key for status
pass             (protected_archive.zip/home/kali/Desktop/secret.txt)
1g 0:00:00:00 DONE (2026-11-20 15:48) 50.00g/s 350.0p/s 350.0c/s 350.0C/s 123456..dvwa2026
Session completed

$ john --show /home/kali/Desktop/archive_hash.txt
protected_archive.zip/home/kali/Desktop/secret.txt:pass:home/kali/Desktop/secret.txt:protected_archive.zip::/home/kali/Desktop/protected_archive.zip

1 password hash cracked, 0 left
```

**Result: password `pass` recovered instantly** (0 seconds elapsed — John's PKZIP mode is extremely fast, confirmed by the 350 candidates/sec rate even on this small wordlist).

Screenshot: `2c-02-zip2john-hash-and-john-crack.png` (bottom portion).

---

## 4. What the hash format reveals about protection strength

The `$pkzip$` hash format is the signature of **legacy PKZIP/ZipCrypto encryption**, and its presence alone tells us the archive's protection is fundamentally weak, independent of password complexity:

- **Weak, broken cipher design:** ZipCrypto is a proprietary stream cipher from the late 1980s with well-documented cryptanalytic weaknesses (most notably Biham & Kocher's known-plaintext attack, which can recover the internal key state — and in some cases derive the password — from as little as 12 bytes of known/guessable plaintext, without needing a password dictionary at all).
- **No key-stretching / fast hashing:** unlike modern password-based encryption, PKZIP's key derivation does virtually no computational work per guess, which is why John the Ripper reported a throughput of **350 candidates per second** — orders of magnitude faster than cracking a slow, deliberately expensive hash like bcrypt or Argon2 (a direct real-world link to the Task 2 "Keep in mind" note: *bcrypt or Argon2 is the defence* against fast offline cracking).
- **Contrast with `$zip2$` (AES):** had the archive been created with AES-256 encryption (e.g. via `zip -e --password ... -Z aes256` style options or tools like 7-Zip with AES), `zip2john` would report a `$zip2$` hash instead. AES-256-encrypted ZIPs use PBKDF2 key derivation, which is both cryptographically modern and deliberately slower per guess — making brute-force/dictionary attacks dramatically more expensive, even though the underlying attack *methodology* (extract hash → wordlist attack) would be identical.
- **Practical implication:** the hash format signature is itself diagnostic. Seeing `$pkzip$` in an extracted hash immediately tells an analyst (or an attacker) that the archive's confidentiality rests on an outdated, structurally weak cipher — the password strength matters far less here than it would for a `$zip2$`/AES archive, because PKZIP's own cryptographic weaknesses can be exploited independent of the password's complexity.

---

## Summary

| Step | Tool | Result |
|---|---|---|
| Create protected ZIP | `zip -e` | Archive created, password `pass` |
| Extract hash | `zip2john` | Hash format: **`$pkzip$`** (legacy ZipCrypto, not AES) |
| Crack | `john --wordlist` | Cracked instantly (0s elapsed, 350 candidates/sec) — password `pass` recovered |
| Format implication | — | `$pkzip$` signals a structurally weak legacy cipher (vulnerable even to known-plaintext attacks independent of password strength); `$zip2$`/AES would indicate modern, PBKDF2-backed, far more resistant protection |
