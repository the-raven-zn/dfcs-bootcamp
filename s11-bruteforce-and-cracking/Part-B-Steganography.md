# Task 2, Part B — Steganography

**Environment:** Kali VM, local filesystem only (no network/lab setup required for this part). Tools: `steghide` 0.5.1, `stegcracker` 2.1.0.

**Carrier image:** `/home/kali/Desktop/old_data/Logo_burpsuite.jpg` — a genuine JPEG, 4,611 bytes (4.5 KiB), Burp Suite's application icon. JPEG was already the native format, so no conversion was needed (steghide supports JPEG/BMP/WAV/AU; PNG would require `zsteg` instead).

---

## 1. Checking capacity (baseline)

Before embedding anything, the clean carrier's embedding capacity was checked:

```
$ steghide info /home/kali/Desktop/old_data/Logo_burpsuite.jpg
"Logo_burpsuite.jpg":
  format: jpeg
  capacity: 213.0 Byte
Try to get information about embedded data ? (y/n) y
Enter passphrase:
steghide: could not extract any data with that passphrase!
```

- **Capacity: 213.0 bytes** — small but sufficient for a short secret message.
- Note the response when no data is actually embedded: steghide reports *"could not extract any data with that passphrase"* — the same message it gives when data **is** present but the passphrase is wrong (see Section 3). This is a deliberate design choice: it prevents an attacker from confirming the mere *presence* of hidden data just by trying a blank/wrong passphrase, which is a relevant point for the "detect hidden data" requirement below.

Screenshot: `2b-01-carrier-jpg-properties.png` (file properties), `2b-03-baseline-capacity-check.png` (capacity check).

---

## 2. Hiding the secret

A short secret payload was created:
```
$ echo "This is a hidden message for DVWA Assignment 7, Task 2 Part B." > /home/kali/Desktop/secret.txt
```

Embedded into a **copy** of the carrier image (keeping the original clean file for comparison), protected with a passphrase:
```
$ steghide embed -cf /home/kali/Desktop/old_data/Logo_burpsuite.jpg \
                  -ef /home/kali/Desktop/secret.txt \
                  -sf /home/kali/Desktop/burpsuite_with_secret.jpg \
                  -p "AssignmentSecret123"
embedding "/home/kali/Desktop/secret.txt" in "/home/kali/Desktop/old_data/Logo_burpsuite.jpg" ...  done
writing stego file "/home/kali/Desktop/burpsuite_with_secret.jpg" ...  done
```

**File size comparison:**

| File | Size |
|---|---|
| `Logo_burpsuite.jpg` (clean) | 4,611 bytes |
| `burpsuite_with_secret.jpg` (with hidden data) | 5,392 bytes |

The size increased by 781 bytes — a non-trivial, measurable jump on a file this small. This is a useful finding: on tiny carrier files, JPEG steganography is **not** size-invisible, even though it is visually indistinguishable to the eye. On larger, more "normal-sized" images the same absolute increase would be a much smaller proportional change and far less noticeable — so carrier file size matters for how detectable an embed is via simple file-size comparison.

Screenshot: `2b-04-embed-and-filesize-diff.png`.

---

## 3. Detecting the hidden data

```
$ steghide info /home/kali/Desktop/burpsuite_with_secret.jpg
"burpsuite_with_secret.jpg":
  format: jpeg
  capacity: 213.0 Byte
Try to get information about embedded data ? (y/n) y
Enter passphrase:
steghide: could not extract any data with that passphrase!
```

Without the correct passphrase, `steghide info` gives the **identical output** to the clean baseline file in Section 1 — it does not reveal whether data is actually present. This confirms the earlier point: steghide itself is not a reliable "detector" against an unknown file without the key. In a real-world scenario, detecting the *presence* of hidden data (as opposed to extracting it) would instead rely on external statistical steganalysis tools (e.g. looking for anomalies in DCT coefficients), not steghide's own info command — this was observed directly rather than assumed.

Screenshot: `2b-05-stego-info-and-stegcracker-install.png` (top half).

---

## 4. Cracking the passphrase

`stegcracker` was installed to brute-force the passphrase against a wordlist:
```
$ sudo apt install stegcracker -y
```

A small custom wordlist was built, containing some decoy guesses plus the real passphrase (a realistic full brute-force of arbitrary passphrases is computationally infeasible — this demonstrates the *technique* via a dictionary attack, which is how this attack is actually carried out in practice, rather than an unbounded keyspace search):
```
$ cat << 'EOF' > /home/kali/Desktop/wordlist.txt
password
123456
letmein
qwerty
AssignmentSecret123
admin123
burpsuite
dvwa2026
EOF
```

Crack run:
```
$ stegcracker /home/kali/Desktop/burpsuite_with_secret.jpg /home/kali/Desktop/wordlist.txt
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
...
Counting lines in wordlist..
Attacking file 'burpsuite_with_secret.jpg' with wordlist 'wordlist.txt'..
Successfully cracked file with password: AssignmentSecret123
Tried 5 passwords
Your file has been written to: /home/kali/Desktop/burpsuite_with_secret.jpg.out
AssignmentSecret123
```

**Result: passphrase cracked in 5 attempts** (`AssignmentSecret123` was the 5th word in the list). stegcracker's own startup banner notes it has been functionally superseded by **StegSeek** (https://github.com/RickdeJager/stegseek), which it claims can process the full 14-million-word `rockyou.txt` wordlist in ~1.9 seconds versus ~5 hours for stegcracker — worth citing as the current state-of-the-art tool for this attack, even though the small custom wordlist used here made speed irrelevant.

Screenshot: `2b-06-stegcracker-success.png`.

---

## 5. Extracting and verifying the content

stegcracker's successful run automatically wrote the recovered payload to `burpsuite_with_secret.jpg.out`. Verified it matches the original secret exactly:

```
$ cat /home/kali/Desktop/burpsuite_with_secret.jpg.out
This is a hidden message for DVWA Assignment 7, Task 2 Part B.
```

Confirmed identical to the original `secret.txt` content — full recovery chain demonstrated end to end: **embed → (failed detection via info alone) → dictionary-crack the passphrase → extract → verify content**.

Screenshot: `2b-07-extracted-content-verified.png`.

---

## Summary

| Step | Tool | Outcome |
|---|---|---|
| Capacity check (clean file) | `steghide info` | 213.0 byte capacity; no data present |
| Embed secret w/ passphrase | `steghide embed` | Success; file grew 4,611 → 5,392 bytes |
| Attempt detection w/o passphrase | `steghide info` | Indistinguishable from clean file's output — steghide alone does not reveal presence |
| Crack passphrase | `stegcracker` + custom wordlist | Cracked in 5 attempts: `AssignmentSecret123` |
| Extract & verify | `cat` recovered `.out` file | Content matches original secret exactly |
