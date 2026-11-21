# Task 2, Part A — Brute Force (DVWA: Low / Medium / High)

**Environment:** DVWA Brute Force module (`/vulnerabilities/brute/`), accessed locally inside the Kali VM at `http://127.0.0.1:42001`. Burp Suite Community Edition, Intruder — Sniper attack. Payload wordlist for all three levels: `123456, letmein, admin, password, qwerty`. Target account: `admin`, correct password: `password`.

All three security levels were tested by capturing a real login request in Burp Proxy, sending it to Intruder, marking only the `password` parameter value as the payload position, and firing the same five-word list plus baseline (six total requests) at each level.

---

## Low security

- Security level set to **Low** via DVWA Security page.
- A wrong-login request was captured in Burp Proxy and sent to Intruder.
- **Gotcha encountered:** the request captured by Burp did not carry a `Cookie` header, so every attempt returned a uniform 302 redirect regardless of password — the server never saw a valid session to attach the login attempt to. Fixed by manually adding `Cookie: PHPSESSID=<value>; security=low` as a header line before firing the attack.
- **Results:**

| Payload | Status | Length |
|---|---|---|
| (baseline) | 200 | 4699 |
| 123456 | 200 | 4699 |
| letmein | 200 | 4699 |
| admin | 200 | 4699 |
| **password** | 200 | **4737** ← distinct response, successful login |
| qwerty | 200 | 4699 |

- **Completion time:** attack ran to completion in well under a minute (Burp Community throttles Intruder, so absolute time is not representative of a real/Pro-speed attack — it is used here only for *relative* comparison between the three levels).
- **Outcome:** full success, no blocking, no delay, no CAPTCHA, no token requirement. This matches Low's design intent — "no security measures at all."

Screenshot: `2a-01-low-intruder-results-success.png`

---

## Medium security

- Security level set to **Medium**. The Brute Force page was reloaded after the change to obtain a fresh session/security cookie pair, and a new wrong-login request was captured and sent to a new Intruder tab (an earlier attempt that reused a stale `security=low` cookie was discarded as invalid evidence).
- Same cookie-header gotcha as Low — the captured request again showed **0 request cookies** in Burp's Inspector, so the `Cookie: PHPSESSID=<value>; security=medium` header was added manually before marking the payload position and firing.
- **Results:**

| Payload | Status | Response time (ms) | Length |
|---|---|---|---|
| (baseline) | 200 | 2007 | 4708 |
| 123456 | 200 | 2008 | 4708 |
| letmein | 200 | 2006 | 4708 |
| admin | 200 | 2008 | 4708 |
| **password** | 200 | **7** | **4746** ← distinct, successful login |
| qwerty | 200 | 2009 | 4708 |

- **Completion time:** whole attack completed in roughly a minute — not meaningfully longer than Low despite the per-request delay on wrong guesses, because Intruder's own throttling in Burp Community already dominates the pacing.
- **Why Medium does not stop the attack (required paragraph):** DVWA's Medium brute-force page adds no real anti-automation control — it only changes *how* a failed attempt is rendered. Every wrong guess took roughly two seconds to respond, while the single correct guess (`password`) returned in just 7 ms; this is the *reverse* of a deliberate throttle, and most likely reflects the failed-login code path doing extra work (re-rendering the login form with an error message) rather than any intentional rate-limiting, lockout, or CAPTCHA logic. There is no cap on the number of attempts, no account lockout after repeated failures, and no requirement that slows a scripted/automated client more than a human. A delay that is not tied to *attempt count* and does not block or lock the account is not a defense against brute force — it can at most make a human attacker mildly impatient, while an automated tool (as demonstrated here) simply absorbs the wait and keeps going. Real defenses would need to be attempt-aware (progressive lockout, CAPTCHA after N failures, or rate-limiting per account/IP) rather than a flat per-request pause.

Screenshots: `2a-03-medium-intruder-results-success.png` (results grid), `2a-04-medium-cookie-header-positions.png` (Positions tab, confirming the valid `security=medium` cookie was in place for this run — distinguishing it from the earlier invalid attempt).

---

## High security

- Security level set to **High**.
- Inspection of DVWA's server-side source (`vulnerabilities/brute/source/high.php`) showed two controls not present at Low/Medium:
  1. An **anti-CSRF token** check: `checkToken( $_REQUEST['user_token'], $_SESSION['session_token'], 'index.php' )`, with `generateSessionToken()` called at the end of **every** page load — meaning the token value changes each time the page (or its source) is loaded, not only after a login submission.
  2. A **randomised delay on failure**: `sleep( rand(0, 3) )`, i.e. 0–3 seconds, unlike Medium's effectively fixed delay.
- The live `user_token` value was read from the Brute Force form's hidden input and used to build one request in Burp, which was then sent to Intruder with the token value left **static** across all six requests (a naive Sniper attack does not refresh the token per request).
- **Results:**

| Payload | Status | Length |
|---|---|---|
| (baseline) | 302 | 295 |
| 123456 | 302 | 295 |
| letmein | 302 | 295 |
| admin | 302 | 295 |
| password | 302 | 295 |
| qwerty | 302 | 295 |

- All six requests — including the one carrying the correct password — were rejected identically (302 redirect, length 295) by the anti-CSRF check. Following the redirect confirmed the cause directly: the DVWA Security page displayed six stacked **"CSRF token is incorrect"** messages, one per rejected request.
- **Root cause:** the static token became invalid before Intruder's first request was even sent — most likely because viewing the page source to copy the token itself triggered another page load, and `generateSessionToken()` regenerates the token unconditionally on every load, including that one. By the time Intruder fired, the token in the request no longer matched `$_SESSION['session_token']`.
- **Completion time:** attack completed quickly (all requests uniformly rejected; no login processing occurred at all — `checkToken()` short-circuits before the SQL query or password check is reached).
- **Outcome:** **0/6 requests succeeded.** A naive, static-payload Sniper attack is fully defeated at High. This is the expected and correct result: High's anti-CSRF control is tightly coupled to page state (not merely to the login POST/GET itself), so any automated attack that doesn't re-scrape a fresh token per request — e.g. via Burp's session-handling rules/macros, a Pro-only feature not available here in Community Edition — will fail outright rather than merely being slowed down.

Screenshots: `2a-05-high-intruder-positions-with-token.png` (request with static token marked), `2a-06-high-intruder-results-all-blocked.png` (results grid, all 302/295), `2a-07-high-csrf-token-incorrect-messages.png` (resulting CSRF rejection messages, confirming the cause).

---

## Summary across levels

| Level | Attack result | Key control | Effectiveness |
|---|---|---|---|
| Low | 1/6 succeeded (`password`) | None | No protection |
| Medium | 1/6 succeeded (`password`) | Per-attempt delay (fixed, failure path only) | Ineffective — not attempt-count-aware, doesn't block automation |
| High | 0/6 succeeded | Anti-CSRF token (regenerated every page load) + randomised 0–3s delay | Fully blocks naive automated attack |

**One-paragraph explanation (restated for the submission requirement):** Medium's extra response time on failed logins is not a real anti-brute-force defense — it is not tied to how many attempts have been made, it does not lock the account, and it does not distinguish a human from an automated client; it simply slows down every failed request equally, which an automated tool tolerates without difficulty, as shown by the `password` payload still succeeding exactly as it did at Low. High, by contrast, succeeds in stopping the naive attack, but through an unrelated mechanism — an anti-CSRF token tied to page state — rather than through rate-limiting or lockout; a determined attacker would need to defeat the token requirement specifically (e.g. by scraping a fresh token per request), not simply wait out a delay.
