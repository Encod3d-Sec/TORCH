---
title: "Account Takeover (ATO)"
type: technique
tags: [account-takeover, authentication, oauth, jwt, exploitation, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-15
sources: [payloadsallthethings-accounttakeover, hacktricks-web]
---

# Account Takeover

## What it is

Gaining unauthorized full control of another user's account. ATO is the *outcome*; the routes run through password reset, registration/identity logic, OAuth/SSO, and chained web bugs. The highest-value web finding class. Overlaps [[authentication-attacks]], [[oauth-attacks]], [[jwt-attacks]]; driven by the `hunt-auth` skill.

## Password reset attacks
- **Reset poisoning:** inject `Host` / `X-Forwarded-Host` so the reset email link points to your domain -> victim clicks -> token leaks (`https://attacker/reset?token=...`).
- **Token leak via Referer:** a 3rd-party link on the reset page leaks the token in `Referer` to the external site.
- **Email parameter pollution / CC:** send the token to you while resetting the victim:
```text
email=victim@x.com&email=attacker@x.com
{"email":["victim@x.com","attacker@x.com"]}
email=victim@x.com%0d%0acc:attacker@x.com
email=victim@x.com,attacker@x.com
```
- **Weak tokens:** guessable (timestamp/userID/sequential), no expiry, reusable, or returned in the API JSON response.
- **Username collision:** register `"admin "` (trailing space); reset for the padded name but the backend trims and resets the real `admin` (CVE-2020-7245, CTFd).
- **Unicode normalization:** register `demⓞ@gmail.com`; if normalized to `demo@gmail.com` after the uniqueness check, your reset hits the victim.
- **Host-of-trust / no current-password:** change-email / change-password endpoints that do not require the current password or a fresh session.

## Registration & identity logic
- **Pre-account-takeover:** register the victim's email (unverified) before they sign up; when they later sign in via OAuth, accounts merge under your password.
- **Email change without re-verification**; **response manipulation** (change `"success":false`->`true`, or strip an MFA step).

## ATO via chained web bugs
- **XSS** -> steal session / add attacker email ([[xss]]).
- **CSRF** -> change-email/password form ([[csrf]]).
- **Request smuggling** -> capture another user's request/session ([[http-request-smuggling]]).
- **JWT** -> edit `sub`/`email`, `alg:none`, weak-secret crack ([[jwt-attacks]]).
- **IDOR** on `/account/{id}` update endpoints ([[access-control]]).
- **OAuth** redirect_uri/`state` bugs -> steal the code ([[oauth-attacks]]).

## Account pre-hijacking and registration/upsert ATO
Deltas beyond the reset-poisoning/referrer-leak content above: pre-hijacking (act on the
victim's email before they register, then regain access), signup upsert ATO, and OTP multi-value
smuggling.

Pre-hijacking (Microsoft MSRC classes), test each against the signup/SSO-link/email-change flows:
- Classic-Federated merge: register a classic account with the victim's email + password; when the
  victim later signs up via SSO, an insecure merge leaves the attacker still logged in.
- Unexpired session: create the account and hold a long-lived session; check it survives the
  victim's later password reset / MFA enablement.
- Trojan identifier: add a secondary email/phone/IdP to the pre-created account, then use it to
  reset after the victim takes over.
- Unexpired email change: start an email change to attacker mail, withhold confirmation, complete it
  after the victim starts using the account.
- Non-verifying IdP: assert `victim@...` via an IdP that does not verify email ownership; the RP
  merges on email without checking `email_verified`.

Verify after any reset/email-change that all sessions/tokens are invalidated, pending changes are
cancelled, and linked identifiers are re-verified.

Registration-as-Reset (upsert ATO): some signup handlers upsert on an existing email. A minimal
`{"email":"victim@x.com","password":"New@1"}` to a discovered registration endpoint (harvest from
JS bundles / mobile traffic; a GET returning "Only POST allowed" hints the verb) overwrites the
victim password pre-auth, no token/OTP. Full ATO.

OTP / verification weaknesses (registration + reset): guessable short OTP with no rate limit
(race/parallel guesses, Turbo Intruder, IP/header rotation), OTP reuse across actions, and
multi-value smuggling where the backend verifies if any submitted code matches. Also test
Host-header poisoning on verification links.

## Phone-number injection and contact-discovery presence oracle
Phone-number fields are a second injection surface: append strings after a valid number to reach XSS/SQLi/SSRF sinks or to smuggle OTP-bypass values, since backends often normalize/validate the numeric part but pass the tail through. Test with injection suffixes (`+15551234567'`, `+15551234567<script>`, `+15551234567||sleep(5)`) and OTP endpoints for multi-value smuggling.

Contact-discovery presence oracle (phone-centric messengers): the client's address-book sync endpoint reveals which numbers are registered. Instrument an official client to capture the authenticated address-book upload blob (normalized E.164), then replay it with attacker-generated numbers, reusing the same device token/cookies. Providers accept thousands of identifiers per request and return registered/unregistered + metadata, enabling mass enumeration without messaging victims. Model each country's dialing plan (country code + valid mobile NDC ranges) to skip dead candidates:

```python
from itertools import product
prefix = "+91"                      # seed only real allocations, not full 0-9^10
for suffix in product("0123456789", repeat=10):
    enqueue(prefix + "".join(suffix))
```

Scale horizontally (SIM banks, cloud devices, residential proxies) to dodge per-account/IP/ASN throttling. Feed leaked breach numbers to learn which identities are still active before phishing/SIM-swap. If the protocol exposes a per-account identity public key during session setup, dedupe keys across enumerated numbers to reveal multi-SIM account farms.

## Real-world
Reset poisoning, OAuth pre-ATO, and "change email without current password" are recurring high-bounty HackerOne reports. CVE-2020-7245 (CTFd username collision) is the canonical normalization case.

## Detection and defence
Single-use, short-lived, high-entropy reset tokens bound to the user; never trust `Host` for email links (use a fixed canonical base URL); require current password + re-auth for email/password/MFA changes; verify email before merge/login; normalize+canonicalize identifiers **before** uniqueness checks; set `Referrer-Policy: no-referrer` on sensitive pages.

## Tools
Burp ([[burp-suite]]) + Collaborator, `nuclei` reset/takeover templates. Driven by the `hunt-auth` skill.

## Sources
- PayloadsAllTheThings - Account Takeover

### IDOR / missing-auth password overwrite (reset endpoint trusts a client-supplied identity)

Distinct from reset-poisoning and email-parameter-pollution (both *capture a token*): here the reset
action itself has no ownership check. The endpoint takes an account identifier (`email`/`username`/
`uname`/`id`) plus a new password and overwrites it directly, with no current-password, no token, and
no session-to-identity binding. Register any low-priv account, open the "reset/change password" form,
and change the identity field to the admin's.

The tell is a reset form that pre-fills your own identifier in a field marked `readonly` or `hidden`
(`<input ... name="uname" value="you@x.com" readonly>`). `readonly`/`hidden` are client-side only, so
the server trusts whatever you POST:

```http
POST /reset HTTP/1.1
Content-Type: application/x-www-form-urlencoded

uname=admin@target&npass=NewPass!23&cpass=NewPass!23
```

Response "Password changed" -> log in as the victim. Probe adjacent fields for mass-assignment too
(`role=admin`, `is_admin=1`). Fix: bind the reset to the authenticated session (or a token emailed to
the account's own address), never to a request-supplied identifier.

<!-- promoted-slug: ato-reset-idor-overwrite -->
