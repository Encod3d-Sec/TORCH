---
name: hunt-auth
description: Auth bypass and ATO hunting - legacy protocol matrix (XMLRPC, SharePoint /_vti_bin/, EWS, Citrix, etc.), JWT manipulation, password reset poisoning, SAML auth bypass, session fixation. Wiki-first, FIND schema output.
---

# Hunt: Auth Bypass & Account Takeover

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "authentication bypass account takeover password reset poisoning session fixation legacy protocol" via wiki-search MCP
```

Hub: [[web-moc]] (live index). Primary page: [[authentication-attacks]]. Payload arsenal: `wiki/payloads/{auth-bypass,jwt,oauth-saml,session,mfa-bypass,crypto}.md`.
Anchors: [[session-management-attacks]], [[mfa-bypass]].

## Attack surface (ranked)

Probe in this order; a higher entry is more often unguarded than a cleverer payload on the main form is likely to land.

1. **Legacy protocol endpoints** (matrix below) - a second door to the same credential store, frequently with no rate limit, MFA, or CAPTCHA. Probe first on any custom/branded login.
2. **Password reset flows** - host-header poisoning, token in Referer, token reuse/expiry, reset that does not invalidate live sessions.
3. **Session and MFA** - fixation, missing rotation on privilege change, MFA-optional endpoints, JWT manipulation.
4. **Read the login form's fields, not just the endpoint.** A login that takes **username only, no password field** is instant ATO - just submit the privileged/target username (custom auth on a CTF/lab app does this constantly). Same for a "just email"/"just token" form with no secret.
5. **Predictable/leaked signing key -> forge as any user.** When auth or a "signed message" rests on a per-user key, hunt for a `/debug`, docs, or `/about` endpoint (or source) that discloses the **key-derivation** (deterministic seed like `f(username, CONST)`, `nextprime(int(SHA256(seed)))`). If the derivation is known, reconstruct the private key offline and forge signatures/sessions/JWTs for admin - no factoring, modulus size irrelevant. Build + oracle-brute steps in [[cryptography-attacks]] ("RSA private key from a known/deterministic seed").

## Legacy Protocol Matrix (Probe First on Any Custom-Branded Login)

When a target has a custom/branded login UI, ALWAYS probe the platform's legacy protocol endpoints. These often accept native credentials with NO rate limit, NO MFA, NO CAPTCHA.

| Target tech | Legacy endpoint | Bypass surface |
|---|---|---|
| WordPress | `/xmlrpc.php` | Native WP creds; bypasses SSO, MFA, IP-allow on /wp-login.php |
| SharePoint | `/_vti_bin/Authentication.asmx` | SOAP Login op; FedAuth cookie returned; no rate limit observed |
| SharePoint REST | `/_api/contextinfo` (POST) | Anonymous FormDigest issuance |
| Atlassian Jira/Confluence | `/rest/auth/1/session` | Native creds accepted even when Atlassian Access SSO enforced on UI |
| Exchange / OWA | `/EWS/Exchange.asmx`, `/Microsoft-Server-ActiveSync` | NTLM/Basic; bypasses OWA MFA restrictions |
| Citrix NetScaler | `/vpn/index.html`, `/cgi/login` | Native AD credentials independent of MFA wrappers |
| F5 BIG-IP | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin creds |
| Spring Boot | `/actuator/*` | Sometimes anonymously enumerable |
| Jenkins | `/jnlpJars/jenkins-cli.jar`, `/script` | API tokens + native auth |
| Apache Tomcat | `/manager/html` | Native Tomcat realm creds |
| Drupal | `/user/login?_format=json` | JSON POST accepts native passwords independent of SSO middleware |
| Generic ASP.NET | `*.asmx?WSDL`, `trace.axd`, `elmah.axd` | Each ASMX may take creds independently |

**How to use:**
1. Identify tech stack from headers/paths
2. Probe legacy endpoint anonymously (confirm reachable, not 403/404)
3. Test with synthetic credentials - confirm differential (success vs failure)
4. Verify NO rate limit against a synthetic or your OWN test account (never a real user - every failed attempt counts toward account lockout): send a bounded burst - 5 by default per hunt-core, 20 ceiling with operator approval, 0 under `no_bruteforce` - and confirm uniform timing, no `429`, no lockout counter. The ABSENCE of the limit is the finding; do not actually brute-force to prove it.
5. Confirmed when the endpoint takes native creds with no rate limit / MFA / CAPTCHA (severity below).

## JWT Attacks
```bash
# 1. Decode JWT
echo "HEADER.PAYLOAD.SIGNATURE" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# 2. Test none algorithm
# Change "alg":"RS256" -> "alg":"none", remove signature
eyJhbGciOiJub25lIn0.PAYLOAD.

# 3. HS256/RS256 key confusion
# If RS256, try signing with public key as HS256 secret
```

## ATO Attack Paths (Priority Order)
1. **Password reset poisoning**: `POST /forgot-password` with `X-Forwarded-Host: attacker.com` -> reset link sent to attacker
2. **Reset token in Referer leak**: reset page loads external analytics -> full Referer with token leaked
3. **Email change without re-auth**: `PUT /api/user/email {"new_email": "attacker@evil.com"}` without current_password
4. **Session fixation**: set session cookie before auth -> persists after login
5. **IDOR -> ATO chain**: `PATCH /api/users/{victim_uid}` with attacker session -> change victim email -> reset password

## Methodology
1. Map all authentication entry points (main, admin, API, partner, mobile)
2. Identify auth mechanism per entry (forms, SAML, OAuth, API key, session)
3. Test legacy endpoints per tech stack (use matrix above)
4. Probe XMLRPC if WordPress: `system.listMethods`, `wp.getUsersBlogs`
5. Test JWT if present: none algorithm, key confusion, weak secret
6. Test password reset: host header injection, token in Referer, token reuse after expiry
7. Test email change: no re-auth, no confirmation
7a. On a legacy PHP/MySQL stack (old Apache/PHP banner) with self-registration, try **SQL truncation** to forge a duplicate of a privileged username (register `admin`+spaces+junk, log in as `admin`/yourpass) - see [[authentication-attacks]] "SQL Truncation Duplicate-Account Auth Bypass".
8. Verify impact: demonstrate full ATO on test account B from attacker session A, then clear the confirmation gate below
9. **Distill when confirmed** (per hunt-core): a reusable legacy-endpoint bypass or JWT variant, GENERIC (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/authentication-attacks.md`

## Drive it through Burp

Push the load-bearing requests through Burp for operator visibility (`Skill(hunt-burp)`):
- The password-reset request with the injected `X-Forwarded-Host` / `Host`, and each JWT-tampered request (`alg:none`, key-confusion), go to **Repeater** so the operator can replay and inspect them.
- The bounded rate-limit / lockout probe (matrix step 4) goes to **Intruder** with the hunt-core bound, never a hand-rolled loop.
- `scripts/capture.sh burp` grabs the request+response PoC the moment it lands.

## Confirmation gate

**NOT confirmation:** a `200` on the login page or reset form; a different or friendlier error message; a password-reset email merely received; a JWT that decodes cleanly or whose `alg`/claims you edited and the server did not reject; a legacy endpoint that returns `200` to an anonymous probe; the server "accepting" a modified token without acting on it.

**IS confirmation:** an authenticated session obtained as a *different* user - exercise a capability only that account has - OR a reset token that actually resets another account's password and lets you log in as them. Reproduced from scratch in a clean session (fresh profile, no cached cookies) per hunt-core, with your own account ruled out as the thing you logged into.

## Chaining

- **Reset poisoning / token leak -> ATO.** A host-header or Referer-leaked reset token completes a full victim takeover - report the chain, not the leak alone.
- **Trusted JWT claim -> ATO.** A `sub`/`user_id` the server trusts plus a weak or strippable signature is arbitrary account takeover.
- **Hand off `hunt-federation`** for SSO/OAuth/SAML redirect_uri, state CSRF, and XSW signature attacks; this skill covers the SAML *auth-bypass* surface only.
- **Hand off `hunt-idor`** for the trusted-identifier overlap - a `PATCH /users/{victim}` that rewrites a victim email is an IDOR that chains straight back here to reset-based ATO (ATO path 5).

## Evasion

When the primary login rate-limits or enforces MFA, the bypass is usually a *different entry point to the same credential store*, not a cleverer payload: the legacy endpoints above, an alternate host (mobile/partner/API), an older API version, or a SOAP/JSON variant of the same auth call. For a hardened reset flow, vary the host-header injection vector (`X-Forwarded-Host`, dual `Host` headers, absolute-URI request line) rather than repeating one form.

## Severity

Rated on demonstrated impact (per hunt-core), not the mechanism.

| Condition | Typical |
|---|---|
| Auth bypass reaching an authenticated context with no credentials | critical |
| Full ATO of a victim account (reset poisoning, trusted-JWT claim, session fixation) | critical / high |
| Full ATO requiring one victim click | high |
| Unlimited credential brute-force endpoint confirmed (legacy protocol, no rate limit) | critical / high |
| Legacy endpoint reachable, accepts native creds, no rate limit, no creds tested yet | medium |

Unauthenticated outranks authenticated. A precondition you cannot satisfy (a victim click, a cred list you do not hold) lowers it.
