---
name: chrome-devtools-browser
description: Bring up a REAL, visible, interactive chromium on the Kali VM that the operator logs into (Smart-ID / Mobile-ID / any manual auth or MFA/CAPTCHA), while the agent drives and observes it live through the chrome-devtools MCP (navigate, DOM snapshot, network capture, screenshots, console, evaluate). Use whenever a target needs a MANUAL login the agent cannot complete headlessly, when you need to capture an authenticated session / the real API calls a page makes, or to confirm/screenshot a DOM-XSS. Triggers - "open a browser", "log in manually", "smart-id / mobile-id / national id login", "mfa / 2fa login", "solve the captcha", "drive the browser", "capture the authenticated session / network".
---

# chrome-devtools-browser

Headless `browser.sh` cannot solve a human login. This skill brings up a **visible** chromium on the
Kali desktop (`:0`) the operator can click and type into, with its DevTools port tunnelled back so the
**chrome-devtools MCP** drives and watches it. Two roles at once: the human authenticates; the agent
observes + acts. The VM holds the VPN/egress path, so it reaches both internet and in-scope targets.

## 1. Bring it up (one command)

```bash
bash scripts/browser-visible.sh <login-url> --profile bbtest-<eng>
# e.g. bash scripts/browser-visible.sh https://target.example/ib --profile bbtest-<eng>
```

It resolves the VM's seat session, unlocks/wakes `:0`, frees the CDP port, launches chromium **as the
seat user on `:0`** in a named tmux session (a dedicated per-engagement profile, so the operator's own
profile/cookies stay clean), then reuses `scripts/browser.sh` to forward CDP to `http://127.0.0.1:9222`.
It prints `VISIBLE on :0` when a real on-screen window exists (not merely a listening port). If it prints
a `no (:N) desktop session` message, the VM has no desktop - fall back to `scripts/browser.sh` (headless).

## 2. Attach + hand off for login

- The chrome-devtools MCP attaches to `http://127.0.0.1:9222`. Confirm with `list_pages`; `navigate_page`
  to the login URL if needed.
- **Stay off the browser while the operator enters credentials.** Take a `take_screenshot` so they can
  confirm the page, then wait for their "logged in" before you drive again. The operator owns credential
  entry and the phone approval; the agent never types a personal code / PIN.

## 3. Drive + observe (chrome-devtools MCP capability map)

| Need | MCP tool |
|------|----------|
| List/select tabs | `list_pages` (select the target tab; ignore the operator's other tabs) |
| Go to a page / back / reload | `navigate_page` |
| Rendered DOM (elements + uids) | `take_snapshot` |
| Visual PoC / confirm state | `take_screenshot` -> a `web` evidence image (hand to `Skill(screenshot)`/`Skill(evidence)`) |
| **The real API calls the app makes** | `list_network_requests` (add `includePreservedRequests:true` to span the login redirects); this is the authenticated API map a curl crawl never sees |
| One request's headers/body/cookies | `get_network_request <reqid>` |
| Console / JS errors | `list_console_messages` |
| Read client config / globals, confirm DOM-XSS | `evaluate_script` (e.g. `__NEXT_DATA__`, `window.*`, fire a payload in the real DOM) |

Once authenticated, the captured `/…` API calls feed the hunt skills: `Skill(hunt-idor)` / `Skill(hunt-api)`
(BOLA on id-keyed endpoints), `Skill(hunt-xss)` (DOM-XSS via `evaluate_script`), business-logic on the
authed flows. Load-bearing requests still go to Burp Repeater when reachable (`Skill(hunt-burp)`).

## 4. Field notes

- **A `200 {"message":"Unable to login"}` with NO `Set-Cookie`** = the server rejected at an account/state
  check and issued no session -> nothing to pivot (not a bug). A `Set-Cookie`/JWT issued *before* such a
  check is a real authz-bypass lead - test the gated endpoints with that cookie.
- `dbus`/GPU errors in the tmux pane are non-fatal VM noise; judge success by `VISIBLE on` + `list_pages`.
- Data minimisation on the authed surface: prove IDOR/BOLA with your own account + stop at the first
  adjacent-id differential; never pull another customer's real PII.

## Safety

- The CDP port is **unauthenticated = total control of the browser** (read any tab, lift session cookies).
  It stays loopback-only + `ssh -L`; never bind `0.0.0.0` / expose it to the LAN.
- Named tmux session only (`cdpbrowser`); never `tmux kill-server` (the VPN/other work may live in tmux).
- Dedicated `--profile` per engagement; the port-free step warns it drops any tabs on that port.

## Teardown

```bash
bash scripts/browser.sh stop                                   # drop the CDP tunnel
bash /root/vm.sh 'tmux kill-session -t cdpbrowser'             # close the VM browser
```

Setup / recipe rationale + the dead-ends that shaped this: `scripts/browser.sh`, `scripts/shot.py`
(seat-session resolution), and the engagement `failures.md` note.
