# Harness Discipline via the Driver — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make four recurring CTF/box behaviors (call redteamlead at stop-tells, msfconsole-owned reverse-shell pops, searchsploit+msf-first exploit search, no hand-rolling) reliable by encoding them in the deterministic driver and hardening skill prose — without any throttling enforcement hook.

**Architecture:** The driver (`scripts/campaign.py`) gains (a) contextual posture lines it re-asserts every turn, and (b) a read of passive stop-tell counters that emit a hard "call redteamlead" STOP at data-derived thresholds. A PostToolUse hook (`recon-capture.py`) writes those counters passively (never denies/nudges). The throttling code in `drift-guard.py` and the false-firing stabilize nudge in `recon-capture.py` are removed. Skill prose is hardened to match.

**Tech Stack:** Python 3 (stdlib only), pytest 9, existing vault hook/driver framework.

**Spec:** `docs/specs/2026-08-17-harness-discipline-driver.md`

## Global Constraints

- **Stdlib only.** No new dependencies. Hooks and driver import only stdlib + existing local modules (`_engagement`, `_telemetry`, `campaign`).
- **Hooks fail open.** Any exception → exit 0, allow. Never trap the operator. The new counter writes are best-effort and wrapped in try/except.
- **No new `deny`.** The only `permissionDecision: deny` in the codebase after this work is `scope-guard.py` (scope/RoE). Nothing added here denies or injects blocking context.
- **Counter state lives in `.campaign.json`** under key `tells` (a dict), alongside the existing `off_board_streak`/`emitted_bins`/`pass` keys the driver and hooks already read/write there.
- **Commits:** this repo commits only on the operator's go. Commit steps are written out per task; the operator decides when to run them.
- **Reverse-shell rule (verbatim, for all prose tasks):** catch every reverse-shell pop through `msfconsole multi/handler`; payload meterpreter-first, plain `shell_reverse_tcp`/listener backup when meterpreter is blocked or unstable (routine on Windows/EDR); no raw `nc` as the default catch; SSH/evil-winrm/existing-cred footholds stay as-is. pwncat-cs is dropped.

---

### Task 1: Driver reads stop-tell counters → RTL STOP (`campaign.py`)

Add the enforcement (read) half of the RTL counter: `cmd_next` prints a hard STOP directing `Skill(redteamlead)` when a tell threshold is met, and suppresses it once redteamlead has actually fired.

**Files:**
- Modify: `scripts/campaign.py` (add module-level `_TELL_THRESH`/`_TELL_MSG` near the other constants ~line 1032; add `_tells_stop(d, st)` helper near `_drift`/`_row_effort` ~line 701; call it in `cmd_next` right after the SOLVED short-circuit, campaign.py:1119-1121)
- Test: `tests/test_tells.py`

**Interfaces:**
- Consumes: `_load_state(d)` → `st` dict; `_skill_fired_since(d, skill, since_iso)` → `(fired: bool, oracle: bool)` (campaign.py:656); `.campaign.json["tells"]` = `{"crack_fail": int, "box_000": int, "ts": iso_str}` (written by Task 2).
- Produces: `_tells_stop(d, st) -> str | None` — the STOP message to print, or None. `cmd_next` prints it and returns 0 before serving a row.

- [ ] **Step 1: Confirm the redteamlead event name recorded in `.events.jsonl`**

Run: `grep -nE 'redteamlead|skill|Skill\(' scripts/campaign.py | grep -i fired; sed -n '656,690p' scripts/campaign.py`
Expected: read `_skill_fired_since` to see whether it matches the skill by bare name (`redteamlead`) or `Skill(redteamlead)`. Use that exact form in Step 3's `_skill_fired_since(d, <form>, since)` call. (If unclear, also `grep -n 'def hook\|def drift\|skill' skills/hooks/tool-telemetry.py`.)

- [ ] **Step 2: Write the failing test**

```python
# tests/test_tells.py
import json, os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
CAMPAIGN = os.path.join(VAULT, "scripts", "campaign.py")
FIX = os.path.join(HERE, "fixtures", "campaign")

def _mk(tmp_path):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    open(d / "state.md", "w").write(
        "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n\n"
        "| asset | ip | os | services | access | owned | notes |\n"
        "|-------|----|----|----------|--------|-------|-------|\n"
        "| 10.10.1.1 | 10.10.1.1 | Linux | http | port-open | no | web |\n")
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "init", "--type", "ctf"],
                   capture_output=True, text=True)
    return d

def _set_tells(d, **kw):
    sp = d / ".campaign.json"
    st = json.load(open(sp))
    st["tells"] = kw
    json.dump(st, open(sp, "w"))

def _next(d):
    return subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "next"],
                          capture_output=True, text=True).stdout

def test_crack_fail_two_prints_rtl_stop(tmp_path):
    d = _mk(tmp_path)
    _set_tells(d, crack_fail=2, ts="2020-01-01T00:00:00")
    out = _next(d)
    assert "STOP" in out and "redteamlead" in out and "wordlist" in out

def test_box_000_three_prints_rtl_stop(tmp_path):
    d = _mk(tmp_path)
    _set_tells(d, box_000=3, ts="2020-01-01T00:00:00")
    out = _next(d)
    assert "STOP" in out and "redteamlead" in out

def test_below_threshold_no_stop(tmp_path):
    d = _mk(tmp_path)
    _set_tells(d, crack_fail=1, box_000=2, ts="2020-01-01T00:00:00")
    out = _next(d)
    assert "STOP" not in out

def test_redteamlead_fired_clears_stop(tmp_path):
    d = _mk(tmp_path)
    _set_tells(d, crack_fail=2, ts="2020-01-01T00:00:00")
    # a redteamlead event AFTER the tell timestamp clears the STOP
    with open(d / ".events.jsonl", "a") as f:
        f.write(json.dumps({"ts": "2099-01-01T00:00:00", "skill": "redteamlead"}) + "\n")
    out = _next(d)
    assert "STOP" not in out
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd <VAULT> && python3 -m pytest tests/test_tells.py -v`
Expected: FAIL (STOP text absent — helper not implemented). `test_below_threshold_no_stop` may pass trivially; the other three must fail.

- [ ] **Step 4: Implement `_tells_stop` and wire it into `cmd_next`**

Add near campaign.py:1032 (by `HIGH_VALUE_CLASSES`):

```python
_TELL_THRESH = {"crack_fail": 2, "box_000": 3}
_TELL_MSG = {
    "crack_fail": ("STOP: %d verified hashes failed the wordlist -> the creds are out-of-band "
                   "(email/note/KeePass/config). Call Skill(redteamlead) before another crack, or "
                   "read the app's OTHER surfaces (LFI/source, a second vhost, mail)."),
    "box_000": ("STOP: the box is starving under your own exploit loop (%dx 000/timeout). A vector "
                "that DoSes a lab box is almost never intended - serialize requests, or call "
                "Skill(redteamlead) to re-pick the vector."),
}
```

Add the helper near campaign.py:701 (by `_drift`). Use the redteamlead-name form confirmed in Step 1:

```python
def _tells_stop(d, st):
    """A hard STOP -> Skill(redteamlead) when a stop-tell counter crosses its threshold, unless a
    redteamlead firing is newer than the last tell bump (agent already consulted RTL). Returns the
    message string or None."""
    tells = st.get("tells") or {}
    since = tells.get("ts")
    try:
        if since and _skill_fired_since(d, "redteamlead", since)[0]:
            return None
    except Exception:
        pass
    for key, thresh in _TELL_THRESH.items():
        n = int(tells.get(key, 0) or 0)
        if n >= thresh:
            return _TELL_MSG[key] % n
    return None
```

Wire into `cmd_next` right after the SOLVED short-circuit (campaign.py:1119-1121), before `rows = read_board(d)`:

```python
    if _is_solved(d):
        return _closeout(d, st, tconf, "state.md marked SOLVED")
    _stop = _tells_stop(d, st)
    if _stop:
        print(_stop)
        print("  (reset: the STOP clears once Skill(redteamlead) fires. Then run `next` again.)")
        return 0
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd <VAULT> && python3 -m pytest tests/test_tells.py -v`
Expected: PASS (4/4).

- [ ] **Step 6: Regression — the rest of the driver still works**

Run: `cd <VAULT> && python3 -m pytest tests/test_campaign.py tests/test_antidrift_e2e.py -q`
Expected: PASS (no regressions from the early-return).

- [ ] **Step 7: Commit**

```bash
git add scripts/campaign.py tests/test_tells.py
git commit -m "campaign: RTL STOP when a stop-tell counter crosses threshold"
```

---

### Task 2: Passive stop-tell counters + drop stabilize nudge (`recon-capture.py`)

The write half of the RTL counter, plus removal of the false-firing stabilize nudge (both live in `recon-capture.py`, so they ship together as this file's exploit-phase rework).

**Files:**
- Modify: `scripts/../skills/hooks/recon-capture.py` — add a `_bump_tells(d, cmd, text)` call in `main()`; remove the RCE→stabilize nudge block (~lines 886-905, the "STOP hand-poking one-liners / pop a reverse shell into tmux / STABILIZE it" advisory)
- Test: `tests/test_tells_hook.py`; update `tests/test_recon_capture_rce_shell.py`

**Interfaces:**
- Consumes: `_response_text(data)` (recon-capture.py:253) → tool output string; `_engagement.active_dir()` → engagement dir or None; `.campaign.json` (may be absent → no-op).
- Produces: increments `.campaign.json["tells"]["crack_fail"|"box_000"]` and stamps `["tells"]["ts"]`. Never emits `deny` or `additionalContext`. Read by Task 1.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tells_hook.py
import json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
HOOK = os.path.join(VAULT, "skills", "hooks", "recon-capture.py")

def _run(payload, active_dir):
    env = dict(os.environ, OBSIDIAN_VAULT=VAULT)
    # point the active engagement at active_dir via targets/active.md convention used by _engagement
    return subprocess.run([sys.executable, HOOK], input=json.dumps(payload),
                          capture_output=True, text=True, env=env)

def _mk_campaign(tmp_path):
    d = tmp_path / "targets" / "eng"
    d.mkdir(parents=True)
    json.dump({"type": "ctf", "pass": 6, "tells": {}}, open(d / ".campaign.json", "w"))
    (tmp_path / "targets" / "active.md").write_text("eng\n")
    return d

def _tells(d):
    return json.load(open(d / ".campaign.json")).get("tells", {})

def test_crack_fail_increments(tmp_path, monkeypatch):
    d = _mk_campaign(tmp_path)
    monkeypatch.setenv("VAULT_TARGETS", str(tmp_path / "targets"))  # if _engagement honors it; else adapt
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "bash /root/vm.sh 'john --wordlist=rockyou.txt h'"},
               "tool_response": {"stdout": "No password hashes cracked (see FAQ)"}}
    _run(payload, d)
    assert _tells(d).get("crack_fail", 0) >= 1

def test_box_000_increments_then_resets_on_success(tmp_path):
    d = _mk_campaign(tmp_path)
    bad = {"tool_name": "Bash",
           "tool_input": {"command": "curl -s -o /dev/null -w '%{http_code}' http://10.10.1.1/x"},
           "tool_response": {"stdout": "000"}}
    _run(bad, d); _run(bad, d)
    assert _tells(d).get("box_000", 0) >= 2
    ok = {"tool_name": "Bash",
          "tool_input": {"command": "curl -s -o /dev/null -w '%{http_code}' http://10.10.1.1/x"},
          "tool_response": {"stdout": "200"}}
    _run(ok, d)
    assert _tells(d).get("box_000", 0) == 0
```

> **Executor note:** how `_engagement.active_dir()` locates the active engagement in a test sandbox may differ from the env hints above. Before writing the impl, read `skills/hooks/_engagement.py` (`active_dir`) and mirror however the EXISTING recon-capture tests (`tests/test_recon_capture_rce_shell.py`) set up their sandbox — reuse that exact fixture mechanism rather than the placeholder env vars above.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd <VAULT> && python3 -m pytest tests/test_tells_hook.py -v`
Expected: FAIL (counters not written).

- [ ] **Step 3: Implement `_bump_tells` and call it in `main()`**

Add to `recon-capture.py` (place the call early in `main()` after `_response_text` and the active-dir resolve, guarded on `.campaign.json` existing):

```python
_CRACK_FAIL_RE = re.compile(r"No password hashes cracked|0 password hashes cracked|\b0g 0:00", re.I)
_HTTP_DEAD_RE = re.compile(r"\b000\b|empty reply from server|connection timed out|couldn't connect", re.I)
_HTTP_OK_RE = re.compile(r"\bHTTP/\d\.\d\s+[2345]\d\d\b|\b[2345]\d\d\b")

def _bump_tells(d, cmd, text):
    """Passive stop-tell counters in .campaign.json. Never denies/injects (fail-open)."""
    sp = os.path.join(d, ".campaign.json")
    if not os.path.isfile(sp):
        return
    try:
        st = json.load(open(sp, encoding="utf-8"))
    except Exception:
        return
    tells = st.setdefault("tells", {})
    changed = False
    if re.search(r"\b(john|hashcat)\b", cmd) and _CRACK_FAIL_RE.search(text or ""):
        tells["crack_fail"] = int(tells.get("crack_fail", 0) or 0) + 1
        changed = True
    if re.search(r"\b(curl|wget|http|nc|ncat)\b", cmd):
        if _HTTP_DEAD_RE.search(text or ""):
            tells["box_000"] = int(tells.get("box_000", 0) or 0) + 1
            changed = True
        elif _HTTP_OK_RE.search(text or ""):
            if tells.get("box_000"):
                tells["box_000"] = 0
                changed = True
    if changed:
        import datetime
        tells["ts"] = datetime.datetime.now().isoformat(timespec="seconds")
        try:
            json.dump(st, open(sp, "w", encoding="utf-8"), indent=1)
        except Exception:
            pass
```

Call it in `main()` (find where `d = _engagement.active_dir()` / `_response_text(data)` are already computed and add):

```python
    if d:
        _bump_tells(d, cmd, _response_text(data))
```

- [ ] **Step 4: Remove the stabilize nudge**

Delete the RCE→reverse-shell→STABILIZE advisory block (~recon-capture.py:886-905, the fire-once nudge that says "STOP hand-poking one-liners: pop a reverse shell into tmux ... STABILIZE it"). This is the block that false-fired on frank's SSH session. Leave the OOB correlation and fingerprint routing intact.

- [ ] **Step 5: Update the existing stabilize test**

Run: `cd <VAULT> && python3 -m pytest tests/test_recon_capture_rce_shell.py -v`
Expected: the test asserting the stabilize nudge FIRES now fails. Edit that test to assert the nudge is ABSENT (invert the assertion), matching the removal. Keep any assertion about fingerprint routing / OOB correlation unchanged.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd <VAULT> && python3 -m pytest tests/test_tells_hook.py tests/test_recon_capture_rce_shell.py tests/test_recon_capture_meta_guard.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add skills/hooks/recon-capture.py tests/test_tells_hook.py tests/test_recon_capture_rce_shell.py
git commit -m "recon-capture: passive stop-tell counters; drop false-firing stabilize nudge"
```

---

### Task 3: Posture lines in the driver (`campaign.py`)

Contextual, deterministic reminders of the four behaviors, emitted from both the pre-board path and the row path so `next` pays off on turn 1.

**Files:**
- Modify: `scripts/campaign.py` — `cmd_next` row path (~1189-1266); `_pre_board_next` (~1281-1308); fold the no-handroll clause into the `G8: tool-first` line (campaign.py:1257)
- Test: `tests/test_posture.py`

**Interfaces:**
- Consumes: `CODE_EXEC_CLASSES` (campaign.py:1038); `st["footholds"]` dict; `row["vuln class"]`; `st["pass"]`.
- Produces: printed POSTURE lines. No new state, no new public function required (inline prints are fine).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_posture.py
import os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
CAMPAIGN = os.path.join(VAULT, "scripts", "campaign.py")
FIX = os.path.join(HERE, "fixtures", "campaign")

def _mk(tmp_path, services, cls_hint):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    open(d / "state.md", "w").write(
        "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n\n"
        "| asset | ip | os | services | access | owned | notes |\n"
        "|-------|----|----|----------|--------|-------|-------|\n"
        "| 10.10.1.1 | 10.10.1.1 | Linux | %s | port-open | no | %s |\n" % (services, cls_hint))
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "init", "--type", "ctf"],
                   capture_output=True, text=True)
    # drive to a served row: pass-done x5 then board
    for _ in range(5):
        subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "pass-done"], capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "board"], capture_output=True, text=True)
    return d

def _next(d):
    return subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "next"],
                          capture_output=True, text=True).stdout

def test_code_exec_row_prints_msf_shell_line(tmp_path):
    # a service that yields an RCE/upload row and no live foothold
    d = _mk(tmp_path, "http apache", "rce")
    out = _next(d)
    assert "multi/handler" in out.lower() or "msfconsole" in out.lower()

def test_no_handroll_folded_into_g8(tmp_path):
    d = _mk(tmp_path, "http apache", "rce")
    out = _next(d)
    assert "hand-rolled" in out.lower() or "hand-roll" in out.lower()

def test_preboard_fingerprint_pass_prints_searchsploit(tmp_path):
    d = tmp_path / "eng2"
    shutil.copytree(FIX, d)
    open(d / "state.md", "w").write(
        "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n")
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "init", "--type", "ctf"],
                   capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "pass-done"], capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "pass-done"], capture_output=True, text=True)
    out = subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "next"],
                         capture_output=True, text=True).stdout  # pass 2 = fingerprint
    assert "searchsploit" in out.lower()
```

> **Executor note:** the exact vuln class the board derives from `services`/`notes` depends on `playbook.json`. Before finalizing the test, run `campaign.py board` then `campaign.py next` on the fixture and read the served `ROW ... x <class>` line to pick a `services`/`cls_hint` pair that reliably yields a `CODE_EXEC_CLASSES` row. Adjust the fixture inputs, not the assertions.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd <VAULT> && python3 -m pytest tests/test_posture.py -v`
Expected: FAIL (no posture lines yet).

- [ ] **Step 3: Implement the msf-shell + no-handroll lines in the row path**

In `cmd_next`, after the `ROW`/`FOOTHOLD` prints (~campaign.py:1190-1195) and before `REQUIRED, in order:` (campaign.py:1206), add:

```python
    rowcls_l = (row.get("vuln class") or "").strip().lower()
    if rowcls_l in CODE_EXEC_CLASSES and not win:
        print("POSTURE   catch the pop through `msfconsole multi/handler` (meterpreter first; plain "
              "shell_reverse_tcp/listener backup when meterpreter is blocked - routine on Windows/EDR). "
              "No raw-nc default. SSH/evil-winrm/cred footholds stay as-is.")
```

Fold no-handroll into the existing `G8: tool-first` line. Change campaign.py:1257 from:

```python
            print("  %d. run: %s          [G8: tool-first]" % (n, inv))
```
to:
```python
            print("  %d. run: %s          [G8: tool-first; no hand-rolled /dev/tcp/curl/urllib "
                  "loops - if no tool fits, say why in one line]" % (n, inv))
```

- [ ] **Step 4: Implement the searchsploit line in pre-board + version-known rows**

In `_pre_board_next` add, after the guidance print (~campaign.py:1302), when `p in (2, 3)`:

```python
    if p in (2, 3):
        print("POSTURE   version fingerprinted -> `searchsploit <app> <ver>` + "
              "`msfconsole -qx 'search <app>'` BEFORE hand-rolling or deep-diving a CVE.")
```

(Pass-3 guidance already mentions searchsploit; this adds the msf pairing and makes it a POSTURE line the version-known row path can also print — optionally mirror it in the row path when the row's tech column carries a version, if cheap.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd <VAULT> && python3 -m pytest tests/test_posture.py -v`
Expected: PASS (3/3).

- [ ] **Step 6: Regression**

Run: `cd <VAULT> && python3 -m pytest tests/test_campaign.py tests/test_antidrift_e2e.py tests/test_tells.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add scripts/campaign.py tests/test_posture.py
git commit -m "campaign: contextual posture lines (msf-shell, searchsploit-first, no-handroll)"
```

---

### Task 4: Declaw `drift-guard.py` (remove throttling)

Remove the escalating `deny` and the time-based auto-rtl; downgrade scanner-cap from `deny` to advisory. Keep the self-kill advisory.

**Files:**
- Modify: `skills/hooks/drift-guard.py` — remove the off-board `deny` branch (drift-guard.py:296-307, keep only the advisory `else` branch); remove the 5-min time-based auto-rtl block (drift-guard.py:248-259); change `_scanner_cap` emission from `deny` to advisory (drift-guard.py:235-241, always take the `additionalContext` path)
- Test: update `tests/test_drift_guard.py`, `tests/test_autortl.py`

**Interfaces:**
- Consumes: unchanged inputs (PreToolUse Bash payload).
- Produces: at most `additionalContext` advisories; NO `permissionDecision: deny` anywhere in this hook after the change.

- [ ] **Step 1: Update the tests to the new contract (these become the failing spec)**

Edit `tests/test_drift_guard.py`: the test asserting a 3rd off-board call returns `permissionDecision: deny` → change to assert the output has NO `deny` and DOES carry the `DRIFT (off-board ...)` advisory. The scanner-cap test asserting `deny` → assert advisory (`SCANNER-CAP`/`additionalContext`), no `deny`.
Edit `tests/test_autortl.py`: the time-based auto-rtl (5-min drift → redteamlead nudge) is removed from drift-guard; change the test to assert drift-guard no longer emits the time-based auto-rtl, OR move/retire the test (the RTL trigger now lives in `campaign.py` via `tests/test_tells.py`). Prefer: assert absence in drift-guard and leave a comment pointing to `test_tells.py`.

- [ ] **Step 2: Run to verify they fail**

Run: `cd <VAULT> && python3 -m pytest tests/test_drift_guard.py tests/test_autortl.py -v`
Expected: FAIL (hook still denies / still emits time-based auto-rtl).

- [ ] **Step 3: Remove the off-board deny branch**

In `drift-guard.py` replace the `if streak >= 3 and _enforcing() and not _post_foothold(...)` deny block (drift-guard.py:296-307) so ALL off-board cases take the advisory print (the existing `else` block, drift-guard.py:308-316). Keep the streak counter increment/telemetry. Net: off-board is advisory-only, never denies.

- [ ] **Step 4: Remove the time-based auto-rtl block**

Delete drift-guard.py:248-259 (the `since is not None and since > 300` auto-rtl injection). The RTL trigger is now the tell-counter STOP in `campaign.py` (Task 1) — a real signal, not 5-min idle.

- [ ] **Step 5: Downgrade scanner-cap to advisory**

In the `_HEAVY_RE`/`_scanner_cap` handling (drift-guard.py:227-242), always emit the `additionalContext` advisory form; never the `permissionDecision: deny` form. Keep the `_scanner_cap` detection logic (it still records launches and warns on a concurrent 2nd heavy scanner).

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd <VAULT> && python3 -m pytest tests/test_drift_guard.py tests/test_autortl.py tests/test_hooks.py tests/test_antidrift_e2e.py -v`
Expected: PASS. Confirm no `deny` string is produced by drift-guard in any path.

- [ ] **Step 7: Commit**

```bash
git add skills/hooks/drift-guard.py tests/test_drift_guard.py tests/test_autortl.py
git commit -m "drift-guard: remove throttling deny + time-based auto-rtl; scanner-cap -> advisory"
```

---

### Task 5: Harden skill prose (C)

Make the four behaviors MUST-level in the skills, drop pwncat, and add the per-step driver-run mandate. No unit tests; verification is a phrase-presence grep + read-through.

**Files:**
- Modify: `skills/workflow/ctf-box/SKILL.md` (lines ~85, ~88, ~94, and a new top-of-skill mandate)
- Modify: `skills/hunt/hunt-core/SKILL.md` (stop-conditions section)
- Modify: `skills/workflow/ctf-workflow/SKILL.md`, `skills/workflow/pt-workflow/SKILL.md` (per-step driver mandate)

- [ ] **Step 1: ctf-box — reverse-shell rule + drop pwncat**

Rewrite line ~94 ("Prefer a real handler over a raw `nc` listener") to the verbatim reverse-shell rule from Global Constraints, phrased as MUST. Remove the pwncat-cs sentence/recommendation. Keep the meterpreter `autoroute`/`portfwd`/`socks` note.

- [ ] **Step 2: ctf-box — searchsploit+msf as a hard step**

Line ~85: change the searchsploit+metasploit "quick-win reflex" to a hard step: "On any version fingerprint you MUST run `searchsploit <app> <ver>` and `msfconsole -qx 'search <app>'` before hand-rolling or deep-diving a CVE."

- [ ] **Step 3: ctf-box — RTL on the FIRST tell**

Line ~88: change "When the next door is not obvious, call `Skill(redteamlead)`" to "Call `Skill(redteamlead)` on the FIRST tell (2 verified hashes fail the wordlist, or the box returns 000/crashes under your exploit loop) - do not grind a 3rd hash or tune the tooling." Align wording to the Task-1 thresholds.

- [ ] **Step 4: ctf-box — driver-run mandate (top of skill)**

Add near the top (by the existing GATE lines, ctf-box.md:12): "Run `python3 scripts/campaign.py next` before every exploit step and `done`/`pass-done` after - the driver reprints the required posture (msf-shell, searchsploit-first, RTL stop-tells) and is the forcing function now that the drift-guard deny is gone."

- [ ] **Step 5: hunt-core — align stop-conditions**

In hunt-core's Stop conditions, state the two hard tells and thresholds (2 failed cracks / 3x box-000 → `Skill(redteamlead)`, not grind) to match the driver STOP.

- [ ] **Step 6: ctf-workflow + pt-workflow — reassert driver mandate**

Add/repeat the "run `campaign.py next` before every exploit step" line in each workflow skill's execution-loop section.

- [ ] **Step 7: Verify phrase presence + no pwncat**

Run:
```bash
cd <VAULT>
grep -in 'multi/handler\|meterpreter' skills/workflow/ctf-box/SKILL.md
grep -in 'searchsploit' skills/workflow/ctf-box/SKILL.md
grep -in 'first tell\|redteamlead' skills/workflow/ctf-box/SKILL.md skills/hunt/hunt-core/SKILL.md
grep -in 'campaign.py next' skills/workflow/ctf-box/SKILL.md skills/workflow/ctf-workflow/SKILL.md skills/workflow/pt-workflow/SKILL.md
grep -in 'pwncat' skills/workflow/ctf-box/SKILL.md   # expect: no matches
```
Expected: each positive grep hits; the pwncat grep returns nothing.

- [ ] **Step 8: Commit**

```bash
git add skills/workflow/ctf-box/SKILL.md skills/hunt/hunt-core/SKILL.md skills/workflow/ctf-workflow/SKILL.md skills/workflow/pt-workflow/SKILL.md
git commit -m "skills: msf-owns-the-pop (drop pwncat), searchsploit-first, RTL-on-first-tell, driver-run mandate"
```

---

### Task 6: Belt-and-suspenders + full-suite gate

Seed scope templates and confirm the whole subsystem is green.

**Files:**
- Modify: `setup/templates/ctf/scope.md`, `setup/templates/pentest/scope.md`, `setup/templates/bugbounty/scope.md`
- Verify: `Skill(campaign-health)` smoke test path

- [ ] **Step 1: Check whether the templates already carry the 8 envelope keys**

Run: `cd <VAULT> && for t in ctf pentest bugbounty; do echo "== $t =="; grep -cE 'autonomy|enum_cap|write_policy|oob_allowed|scanners|budget_requests|rate_per_host|target_severity' setup/templates/$t/scope.md; done`
Expected: prints a count per type. If any is < 8, seed that template. If all are 8, skip Steps 2-3 (self-heal already covers it; nothing to do).

- [ ] **Step 2: Seed missing envelope keys**

For each template missing keys, add the 8 keys inside the frontmatter with per-type defaults (ctf defaults = `CTF_ENVELOPE_DEFAULTS`, campaign.py:120; pentest/bugbounty: mirror but set `target_severity` appropriately, `autonomy: full`). Match the exact key names in `ENVELOPE_KEYS` (campaign.py:37).

- [ ] **Step 3: Verify a fresh engagement inits clean**

Run: `cd <VAULT> && bash setup/new-engagement.sh _smoketest ctf >/dev/null 2>&1; python3 scripts/campaign.py --eng targets/_smoketest init --type ctf; echo "rc=$?"; rm -rf targets/_smoketest`
Expected: `rc=0`, no "missing required envelope keys" error.

- [ ] **Step 4: Full suite + health check**

Run:
```bash
cd <VAULT> && python3 -m pytest tests/ -q
python3 scripts/campaign-doctor.py 2>&1 | tail -20   # or: Skill(campaign-health)
```
Expected: pytest green (or only pre-existing unrelated failures — diff against a baseline run captured before Task 1); campaign-doctor smoke test (init→board→next) passes.

- [ ] **Step 5: Commit**

```bash
git add setup/templates/ctf/scope.md setup/templates/pentest/scope.md setup/templates/bugbounty/scope.md
git commit -m "templates: seed scope envelope keys (belt-and-suspenders over self-heal)"
```

---

## Notes for the executor

- **Capture a pytest baseline before Task 1** (`python3 -m pytest tests/ -q > /tmp/baseline.txt`) so "no new failures" is checkable against pre-existing reds, not an absolute green.
- **`<VAULT>`** = the machine's vault path (this machine: `/mnt/c/Users/TZ/Documents/ObsidianVaults/ClaudeBrain`). Resolve via `setup/vault-path.sh` if scripting.
- Tasks 1 and 3 both edit `cmd_next`; do them in order (1 then 3) to avoid overlapping edits.
- The two behavior removals (Task 2 stabilize nudge, Task 4 deny/auto-rtl) are the load-bearing "stop throttling" change — after them, verify by grep that `permissionDecision.*deny` appears only in `scope-guard.py`: `grep -rn 'permissionDecision.*deny' skills/hooks/`.
