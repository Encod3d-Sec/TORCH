---
title: "CUPP (Common User Passwords Profiler)"
type: tool
tags: [brute-force, cracking, osint, passwords, tool, wordlist]
date_created: 2026-07-16
date_updated: 2026-07-16
sources: []
phase: crack
---

## Purpose

**CUPP** generates a TARGETED wordlist from a person's personal info (name, surname, nickname, birthdate, partner, pet, company, keywords) using predictable mutation rules (capitalisation, year/number append, special chars, leet-speak). Reach for it when a login's password is likely derived from the target's own personal info or a stated pattern (OSINT pulled from a profile/social/careers page), not for a generic rockyou brute force.

## Install / setup

```bash
git clone https://github.com/Mebus/cupp.git
# or on Kali:
sudo apt install cupp -y
```

Lives in `/opt/arsenal/cupp` under this harness.

## Core usage

```bash
python3 cupp.py -i
```

Interactive mode prompts for: First Name / Surname / Nickname / Birthdate (DDMMYYYY) / partner's name+nickname+birthdate / child's name+nickname+birthdate / pet's name / company name / keywords, then "special chars?" / "random numbers?" / "leet mode?". Blank answers are accepted (length-0 skips that field). Output is written to `<firstname>.txt`.

### Non-interactive (SSH bridge with no stdin forwarding)

When `-i` is run over an SSH bridge that doesn't forward a TTY/stdin, feed the answers from a file instead of typing them:

```bash
python3 cupp.py -i < answers.txt
```

`answers.txt` = one answer per line, in prompt order; leave a blank line for any field you want to skip.

## Common use cases

- OSINT turned up a name, birthdate, and pet/company from a LinkedIn/careers/about page -> feed those into CUPP, then brute the login with the result.
- A stated or guessed password pattern (e.g. "FirstnameYear!") -> answer the relevant CUPP fields and enable special-chars/leet to generate the mutation set.

## Post-filter tip

CUPP with special-chars + random-numbers enabled explodes the list quickly. Filter to the likely subset first, e.g. date-bearing clean candidates:

```bash
grep -E '1995|1402' name.txt | grep -vE '[^A-Za-z0-9]'
```

Then fall back to the full unfiltered list if the filtered subset misses.

Feed the resulting wordlist to [[hydra]], medusa, or [[john]] against the login/SSH target.

## Tips and gotchas

- Blank fields are fine; CUPP just skips permutations for that field, it does not error.
- The `-i < answers.txt` trick works for any tool that normally expects an interactive terminal when the transport (SSH bridge, some MCP shells) does not forward stdin/TTY.
- Combine with [[cewl]] when the password may mix personal info with company/site vocabulary (feed CeWL's word list into CUPP's "keywords" field).

## Related techniques

- [[hydra]]: feed the generated wordlist to `-P` for online brute force
- [[john]]: crack an extracted hash with the CUPP list via `--wordlist`
- [[password-cracking]], [[password-attacks]]

## Sources
