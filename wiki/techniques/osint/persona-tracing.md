---
title: "Persona Tracing & Social Photo Geolocation"
type: technique
tags: [osint, geolocation, sock-puppet, username-enumeration, recon, thm]
phase: recon
date_created: 2026-08-19
date_updated: 2026-08-19
sources: [thm-osint-persona]
---

# Persona Tracing & Social Photo Geolocation

Following one real person/persona from a single leaked artifact (a chat screenshot,
a username, a shared link) across their scattered public accounts, then geolocating a
photo they posted. Complements [[git-exposure]] and [[secret-hunting]] (infrastructure
OSINT); this page is the identity/person half. EXIF mechanics live in [[digital-forensics]].

## The pivot chain (person OSINT)

Person OSINT is a chain of pivots, each artifact handing you the selector for the next
account. A recurring shape:

```
leaked chat/screenshot  ->  a shared profile LINK or a HANDLE
   -> platform A profile (real display name in bio)         # identity
   -> a linked account / same handle on platform B          # cross-platform pivot
   -> leaked contact detail in metadata (commit email, ...) # accidental exposure
   -> a geotagged/landmarked photo on platform C            # physical location
   -> landmark geolocation -> street/business -> transit stop
```

Read every artifact END TO END before pivoting: the screenshot's real payload is often a
URL or a username in the corner, not the chat text. One handle reused across sites
(`user123` on GitHub, Threads, Instagram, a route-tracker) collapses the whole graph;
try the exact handle on each platform directly, and check each profile's "external links"
row (it names the next account for free).

## GitHub commit-author email leak

A GitHub profile can hide the email while the commit metadata exposes it. The public
REST API returns the author/committer email of every commit even when the web UI does not:

```bash
curl -s https://api.github.com/repos/<user>/<repo>/commits | \
  python3 -c 'import sys,json; [print(c["commit"]["author"]) for c in json.load(sys.stdin)]'
# or per-commit: append .patch to a commit URL -> the From: header carries the email
curl -s https://github.com/<user>/<repo>/commit/<sha>.patch | grep -m1 ^From:
```

The profile-README repo (`<user>/<user>`) almost always has an "Initial commit" whose
author email is the person's real address, often a DIFFERENT account name than the handle
(the tell that it was committed from their primary identity). This is the classic
"accidentally exposed email" in a persona challenge.

## Geolocating a social photo (EXIF is stripped)

Threads/Instagram/Facebook/X re-encode uploads and strip ALL metadata, so `exiftool` on
the downloaded file returns nothing (`NO EXIF`, no GPS). Geolocate from what is IN the
frame instead:

- **Business signage** -> look up that company's address. Beware: query the brand name
  ALONE, then read the primary site's own contact/locations page. Searching `<brand> <cityX>`
  biases a city-directory result back to cityX and can self-confirm a wrong city.
- **Transit-stop totems / directional signs** -> the station name and line are usually
  legible after upscaling; they geolocate to a stop directly.
- Secondary anchors: license-plate country band, road-marking style, language/diacritics
  on signs, architecture, a distinctive billboard.

Pull the FULL-RES image, not the page thumbnail (a thumbnail is unreadable). Grab the CDN
`src` from the rendered DOM, download, then crop + upscale the sign region:

```bash
# in the browser devtools/console on the post page:
#   [...document.querySelectorAll('img')].map(i=>[i.src,i.naturalWidth]).filter(x=>x[1]>800)
curl -sL -A 'Mozilla/5.0' '<fbcdn/instagram full-res url>' -o photo.jpg
python3 -c "from PIL import Image; im=Image.open('photo.jpg'); \
im.crop((x0,y0,x1,y1)).resize((w*8,h*8), Image.LANCZOS).save('sign.png')"
```

A JS-heavy social site behind a cookie/login wall needs a real browser (devtools MCP /
headless chromium), not a plain fetch; dismiss the consent modal, then screenshot or scrape
the `src`. A geotag chain can end at a specific transit stop / venue that answers "where did
they get off / go".

## Answer & verification gotchas (failure deltas)

- **Diacritic-sensitive answer checkers.** Some room checkers compare EXACT original-language
  spelling: the ASCII-folded form is REJECTED and the accented form ACCEPTED (e.g. a Romanian
  place name with `ț/ă/ș`). When a place answer with a foreign name bounces, resubmit with the
  native diacritics before assuming the answer is wrong.
- **Do not let a search query self-confirm.** A query with a location baked in returns that
  location's directories; that is selection bias, not evidence. Establish location from the
  photo's own landmarks independently.
- **Do not trust search-engine answer-synthesis as a source.** An AI search summary that
  "quotes writeups" can hallucinate specific values (a phone, a city). Only a page/profile you
  actually fetched is primary evidence; a summary is a lead to verify, never the answer.
- **Do the framed active-OSINT step.** When a room explicitly says it includes an active-OSINT
  interaction ("email this address", "the response is part of the setup"), that interaction IS
  the intended primary source for a contact detail (an auto-reply signature carries the phone/
  city/company). Substituting a third-party value skips the evidence. Interact only inside the
  sanctioned lab; note it uses the sender's identity, so confirm before sending from a real account.

<!-- promoted-slug: persona-tracing -->
