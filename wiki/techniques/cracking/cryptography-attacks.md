---
title: "Cryptography Attacks (CTF + Applied)"
type: technique
tags: [crypto, ctf, rsa, aes, padding-oracle, ecdsa, prng, hash-length-extension]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-07-14
sources: [hacktricks-crypto]
---

## What it is

Breaking cryptography through implementation flaws and misuse rather than brute force: weak parameters, mode misuse, oracle leaks, nonce/key reuse, and predictable randomness. The dominant CTF crypto category and a real-world finding class (JWT, TLS, custom token schemes).

## How it works

Textbook primitives are secure; deployments are not. Attacks exploit small exponents, repeated nonces, malleable modes, side-channel oracles, and homebrew constructions. Identify the primitive, find the misuse, apply the matching attack.

## Attack phases
Exploitation (CTF challenge solving; applied to JWT/token/TLS findings during web + AD work).

## Prerequisites
- The ciphertext/scheme, and ideally the source or an oracle (encrypt/decrypt endpoint, error differences, timing).
- Public parameters (RSA `n,e`; curve; IV/nonce handling).

## Methodology

### RSA
```bash
# triage: factor n, weak params, then decrypt
RsaCtfTool --publickey key.pem --uncipher cipher.bin   # tries 30+ attacks
python3 -c "import factordb"   # factordb.com lookup for known n
```
- Small `e` (e=3) + short message -> cube root (`gmpy2.iroot(c,3)`); Hastad broadcast (same m, e recipients).
- Close primes -> Fermat factorization. Small `d` -> Wiener. Shared prime across keys -> batch GCD.
- Common modulus (same n, two e, gcd(e1,e2)=1) -> extended Euclid. LSB/parity decryption oracle -> binary search plaintext.

### Block ciphers (AES/DES)
- **ECB**: identical plaintext blocks -> identical ciphertext. Cut-and-paste blocks; byte-at-a-time ECB decryption against an encryption oracle (append controlled prefix).
- **CBC bit-flipping**: XOR ciphertext block `C[i-1]` to flip chosen plaintext bytes in `P[i]` (e.g. flip `admin=0` -> `admin=1`).
- **CBC padding oracle**: decryption error vs padding error distinction -> `padbuster URL ciphertext blocksize`; recover/forge plaintext without the key. **Forging (CBC-R) is the payload**, not just decryption: if the decrypted value is *used* server-side (run as a shell command, put in a SQL query, deserialized), forge a ciphertext decrypting to your injection -> **RCE/SQLi without the key** (THM Decryptify: decrypted `?date=` was run via `shell_exec`, output echoed; forge `cat /flag` -> RCE). Fingerprint the cipher from the openssl error it leaks: an **8-byte IV/block = a 64-bit cipher (DES/3DES/Blowfish/CAST5), NOT AES** (16-byte) -- stop trying AES keys. Oracle signal = a distinct "padding error" string vs a clean render. No `padbuster`? A ~60-line Python oracle does decrypt + CBC-R encrypt (recover intermediate `D(C)` byte-by-byte, then `IV/prev = D(C) xor P`).
- **Keystream/OTP reuse** (CTR, stream, reused IV): `C1 xor C2 = P1 xor P2` -> crib-drag. GCM nonce reuse -> forge auth tag (recover H).

### Hashes
- **Length extension** (MD5/SHA1/SHA256 MAC = `H(secret||msg)`): `hashpump -s sig -d known -a append -k keylen` to forge valid MAC for extended message.
- Weak hash collisions (MD5 chosen-prefix). Cracking -> see [[hash-capture-and-cracking]] and [[password-cracking]].

### PRNG / randomness
- Mersenne Twister: 624 consecutive 32-bit outputs -> recover state -> predict (`randcrack`). LCG: solve from a few outputs. Time-seeded -> brute the seed window. See [[insecure-randomness]].
- **Seed-from-known-inputs token forge** (weak invite/reset tokens): when a token is `f(mt_srand(seed(known_inputs, CONST)); mt_rand())` and the seed derives from attacker-known values (email length/chars) plus one unknown constant, you don't need 624 outputs -- recover `CONST` offline from **ONE leaked (input, output) pair** (often disclosed in a log/`/logs/app.log`) by brute-forcing `CONST` locally until the pair reproduces, then forge tokens for any other user. Replicate the target's PRNG exactly: **PHP's `mt_rand` is stable across 7.1+**, so PHP 8 cli reproduces a PHP 7.x target. (THM Decryptify: `seed=hexdec(strlen(email)+CONST+hexdec(substr(email,0,8)))`, one log line gave the pair, `CONST=99999` fell out, forged any invite code.)

### ECC / signatures
- **ECDSA nonce reuse** (same `k` for two sigs) -> recover private key algebraically. Predictable/biased `k` -> lattice (LLL) attack. Invalid-curve / small-subgroup -> recover key mod small primes (CRT).

### Classical / encoding
- Caesar/Vigenere/substitution -> `dcode.fr`, CyberChef, frequency analysis. XOR -> `xortool -c ' '`. Encoding chains -> [[encoding-transformations]].

## Bypasses and variants
- Multi-layer: base64 -> XOR -> RSA. Always re-`file`/entropy-check decoded output.
- Custom hash/cipher: model in `z3` or `sage` and solve symbolically.

## Detection and defence
Use vetted libraries (libsodium); authenticated encryption (AES-GCM with unique nonces); constant-time comparison; CSPRNG (`secrets`, `/dev/urandom`); RSA-OAEP not textbook RSA; reject reused nonces.

## Tools
`RsaCtfTool`, `sage`, `factordb`, `hashpump`, `xortool`, `padbuster`, CyberChef, `z3`, `randcrack`. Hash cracking: [[wiki/tools/hashcat]], [[password-cracking]].

## Structured-limb ("short-sleeve") RSA key factoring

A broken big-integer RNG can leak structure straight into the public modulus: each 32/64/128-bit limb carries only a few random bytes and the rest are zero, so `n` shows regularly-spaced zero windows at a fixed stride. Classic bug is sizing a `bits/32` limb array but filling only that many bytes, giving each limb ~8 bits of entropy. When both primes are structured this way, `n` factors from the public key alone.

Detection and attack:
```text
# 1. dump n in hex, look for repeated zero windows at a 32/64/128-bit stride
# 2. re-slice n into limbs base B=2^w; if each limb is unusually small it is short-sleeve
# 3. write n as a polynomial f_n(x) in base B  (n = sum n_i * B^i)
# 4. factor f_n(x) over the integers in Sage; evaluate candidate factors at x=B
# 5. verify which candidates multiply back to n
```
If low-end alignment fails, search shifts i,j so `2^i*p` and `2^j*q` become sparse, factor, then recombine. Audit real SSH/TLS host keys for this and related weak-key classes with `badkeys`. A reused broken routine also cripples DSA: a structured private exponent shrinks the discrete-log search enough for baby-step giant-step. This does not touch correctly-generated RSA.

## CTR/GCM nonce reuse: structured known-plaintext and PKCS#8 key-offset recovery

Beyond the `C1 xor C2 = P1 xor P2` crib-dragging noted above, structured data gives you huge free known-plaintext regions, and structured secrets leak even without full plaintext.

- Highly-structured carriers (X.509 certs, file headers, JSON/CBOR, ASN.1) let you XOR the ciphertext against the predictable body to recover long keystream stretches, then decrypt anything else encrypted under the same key+IV at the same offsets.
- Same-format secrets under a reused keystream leak by field alignment. Two PKCS#8 RSA keys of the same modulus size place their prime factors at matching offsets (~99.6% alignment for 2048-bit). XOR the two ciphertexts and you isolate `p xor p'` / `q xor q'`, brute-recoverable in seconds.
- A constant/default library IV (e.g. `000...01`) turns CTR into a repeated one-time pad on every message. Treat any AEAD nonce reuse (CTR/GCM/GCM-SIV) as critical: keystream recovery plus, for GCM under repeated nonce, authentication-tag forgery (recover H).
- CTR/CBC without a tag are malleable: bit-flips in ciphertext flip the same plaintext bits, a privilege-escalation primitive when integrity is absent. Fix is AEAD with enforced tag verification.

## CBC-MAC variable-length forgery

CBC-MAC (`tag = last block of CBC-encrypt(key, msg, IV=0)`) is only secure for fixed-length messages with domain separation. Tokens/cookies that MAC a username or role with CBC-MAC are forgeable: given tags for chosen messages, you can craft a tag for a concatenation without the key by exploiting how CBC chains blocks (the tag of msg1 becomes the effective IV for the tail). Recognize it in CTF cookies of the form `data || tag`. Defenses: HMAC-SHA256/512, correctly-used AES-CMAC, and binding the message length into the MAC input.

## Sources

- HackTricks (crypto), ingest slug `hacktricks-crypto`.

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[crypto]]

## Home-rolled crypt()-per-block cookies are ECB (salt-exposed offline forge + reflected-header oracle)

A token built as `foreach (str_split($plain,8) as $b) $out .= crypt($b,$SALT);` is ECB by another
name: each 8-byte chunk is enciphered independently. Fingerprint from the wire, not the source: the
cookie is a run of fixed 13-char blocks, each a 2-char DES salt + 11-char hash, the salt constant
within one token but random per issue. The exposed salt removes the usual "need an oracle" caveat on
the two ECB attacks:

- **Forge with no key, offline.** Plaintext is `user:UA:SECRET`. If two roles are the same length
  (`guest`/`admin`, both 5) only block 0 differs; every later block enciphers the identical
  `UA:SECRET` tail. Fetch a normal cookie, keep blocks `1..N` verbatim, recompute ONLY block 0 as
  `crypt("admin:"+UA[0:2], salt)` locally (salt = cookie's first 2 bytes, `crypt` is public) -> submit
  as admin. No encrypt-oracle endpoint, no key.
- **Recover the appended SECRET byte-at-a-time.** A reflected value in the plaintext (here the
  `User-Agent`) is the controlled-prefix lever: pick a UA length `L` with `(L+i) % 8 == 0` so secret
  byte `i` is the last byte of a block with 7 known bytes before it, then brute 95 printable chars
  against that block using the salt from the same response. The cookie-issuing endpoint IS the oracle.

<!-- promoted-slug: crypt-per-block-ecb-cookie -->

### RSA private key from a known/deterministic seed (no factoring)

When keygen is **deterministic from an attacker-known seed**, rebuild the private key directly - no
factoring, regardless of modulus size. The tell: a docs / `/debug` endpoint (or source) spelling out
the derivation, e.g. seed = `f(username, CONST)`, `p = nextprime(int(SHA256(seed)))`, `q =
nextprime(int(SHA256(seed + b"pki")))`, `n = p*q`, `e = 65537`. Reproduce it exactly and compute `d
= pow(e, -1, (p-1)*(q-1))`; the advertised size ("RSA-2048") is often a decoy - the real `n` can be
~512-bit.
- **Match "nextprime" precisely:** "check consecutive integers until prime" INCLUDES the start value,
  so `p = x if isprime(x) else nextprime(x)` (sympy's `nextprime` returns strictly `>x` and is
  off-by-one when the hash int is itself prime).
- **A public verify endpoint is a signature oracle.** Reconstruct the signer's key, sign a message,
  submit -> valid/invalid confirms both the key AND the padding. Padding is usually unknown, so brute
  the handful against the oracle: `PSS(MAX salt)`, `PSS(32)`, `PSS(0)`, `PKCS1v15`, with `e` in
  `{65537, 3, 17}` (build the key with the `cryptography` lib's `RSAPrivateNumbers`; ensure `p>q`).
- Same primitive breaks any per-user signed-message / JWT / token scheme keyed on the seed: forge as
  any user (admin), decrypt private messages, impersonate. Distinct from the PRNG-token forge above
  (which recovers a hidden CONST from one output pair; here the whole derivation is disclosed).
- Web pairing seen repeatedly: passwordless/username-only login for the session + this forge for the
  "cryptographic" gate. See [[insecure-randomness]].

<!-- promoted-slug: rsa-deterministic-seed-keygen -->
