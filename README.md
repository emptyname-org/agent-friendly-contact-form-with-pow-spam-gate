# Intelligent Agent Friendly Contact Form with Proof-of-Work Spam Gate

A spam gate for contact forms. It filters out dumb bots — the ones that POST to
the endpoint without running anything. Humans and intelligent agents both get
through, because both can solve the proof. It does not stop an attacker who runs
the solver; it imposes a per-message CPU cost.

The proof of work is hashcash, the same scheme as Bitcoin mining: find a nonce
whose SHA-256 hash is below a target. The browser solves it automatically; the
server verifies in one hash.

No CAPTCHA, no third party, no database. PHP and JavaScript.

## Architecture

Hashcash (SHA-256 partial preimage below a target), delivered as a
challenge-on-submit exchange so the page can stay static:

1. The client POSTs the form.
2. With no valid proof, the server replies (HTTP 200) with a JSON challenge that
   states what to compute:
   ```json
   {
     "need_proof": true,
     "scheme": "hashcash-sha256",
     "formula": "find an integer nonce so that the first 4 bytes of SHA-256(challenge + \":\" + nonce), read as a big-endian integer, are <= target",
     "howto": "Find nonce per \"formula\", then re-POST this form (name,email,message) with challenge and sig unchanged plus your nonce.",
     "challenge": "9f3a...:1781785223",
     "sig": "hmac-sha256(challenge)",
     "target": 2047,
     "bits": 21
   }
   ```
3. The client finds a `nonce` such that the first 4 bytes of
   `SHA-256(challenge + ":" + nonce)` are `<= target`, then re-POSTs the form
   with `challenge` and `sig` unchanged plus the `nonce`.
4. The server verifies in O(1): the `sig` proves it issued the challenge (HMAC,
   timing-safe), the embedded timestamp proves freshness, one SHA-256 proves the
   work, and a single-use cache proves it was not replayed.

The rules are in the challenge response, so reading the JavaScript is not
required — a browser (`script.js`) and an automated client follow the same
steps.

## Files

```
┌─────────────┬─────────────────────────────────────────────────────┐
│ File        │ Purpose                                             │
├─────────────┼─────────────────────────────────────────────────────┤
│ index.html  │ Demo contact form                                   │
│ script.js   │ Browser solver (synchronous SHA-256)                │
│ style.css   │ Demo styling (replace with your own)                │
│ message.php │ Handler — edit the CONFIG block at the top          │
│ pow.php     │ Proof-of-work helpers (issue / verify / single-use) │
└─────────────┴─────────────────────────────────────────────────────┘
```

## Install

1. Copy the files into your site.
2. Generate a secret:
   ```sh
   openssl rand -hex 32 > pow_secret
   ```
3. Edit the CONFIG block at the top of `message.php` (recipient, From, subject
   prefix, difficulty).
4. For production, put the secret and runtime files outside the web root and
   point the constants at them:
   ```php
   define('POW_SECRET_FILE', __DIR__ . '/../private/pow_secret');
   define('POW_SPENT_FILE',  __DIR__ . '/../private/pow_spent');
   define('POW_LOG_FILE',    __DIR__ . '/../private/contact.log');
   ```
   The PHP user must read `pow_secret` and read/write `pow_spent` (and
   `contact.log` if logging).

Requirements: PHP 7+ (`hash` extension). The browser solver is ES5 + typed
arrays; no BigInt, no WebCrypto.

## Tuning difficulty

`POW_BITS` (in the `message.php` CONFIG block, default 20) is the number of
leading zero bits required; expected work is about `2^BITS` hashes.

```
┌──────┬────────┬───────────────┐
│ BITS │ hashes │ browser solve │
├──────┼────────┼───────────────┤
│ 18   │ 260 k  │ ~0.2 s        │
│ 20   │ 1.0 M  │ ~0.5–1 s      │
│ 22   │ 4.2 M  │ ~2–4 s        │
└──────┴────────┴───────────────┘
```

The solve is a random search, so the time is variable (geometric): median
~0.7×`2^BITS`, p99 ~4.6×`2^BITS`. Difficulty is capped at 32 bits (only the
first 4 bytes of the digest are compared).

## Security notes

Rejected, each checked server-side in O(1):

- **Forged-PoW rejection** — a wrong nonce fails the SHA-256 target check.
- **Challenge-tampering rejection** — altering the challenge breaks its HMAC `sig`.
- **Signature-forgery rejection** — a wrong `sig` fails the timing-safe HMAC check.
- **Replay rejection** — a solved challenge is single-use (`pow_spent`).
- **Expiry enforcement** — a challenge older than `POW_WINDOW` is rejected as stale.

Other:

- Difficulty is fixed server-side; a client-sent `target` is ignored.
- The single-use cache is file-backed (survives restarts) and self-pruning
  (entries dropped past `POW_WINDOW`).
- Mail headers are sanitized against CR/LF injection.

## License

CC0 1.0 Universal (public domain) — see [LICENSE](LICENSE).
