# Dumbouncer

**Dumb bots bounce.** 


## An Intelligent Agents Friendly, POW Spam Gate for Contact Forms.

Every sender must solve a configurable hashcash challenge before a message is accepted:

- **Intelligent Agents** - the challenge states its own rules, so automated clients can solve it.
- **Humans** - the browser solves it automatically. There is no CAPTCHA.
- **Dumb bots** - clients that POST without running the challenge are rejected.

Dumbouncer does not stop clients that intentionally run the solver. It adds a
small, configurable, CPU cost to each accepted message.

No database. No third party. PHP and JavaScript only.

## Architecture

Dumbouncer uses hashcash, the scheme used for Bitcoin mining: find a nonce whose
SHA-256 hash is below a target.

The form can stay static. Proof-of-work is handled by a challenge-on-submit
exchange:

1. The client POSTs the form.
2. If no valid proof is included, the server replies (HTTP 200) with a JSON
   challenge.
3. The client finds a `nonce` such that the first 4 bytes of
   `SHA-256(challenge + ":" + nonce)`, read as a big-endian integer, are
   `<= target`.
4. The client re-POSTs the form with `challenge` and `sig` unchanged plus the
   `nonce`.
5. The server verifies in O(1): the `sig` proves it issued the challenge (HMAC,
   timing-safe), the embedded timestamp proves freshness, one SHA-256 proves the
   work, and a single-use cache proves it was not replayed.

Example challenge:

```json
{
  "need_proof": true,
  "scheme": "hashcash-sha256",
  "formula": "find an integer nonce so that the first 4 bytes of SHA-256(challenge + \":\" + nonce), read as a big-endian integer, are <= target",
  "howto": "Find nonce per \"formula\", then re-POST this form with challenge and sig unchanged plus your nonce.",
  "challenge": "9f3a...:1781785223",
  "sig": "hmac-sha256(challenge)",
  "target": 4095,
  "bits": 20
}
```

The rules are included in the challenge response, so automated clients do not
need to inspect the JavaScript - a browser (`script.js`) and an automated client
follow the same steps.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Demo contact form |
| `script.js` | Browser proof-of-work solver (synchronous SHA-256) |
| `style.css` | Demo styling (replace with your own) |
| `message.php` | Form handler and proof-of-work logic |

`message.php` is self-contained: proof issuing, verification, replay protection,
and configuration all live in the same file, so there is no other PHP to
include.

## Install

1. Copy the files into your site and point the form's `action` at `message.php`.
2. Set the recipient address at the top of `message.php`:

   ```php
   define('POW_RECIPIENT', 'you@example.com');
   ```

On first use, Dumbouncer creates a 256-bit HMAC secret automatically (`0600`).
Every other setting has a working default.

### Optional

The CONFIG block holds every setting. For production, you may want to place the secret and
runtime files outside the web root:

```php
define('POW_SECRET_FILE', __DIR__ . '/../private/pow_secret');
define('POW_SPENT_FILE',  __DIR__ . '/../private/pow_spent');
define('POW_LOG_FILE',    __DIR__ . '/../private/contact.log');
```

The PHP user must be able to read/write these files. To set the secret yourself
instead of having it generated, write 32 random bytes (hex) to `POW_SECRET_FILE`.

## Configuration

`POW_BITS` sets the difficulty: the number of leading zero bits required, i.e.
about `2^BITS` hashes to solve.

| Bits | Expected hashes | Typical browser time |
| ---: | ---: | ---: |
| 18 | ~260k | ~0.2s |
| 20 | ~1.0M | ~0.5-1s |
| 22 | ~4.2M | ~2-4s |

The solve is a random search, so the time is variable (geometric): median
~0.7×`2^BITS`, p99 ~4.6×`2^BITS`. Higher values increase cost for both users and
spam. Difficulty is capped at 32 bits (only the first 4 bytes of the digest are
compared).

## Security notes

Dumbouncer checks each submission server-side, in O(1):

- invalid nonces fail the SHA-256 target check
- modified challenges fail the timing-safe HMAC verification
- reused challenges are rejected (single-use)
- expired challenges are rejected (older than `POW_WINDOW`)
- client-sent difficulty values are ignored, and difficulty is fixed server-side
- mail headers are sanitized against CR/LF injection

Replay protection is file-backed (survives restarts) and pruned automatically.

## Requirements

- PHP 7+ with the `hash` extension
- A JavaScript-enabled browser for the demo solver

The browser solver uses ES5 and typed arrays. It does not require BigInt or
WebCrypto.

## License

CC0 1.0 Universal (public domain) - see [LICENSE](LICENSE).
