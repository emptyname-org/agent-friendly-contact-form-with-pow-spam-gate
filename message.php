<?php
/*
 * Dumbouncer — drop-in contact-form handler with a proof-of-work spam gate
 * (challenge-on-submit). Dumb bots bounce; humans and agents solve the proof.
 *
 * Single file: the hashcash helpers (issue / verify / single-use) are inlined at
 * the bottom — no other PHP to include. The browser solver is script.js.
 *
 * Minimal install: drop this file next to your form, set POW_RECIPIENT below,
 * point the form's `action` at it. The HMAC secret is generated automatically on
 * the first request (see pow_secret()); nothing else is required.
 *
 * Protocol (no JavaScript required — the form's `action` is the only thing a
 * client must discover):
 *   - A client POSTs the form.
 *   - If there is no valid proof yet, the server replies HTTP 200 with a JSON
 *     CHALLENGE that states exactly what to compute:
 *         { "need_proof":true, "scheme":"hashcash-sha256",
 *           "formula":"find an integer nonce so the first 4 bytes of
 *                      SHA-256(challenge + \":\" + nonce), big-endian, are <= target",
 *           "howto":"...", "challenge":"<hex:unixtime>", "sig":"<hmac>",
 *           "target":<int>, "bits":<int> }
 *   - The client searches for such a nonce and re-POSTs the same fields plus
 *     challenge, sig (unchanged) and nonce.  Verification is one SHA-256.
 *
 * A blind bot that ignores the challenge never sends a valid nonce -> rejected.
 * An honest client (browser via script.js, or any automated client that reads
 * the challenge) does the work and gets through.  See README.md.
 *
 * Final status codes (plain text, read by script.js):
 *   1 sent · 2 send-failed/misconfigured · 3 invalid email · 4 missing field
 */

// ============================ CONFIG — edit this ============================

// REQUIRED — the one thing you must set.
define('POW_RECIPIENT',  'you@example.com');                       // where messages go

// COMMON — sensible defaults; change to taste.
define('POW_FROM',       'Website contact <noreply@example.com>'); // envelope/From identity
define('POW_SUBJECT',    '[contact] ');                            // subject prefix

// DIFFICULTY — the one knob you tune. Number of leading zero bits required,
// i.e. ~2^POW_BITS hashes to solve. The browser solver adapts automatically
// (it reads the target from the challenge), so you only ever change it here.
//   18 ≈ 0.2s · 20 ≈ 0.5-1s (recommended) · 22 ≈ 2-4s   (median; p99 ~4.6x)
define('POW_BITS',       20);

// CHALLENGE LIFETIME — seconds a freshly issued challenge stays valid. It only
// needs to cover the solve + round-trips (the challenge is minted at submit
// time, not page load), so seconds, not minutes. Also bounds the single-use
// cache: spent challenges are pruned POW_WINDOW seconds after issue.
define('POW_WINDOW',     300);

// ADVANCED — paths and limits. Defaults work as-is (files land next to this
// script). The secret is auto-generated on first run if POW_SECRET_FILE is
// missing. For production, point these OUTSIDE the web root, e.g.
// __DIR__.'/../private/pow_secret', and the PHP user must read pow_secret and
// read/write pow_spent (and contact.log if logging).
define('POW_SECRET_FILE', __DIR__ . '/pow_secret');                // HMAC secret (auto-created if absent)
define('POW_SPENT_FILE',  __DIR__ . '/pow_spent');                 // single-use cache
define('POW_LOG_FILE',    __DIR__ . '/contact.log');               // submission log (or '' to disable)
define('POW_MAXNONCE',    19);                                     // max decimal digits accepted for a nonce
// ===========================================================================

function pval($k) { $v = $_POST[$k] ?? ''; return is_string($v) ? trim($v) : ''; }

function logrec($code, $reason) {
  if (POW_LOG_FILE === '') return;
  $rec = array(
    't'      => date('c'),
    'ip'     => $_SERVER['REMOTE_ADDR'] ?? '',
    'code'   => $code,
    'reason' => $reason,
    'name'   => substr(pval('name'), 0, 120),
    'email'  => substr(pval('email'), 0, 200),
    'ua'     => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200),
  );
  @file_put_contents(POW_LOG_FILE, json_encode($rec) . "\n", FILE_APPEND | LOCK_EX);
}
function finish($code, $reason = '') { logrec($code, $reason); echo $code; exit; }

function challenge_json() {
  $p = pow_issue();
  if ($p === null) { http_response_code(500); echo '{"error":"misconfigured: no secret"}'; exit; }
  $p['scheme']  = 'hashcash-sha256';
  $p['formula'] = 'find an integer nonce so that the first 4 bytes of '
                . 'SHA-256(challenge + ":" + nonce), read as a big-endian integer, are <= target';
  return $p;
}

// Optional machine endpoint: GET ?puzzle returns a challenge as JSON.
if (isset($_GET['puzzle'])) {
  header('Content-Type: application/json'); header('Cache-Control: no-store');
  echo json_encode(challenge_json(), JSON_UNESCAPED_SLASHES);
  exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { http_response_code(405); header('Allow: POST'); exit; }

// challenge-response: no valid proof (or a replayed one) -> hand back a fresh challenge.
// pow_verify() checks the signature, freshness and the hash; pow_spend() then
// enforces single use so a solved proof cannot be replayed within the window.
if (!pow_verify(pval('challenge'), pval('sig'), pval('nonce')) || !pow_spend(pval('challenge'))) {
  header('Content-Type: application/json'); header('Cache-Control: no-store');
  $p = challenge_json();
  $p['need_proof'] = true;
  $p['howto']      = 'Find nonce per "formula", then re-POST this form (name,email,message) '
                   . 'with challenge and sig unchanged plus your nonce.';
  logrec('c', 'challenge-issued');
  echo json_encode($p, JSON_UNESCAPED_SLASHES);
  exit;
}

// valid proof from here on
$name = pval('name'); $email = pval('email'); $message = pval('message');
if ($email === '' || $message === '') finish('4', 'missing-field');
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) finish('3', 'bad-email');

$email   = str_replace(array("\r", "\n"), '', $email);                 // header-injection guard
$name    = substr(str_replace(array("\r", "\n"), '', $name), 0, 120);
$message = substr($message, 0, 20000);

$subject = POW_SUBJECT . ($name !== '' ? $name : '(no name)');
$body    = "Name: $name\nEmail: $email\n\nMessage:\n\n$message\n";
$headers = 'From: ' . POW_FROM . "\r\n"
         . 'Reply-To: ' . $email . "\r\n"
         . "MIME-Version: 1.0\r\n"
         . "Content-Type: text/plain; charset=utf-8\r\n";
$ok = mail(POW_RECIPIENT, $subject, $body, $headers);
finish($ok ? '1' : '2', $ok ? 'sent' : 'mail-fail');


// ===================== Hashcash proof-of-work helpers ======================
// SHA-256 partial preimage, bitcoin-style target. Pure PHP: issuing a challenge
// is one HMAC, verifying a solution is one SHA-256. No bignum, no extensions
// beyond the always-available `hash` extension.

/* The HMAC secret. Read from POW_SECRET_FILE; if that file is absent, generate
   a 256-bit secret and write it (0600) on first run, so a fresh install needs
   no `openssl` step. 'x' open mode makes creation atomic: concurrent first
   requests can't clobber each other — the loser falls through and re-reads the
   winner's secret. Pre-create the file yourself (outside the web root) to skip
   auto-generation entirely. Returns '' only if no secret exists and none can be
   written, which surfaces as a "misconfigured" 500. */
function pow_secret() {
  static $s = null;
  if ($s !== null) return $s;
  if (is_readable(POW_SECRET_FILE)) {
    $s = trim(file_get_contents(POW_SECRET_FILE));
    if ($s !== '') return $s;
  }
  $new = bin2hex(random_bytes(32));
  $fh = @fopen(POW_SECRET_FILE, 'x');
  if ($fh) {
    @chmod(POW_SECRET_FILE, 0600);
    fwrite($fh, $new . "\n");
    fclose($fh);
    return $s = $new;
  }
  $s = is_readable(POW_SECRET_FILE) ? trim(file_get_contents(POW_SECRET_FILE)) : '';
  return $s;
}

/* Largest allowed value of the first 4 bytes of the digest = require that many
   leading zero bits.  target = 2^(32-BITS) - 1. */
function pow_target() { return (2 ** (32 - POW_BITS)) - 1; }

function pow_sign($challenge, $key) { return hash_hmac('sha256', $challenge, $key); }

/* Issue a fresh, signed challenge: array{challenge, sig, target, bits} or null. */
function pow_issue() {
  $key = pow_secret();
  if ($key === '') return null;
  $challenge = bin2hex(random_bytes(8)) . ':' . time();   // random : unix-time
  return array(
    'challenge' => $challenge,
    'sig'       => pow_sign($challenge, $key),
    'target'    => pow_target(),
    'bits'      => POW_BITS,
  );
}

/* Verify a submitted (challenge, sig, nonce). One SHA-256 — microseconds.
   Checks: we signed this challenge (timing-safe), it is still fresh, and
   the first 4 bytes of SHA-256(challenge ":" nonce) are <= target. */
function pow_verify($challenge, $sig, $nonce) {
  $key = pow_secret();
  if ($key === '' || $challenge === '' || $sig === '' || $nonce === '') return false;
  if (!ctype_digit($nonce) || strlen($nonce) > POW_MAXNONCE) return false;
  if (!hash_equals(pow_sign($challenge, $key), $sig)) return false;
  $parts = explode(':', $challenge);
  $ts = isset($parts[1]) ? (int)$parts[1] : 0;
  $now = time();
  if ($ts <= 0 || ($now - $ts) > POW_WINDOW || ($ts - $now) > 60) return false;
  $h = hash('sha256', $challenge . ':' . $nonce);
  return hexdec(substr($h, 0, 8)) <= pow_target();
}

/* Single-use enforcement: record a challenge as spent and return true the FIRST
   time it is seen, false on any later replay (within the freshness window).
   File-backed, locked, self-pruning. Fails OPEN (returns true) if the cache file
   is unwritable, so a permissions problem degrades to "no replay protection"
   rather than breaking the form — see README. Call only AFTER pow_verify() passes. */
function pow_spend($challenge) {
  $fh = @fopen(POW_SPENT_FILE, 'c+');
  if (!$fh) return true;
  if (!flock($fh, LOCK_EX)) { fclose($fh); return true; }
  $now = time();
  $cutoff = $now - POW_WINDOW - 120;
  $keep = array();
  $seen = false;
  rewind($fh);
  while (($line = fgets($fh)) !== false) {
    $line = rtrim($line, "\n");
    if ($line === '') continue;
    $sp = strpos($line, ' ');
    if ($sp === false) continue;
    $ts = (int)substr($line, 0, $sp);
    $c  = substr($line, $sp + 1);
    if ($ts < $cutoff) continue;          // prune expired
    if ($c === $challenge) $seen = true;
    $keep[] = $ts . ' ' . $c;
  }
  if (!$seen) $keep[] = $now . ' ' . $challenge;
  ftruncate($fh, 0); rewind($fh);
  fwrite($fh, $keep ? implode("\n", $keep) . "\n" : '');
  fflush($fh); flock($fh, LOCK_UN); fclose($fh);
  return !$seen;
}
