<?php
/*
 * Hashcash proof-of-work helpers — SHA-256 partial preimage, bitcoin-style target.
 *
 * Pure PHP: issuing a challenge is one HMAC, verifying a solution is one SHA-256.
 * No bignum, no extensions beyond the always-available `hash` extension.
 *
 * Override any of these BEFORE requiring this file (e.g. in message.php):
 *   POW_BITS        difficulty — required leading zero bits  (~2^BITS hashes to solve)
 *   POW_WINDOW      challenge lifetime in seconds
 *   POW_MAXNONCE    max decimal digits accepted for a nonce  (bounds verify input)
 *   POW_SECRET_FILE path to the HMAC secret (generate: `openssl rand -hex 32 > pow_secret`)
 */

if (!defined('POW_BITS'))        define('POW_BITS', 20);
if (!defined('POW_WINDOW'))      define('POW_WINDOW', 300);
if (!defined('POW_MAXNONCE'))    define('POW_MAXNONCE', 19);
if (!defined('POW_SECRET_FILE')) define('POW_SECRET_FILE', __DIR__ . '/pow_secret');
if (!defined('POW_SPENT_FILE'))  define('POW_SPENT_FILE',  __DIR__ . '/pow_spent');

function pow_secret() {
  static $s = null;
  if ($s !== null) return $s;
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
