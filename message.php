<?php
/*
 * Drop-in contact-form handler with a proof-of-work spam gate (challenge-on-submit).
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
define('POW_RECIPIENT',  'you@example.com');                       // where messages go
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

// In production, put these OUTSIDE the web root (e.g. __DIR__.'/../private/...'):
define('POW_SECRET_FILE', __DIR__ . '/pow_secret');                // `openssl rand -hex 32 > pow_secret`
define('POW_LOG_FILE',    __DIR__ . '/contact.log');               // submission log (or '' to disable)
// ===========================================================================

require __DIR__ . '/pow.php';

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
