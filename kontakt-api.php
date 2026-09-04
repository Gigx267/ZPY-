<?php
/**
 * ZPYU — Kontaktformular-Backend
 * Anti-Spam: Honeypot, Timestamp-Check, Rechenaufgabe, Rate-Limit,
 * Header-Injection-Schutz, Content-Filter.
 * Nimmt POST vom Formular #kontakt-form.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// ── KONFIGURATION ─────────────────────────
$MAIL_TO_HANSA  = 'contacthansa@zpyu.de';
$MAIL_TO_GRAFEN = 'contactgrafen@zpyu.de';
$MAIL_TO_FALLBK = 'info@zpyu.de';
$MAIL_FROM      = 'noreply@zpyu.de';
$MIN_SECONDS    = 3;
$MAX_SECONDS    = 3600 * 2;
$RATE_MAX       = 5;
$RATE_WINDOW    = 3600;
$RATE_FILE      = sys_get_temp_dir() . '/zpyu_kontakt_rate.json';
$LOG_FILE       = __DIR__ . '/kontakt.log';

// ── HILFSFUNKTIONEN ───────────────────────
function respond($ok, $msg = '', $code = 200) {
    http_response_code($code);
    echo json_encode(['success' => $ok, 'message' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}
function client_ip() { return $_SERVER['REMOTE_ADDR'] ?? 'unknown'; }
function log_line($msg) {
    global $LOG_FILE;
    @file_put_contents($LOG_FILE, date('Y-m-d H:i:s') . ' ' . $msg . "\n", FILE_APPEND | LOCK_EX);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') respond(false, 'Only POST allowed.', 405);

// ── HONEYPOT (Feld "website" im Original-Formular) ──────
if (!empty($_POST['website'])) {
    log_line('SPAM honeypot from ' . client_ip());
    respond(true, '');
}

// ── TIMESTAMP ────────────────────────────
$ts = intval($_POST['zpyu_ts'] ?? 0);
$now_ms = intval(microtime(true) * 1000);
$age_s = ($now_ms - $ts) / 1000;
if ($ts <= 0 || $age_s < $MIN_SECONDS) {
    log_line('SPAM too fast (' . $age_s . 's) from ' . client_ip());
    respond(true, '');
}
if ($age_s > $MAX_SECONDS) respond(false, 'Formular abgelaufen. Bitte Seite neu laden.');

// ── RECHENAUFGABE ────────────────────────
$a = intval($_POST['zpyu_math_a'] ?? -1);
$b = intval($_POST['zpyu_math_b'] ?? -1);
$r = intval($_POST['zpyu_math_r'] ?? -1);
if ($a < 0 || $b < 0 || ($a + $b) !== $r) {
    respond(false, 'Sicherheitsfrage nicht korrekt beantwortet.');
}

// ── RATE-LIMIT ───────────────────────────
$ip = client_ip();
$rates = file_exists($RATE_FILE) ? (json_decode(@file_get_contents($RATE_FILE), true) ?: []) : [];
$cutoff = time() - $RATE_WINDOW;
foreach ($rates as $rip => $entries) {
    $rates[$rip] = array_values(array_filter($entries, fn($t) => $t > $cutoff));
    if (empty($rates[$rip])) unset($rates[$rip]);
}
if (count($rates[$ip] ?? []) >= $RATE_MAX) {
    log_line('RATE-LIMIT hit from ' . $ip);
    respond(false, 'Zu viele Anfragen. Bitte in einer Stunde erneut versuchen.', 429);
}
$rates[$ip][] = time();
@file_put_contents($RATE_FILE, json_encode($rates), LOCK_EX);

// ── EINGABEN ─────────────────────────────
$firstname = trim($_POST['firstname'] ?? '');
$lastname  = trim($_POST['lastname']  ?? '');
$email     = trim($_POST['email']     ?? '');
$anliegen  = trim($_POST['anliegen']  ?? '');
$message   = trim($_POST['message']   ?? '');

if (strlen($firstname) < 1 || strlen($firstname) > 60) respond(false, 'Bitte gültigen Vornamen eingeben.');
if (strlen($lastname)  < 1 || strlen($lastname)  > 60) respond(false, 'Bitte gültigen Nachnamen eingeben.');
if (!filter_var($email, FILTER_VALIDATE_EMAIL))         respond(false, 'Bitte gültige E-Mail-Adresse eingeben.');
if ($anliegen === '')                                    respond(false, 'Bitte Anliegen auswählen.');
if (strlen($message) > 5000)                             $message = substr($message, 0, 5000);

// Header-Injection
foreach ([$firstname, $lastname, $email, $anliegen] as $v) {
    if (preg_match('/[\r\n]/', $v)) {
        log_line('HEADER-INJECT attempt from ' . $ip);
        respond(false, 'Ungültige Eingabe.');
    }
}

// Spam-Muster
$spam_patterns = ['/\bviagra\b/i', '/\bcasino\b/i', '/https?:\/\/.*https?:\/\/.*https?:\/\//i', '/(SEO|backlink)s?\s.*(offer|service|angebot)/i'];
foreach ($spam_patterns as $p) {
    if (preg_match($p, $message)) {
        log_line('SPAM pattern from ' . $ip);
        respond(true, '');
    }
}

// ── ZIELADRESSE JE NACH ANLIEGEN ─────────
$mail_to = $MAIL_TO_FALLBK;
if (strpos($anliegen, 'hansa') !== false)  $mail_to = $MAIL_TO_HANSA;
elseif (strpos($anliegen, 'graf') !== false) $mail_to = $MAIL_TO_GRAFEN;

// ── MAIL ─────────────────────────────────
$name = $firstname . ' ' . $lastname;
$anliegen_map = [
    'ersttermin-hansa' => 'Ersttermin Hansaallee',
    'ersttermin-graf'  => 'Ersttermin Grafenberger Allee',
    'endokrin'         => 'Endokrine Sprechstunde',
    'allgemein'        => 'Allgemeinmedizinische Sprechstunde',
    'metabolik'        => 'Metabolik-CheckUp',
    'infekt'           => 'Infektionssprechstunde',
    'video'            => 'Videosprechstunde',
    'verlauf'          => 'Verlaufskontrolle / Befundbesprechung',
    'rezept'           => 'Rezept / AU-Bestellung',
    'international'    => 'Internationale Anfrage',
    'firma'            => 'Firmenkunden / CheckUp',
    'info'             => 'Allgemeine Informationen',
];
$anliegen_label = $anliegen_map[$anliegen] ?? $anliegen;

$subject   = '[ZPYU Kontakt] ' . $anliegen_label;
$mail_body =
    "Neue Anfrage über das Kontaktformular:\n\n" .
    "Name:     $name\n" .
    "E-Mail:   $email\n" .
    "Anliegen: $anliegen_label\n" .
    "IP:       $ip\n" .
    "Zeit:     " . date('Y-m-d H:i:s') . "\n\n" .
    "---\n\n" .
    ($message !== '' ? $message : '(keine weitere Nachricht)') . "\n";

$headers  = 'From: ZPYU Web <' . $MAIL_FROM . ">\r\n";
$headers .= 'Reply-To: ' . $email . "\r\n";
$headers .= 'X-Mailer: ZPYU-Web' . "\r\n";
$headers .= 'Content-Type: text/plain; charset=UTF-8' . "\r\n";

$sent = @mail($mail_to, $subject, $mail_body, $headers, '-f' . $MAIL_FROM);

if ($sent) {
    log_line("OK $ip $email \"$anliegen_label\" → $mail_to");
    respond(true, 'Nachricht gesendet.');
} else {
    log_line("MAIL-FAIL $ip $email");
    respond(false, 'Nachricht konnte nicht gesendet werden. Bitte direkt an ' . $mail_to . ' schreiben.');
}
