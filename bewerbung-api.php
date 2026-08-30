<?php
/**
 * ZPYU — Bewerbungsformular-Backend
 * Wie kontakt-api.php + Datei-Upload für Lebenslauf.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// ── KONFIGURATION ─────────────────────────
$MAIL_TO       = 'karriere@zpyu.de';
$MAIL_FROM     = 'noreply@zpyu.de';
$MIN_SECONDS   = 3;
$MAX_SECONDS   = 3600 * 4;
$RATE_MAX      = 3;                 // strenger für Bewerbungen
$RATE_WINDOW   = 3600;
$RATE_FILE     = sys_get_temp_dir() . '/zpyu_bewerbung_rate.json';
$LOG_FILE      = __DIR__ . '/bewerbung.log';
$UPLOAD_DIR    = __DIR__ . '/bewerbungen/'; // sicherstellen: .htaccess "deny from all"
$MAX_FILE_SIZE = 8 * 1024 * 1024;
$ALLOWED_MIME  = [
    'application/pdf'                                                         => 'pdf',
    'application/msword'                                                       => 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'  => 'docx',
];

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

// ── HONEYPOT ─────────────────────────────
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
    respond(false, 'Zu viele Bewerbungen. Bitte in einer Stunde erneut versuchen.', 429);
}
$rates[$ip][] = time();
@file_put_contents($RATE_FILE, json_encode($rates), LOCK_EX);

// ── EINGABEN ─────────────────────────────
$firstname = trim($_POST['firstname'] ?? '');
$lastname  = trim($_POST['lastname']  ?? '');
$email     = trim($_POST['email']     ?? '');
$phone     = trim($_POST['phone']     ?? '');
$position  = trim($_POST['position']  ?? 'Initiativbewerbung');
$message   = trim($_POST['message']   ?? '');

if (strlen($firstname) < 1 || strlen($firstname) > 60) respond(false, 'Bitte gültigen Vornamen eingeben.');
if (strlen($lastname)  < 1 || strlen($lastname)  > 60) respond(false, 'Bitte gültigen Nachnamen eingeben.');
if (!filter_var($email, FILTER_VALIDATE_EMAIL))         respond(false, 'Bitte gültige E-Mail-Adresse eingeben.');
if (strlen($phone) > 40)                                 respond(false, 'Telefonnummer zu lang.');
if (strlen($message) > 5000)                             $message = substr($message, 0, 5000);
if (strlen($position) > 80)                              $position = substr($position, 0, 80);

foreach ([$firstname, $lastname, $email, $phone, $position] as $v) {
    if (preg_match('/[\r\n]/', $v)) {
        log_line('HEADER-INJECT attempt from ' . $ip);
        respond(false, 'Ungültige Eingabe.');
    }
}

// ── DATEI-UPLOAD ─────────────────────────
$attachment_path = null;
$attachment_name = null;
if (isset($_FILES['cv']) && $_FILES['cv']['error'] !== UPLOAD_ERR_NO_FILE) {
    $f = $_FILES['cv'];
    if ($f['error'] !== UPLOAD_ERR_OK) {
        log_line('UPLOAD-ERR ' . $f['error'] . ' from ' . $ip);
        respond(false, 'Datei-Upload fehlgeschlagen. Bitte erneut versuchen oder ohne Anhang senden.');
    }
    if ($f['size'] > $MAX_FILE_SIZE) respond(false, 'Datei zu groß (max. 8 MB).');
    if ($f['size'] <= 0)             respond(false, 'Datei ist leer.');

    // MIME per fileinfo prüfen (nicht dem Client vertrauen)
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $real_mime = $finfo->file($f['tmp_name']);
    if (!isset($ALLOWED_MIME[$real_mime])) {
        respond(false, 'Nur PDF, DOC oder DOCX erlaubt.');
    }
    $ext = $ALLOWED_MIME[$real_mime];

    if (!is_dir($UPLOAD_DIR)) @mkdir($UPLOAD_DIR, 0750, true);
    if (!is_dir($UPLOAD_DIR)) respond(false, 'Server-Konfiguration fehlerhaft.');

    // .htaccess anlegen falls fehlt
    $ht = $UPLOAD_DIR . '.htaccess';
    if (!file_exists($ht)) @file_put_contents($ht, "Require all denied\nDeny from all\n");

    // Sicherer Zufalls-Dateiname (verhindert Kollisionen und Pfad-Tricks)
    $safe_name = date('Ymd_His') . '_' . bin2hex(random_bytes(6)) . '.' . $ext;
    $target = $UPLOAD_DIR . $safe_name;
    if (!move_uploaded_file($f['tmp_name'], $target)) {
        log_line('UPLOAD-MOVE-FAIL from ' . $ip);
        respond(false, 'Datei konnte nicht gespeichert werden.');
    }
    @chmod($target, 0640);
    $attachment_path = $target;
    // Original-Dateiname säubern für den Betreff/Body
    $orig = basename($f['name']);
    $attachment_name = preg_replace('/[^A-Za-z0-9._\- ]/', '_', $orig);
    if (strlen($attachment_name) > 100) $attachment_name = substr($attachment_name, 0, 100);
}

// ── MAIL VERSENDEN ──────────────────────
$name    = $firstname . ' ' . $lastname;
$subject = '[ZPYU Bewerbung] ' . $position . ' — ' . $name;
$body =
    "Neue Bewerbung über das Karriere-Portal:\n\n" .
    "Name:     $name\n" .
    "E-Mail:   $email\n" .
    "Telefon:  " . ($phone !== '' ? $phone : '(nicht angegeben)') . "\n" .
    "Position: $position\n" .
    "IP:       $ip\n" .
    "Zeit:     " . date('Y-m-d H:i:s') . "\n\n" .
    "---\n\n" .
    ($message !== '' ? $message : '(keine weitere Nachricht)') . "\n" .
    ($attachment_path
        ? "\n---\nLebenslauf-Anhang: $attachment_name\nGespeichert unter: $attachment_path\n"
        : "\n---\n(kein Lebenslauf beigefügt)\n");

$headers  = 'From: ZPYU Karriere <' . $MAIL_FROM . ">\r\n";
$headers .= 'Reply-To: ' . $email . "\r\n";
$headers .= 'X-Mailer: ZPYU-Web' . "\r\n";
$headers .= 'Content-Type: text/plain; charset=UTF-8' . "\r\n";

// Anmerkung zum Anhang:
// Der Anhang wird auf dem Server abgelegt (Verzeichnis per .htaccess gesperrt)
// und im Body als Pfad genannt. Ein echter MIME-Multipart-Versand wäre möglich,
// setzt aber einen konfigurierten SMTP-Server voraus (PHPMailer o.ä.).
// Für den Bewerbungs-Workflow ist der Server-Ablageplatz + interne Notiz
// robuster als ein Attachment, das an fremden Spam-Filtern hängenbleibt.

$sent = @mail($MAIL_TO, $subject, $body, $headers, '-f' . $MAIL_FROM);

if ($sent) {
    log_line("OK $ip $email \"$position\"" . ($attachment_path ? ' [CV]' : ''));
    respond(true, 'Bewerbung eingegangen.');
} else {
    log_line("MAIL-FAIL $ip $email");
    respond(false, 'Bewerbung konnte nicht gesendet werden. Bitte direkt an ' . $MAIL_TO . ' schreiben.');
}
