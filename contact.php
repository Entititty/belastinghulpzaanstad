<?php
/**
 * contact.php — verwerkt het contact- en terugbelformulier van /contact/.
 * Stuurt een e-mail naar info@belastinghulpzaanstad.nl en stuurt de bezoeker
 * terug naar /contact/?ok=1 (gelukt) of /contact/?fout=1 (mislukt).
 *
 * Vereist: PHP-FPM op de VPS + een werkende mail-verzending (sendmail/SMTP).
 * Zie server-setup/nginx-php-snippet.conf voor de nginx-configuratie.
 */

$RECIPIENT = 'info@belastinghulpzaanstad.nl';
$FROM      = 'no-reply@belastinghulpzaanstad.nl'; // afzender op de server; niet spoofen
$OK        = '/contact/?ok=1';
$FOUT      = '/contact/?fout=1';

function redirect($url) { header('Location: ' . $url, true, 303); exit; }
function clean($v) { return trim(str_replace(array("\r", "\n", "%0a", "%0d"), ' ', (string)$v)); }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') { redirect($FOUT); }

// Honeypot: bots vullen dit verborgen veld; mensen niet.
if (!empty($_POST['website'])) { redirect($OK); }

$formtype = clean($_POST['formtype'] ?? 'bericht');
$naam     = clean($_POST['naam'] ?? '');
$telefoon = clean($_POST['telefoon'] ?? '');
$email    = clean($_POST['email'] ?? '');
$akkoord  = isset($_POST['akkoord']);

// Verplichte velden.
if ($naam === '' || $telefoon === '' || !$akkoord) { redirect($FOUT); }
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) { redirect($FOUT); }

if ($formtype === 'terugbelverzoek') {
    $onderwerp = 'Terugbelverzoek via de website';
    $dagdeel   = clean($_POST['dagdeel'] ?? 'Maakt niet uit');
    $body  = "Terugbelverzoek via belastinghulpzaanstad.nl\n\n";
    $body .= "Naam:            $naam\n";
    $body .= "Telefoon:        $telefoon\n";
    $body .= "Bereikbaar:      $dagdeel\n";
} else {
    $keuze   = clean($_POST['onderwerp'] ?? 'Iets anders');
    $bericht = trim((string)($_POST['bericht'] ?? ''));
    if ($bericht === '') { redirect($FOUT); }
    $onderwerp = 'Contactformulier: ' . $keuze;
    $body  = "Bericht via belastinghulpzaanstad.nl\n\n";
    $body .= "Naam:            $naam\n";
    $body .= "Telefoon:        $telefoon\n";
    $body .= "E-mail:          " . ($email !== '' ? $email : '(niet opgegeven)') . "\n";
    $body .= "Onderwerp:       $keuze\n\n";
    $body .= "Bericht:\n" . $bericht . "\n";
}

$headers  = "From: Belastinghulp Zaanstad <$FROM>\r\n";
if ($email !== '') { $headers .= "Reply-To: $naam <$email>\r\n"; }
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

$sent = @mail($RECIPIENT, '=?UTF-8?B?' . base64_encode($onderwerp) . '?=', $body, $headers);

redirect($sent ? $OK : $FOUT);
