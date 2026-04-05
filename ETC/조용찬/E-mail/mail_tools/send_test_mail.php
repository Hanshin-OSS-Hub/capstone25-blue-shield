<?php
$host = getenv('SMTP_HOST') ?: 'mail_server';
$port = (int)(getenv('SMTP_PORT') ?: 25);
$from = getenv('MAIL_FROM') ?: 'test@company.local';
$to   = getenv('MAIL_TO') ?: 'ceo@company.local';
$subject = getenv('MAIL_SUBJECT') ?: 'Test Mail';
$body = getenv('MAIL_BODY') ?: 'hello from client';

function smtp_cmd($fp, $cmd = null) {
    if ($cmd !== null) {
        fwrite($fp, $cmd . "\r\n");
    }
    $resp = '';
    while (($line = fgets($fp, 512)) !== false) {
        $resp .= $line;
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }
    return $resp;
}

$fp = fsockopen($host, $port, $errno, $errstr, 10);
if (!$fp) {
    die("SMTP connect failed: $errstr ($errno)\n");
}

echo smtp_cmd($fp);
echo smtp_cmd($fp, "HELO company.local");
echo smtp_cmd($fp, "MAIL FROM:<$from>");
echo smtp_cmd($fp, "RCPT TO:<$to>");
echo smtp_cmd($fp, "DATA");
echo smtp_cmd($fp, "Subject: $subject\r\n\r\n$body\r\n.");
echo smtp_cmd($fp, "QUIT");

fclose($fp);
echo "done\n";