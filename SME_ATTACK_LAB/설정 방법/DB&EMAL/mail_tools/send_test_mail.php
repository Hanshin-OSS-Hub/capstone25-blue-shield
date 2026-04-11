<?php
declare(strict_types=1);

/**
 * SMTP 테스트 메일 발송 스크립트
 * 우선순위:
 * 1) 명령행 인자 (제목, 본문)
 * 2) MAIL_SUBJECT / MAIL_BODY
 * 3) MAIL_SUBJECT_PREFIX + 기본 제목
 * 4) 기본값
 *
 * 호스트/포트는 새 변수명(MAIL_SMTP_*)과 구 변수명(SMTP_*)을 둘 다 지원.
 */

$host = getenv('MAIL_SMTP_HOST') ?: getenv('SMTP_HOST') ?: 'mail_server';
$port = (int)(getenv('MAIL_SMTP_PORT') ?: getenv('SMTP_PORT') ?: '25');
$from = getenv('MAIL_FROM') ?: 'test@company.local';
$to   = getenv('MAIL_TO') ?: 'ceo@company.local';
$prefix = getenv('MAIL_SUBJECT_PREFIX') ?: '[client]';

$subject = $argv[1] ?? getenv('MAIL_SUBJECT') ?: ($prefix . ' test mail');
$body = $argv[2] ?? getenv('MAIL_BODY') ?: ('Generated at ' . date('c') . "\nSource container: " . (gethostname() ?: 'php-client'));

function smtp_read($fp): string {
    $response = '';
    while (!feof($fp)) {
        $line = fgets($fp, 515);
        if ($line === false) {
            break;
        }
        $response .= $line;
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }
    return $response;
}

function smtp_expect(string $response, array $codes): void {
    foreach ($codes as $code) {
        if (str_starts_with($response, (string)$code)) {
            return;
        }
    }
    throw new RuntimeException('SMTP unexpected response: ' . trim($response));
}

function smtp_cmd($fp, ?string $cmd = null, array $okCodes = [250]): string {
    if ($cmd !== null) {
        fwrite($fp, $cmd . "\r\n");
    }
    $response = smtp_read($fp);
    smtp_expect($response, $okCodes);
    return $response;
}

$fp = fsockopen($host, (string)$port, $errno, $errstr, 10);
if (!$fp) {
    fwrite(STDERR, "SMTP connect failed: {$errstr} ({$errno})\n");
    exit(1);
}
stream_set_timeout($fp, 10);

try {
    echo smtp_cmd($fp, null, [220]);
    echo smtp_cmd($fp, 'HELO company.local', [250]);
    echo smtp_cmd($fp, "MAIL FROM:<{$from}>", [250]);
    echo smtp_cmd($fp, "RCPT TO:<{$to}>", [250, 251]);
    echo smtp_cmd($fp, 'DATA', [354]);

    $headers = [
        "From: {$from}",
        "To: {$to}",
        "Subject: {$subject}",
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Date: ' . date(DATE_RFC2822),
        'Message-ID: <' . uniqid('', true) . '@' . (gethostname() ?: 'php-client') . '>',
    ];

    $payload = implode("\r\n", $headers) . "\r\n\r\n" . $body . "\r\n.";
    echo smtp_cmd($fp, $payload, [250]);
    echo smtp_cmd($fp, 'QUIT', [221]);
    echo "MAIL SENT OK\n";
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
} finally {
    fclose($fp);
}
