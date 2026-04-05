<?php
session_start();

// === 환경 설정 ===
$VAULT_ADDR = getenv('VAULT_ADDR') ?: 'http://192.168.20.50:8200/v1/secret/data/';
$VAULT_TOKEN = getenv('VAULT_TOKEN') ?: getenv('VAULT_DEV_ROOT_TOKEN_ID') ?: 'my_root_token';

$DB_HOST = getenv('DB_HOST') ?: 'host.docker.internal';
$DB_NAME = getenv('DB_NAME') ?: 'admin_portal';
$DB_USER = getenv('DB_USER') ?: 'portal_user';
$DB_PASS = getenv('DB_PASS') ?: 'StrongPortalPass!123';

$IMAP_HOST = getenv('IMAP_HOST') ?: 'mail_server';
$IMAP_PORT = (int)(getenv('IMAP_PORT') ?: '143');
$MAILSTORE_BASE = getenv('MAILSTORE_BASE') ?: '/mailstore';

try {
    $pdo = new PDO(
        "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4",
        $DB_USER,
        $DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
} catch (PDOException $e) {
    die('DB 연결 실패: ' . $e->getMessage());
}

function audit_log(PDO $pdo, $adminId, string $action, ?string $targetType = null, $targetId = null): void {
    $stmt = $pdo->prepare("INSERT INTO audit_logs (admin_id, action, target_type, target_id, ip_address) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([
        $adminId,
        $action,
        $targetType,
        $targetId,
        $_SERVER['REMOTE_ADDR'] ?? null
    ]);
}

function json_input(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') return [];
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function require_login_json(): void {
    if (!isset($_SESSION['admin'])) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => '로그인이 필요합니다.']);
        exit;
    }
}

function is_superadmin(): bool {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'superadmin';
}

function require_superadmin_json(): void {
    require_login_json();
    if (!is_superadmin()) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'error' => 'superadmin 권한이 필요합니다.']);
        exit;
    }
}

function vault_get_secret($name) {
    global $VAULT_ADDR, $VAULT_TOKEN;
    $url = rtrim($VAULT_ADDR, '/') . '/' . rawurlencode($name);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "X-Vault-Token: {$VAULT_TOKEN}",
        'Content-Type: application/json'
    ]);
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!$res) return ['error' => 'Vault 응답 없음'];
    $json = json_decode($res, true);
    if ($code >= 400) return ['error' => 'Vault 오류: ' . ($json['errors'][0] ?? $code)];
    return $json;
}

function provision_maildir(string $base, string $email): array {
    $email = strtolower(trim($email));
    if (!str_contains($email, '@')) {
        return ['ok' => false, 'warning' => '이메일 형식이 올바르지 않습니다.'];
    }
    [$local, $domain] = explode('@', $email, 2);
    $maildir = rtrim($base, '/') . '/' . $domain . '/' . $local . '/Maildir';
    $paths = [$maildir, $maildir . '/cur', $maildir . '/new', $maildir . '/tmp'];

    if (!is_dir($base)) {
        return ['ok' => false, 'warning' => "메일 저장소 경로({$base})가 없습니다."];
    }

    foreach ($paths as $p) {
        if (!is_dir($p) && !@mkdir($p, 0775, true) && !is_dir($p)) {
            return ['ok' => false, 'warning' => "메일함 폴더 생성 실패: {$p}"];
        }
    }

    @chown(rtrim($base, '/') . '/' . $domain . '/' . $local, 5000);
    @chgrp(rtrim($base, '/') . '/' . $domain . '/' . $local, 5000);
    @chown($maildir, 5000); @chgrp($maildir, 5000);
    @chown($maildir . '/cur', 5000); @chgrp($maildir . '/cur', 5000);
    @chown($maildir . '/new', 5000); @chgrp($maildir . '/new', 5000);
    @chown($maildir . '/tmp', 5000); @chgrp($maildir . '/tmp', 5000);

    return ['ok' => true, 'maildir' => $maildir];
}

function decode_mime_header_text(?string $text): string {
    if ($text === null || $text === '') return '';
    if (!function_exists('imap_mime_header_decode')) return $text;
    $parts = imap_mime_header_decode($text);
    $out = '';
    foreach ($parts as $part) {
        $charset = strtolower($part->charset ?? 'default');
        $fragment = $part->text ?? '';
        if ($charset !== 'default' && $charset !== 'utf-8') {
            $converted = @mb_convert_encoding($fragment, 'UTF-8', strtoupper($charset));
            $out .= $converted !== false ? $converted : $fragment;
        } else {
            $out .= $fragment;
        }
    }
    return $out;
}

function mail_open(string $email, string $password) {
    global $IMAP_HOST, $IMAP_PORT;
    if (!function_exists('imap_open')) {
        return ['ok' => false, 'error' => 'PHP IMAP 확장이 설치되어 있지 않습니다.'];
    }
    $mailbox = sprintf('{%s:%d/imap/notls}INBOX', $IMAP_HOST, $IMAP_PORT);
    $inbox = @imap_open($mailbox, $email, $password, OP_READONLY, 1);
    if (!$inbox) {
        $errors = imap_errors();
        return ['ok' => false, 'error' => $errors ? implode(' | ', $errors) : 'IMAP 연결 실패'];
    }
    return ['ok' => true, 'inbox' => $inbox];
}

function get_mail_account(PDO $pdo, int $id): ?array {
    $stmt = $pdo->prepare("SELECT id, email_address, display_name, mail_password, is_active FROM email_accounts WHERE id = ?");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    return $row ?: null;
}

if (isset($_GET['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    $action = $_GET['action'];

    if ($action === 'login') {
        $data = json_input();
        $user = trim($data['user'] ?? '');
        $pw = $data['pw'] ?? '';

        $stmt = $pdo->prepare("
            SELECT id, username, password_hash, full_name, role, is_active
            FROM admins
            WHERE username = ?
            LIMIT 1
        ");
        $stmt->execute([$user]);
        $admin = $stmt->fetch();

        if ($admin && (int)$admin['is_active'] === 1 && password_verify($pw, $admin['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['admin'] = $admin['username'];
            $_SESSION['admin_id'] = (int)$admin['id'];
            $_SESSION['full_name'] = $admin['full_name'];
            $_SESSION['role'] = $admin['role'];

            $pdo->prepare("UPDATE admins SET last_login_at = NOW() WHERE id = ?")->execute([$admin['id']]);
            audit_log($pdo, (int)$admin['id'], 'LOGIN_SUCCESS', 'admin', (int)$admin['id']);

            echo json_encode([
                'ok' => true,
                'user' => $admin['username'],
                'full_name' => $admin['full_name'],
                'role' => $admin['role']
            ]);
            exit;
        }

        audit_log($pdo, null, 'LOGIN_FAIL', 'admin', null);
        echo json_encode(['ok' => false, 'error' => '인증 실패']);
        exit;
    }

    if ($action === 'logout') {
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
        echo json_encode(['ok' => true]);
        exit;
    }

    require_login_json();

    if ($action === 'metrics') {
        $client = $_GET['client'] ?? null;
        $rand = fn($min, $max) => rand($min, $max);
        if ($client) {
            echo json_encode(['ok'=>true,'client'=>$client,'cpu'=>$rand(1,90),'mem'=>$rand(5,95),'resp'=>$rand(10,800)]);
            exit;
        }
        $list = ['admin_entry','client_a_OWASP','client_b_dvwa','client_c_bwapp','key_vault_server','mail_server'];
        $out = [];
        foreach ($list as $c) $out[$c] = ['cpu'=>$rand(1,90),'mem'=>$rand(5,95),'resp'=>$rand(10,800)];
        echo json_encode(['ok'=>true,'metrics'=>$out]);
        exit;
    }

    if ($action === 'get_key') {
        $client = $_GET['client'] ?? null;
        if (!$client) { echo json_encode(['ok'=>false,'error'=>'client 파라미터 필요']); exit; }
        $res = vault_get_secret($client);
        if (isset($res['data']['data'])) {
            echo json_encode(['ok'=>true,'secret'=>$res['data']['data']]);
            exit;
        }
        echo json_encode(['ok'=>false,'error'=>'Vault에서 비밀을 읽을 수 없습니다','raw'=>$res]);
        exit;
    }

    if ($action === 'validate_key') {
        $client = $_GET['client'] ?? null;
        $data = json_input();
        $provided = $data['api_key'] ?? null;
        if (!$client || !$provided) { echo json_encode(['ok'=>false,'error'=>'client 및 api_key 필요']); exit; }
        $res = vault_get_secret($client);
        if (isset($res['data']['data']['api_key'])) {
            $real = $res['data']['data']['api_key'];
            if (hash_equals((string)$real, (string)$provided)) {
                $_SESSION['access_' . $client] = true;
                echo json_encode(['ok'=>true]); exit;
            }
            echo json_encode(['ok'=>false,'error'=>'API 키 불일치']); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'Vault에서 api_key를 찾을 수 없음','raw'=>$res]); exit;
    }

    if ($action === 'inspect') {
        $client = $_GET['client'] ?? null;
        if (!$client) { echo json_encode(['ok'=>false,'error'=>'client 파라미터 필요']); exit; }
        $dockerSock = '/var/run/docker.sock';
        if (is_readable($dockerSock) && function_exists('shell_exec')) {
            $cmd = sprintf('docker inspect %s 2>&1', escapeshellarg($client));
            $output = shell_exec($cmd);
            if ($output === null) {
                echo json_encode(['ok'=>false,'error'=>'docker inspect 실행 실패']); exit;
            }
            $json = json_decode($output, true);
            echo json_encode(['ok'=>true,'inspect'=>$json]); exit;
        }
        $sim = [
            'Id' => 'sim-' . $client,
            'Name' => '/' . $client,
            'Config' => ['Image' => 'example/image:latest','Env'=>['APP_ENV=prod']],
            'NetworkSettings' => ['IPAddress' => '192.168.20.10'],
            'Mounts' => [['Source'=>'/var/lib/docker/volumes/'.$client,'Destination'=>'/data','Mode'=>'rw']]
        ];
        echo json_encode(['ok'=>true,'inspect'=>$sim,'files'=>['README.md','logs/app.log','config.yml']]);
        exit;
    }

    if ($action === 'get_file') {
        $client = $_GET['client'] ?? null;
        $path = $_GET['path'] ?? null;
        if (!$client || !$path) { echo json_encode(['ok'=>false,'error'=>'client 및 path 파라미터 필요']); exit; }
        $dockerSock = '/var/run/docker.sock';
        if (is_readable($dockerSock) && function_exists('shell_exec')) {
            $cmd = sprintf('docker exec %s sh -c %s 2>&1', escapeshellarg($client), escapeshellarg('cat ' . $path));
            $output = shell_exec($cmd);
            if ($output === null) { echo json_encode(['ok'=>false,'error'=>'파일 읽기 실패']); exit; }
            echo json_encode(['ok'=>true,'content'=>$output]); exit;
        }
        echo json_encode(['ok'=>true,'content'=>"# Sample file for {$client}\nThis is a simulated file content for {$path}.\n"]);
        exit;
    }

    if ($action === 'email_accounts_list') {
        $stmt = $pdo->query("
            SELECT id, email_address, login_id, display_name, department, mailbox_quota_mb, is_active, created_at
            FROM email_accounts
            ORDER BY id DESC
        ");
        echo json_encode(['ok' => true, 'rows' => $stmt->fetchAll()]);
        exit;
    }

    if ($action === 'email_accounts_create') {
        $data = json_input();
        $email = strtolower(trim($data['email_address'] ?? ''));
        $loginId = trim($data['login_id'] ?? '');
        $displayName = trim($data['display_name'] ?? '');
        $department = trim($data['department'] ?? '');
        $password = (string)($data['password'] ?? '');
        $quota = (int)($data['mailbox_quota_mb'] ?? 1024);

        if ($email === '' || $loginId === '' || $displayName === '' || $password === '') {
            echo json_encode(['ok' => false, 'error' => '필수 항목을 입력하세요.']);
            exit;
        }

        $stmt = $pdo->prepare("
            INSERT INTO email_accounts
            (email_address, login_id, display_name, department, password_hash, mail_password, mailbox_quota_mb, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ");

        try {
            $stmt->execute([
                $email,
                $loginId,
                $displayName,
                $department,
                password_hash($password, PASSWORD_DEFAULT),
                $password, // 실습용: 메일 서버 SQL 인증을 위한 평문
                $quota
            ]);
            $newId = (int)$pdo->lastInsertId();
            audit_log($pdo, $_SESSION['admin_id'] ?? null, 'CREATE_EMAIL_ACCOUNT', 'email_account', $newId);

            $prov = provision_maildir($MAILSTORE_BASE, $email);
            echo json_encode([
                'ok' => true,
                'id' => $newId,
                'maildir' => $prov
            ]);
        } catch (PDOException $e) {
            echo json_encode(['ok' => false, 'error' => '중복된 이메일 또는 로그인 ID입니다.']);
        }
        exit;
    }

    if ($action === 'email_accounts_toggle') {
        $data = json_input();
        $id = (int)($data['id'] ?? 0);
        $isActive = isset($data['is_active']) ? (int)!!$data['is_active'] : 1;
        if ($id <= 0) {
            echo json_encode(['ok' => false, 'error' => '유효하지 않은 ID입니다.']);
            exit;
        }
        $stmt = $pdo->prepare("UPDATE email_accounts SET is_active = ? WHERE id = ?");
        $stmt->execute([$isActive, $id]);
        audit_log($pdo, $_SESSION['admin_id'] ?? null, $isActive ? 'ENABLE_EMAIL_ACCOUNT' : 'DISABLE_EMAIL_ACCOUNT', 'email_account', $id);
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($action === 'mail_accounts_list') {
        require_superadmin_json();
        $stmt = $pdo->query("
            SELECT id, email_address, display_name
            FROM email_accounts
            WHERE is_active = 1
            ORDER BY email_address ASC
        ");
        echo json_encode(['ok' => true, 'rows' => $stmt->fetchAll()]);
        exit;
    }

    if ($action === 'mail_messages') {
        require_superadmin_json();
        $accountId = (int)($_GET['account_id'] ?? 0);
        if ($accountId <= 0) {
            echo json_encode(['ok' => false, 'error' => 'account_id가 필요합니다.']);
            exit;
        }
        $account = get_mail_account($pdo, $accountId);
        if (!$account || (int)$account['is_active'] !== 1) {
            echo json_encode(['ok' => false, 'error' => '활성화된 메일 계정을 찾을 수 없습니다.']);
            exit;
        }
        $open = mail_open($account['email_address'], (string)$account['mail_password']);
        if (!$open['ok']) {
            echo json_encode($open);
            exit;
        }
        $inbox = $open['inbox'];

        $messageNumbers = @imap_search($inbox, 'ALL');
        $rows = [];
        if (is_array($messageNumbers)) {
            rsort($messageNumbers, SORT_NUMERIC);
            $messageNumbers = array_slice($messageNumbers, 0, 20);
            foreach ($messageNumbers as $msgno) {
                $overviewArr = @imap_fetch_overview($inbox, (string)$msgno, 0);
                $overview = $overviewArr[0] ?? null;
                if (!$overview) continue;
                $rows[] = [
                    'msgno' => (int)$msgno,
                    'subject' => decode_mime_header_text($overview->subject ?? '(제목 없음)'),
                    'from' => decode_mime_header_text($overview->from ?? ''),
                    'date' => $overview->date ?? '',
                    'seen' => !empty($overview->seen),
                ];
            }
        }
        imap_close($inbox);
        audit_log($pdo, $_SESSION['admin_id'] ?? null, 'READ_MAILBOX', 'email_account', $accountId);
        echo json_encode(['ok' => true, 'messages' => $rows, 'account' => ['id' => $account['id'], 'email_address' => $account['email_address'], 'display_name' => $account['display_name']]]);
        exit;
    }

    if ($action === 'mail_message') {
        require_superadmin_json();
        $accountId = (int)($_GET['account_id'] ?? 0);
        $msgno = (int)($_GET['msgno'] ?? 0);
        if ($accountId <= 0 || $msgno <= 0) {
            echo json_encode(['ok' => false, 'error' => 'account_id와 msgno가 필요합니다.']);
            exit;
        }
        $account = get_mail_account($pdo, $accountId);
        if (!$account || (int)$account['is_active'] !== 1) {
            echo json_encode(['ok' => false, 'error' => '활성화된 메일 계정을 찾을 수 없습니다.']);
            exit;
        }
        $open = mail_open($account['email_address'], (string)$account['mail_password']);
        if (!$open['ok']) {
            echo json_encode($open);
            exit;
        }
        $inbox = $open['inbox'];
        $overviewArr = @imap_fetch_overview($inbox, (string)$msgno, 0);
        $overview = $overviewArr[0] ?? null;
        $body = @imap_body($inbox, $msgno, FT_PEEK);
        if (($body === false || $body === '') && function_exists('imap_fetchbody')) {
            $body = @imap_fetchbody($inbox, $msgno, '1', FT_PEEK);
        }
        imap_close($inbox);
        audit_log($pdo, $_SESSION['admin_id'] ?? null, 'READ_MESSAGE', 'email_account', $accountId);
        echo json_encode([
            'ok' => true,
            'message' => [
                'msgno' => $msgno,
                'subject' => decode_mime_header_text($overview->subject ?? '(제목 없음)'),
                'from' => decode_mime_header_text($overview->from ?? ''),
                'date' => $overview->date ?? '',
                'body' => $body !== false ? $body : '(본문을 읽을 수 없습니다.)'
            ]
        ]);
        exit;
    }

    echo json_encode(['ok'=>false,'error'=>'알 수 없는 액션']);
    exit;
}

$isLoggedIn = isset($_SESSION['admin']);

if (isset($_GET['view']) && $_GET['view'] === 'container') {
    $client = $_GET['client'] ?? null;
    if (!$isLoggedIn) { header('Location: ?'); exit; }
    if (!$client) { echo "client 파라미터가 필요합니다."; exit; }
    if (!isset($_SESSION['access_' . $client]) || $_SESSION['access_' . $client] !== true) {
        echo "권한 없음: 먼저 '접속'에서 API 키를 입력해 인증하세요."; exit;
    }
    $secret = vault_get_secret($client);
    $inspect = null;
    $dockerSock = '/var/run/docker.sock';
    if (is_readable($dockerSock) && function_exists('shell_exec')) {
        $out = shell_exec(sprintf('docker inspect %s 2>&1', escapeshellarg($client)));
        $inspect = json_decode($out, true);
    } else {
        $inspect = ['Id' => 'sim-'.$client, 'Name' => '/'.$client];
    }
    $files = ['README.md','config.yml','logs/app.log'];
    ?>
    <!doctype html>
    <html lang="ko">
    <head>
        <meta charset="utf-8">
        <title>컨테이너 상세 - <?php echo htmlspecialchars($client); ?></title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
            :root{--bg:#071025;--card:#07172a;--muted:#9fb7d9;--accent:#4f46e5}
            body{font-family:Inter,Arial,Helvetica,sans-serif;margin:0;padding:18px;background:linear-gradient(180deg,#041028,#071025);color:#e6eef8}
            .top{display:flex;align-items:center;gap:12px;margin-bottom:18px}
            a.back{color:var(--muted);text-decoration:none}
            .wrap{max-width:1000px;margin:0 auto}
            .header{display:flex;justify-content:space-between;align-items:center}
            .card{background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0.01));padding:16px;border-radius:10px;box-shadow:0 8px 30px rgba(2,6,23,0.6);margin-bottom:12px}
            .cols{display:grid;grid-template-columns:1fr 360px;gap:12px}
            pre{background:#02102a;padding:12px;border-radius:8px;color:#dbeafe;overflow:auto}
            .files li{padding:8px;border-radius:6px;list-style:none;margin-bottom:6px;background:rgba(255,255,255,0.02);display:flex;justify-content:space-between;align-items:center}
            .files a{color:#cfe3ff;text-decoration:none}
            .btn{background:var(--accent);color:white;padding:8px 10px;border-radius:8px;border:0;cursor:pointer}
            .modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(2,6,23,0.6)}
            .modal.show{display:flex}
            .modal .panel{background:var(--card);padding:16px;border-radius:10px;max-width:800px;max-height:80vh;overflow:auto}
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="top">
                <a class="back" href="?">← 대시보드로 돌아가기</a>
                <div>컨테이너 상세 보기</div>
            </div>
            <div class="header">
                <h1>컨테이너: <?php echo htmlspecialchars($client); ?></h1>
                <div><button onclick="location.reload()" class="btn">새로고침</button></div>
            </div>
            <div class="cols">
                <div>
                    <div class="card">
                        <h3>Inspect</h3>
                        <pre><?php echo htmlspecialchars(json_encode($inspect, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)); ?></pre>
                    </div>
                    <div class="card">
                        <h3>Vault Secret</h3>
                        <pre><?php echo htmlspecialchars(json_encode($secret, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)); ?></pre>
                    </div>
                </div>
                <aside>
                    <div class="card">
                        <h3>파일 목록</h3>
                        <ul class="files">
                            <?php foreach($files as $f) { echo '<li><span>'.htmlspecialchars($f).'</span><span><a href="#" class="file-link" data-path="'.htmlspecialchars($f).'">보기</a></span></li>'; } ?>
                        </ul>
                    </div>
                </aside>
            </div>
        </div>

        <div id="fileModal" class="modal"><div class="panel"><div style="display:flex;justify-content:space-between;align-items:center"><strong id="fileTitle"></strong><button id="closeModal" class="btn">닫기</button></div><hr><pre id="fileContent">로드 중...</pre></div></div>

        <script>
            document.querySelectorAll('.file-link').forEach(el=>{
                el.addEventListener('click', async (e)=>{
                    e.preventDefault();
                    const path = el.dataset.path;
                    const client = <?php echo json_encode($client); ?>;
                    document.getElementById('fileTitle').textContent = path;
                    document.getElementById('fileContent').textContent = '로드 중...';
                    document.getElementById('fileModal').classList.add('show');
                    try{
                        const res = await fetch(`?action=get_file&client=${encodeURIComponent(client)}&path=${encodeURIComponent(path)}`, { credentials: 'same-origin' });
                        const j = await res.json();
                        document.getElementById('fileContent').textContent = j.ok ? j.content : ('파일을 불러오지 못했습니다: ' + (j.error||''));
                    }catch(err){ document.getElementById('fileContent').textContent = '오류: '+err }
                })
            });
            document.getElementById('closeModal').addEventListener('click', ()=>{ document.getElementById('fileModal').classList.remove('show'); });
        </script>
    </body>
    </html>
    <?php
    exit;
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>통합 서버 관리자 포털</title>
<style>
body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial; padding: 18px; background:#0f172a; color:#e6eef8 }
.center-full { display:flex; align-items:center; justify-content:center; min-height:calc(100vh - 36px); }
.card{ background:linear-gradient(180deg,#0b1220,#071028); padding:16px; border-radius:8px; box-shadow:0 6px 24px rgba(2,6,23,0.6); margin-bottom:12px }
h1,h2,h3{ margin:0 0 8px 0 }
.muted{ color:#9fb7d9 }
.btn{ background:#4f46e5;color:#fff;padding:8px 12px;border-radius:6px;border:0;cursor:pointer }
.btn.ghost{ background:transparent;border:1px solid rgba(255,255,255,0.08) }
.grid{ display:grid; grid-template-columns: 1fr 360px; gap:12px }
.containers{ display:grid; grid-template-columns: repeat(2,1fr); gap:10px }
.container-item{ background:rgba(255,255,255,0.02); padding:10px;border-radius:8px }
.small{ font-size:13px; color:#9fb7d9 }
pre{ background:#051025; padding:10px; border-radius:6px; overflow:auto; white-space:pre-wrap }
.key{ font-family:monospace; color:#f0c674 }
.login-box{ max-width:420px }
.stack{ display:flex; flex-direction:column; gap:12px }
.table-wrap{ overflow:auto }
table.simple{ width:100%; border-collapse:collapse; font-size:14px }
table.simple th, table.simple td{ padding:10px 8px; border-bottom:1px solid rgba(255,255,255,0.06); text-align:left; vertical-align:top }
table.simple th{ color:#9fb7d9; font-weight:600 }
.badge{ display:inline-block; padding:3px 8px; border-radius:999px; font-size:12px; background:rgba(79,70,229,.18); color:#c7d2fe }
.badge.off{ background:rgba(239,68,68,.18); color:#fecaca }
.form-grid{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px }
.field label{ display:block; margin-bottom:6px; font-size:13px; color:#9fb7d9 }
.field input, .field select{ width:100%; padding:8px; border-radius:6px; border:1px solid rgba(255,255,255,0.08); background:#071025; color:#e6eef8 }
.message-list{ max-height:340px; overflow:auto; border:1px solid rgba(255,255,255,0.06); border-radius:8px }
.message-item{ padding:10px; border-bottom:1px solid rgba(255,255,255,0.06); cursor:pointer }
.message-item:hover{ background:rgba(255,255,255,0.03) }
.message-item.active{ background:rgba(79,70,229,.18) }
.two-col{ display:grid; grid-template-columns: 320px 1fr; gap:12px }
</style>
</head>
<body>
<header style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <div>
        <h1>🔐 Secure-Project 통합 관리자 포털</h1>
        <div class="muted">Vault 연동 · 컨테이너 관리 · 이메일 계정 관리 · 메일 열람</div>
    </div>
    <div>
        <?php if($isLoggedIn): ?>
            <div class="small">로그인: <strong><?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['admin']); ?></strong> / <?php echo htmlspecialchars($_SESSION['role'] ?? ''); ?></div>
            <button id="logoutBtn" class="btn">로그아웃</button>
        <?php else: ?>
            <div class="small">로그인 필요</div>
        <?php endif; ?>
    </div>
</header>

<?php if (!$isLoggedIn): ?>
<div class="center-full">
<section class="card login-box" style="width:420px;">
    <h2>관리자 로그인</h2>
    <form id="loginForm">
        <label>아이디</label>
        <input id="user" type="text" style="width:100%;padding:8px;margin-top:6px;margin-bottom:8px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);background:#071025;color:#e6eef8" required>
        <label>비밀번호</label>
        <input id="pw" type="password" style="width:100%;padding:8px;margin-top:6px;margin-bottom:10px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);background:#071025;color:#e6eef8" required>
        <div style="display:flex;gap:8px">
            <button class="btn" type="submit">로그인</button>
            <button id="fillDemo" type="button" class="btn ghost">데모 채우기</button>
        </div>
        <div id="loginMsg" class="small" style="margin-top:8px"></div>
    </form>
</section>
</div>
<?php else: ?>
<main class="grid">
    <div class="stack">
        <section class="card">
            <h2>운영 중인 컨테이너</h2>
            <p class="muted">목록에서 컨테이너를 선택해 성능을 조회하거나 Vault에서 키/내부 정보를 가져올 수 있습니다.</p>
            <div class="containers" id="containersList"></div>
        </section>

        <section class="card">
            <h2>이메일 계정 관리</h2>
            <p class="muted">DB의 <code class="key">email_accounts</code>를 기준으로 메일 서버(Postfix/Dovecot)가 직접 인증합니다. 실습용으로 <code class="key">mail_password</code>는 평문 저장됩니다.</p>
            <div class="stack">
                <form id="createEmailForm" class="card" style="margin:0;background:rgba(255,255,255,0.02);box-shadow:none">
                    <h3>이메일 계정 추가</h3>
                    <div class="form-grid">
                        <div class="field"><label>이메일 주소</label><input type="email" name="email_address" placeholder="ceo@company.local" required></div>
                        <div class="field"><label>로그인 ID</label><input type="text" name="login_id" placeholder="ceo" required></div>
                        <div class="field"><label>표시 이름</label><input type="text" name="display_name" placeholder="CEO" required></div>
                        <div class="field"><label>부서</label><input type="text" name="department" placeholder="Executive"></div>
                        <div class="field"><label>초기 비밀번호</label><input type="text" name="password" placeholder="Mail1234" required></div>
                        <div class="field"><label>메일박스 용량(MB)</label><input type="number" name="mailbox_quota_mb" value="1024"></div>
                    </div>
                    <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
                        <button type="submit" class="btn">계정 생성</button>
                        <div id="createEmailMsg" class="small"></div>
                    </div>
                </form>

                <div class="table-wrap">
                    <table class="simple">
                        <thead>
                        <tr>
                            <th>ID</th><th>Email</th><th>Login ID</th><th>이름</th><th>부서</th><th>상태</th><th>관리</th>
                        </tr>
                        </thead>
                        <tbody id="emailAccountsBody"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <?php if (is_superadmin()): ?>
        <section class="card">
            <h2>메일 열람 (Read-only)</h2>
            <p class="muted">superadmin 전용 기능입니다. 선택한 계정으로 IMAP에 접속해 최근 메일 20개를 읽습니다.</p>
            <div class="stack">
                <div style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
                    <div class="field" style="min-width:280px">
                        <label>메일 계정 선택</label>
                        <select id="mailAccountSelect"></select>
                    </div>
                    <button class="btn" id="loadMailboxBtn">메일함 불러오기</button>
                </div>

                <div class="two-col">
                    <div>
                        <div class="message-list" id="messageList"></div>
                    </div>
                    <div class="card" style="margin:0;background:rgba(255,255,255,0.02);box-shadow:none">
                        <h3 id="messageTitle">메일 본문</h3>
                        <div class="small" id="messageMeta">계정을 선택하고 메일함을 불러오세요.</div>
                        <pre id="messageBody">(본문 없음)</pre>
                    </div>
                </div>
            </div>
        </section>
        <?php endif; ?>

        <section class="card">
            <h2>전체 제어</h2>
            <div style="display:flex;gap:8px;margin-top:8px">
                <button id="refreshAll" class="btn ghost">지표 전체 갱신</button>
                <button id="stopAll" class="btn" style="background:#ef4444">모두 중지(시뮬레이션)</button>
            </div>
        </section>
    </div>

    <aside class="stack">
        <section class="card">
            <h3>최근 액션 / 내부 정보</h3>
            <div id="logArea" class="small"><em>아직 작업이 없습니다.</em></div>
        </section>
        <section class="card">
            <h3>설정 요약</h3>
            <div class="small">Vault: <code class="key"><?php echo htmlspecialchars($VAULT_ADDR); ?></code></div>
            <div class="small">DB: <code class="key"><?php echo htmlspecialchars($DB_HOST . '/' . $DB_NAME); ?></code></div>
            <div class="small">IMAP: <code class="key"><?php echo htmlspecialchars($IMAP_HOST . ':' . $IMAP_PORT); ?></code></div>
            <div class="small">Mailstore: <code class="key"><?php echo htmlspecialchars($MAILSTORE_BASE); ?></code></div>
        </section>
    </aside>
</main>
<?php endif; ?>

<script>
const containers = [
    { id: 'client_a', name: 'Client A - Juice Shop', ip: '192.168.20.10', port: 3000 },
    { id: 'client_b', name: 'Client B - DVWA', ip: '192.168.20.20', port: 80 },
    { id: 'client_c', name: 'Client C - bWAPP', ip: '192.168.20.30', port: 80 },
    { id: 'mail_server', name: 'Mail Server - Postfix/Dovecot', ip: '192.168.20.60', port: 143 }
];

function log(msg){
    const a = document.getElementById('logArea');
    if(!a) return;
    a.innerHTML = `<div style="margin-bottom:8px">${new Date().toLocaleTimeString()} - ${msg}</div>` + a.innerHTML;
}

function renderContainers(){
    const wrap = document.getElementById('containersList');
    if(!wrap) return;
    wrap.innerHTML = '';
    containers.forEach(c=>{
        const box = document.createElement('div');
        box.className = 'container-item';
        box.innerHTML = `<strong>${c.name}</strong><div class="small">id: ${c.id} · ${c.ip}:${c.port}</div><div id="metrics-${c.id}" class="small" style="margin-top:6px">CPU: -- · MEM: -- · 응답: --</div>`;
        const controls = document.createElement('div');
        controls.style.marginTop='8px';
        const btnEnter = document.createElement('button');
        btnEnter.className = 'btn';
        btnEnter.textContent = '접속(내부정보)';
        btnEnter.addEventListener('click', ()=>enterContainer(c.id));
        const btnMetric = document.createElement('button');
        btnMetric.className = 'btn ghost';
        btnMetric.textContent = '지표 갱신';
        btnMetric.style.marginLeft='8px';
        btnMetric.addEventListener('click', ()=>refreshMetric(c.id));
        controls.appendChild(btnEnter); controls.appendChild(btnMetric); box.appendChild(controls); wrap.appendChild(box);
    });
}

async function refreshMetric(id){
    const res = await fetch(`?action=metrics&client=${encodeURIComponent(id)}`, { credentials: 'same-origin' });
    const j = await res.json();
    if (!j.ok){ alert('지표 불러오기 실패'); return; }
    const el = document.getElementById('metrics-'+id);
    if (el) el.textContent = `CPU: ${j.cpu}% · MEM: ${j.mem}% · 응답: ${j.resp}ms`;
    log(`${id} 지표 갱신`);
}

async function enterContainer(id){
    const apiKey = prompt('API Key를 입력하세요 for ' + id + ':');
    if (!apiKey) return;
    const res = await fetch(`?action=validate_key&client=${encodeURIComponent(id)}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ api_key: apiKey })
    });
    const j = await res.json();
    if (!j.ok) { alert('API 키 검증 실패: ' + (j.error||'')); return; }
    log(`${id} API 키 검증 성공`);
    location.href = `?view=container&client=${encodeURIComponent(id)}`;
}

async function loadEmailAccounts(){
    const res = await fetch('?action=email_accounts_list', { credentials: 'same-origin' });
    const j = await res.json();
    const tbody = document.getElementById('emailAccountsBody');
    if(!tbody) return;
    tbody.innerHTML = '';
    if (!j.ok) return;
    j.rows.forEach(row=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${row.id}</td>
            <td>${escapeHtml(row.email_address)}</td>
            <td>${escapeHtml(row.login_id)}</td>
            <td>${escapeHtml(row.display_name)}</td>
            <td>${escapeHtml(row.department || '')}</td>
            <td>${row.is_active == 1 ? '<span class="badge">활성</span>' : '<span class="badge off">비활성</span>'}</td>
            <td><button class="btn ghost" data-id="${row.id}" data-active="${row.is_active == 1 ? 0 : 1}">${row.is_active == 1 ? '비활성화' : '활성화'}</button></td>
        `;
        tr.querySelector('button')?.addEventListener('click', ()=>toggleEmailAccount(row.id, row.is_active == 1 ? 0 : 1));
        tbody.appendChild(tr);
    });
}

async function toggleEmailAccount(id, isActive){
    const res = await fetch('?action=email_accounts_toggle', {
        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({id, is_active: isActive})
    });
    const j = await res.json();
    if(!j.ok){ alert(j.error || '계정 상태 변경 실패'); return; }
    log(`이메일 계정 ${id} 상태 변경`);
    await loadEmailAccounts();
    await loadMailAccountOptions();
}

async function loadMailAccountOptions(){
    const select = document.getElementById('mailAccountSelect');
    if(!select) return;
    const res = await fetch('?action=mail_accounts_list', { credentials:'same-origin' });
    const j = await res.json();
    select.innerHTML = '';
    if(!j.ok){
        const opt = document.createElement('option');
        opt.textContent = '불러오기 실패';
        select.appendChild(opt);
        return;
    }
    j.rows.forEach(row=>{
        const opt = document.createElement('option');
        opt.value = row.id;
        opt.textContent = `${row.email_address} (${row.display_name})`;
        select.appendChild(opt);
    });
}

async function loadMailboxMessages(){
    const select = document.getElementById('mailAccountSelect');
    if(!select || !select.value) return;
    const res = await fetch(`?action=mail_messages&account_id=${encodeURIComponent(select.value)}`, { credentials:'same-origin' });
    const j = await res.json();
    const list = document.getElementById('messageList');
    if(!list) return;
    list.innerHTML = '';
    if(!j.ok){
        list.innerHTML = `<div class="message-item">${escapeHtml(j.error || '메일함 조회 실패')}</div>`;
        return;
    }
    if(!j.messages.length){
        list.innerHTML = `<div class="message-item">메일이 없습니다.</div>`;
        document.getElementById('messageTitle').textContent = '메일 본문';
        document.getElementById('messageMeta').textContent = `${j.account.email_address} / 메일 없음`;
        document.getElementById('messageBody').textContent = '(본문 없음)';
        return;
    }
    document.getElementById('messageMeta').textContent = `${j.account.email_address} / 최근 ${j.messages.length}건`;
    j.messages.forEach(msg=>{
        const div = document.createElement('div');
        div.className = 'message-item';
        div.innerHTML = `<div><strong>${escapeHtml(msg.subject || '(제목 없음)')}</strong></div><div class="small">${escapeHtml(msg.from || '')}</div><div class="small">${escapeHtml(msg.date || '')}</div>`;
        div.addEventListener('click', ()=>loadMessageDetail(select.value, msg.msgno, div));
        list.appendChild(div);
    });
}

async function loadMessageDetail(accountId, msgno, element){
    document.querySelectorAll('.message-item').forEach(el=>el.classList.remove('active'));
    element?.classList.add('active');
    const res = await fetch(`?action=mail_message&account_id=${encodeURIComponent(accountId)}&msgno=${encodeURIComponent(msgno)}`, { credentials:'same-origin' });
    const j = await res.json();
    if(!j.ok){
        document.getElementById('messageTitle').textContent = '메일 본문';
        document.getElementById('messageMeta').textContent = '불러오기 실패';
        document.getElementById('messageBody').textContent = j.error || '메시지 조회 실패';
        return;
    }
    document.getElementById('messageTitle').textContent = j.message.subject || '(제목 없음)';
    document.getElementById('messageMeta').textContent = `${j.message.from || ''} / ${j.message.date || ''}`;
    document.getElementById('messageBody').textContent = j.message.body || '(본문 없음)';
}

function escapeHtml(str){
    return String(str ?? '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]));
}

const loginForm = document.getElementById('loginForm');
if (loginForm){
    loginForm.addEventListener('submit', async (e)=>{
        e.preventDefault();
        const user = document.getElementById('user').value.trim();
        const pw = document.getElementById('pw').value;
        const res = await fetch('?action=login', {
            method:'POST',
            credentials:'same-origin',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({user, pw})
        });
        const j = await res.json();
        const msg = document.getElementById('loginMsg');
        if (j.ok){
            msg.textContent = '로그인 성공 — 페이지를 새로고침합니다.';
            setTimeout(()=>location.reload(), 500);
        } else {
            msg.textContent = '로그인 실패: ' + (j.error || '');
        }
    });
    document.getElementById('fillDemo').addEventListener('click', ()=>{
        document.getElementById('user').value='admin';
        document.getElementById('pw').value='qhdksdlchlrh';
    });
}

document.getElementById('logoutBtn')?.addEventListener('click', async ()=>{
    await fetch('?action=logout', { credentials:'same-origin' });
    location.reload();
});

document.getElementById('refreshAll')?.addEventListener('click', ()=>containers.forEach(c=>refreshMetric(c.id)));
document.getElementById('stopAll')?.addEventListener('click', ()=>{ alert('모두 중지(시뮬레이션)'); log('전체 중지(시뮬레이션)'); });

document.getElementById('createEmailForm')?.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const form = e.currentTarget;
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    payload.mailbox_quota_mb = parseInt(payload.mailbox_quota_mb || '1024', 10);

    const res = await fetch('?action=email_accounts_create', {
        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload)
    });
    const j = await res.json();
    const msg = document.getElementById('createEmailMsg');
    if(!j.ok){
        msg.textContent = '실패: ' + (j.error || '');
        return;
    }
    msg.textContent = j.maildir && j.maildir.ok ? '생성 완료 (Maildir 포함)' : '생성 완료 (Maildir 확인 필요)';
    form.reset();
    form.querySelector('[name="mailbox_quota_mb"]').value = 1024;
    log(`이메일 계정 생성: ${payload.email_address}`);
    await loadEmailAccounts();
    await loadMailAccountOptions();
});

document.getElementById('loadMailboxBtn')?.addEventListener('click', loadMailboxMessages);

renderContainers();
<?php if ($isLoggedIn): ?>
containers.forEach(c=>refreshMetric(c.id));
loadEmailAccounts();
<?php if (is_superadmin()): ?>
loadMailAccountOptions();
<?php endif; ?>
<?php endif; ?>
</script>
</body>
</html>
