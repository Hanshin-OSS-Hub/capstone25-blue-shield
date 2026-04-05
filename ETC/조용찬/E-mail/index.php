<?php
session_start();

// === 설정 ===
$VAULT_ADDR = getenv('VAULT_ADDR') ?: 'http://192.168.20.50:8200/v1/secret/data/'; // Vault 내부 주소 (docker-compose 네트워크 기준)

// Vault 토큰은 환경변수 VAULT_TOKEN 또는 FALLBACK 값 사용
$VAULT_TOKEN = getenv('VAULT_TOKEN') ?: getenv('VAULT_DEV_ROOT_TOKEN_ID') ?: 'my_root_token';

// DB 설정 (WSL 단독이면 127.0.0.1, Docker admin_entry면 host.docker.internal)
$DB_HOST = getenv('DB_HOST') ?: 'host.docker.internal';
$DB_NAME = getenv('DB_NAME') ?: 'admin_portal';
$DB_USER = getenv('DB_USER') ?: 'portal_user';
$DB_PASS = getenv('DB_PASS') ?: 'StrongPortalPass!123';

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

// 간단한 도우미: Vault에서 secret 조회
function vault_get_secret($name) {
    global $VAULT_ADDR, $VAULT_TOKEN;
    $url = rtrim($VAULT_ADDR, '/') . '/' . rawurlencode($name);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        "X-Vault-Token: {$VAULT_TOKEN}",
        'Content-Type: application/json'
    ));
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!$res) return array('error' => 'Vault 응답 없음');
    $json = json_decode($res, true);
    if ($code >= 400) return array('error' => 'Vault 오류: ' . ($json['errors'][0] ?? $code));
    return $json;
}

// 리퀘스트에 따른 AJAX 응답 처리
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    header('Content-Type: application/json; charset=utf-8');

    // 로그인 필요 여부: login/logout/metrics/public allowed
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

    // 인증 필요 for following actions
    if (!isset($_SESSION['admin'])) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => '로그인이 필요합니다.']);
        exit;
    }

    if ($action === 'metrics') {
        // 시뮬레이션된 메트릭 반환
        $client = $_GET['client'] ?? null;
        $rand = function($min,$max){ return rand($min,$max); };
        if ($client) {
            echo json_encode(['ok'=>true,'client'=>$client,'cpu'=>$rand(1,90),'mem'=>$rand(5,95),'resp'=>$rand(10,800)]);
            exit;
        }
        // 전체
        $list = ['admin_entry','client_a_OWASP','client_b_dvwa','client_c_bwapp','key_vault_server'];
        $out = [];
        foreach($list as $c) $out[$c] = ['cpu'=>$rand(1,90),'mem'=>$rand(5,95),'resp'=>$rand(10,800)];
        echo json_encode(['ok'=>true,'metrics'=>$out]);
        exit;
    }

    if ($action === 'get_key') {
        $client = $_GET['client'] ?? null;
        if (!$client) { echo json_encode(['ok'=>false,'error'=>'client 파라미터 필요']); exit; }
        // Vault에서 secret 조회
        $res = vault_get_secret($client);
        // Vault API v2로 저장된 경우 구조: data -> data
        if (isset($res['data']['data'])) {
            $secretData = $res['data']['data'];
            // 예: api_key, internal_info 등 표시
            echo json_encode(['ok'=>true,'secret'=>$secretData]);
            exit;
        }
        echo json_encode(['ok'=>false,'error'=>'Vault에서 비밀을 읽을 수 없습니다','raw'=>$res]);
        exit;
    }

    if ($action === 'validate_key') {
        // 클라이언트에 대한 API 키 검증 요청
        $client = $_GET['client'] ?? null;
        $data = json_decode(file_get_contents('php://input'), true) ?: [];
        $provided = $data['api_key'] ?? null;
        if (!$client || !$provided) { echo json_encode(['ok'=>false,'error'=>'client 및 api_key 필요']); exit; }
        // Vault에서 secret 조회
        $res = vault_get_secret($client);
        if (isset($res['data']['data']['api_key'])) {
            $real = $res['data']['data']['api_key'];
            if (hash_equals((string)$real, (string)$provided)) {
                // 접근 권한 부여 (세션)
                $_SESSION['access_' . $client] = true;
                echo json_encode(['ok'=>true]); exit;
            }
            echo json_encode(['ok'=>false,'error'=>'API 키 불일치']); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'Vault에서 api_key를 찾을 수 없음','raw'=>$res]); exit;
    }

    if ($action === 'inspect') {
        // 클라이언트의 컨테이너 inspect 정보(시뮬레이션 또는 실제 docker inspect)
        $client = $_GET['client'] ?? null;
        if (!$client) { echo json_encode(['ok'=>false,'error'=>'client 파라미터 필요']); exit; }

        // 실제 Docker 소켓이 마운트된 경우 docker inspect 실행
        $dockerSock = '/var/run/docker.sock';
        if (is_readable($dockerSock) && function_exists('shell_exec')) {
            // 컨테이너 명으로 inspect 시도 (주의: 권한 필요)
            $cmd = sprintf('docker inspect %s 2>&1', escapeshellarg($client));
            $output = shell_exec($cmd);
            if ($output === null) {
                echo json_encode(['ok'=>false,'error'=>'docker inspect 실행 실패']); exit;
            }
            $json = json_decode($output, true);
            echo json_encode(['ok'=>true,'inspect'=>$json]); exit;
        }

        // 시뮬레이션 데이터
        $sim = [
            'Id' => 'sim-' . $client,
            'Name' => '/' . $client,
            'Config' => ['Image' => 'example/image:latest','Env'=>['APP_ENV=prod']],
            'NetworkSettings' => ['IPAddress' => '192.168.20.10'],
            'Mounts' => [['Source'=>'/var/lib/docker/volumes/'.$client,'Destination'=>'/data','Mode'=>'rw']]
        ];
        // 예시 파일 목록
        $files = ['README.md','logs/app.log','config.yml'];
        echo json_encode(['ok'=>true,'inspect'=>$sim,'files'=>$files]);
        exit;
    }

    if ($action === 'get_file') {
        $client = $_GET['client'] ?? null;
        $path = $_GET['path'] ?? null;
        if (!$client || !$path) { echo json_encode(['ok'=>false,'error'=>'client 및 path 파라미터 필요']); exit; }

        $dockerSock = '/var/run/docker.sock';
        if (is_readable($dockerSock) && function_exists('shell_exec')) {
            // 실제 환경에서는 docker cp나 docker exec cat으로 파일을 읽을 수 있음
            // 위험: 권한 필요. 여기서는 안전을 위해 허용된 경로만 처리하도록 권장.
            $cmd = sprintf('docker exec %s sh -c %s 2>&1', escapeshellarg($client), escapeshellarg('cat ' . $path));
            $output = shell_exec($cmd);
            if ($output === null) { echo json_encode(['ok'=>false,'error'=>'파일 읽기 실패']); exit; }
            echo json_encode(['ok'=>true,'content'=>$output]); exit;
        }

        // 시뮬레이션 샘플 내용
        $sample = "# Sample file for {$client}\nThis is a simulated file content for {$path}.\n";
        echo json_encode(['ok'=>true,'content'=>$sample]);
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
        $email = trim($data['email_address'] ?? '');
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
            (email_address, login_id, display_name, department, password_hash, mailbox_quota_mb, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        ");

        try {
            $stmt->execute([
                $email,
                $loginId,
                $displayName,
                $department,
                password_hash($password, PASSWORD_DEFAULT),
                $quota
            ]);
            $newId = (int)$pdo->lastInsertId();
            audit_log($pdo, $_SESSION['admin_id'] ?? null, 'CREATE_EMAIL_ACCOUNT', 'email_account', $newId);
            echo json_encode(['ok' => true, 'id' => $newId]);
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

    // 기본: 허용되지 않음
    echo json_encode(['ok'=>false,'error'=>'알 수 없는 액션']);
    exit;
}

// 여기까지 오면 HTML 렌더링 (GET 기본 페이지)
$isLoggedIn = isset($_SESSION['admin']);
// 상세 뷰: ?view=container&client=xxx
if (isset($_GET['view']) && $_GET['view'] === 'container') {
        $client = $_GET['client'] ?? null;
        if (!$isLoggedIn) { header('Location: ?'); exit; }
        if (!$client) { echo "client 파라미터가 필요합니다."; exit; }
        if (!isset($_SESSION['access_' . $client]) || $_SESSION['access_' . $client] !== true) {
                echo "권한 없음: 먼저 '접속'에서 API 키를 입력해 인증하세요."; exit;
        }
        // Vault에서 secret과 inspect 시도
        $secret = vault_get_secret($client);
        // inspect (시뮬레이션 또는 실제)
        $inspect = null;
        $dockerSock = '/var/run/docker.sock';
        if (is_readable($dockerSock) && function_exists('shell_exec')) {
                $out = shell_exec(sprintf('docker inspect %s 2>&1', escapeshellarg($client)));
                $inspect = json_decode($out, true);
        } else {
                $inspect = ['Id' => 'sim-'.$client, 'Name' => '/'.$client];
        }
        // 파일 목록 (시뮬레이션)
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
                    .muted{color:var(--muted)}
                    .files li{padding:8px;border-radius:6px;list-style:none;margin-bottom:6px;background:rgba(255,255,255,0.02);display:flex;justify-content:space-between;align-items:center}
                    .files a{color:#cfe3ff;text-decoration:none}
                    .btn{background:var(--accent);color:white;padding:8px 10px;border-radius:8px;border:0;cursor:pointer}
                    .modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(2,6,23,0.6)}
                    .modal.show{display:flex}
                    .modal .panel{background:var(--card);padding:16px;border-radius:10px;max-width:800px;max-height:80vh;overflow:auto}
                    .small{font-size:13px;color:var(--muted)}
                </style>
            </head>
            <body>
                <div class="wrap">
                    <div class="top">
                        <a class="back" href="?">← 대시보드로 돌아가기</a>
                        <div class="small">컨테이너 상세 보기</div>
                    </div>

                    <div class="header">
                        <h1>컨테이너: <?php echo htmlspecialchars($client); ?></h1>
                        <div>
                            <button onclick="location.href='?view=container&client=<?php echo rawurlencode($client); ?>&refresh=1'" class="btn">새로고침</button>
                        </div>
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
                                <p class="small">파일명을 클릭하면 내용이 모달로 표시됩니다.</p>
                                <ul class="files">
                                    <?php foreach($files as $f) { echo '<li><span>'.htmlspecialchars($f).'</span><span><a href="#" class="file-link" data-path="'.htmlspecialchars($f).'">보기</a></span></li>'; } ?>
                                </ul>
                            </div>
                        </aside>
                    </div>
                </div>

                <!-- 파일 모달 -->
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
                                if (j.ok) document.getElementById('fileContent').textContent = j.content;
                                else document.getElementById('fileContent').textContent = '파일을 불러오지 못했습니다: '+(j.error||'');
                            }catch(err){ document.getElementById('fileContent').textContent = '오류: '+err }
                        })
                    })
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
        /* 로그인 센터링용 래퍼 */
        .center-full { display:flex; align-items:center; justify-content:center; min-height:calc(100vh - 36px); }
        .card{ background:linear-gradient(180deg,#0b1220,#071028); padding:16px; border-radius:8px; box-shadow:0 6px 24px rgba(2,6,23,0.6); margin-bottom:12px }
        h1,h2{ margin:0 0 8px 0 }
        .muted{ color:#9fb7d9 }
        .btn{ background:#4f46e5;color:#fff;padding:8px 12px;border-radius:6px;border:0;cursor:pointer }
        .btn.ghost{ background:transparent;border:1px solid rgba(255,255,255,0.06) }
        .grid{ display:grid; grid-template-columns: 1fr 320px; gap:12px }
        .containers{ display:grid; grid-template-columns: repeat(2,1fr); gap:10px }
        .container-item{ background:rgba(255,255,255,0.02); padding:10px;border-radius:8px }
        .small{ font-size:13px; color:#9fb7d9 }
        pre{ background:#051025; padding:8px; border-radius:6px; overflow:auto }
        .danger{ color:#ffb4b4 }
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
        .field input{ width:100%; padding:8px; border-radius:6px; border:1px solid rgba(255,255,255,0.06); background:#071025; color:#e6eef8 }
    </style>
</head>
<body>
    <header style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
        <div>
            <h1>🔐 Secure-Project 통합 관리자 포털</h1>
            <div class="muted">Vault 연동 · 컨테이너 관리 데모</div>
        </div>
        <div>
            <?php if($isLoggedIn): ?>
                <div class="small">로그인: <strong><?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['admin']); ?></strong></div>
                <button id="logoutBtn" class="btn btn-sm">로그아웃</button>
            <?php else: ?>
                <div class="small">로그인 필요</div>
            <?php endif; ?>
        </div>
    </header>

    <?php if (!$isLoggedIn): ?>
        <div class="center-full">
        <section class="card login-box" style="width:420px;">
            <h2>관리자 로그인</h2>
            <p class="muted">처음 접속 시 ID/PW로 로그인하세요.</p>
            <div style="height:8px"></div>
            <form id="loginForm">
                <label>아이디</label>
                <input id="user" type="text" style="width:100%;padding:8px;margin-top:6px;margin-bottom:8px;border-radius:6px;border:1px solid rgba(255,255,255,0.06);background:#071025;color:#e6eef8" required>
                <label>비밀번호</label>
                <input id="pw" type="password" style="width:100%;padding:8px;margin-top:6px;margin-bottom:10px;border-radius:6px;border:1px solid rgba(255,255,255,0.06);background:#071025;color:#e6eef8" required>
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
            <div>
                <section class="card">
                    <h2>운영 중인 컨테이너</h2>
                    <p class="muted">목록에서 컨테이너를 선택해 성능을 조회하거나 Vault에서 키/내부 정보를 가져올 수 있습니다.</p>
                    <div style="height:10px"></div>
                    <div class="containers" id="containersList">
                        <!-- JS로 채워짐 -->
                    </div>
                </section>

                <section class="card">
                    <h3>전체 제어</h3>
                    <div style="display:flex;gap:8px;margin-top:8px">
                        <button id="refreshAll" class="btn ghost">지표 전체 갱신</button>
                        <button id="stopAll" class="btn" style="background:#ef4444">모두 중지(시뮬레이션)</button>
                    </div>
                </section>

                <section class="card">
                    <h2>이메일 계정 관리</h2>
                    <p class="muted">현재 DB의 <code class="key">email_accounts</code> 테이블을 조회하고 계정을 추가/비활성화합니다.</p>
                    <div class="stack">
                        <form id="createEmailForm" class="card" style="margin:0;background:rgba(255,255,255,0.02);box-shadow:none">
                            <div class="form-grid">
                                <div class="field">
                                    <label for="email_address">이메일 주소</label>
                                    <input id="email_address" name="email_address" type="email" placeholder="ceo@company.local" required>
                                </div>
                                <div class="field">
                                    <label for="login_id">로그인 ID</label>
                                    <input id="login_id" name="login_id" type="text" placeholder="ceo" required>
                                </div>
                                <div class="field">
                                    <label for="display_name">표시 이름</label>
                                    <input id="display_name" name="display_name" type="text" placeholder="CEO" required>
                                </div>
                                <div class="field">
                                    <label for="department">부서</label>
                                    <input id="department" name="department" type="text" placeholder="Executive">
                                </div>
                                <div class="field">
                                    <label for="email_password">초기 비밀번호</label>
                                    <input id="email_password" name="password" type="text" placeholder="Mail1234" required>
                                </div>
                                <div class="field">
                                    <label for="mailbox_quota_mb">용량(MB)</label>
                                    <input id="mailbox_quota_mb" name="mailbox_quota_mb" type="number" value="1024" min="1">
                                </div>
                            </div>
                            <div style="display:flex;gap:8px;margin-top:12px;align-items:center">
                                <button class="btn" type="submit">계정 추가</button>
                                <button id="fillMailDemo" class="btn ghost" type="button">데모 채우기</button>
                                <div id="emailCreateMsg" class="small"></div>
                            </div>
                        </form>

                        <div class="table-wrap">
                            <table class="simple">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Email</th>
                                        <th>Login ID</th>
                                        <th>표시 이름</th>
                                        <th>부서</th>
                                        <th>Quota</th>
                                        <th>상태</th>
                                        <th>동작</th>
                                    </tr>
                                </thead>
                                <tbody id="emailAccountsBody">
                                    <tr><td colspan="8" class="small">불러오는 중...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>
            </div>

            <aside>
                <section class="card">
                    <h3>최근 액션 / 내부 정보</h3>
                    <div id="logArea" class="small"><em>아직 작업이 없습니다.</em></div>
                </section>
                <section class="card" style="margin-top:10px">
                    <h3>Vault 설정</h3>
                    <div class="small">Vault 주소: <code class="key"><?php echo htmlspecialchars($VAULT_ADDR); ?></code></div>
                    <div class="small">(토큰은 서버 환경변수로 관리됩니다)</div>
                </section>
            </aside>
        </main>
    <?php endif; ?>

    <script>
        // 로그인 시 보여줄 클라이언트 목록: 요구사항에 따라 A,B,C만
        const containers = [
            { id: 'client_a', name: 'Client A - Juice Shop', ip: '192.168.20.10', port: 3000 },
            { id: 'client_b', name: 'Client B - DVWA', ip: '192.168.20.20', port: 80 },
            { id: 'client_c', name: 'Client C - bWAPP', ip: '192.168.20.30', port: 80 }
        ];

        function el(tag, cls){ const d = document.createElement(tag); if(cls) d.className = cls; return d }

        // 로그인 폼 처리
        const loginForm = document.getElementById('loginForm');
        if (loginForm){
            loginForm.addEventListener('submit', async (e)=>{
                e.preventDefault();
                const user = document.getElementById('user').value.trim();
                const pw = document.getElementById('pw').value;
                const res = await fetch('?action=login', {method:'POST', credentials: 'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify({user, pw})});
                const j = await res.json();
                const msg = document.getElementById('loginMsg');
                if (j.ok){
                    msg.textContent = '로그인 성공 — 페이지를 새로고침합니다.';
                    setTimeout(()=>location.reload(),700);
                } else {
                    msg.textContent = '로그인 실패: ' + (j.error||'');
                }
            });
            document.getElementById('fillDemo').addEventListener('click', ()=>{ document.getElementById('user').value='admin'; document.getElementById('pw').value='qhdksdlchlrh'; });
        }

        const createEmailForm = document.getElementById('createEmailForm');
        if (createEmailForm){
            createEmailForm.addEventListener('submit', async (e)=>{
                e.preventDefault();
                const payload = {
                    email_address: document.getElementById('email_address').value.trim(),
                    login_id: document.getElementById('login_id').value.trim(),
                    display_name: document.getElementById('display_name').value.trim(),
                    department: document.getElementById('department').value.trim(),
                    password: document.getElementById('email_password').value,
                    mailbox_quota_mb: Number(document.getElementById('mailbox_quota_mb').value || 1024)
                };
                const msg = document.getElementById('emailCreateMsg');
                const res = await fetch('?action=email_accounts_create', {
                    method:'POST',
                    credentials:'same-origin',
                    headers:{'Content-Type':'application/json'},
                    body: JSON.stringify(payload)
                });
                const j = await res.json();
                if (j.ok){
                    msg.textContent = '계정이 추가되었습니다.';
                    createEmailForm.reset();
                    document.getElementById('mailbox_quota_mb').value = 1024;
                    log(`이메일 계정 생성: ${payload.email_address}`);
                    fetchEmailAccounts();
                } else {
                    msg.textContent = '실패: ' + (j.error || '');
                }
            });

            document.getElementById('fillMailDemo')?.addEventListener('click', ()=>{
                document.getElementById('email_address').value = 'ceo@company.local';
                document.getElementById('login_id').value = 'ceo';
                document.getElementById('display_name').value = 'Chief Executive Officer';
                document.getElementById('department').value = 'Executive';
                document.getElementById('email_password').value = 'Mail1234';
                document.getElementById('mailbox_quota_mb').value = 1024;
            });
        }

        // 로그 출력
        function log(msg){ const a = document.getElementById('logArea'); a.innerHTML = `<div style="margin-bottom:8px">${new Date().toLocaleTimeString()} - ${msg}</div>` + a.innerHTML }

        async function fetchEmailAccounts(){
            const res = await fetch('?action=email_accounts_list', { credentials: 'same-origin' });
            if (res.status === 401) { location.reload(); return; }
            const j = await res.json();
            const tbody = document.getElementById('emailAccountsBody');
            if (!tbody) return;
            if (!j.ok) {
                tbody.innerHTML = '<tr><td colspan="8" class="small">목록을 불러오지 못했습니다.</td></tr>';
                return;
            }
            if (!j.rows || j.rows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="small">등록된 이메일 계정이 없습니다.</td></tr>';
                return;
            }
            tbody.innerHTML = '';
            j.rows.forEach(row => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${row.id}</td>
                    <td>${row.email_address}</td>
                    <td>${row.login_id}</td>
                    <td>${row.display_name}</td>
                    <td>${row.department || '-'}</td>
                    <td>${row.mailbox_quota_mb} MB</td>
                    <td><span class="badge ${Number(row.is_active) === 1 ? '' : 'off'}">${Number(row.is_active) === 1 ? '활성' : '비활성'}</span></td>
                    <td>
                        <button class="btn ghost toggle-mail" data-id="${row.id}" data-active="${Number(row.is_active) === 1 ? 0 : 1}">
                            ${Number(row.is_active) === 1 ? '비활성화' : '활성화'}
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

            document.querySelectorAll('.toggle-mail').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const id = Number(btn.dataset.id);
                    const isActive = Number(btn.dataset.active);
                    const res = await fetch('?action=email_accounts_toggle', {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({ id, is_active: isActive })
                    });
                    const j = await res.json();
                    if (!j.ok) {
                        alert('상태 변경 실패: ' + (j.error || ''));
                        return;
                    }
                    log(`이메일 계정 #${id} ${isActive ? '활성화' : '비활성화'}`);
                    fetchEmailAccounts();
                });
            });
        }

        // 렌더 컨테이너 카드
        function renderContainers(){
            const wrap = document.getElementById('containersList'); if(!wrap) return;
            wrap.innerHTML = '';
            containers.forEach(c=>{
                const box = el('div','container-item');
                box.innerHTML = `<strong>${c.name}</strong><div class="small">id: ${c.id} · ${c.ip}:${c.port}</div><div id="metrics-${c.id}" class="small" style="margin-top:6px">CPU: -- · MEM: -- · 응답: --</div>`;
                const controls = el('div'); controls.style.marginTop='8px';
                const btnEnter = el('button','btn'); btnEnter.textContent='접속(내부정보)'; btnEnter.addEventListener('click', ()=>enterContainer(c.id));
                const btnMetric = el('button','btn ghost'); btnMetric.textContent='지표 갱신'; btnMetric.style.marginLeft='8px'; btnMetric.addEventListener('click', ()=>refreshMetric(c.id));
                controls.appendChild(btnEnter); controls.appendChild(btnMetric); box.appendChild(controls); wrap.appendChild(box);
            });
        }

        async function refreshMetric(id){
            const res = await fetch(`?action=metrics&client=${encodeURIComponent(id)}`, { credentials: 'same-origin' });
            if (res.status===401) { alert('로그인 필요'); location.reload(); return }
            const j = await res.json();
            if (!j.ok){ alert('지표 불러오기 실패'); return }
            const elmt = document.getElementById('metrics-'+id);
            if (elmt) elmt.textContent = `CPU: ${j.cpu}% · MEM: ${j.mem}% · 응답: ${j.resp}ms`;
            log(`${id} 지표 갱신`);
        }

        async function enterContainer(id){
            // 접속 전에 API 키 입력받아 검증
            const apiKey = prompt('API Key를 입력하세요 for ' + id + ':');
            if (!apiKey) return;
            const res = await fetch(`?action=validate_key&client=${encodeURIComponent(id)}`, { method: 'POST', credentials: 'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ api_key: apiKey }) });
            if (res.status===401){ alert('로그인 필요'); location.reload(); return }
            const j = await res.json();
            if (!j.ok) { alert('API 키 검증 실패: ' + (j.error||'')); return }
            // 검증 성공 시 상세 페이지로 이동
            log(`${id} API 키 검증 성공, 상세 페이지로 이동`);
            location.href = `?view=container&client=${encodeURIComponent(id)}`;
        }

    document.getElementById('refreshAll')?.addEventListener('click', ()=>{ containers.forEach(c=>refreshMetric(c.id)); });
    document.getElementById('stopAll')?.addEventListener('click', ()=>{ alert('모두 중지(시뮬레이션)'); log('전체 중지(시뮬레이션)'); });
    document.getElementById('logoutBtn')?.addEventListener('click', async ()=>{ await fetch('?action=logout', { credentials: 'same-origin' }); location.reload(); });

        // 페이지 로드 시 렌더
        renderContainers();
        // 초기 전체 메트릭 로드(로그인된 경우만)
        <?php if ($isLoggedIn): ?>
            containers.forEach(c=>refreshMetric(c.id));
            fetchEmailAccounts();
        <?php endif; ?>
    </script>
</body>
</html>