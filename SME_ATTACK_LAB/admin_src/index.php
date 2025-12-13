<?php
session_start();

// === 설정 ===
$VAULT_ADDR = 'http://192.168.20.50:8200/v1/secret/data/'; // Vault 내부 주소 (docker-compose 네트워크 기준)

// Vault 토큰은 환경변수 VAULT_TOKEN 또는 FALLBACK 값 사용
$VAULT_TOKEN = getenv('VAULT_TOKEN') ?: getenv('VAULT_DEV_ROOT_TOKEN_ID') ?: 'my_root_token';

// 데모용 관리자 자격증명 (요구사항에 따라 고정)
$ADMIN_USER = 'admin';
$ADMIN_PW = 'qhdksdlchlrh';

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
        // POST로 전달된 자격 증명 처리
        $data = json_decode(file_get_contents('php://input'), true);
        $user = $data['user'] ?? '';
        $pw = $data['pw'] ?? '';
        if ($user === $ADMIN_USER && $pw === $ADMIN_PW) {
            $_SESSION['admin'] = $ADMIN_USER;
            echo json_encode(['ok' => true, 'user' => $ADMIN_USER]);
            exit;
        }
        echo json_encode(['ok' => false, 'error' => '인증 실패']);
        exit;
    }

    if ($action === 'logout') {
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
                <div class="small">로그인: <strong><?php echo htmlspecialchars($_SESSION['admin']); ?></strong></div>
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

        // 로그 출력
        function log(msg){ const a = document.getElementById('logArea'); a.innerHTML = `<div style="margin-bottom:8px">${new Date().toLocaleTimeString()} - ${msg}</div>` + a.innerHTML }

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
        <?php endif; ?>
    </script>
</body>
</html>