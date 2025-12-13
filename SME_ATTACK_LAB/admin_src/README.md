관리자 포털 (데모)

이 페이지는 데모용 정적 관리자 포털입니다. 주요 기능:

- 초기 로그인: 아이디/비밀번호로 로그인
- 컨테이너 목록: docker-compose.yml에 정의된 서비스별 카드 표시
- 성능 지표: 시뮬레이션된 CPU/MEM/응답 시간 표시
- 컨테이너 접근키: 컨테이너별 접근 토큰을 관리자 비밀번호로 암호화하여 localStorage에 저장

로컬 실행 방법

1. 프로젝트 루트로 이동
2. docker-compose.yml이 있는 경우 다음 명령으로 컨테이너를 올립니다:

```bash
docker-compose up -d
```

3. 브라우저에서 http://localhost:8003 로 접속하면 관리자 포털을 확인할 수 있습니다.

보안 주의사항

- 이 구현은 교육/시연용입니다. 클라이언트측에 관리자 비밀번호를 sessionStorage에 평문으로 저장합니다. 실제 서비스에서는 절대 금지됩니다.
- 키 관리와 인증은 서버사이드에서 안전하게 처리해야 합니다.
- AES-GCM 키 유도 파라미터(반복 횟수, 솔트 관리)를 실환경 기준으로 적절히 조정하세요.

빠른 동작 확인

1. 브라우저에서 http://localhost:8003 로 접속
2. '데모 정보 채우기' 버튼을 눌러 아이디: admin, 비밀번호: demo1234를 입력 후 로그인
3. 컨테이너 목록이 표시되면 '지표 갱신' 또는 각 컨테이너의 '지표 갱신' 버튼을 눌러 값이 바뀌는지 확인
4. '접속' 버튼을 누르면 컨테이너별 접근 키가 생성(또는 복호화)되어 알림으로 표시됩니다.

Inspect(실제/시뮬레이션) 및 파일 조회

- 데모 환경에서는 `inspect`와 `get_file` 액션이 시뮬레이션 데이터를 반환합니다.
- 실제 Docker 컨테이너의 `docker inspect` 결과와 파일을 보려면 웹 컨테이너에 Docker 소켓을 마운트해야 합니다.

예: `docker-compose.yml` 수정 (admin_entry 서비스에 아래 volume 추가)

```yaml
		admin_entry:
			image: php:7.4-apache
			volumes:
				- ./admin_src:/var/www/html
				- /var/run/docker.sock:/var/run/docker.sock:ro
```

그런 다음 `docker-compose up -d`로 재시작하면, 로그인 후 '접속' 버튼으로 실제 `docker inspect <container>` 결과를 반환하려 시도합니다. 또한 `?action=get_file&client=<name>&path=<file>`로 컨테이너 내부 파일을 `docker exec <container> cat <file>`로 읽어오도록 시도합니다.

보안 경고: Docker 소켓을 마운트하면 호스트 루트 권한에 준하는 권한이 컨테이너에 부여됩니다. 절대로 신뢰할 수 없는 코드를 통해 소켓을 노출하지 마세요.

요구사항 대비표

- 디자인 개선: Done
- 초기 로그인(아이디/비밀번호): Done
- 컨테이너별 관리 UI: Done (정적 목록 및 시뮬레이션)
- 컨테이너별 암호화 키 생성/복호화: Done (클라이언트측 AES-GCM 시뮬레이션)

비고: 이 구현은 데모 목적으로 클라이언트 측에서 키를 생성 및 암호화/복호화합니다. 운영환경에서는 서버측 키 관리(예: Hashicorp Vault)와 TLS/인증 토큰 기반의 접근 제어를 반드시 사용하세요.
