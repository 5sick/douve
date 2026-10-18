# 비상 출입구 — 문제가 생겼을 때 다시 들어가는 법

Douve로 SSH(22번)를 닫으면 "Douve가 망가지면 어떻게 들어가지?"가 가장 중요한 질문이 됩니다.
설치 직후 아래 세 가지를 해 두세요.

1. **복구 코드 보관** — 설치 끝에 나온 10개(또는 계정 → 복구 코드 → 새로 만들기)를 서버 밖(비밀번호 관리자, 종이)에.
2. **패스키 두 개 이상** — 휴대폰과 노트북처럼 서로 다른 기기에 (계정 → 패스키 추가).
3. **백업을 서버 밖으로** — Hub가 매일 `/var/lib/douve/backups/auto-YYYYMMDD.db`를 만들고 7개를 남깁니다.
   서버 자체를 잃는 경우를 대비해 가끔 `sudo douve-hub backup`으로 만든 파일을 다른 곳에 복사하세요.
   백업에는 비밀(Agent 키, 세션, 알림 토큰)이 들어 있으니 안전하게 보관하세요.

그리고 **서버에 들어가는 Douve 밖의 길을 하나는 알아 두세요**:
클라우드 콘솔의 직렬 콘솔(OCI "Cloud Shell/Console connection", AWS "EC2 Serial Console", Hetzner "Console" 등),
또는 WireGuard/Tailscale 같은 사설망을 통한 SSH. 공개 22번을 닫는 것은 이 길이 있을 때만 권합니다.

## 상황별

### 패스키 기기를 잃어버렸다 (Hub는 정상)
로그인 화면 → **"패스키를 잃어버렸나요? 복구 코드로 로그인"** → 코드 하나 입력.
로그인 직후 몇 분 동안은 본인 확인이 된 상태라 바로 **패스키 추가**를 할 수 있습니다.
잃어버린 기기의 패스키는 계정 화면에서 삭제하고, 남은 코드가 적으면 새로 만드세요.
복구 코드로 로그인하면 텔레그램으로 알림이 갑니다 — 본인이 아니면 즉시 코드를 새로 만들고 다른 기기를 로그아웃하세요.

### 다시 로그인은 되는데 터미널이 "모르는 패스키"라고 한다
서버는 터미널 신뢰 목록에 있는 패스키만 믿고, 목록을 바꾸려면 서버들이 이미 믿는 관리자 패스키가 필요합니다.
새 패스키는 서버 화면에 "승인 대기 변경"으로 보이니 예전 관리자 패스키로 승인하세요. 서버들이 믿는 관리자
패스키가 하나도 남지 않았다면(전부 잃음) 서버마다 클라우드 콘솔이나 사설망 SSH로 들어가 목록을 지우세요.
다음에 Hub가 보내는 목록을 처음처럼 받습니다:
```sh
sudo douve-agent terminal-trust reset && sudo systemctl restart douve-agent
```

### 복구 코드도 없다 (Hub 서버에 셸로 들어갈 수 있음)
```sh
sudo douve-hub invite --email 나@example.com          # 새 패스키 등록 링크 (24시간)
sudo douve-hub recovery-codes --email 나@example.com  # 복구 코드 새로 (이전 코드 무효)
```
셸은 클라우드 콘솔이나 사설망 SSH로 들어갑니다. 다른 서버의 Douve 웹 터미널은 Hub가 살아 있어야 쓸 수 있습니다.

### Hub가 응답하지 않는다
- 공개(로그인 없음)로 둔 서비스는 입구가 마지막 라우팅 표로 계속 서비스합니다 (입구 재시작 뒤에도).
- Douve 로그인이 필요한 서비스는 안전을 위해 막히고 "로그인 서버에 연결할 수 없습니다"가 보입니다.
- Hub 서버에 들어가서: `systemctl status douve-hub`, `journalctl -u douve-hub -n 100`, `systemctl restart douve-hub`.
- DB가 망가졌다면 자동 백업으로 되돌립니다 (아래 "복원").

### Hub 서버를 통째로 잃었다
새 서버에 Douve 실행 파일을 설치한 뒤(설치기의 1~2단계 또는 릴리스에서 douve-hub만 받아서):
```sh
sudo douve-hub install-service
sudo douve-hub restore douve-backup-....db     # 설정(hub.json)과 DB를 함께 복원
sudo systemctl daemon-reload && sudo systemctl enable --now douve-hub
```
그다음 DNS(또는 Tailscale 이름)가 새 서버를 가리키게 하면, 다른 서버들의 Agent는 같은 주소로 알아서 다시 접속합니다
(Agent 키는 백업 안의 DB에 있으므로 다시 등록할 필요 없음). 입구도 새 서버라면 Douve → 서버 → 입구로 지정.

### 복원
```sh
sudo systemctl stop douve-hub
sudo douve-hub restore /var/lib/douve/backups/auto-20261006.db   # 기존 DB·설정은 *.before-restore-<시각>으로 남음
sudo systemctl start douve-hub
```
설정은 그대로 두고 DB만 되돌리려면 `--keep-config`.

### 입구(edge) 서버가 죽었다
공개 IP가 있는 다른 서버를 Douve → 서버 → **입구로 지정**하고 DNS를 그 서버로 바꿉니다.
인증서는 새 입구가 자동으로 받습니다.
