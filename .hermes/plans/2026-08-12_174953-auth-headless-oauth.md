# Headless OAuth Authentication Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** `gws-cli auth --headless`를 실행한 서버에서 웹브라우저를 열지 않고, 사용자가 다른 컴퓨터의 브라우저에서 Google 로그인을 완료한 뒤 전체 redirect URL을 터미널에 붙여넣어 Google OAuth token을 안전하게 발급·저장할 수 있게 한다.

**Architecture:** 기존 local OAuth의 loopback redirect, `state`, PKCE를 유지하되 headless 모드에서는 HTTP callback 서버와 로컬 브라우저를 사용하지 않는다. CLI가 authorization URL을 출력하고, 사용자가 브라우저에서 승인 후 주소창의 `http://127.0.0.1:<port>/?code=...&state=...` 전체 URL을 복사해 서버 터미널에 입력하면 `Flow.fetch_token(authorization_response=...)`으로 교환한다. 기존 브라우저 기반 `run_local_server()` 경로는 기본값으로 그대로 유지한다.

**Tech Stack:** Python 3.10+, Typer, `google-auth-oauthlib`, OAuth 2.0 Authorization Code + PKCE, pytest, Ruff, mypy

---

## 1. 조사 결론

### 현재 구현

- `src/gws/auth/oauth.py:122-164`의 `LocalAuthProvider._run_auth_flow()`는 `InstalledAppFlow.run_local_server()`를 사용한다.
- callback 서버는 `127.0.0.1:8080-8099` 중 사용 가능한 포트에 열리고, 동일 컴퓨터의 브라우저가 그 주소로 redirect 되어야 한다.
- 브라우저 실행이 불가능한 경우 URL은 출력되지만, 다른 컴퓨터에서 로그인하면 redirect의 `127.0.0.1`은 **브라우저가 실행된 컴퓨터**를 가리키므로 원격 서버의 callback listener로 연결되지 않는다.
- 별도의 relay-server 인증 모드는 이미 존재하며, `gws-cli auth server-login --device`도 지원한다. 그러나 이는 oauth-token-relay 서버를 배포·설정한 경우에만 사용할 수 있으며, local mode의 일반 사용자를 위한 해결책은 아니다.

### Google OAuth 제약

- Desktop application OAuth client는 loopback IP redirect를 지원한다.
- 과거의 OOB/manual copy-paste 방식(`urn:ietf:wg:oauth:2.0:oob`)은 폐지되어 새 기능에서 사용하면 안 된다.
- 제안 방식은 OOB redirect가 아니다. 정상적인 loopback redirect URI, authorization code, `state`, PKCE를 사용하며, 브라우저가 loopback 연결에 실패한 뒤 주소창에 남은 **전체 redirect URL**을 CLI가 전달받아 token endpoint와 교환한다.

### 구현 여부 판단

구현 가능하며 `--headless` 옵션 추가가 타당하다. 단, 다음 두 대안도 문서화한다.

1. **권장 기본:** `gws-cli auth --headless` + 전체 redirect URL 붙여넣기
2. **대안:** SSH local port forwarding으로 기존 callback server에 연결
3. **조직형 배포 대안:** 기존 oauth-token-relay server mode/device flow 사용

---

## 2. 범위와 비범위

### 포함 범위

- `gws-cli auth --headless`
- `gws-cli auth --headless -a <account>`
- local mode에서 브라우저 및 callback HTTP server 없이 인증
- server mode에서 `--headless`를 명시했을 때 자동 브라우저 실행 억제
- `--force`와 `--headless` 동시 사용
- 전체 redirect URL 입력 검증
- JSON 성공·오류 출력 및 기존 exit code 유지
- README, 개발 문서, CLI 도움말, 테스트 추가

### 제외 범위

- Google OOB redirect 복원
- Google client secret 또는 token을 다른 컴퓨터로 복사하는 기능
- 새 relay server 구현
- device authorization grant를 Google Workspace API local mode에 임의 적용
- 비대화형 CI에서 사용자 승인 없이 인증하는 기능
- service account 기반 인증 추가

---

## 3. 사용자 경험 및 수용 기준

### 명령

```bash
gws-cli auth --headless
gws-cli auth --headless --force
gws-cli auth --headless -a work
```

### 예상 흐름

1. CLI가 브라우저를 열지 않는다.
2. stderr에 authorization URL과 단계별 안내를 출력한다.
3. 사용자는 해당 URL을 다른 컴퓨터의 브라우저에서 연다.
4. Google 로그인과 동의를 완료한다.
5. 브라우저가 `http://127.0.0.1:<port>/?code=...&state=...`로 이동하며 연결 오류가 발생할 수 있음을 안내한다.
6. 사용자는 주소창의 **전체 URL**을 복사해 서버 터미널에 붙여넣는다.
7. CLI는 scheme, loopback host, port, `code`, `state`를 검증한다.
8. CLI는 token을 교환하고 기존 암호화 저장 경로에 저장한다.
9. stdout에는 기존 규격의 JSON 성공 결과가 출력된다.

### 필수 수용 기준

- 기본 `gws-cli auth` 동작은 기존과 동일하다.
- `--headless`에서는 `webbrowser.open()`과 `run_local_server()`가 호출되지 않는다.
- 입력 URL의 `state`가 발급 시 값과 다르면 token 교환 전에 실패한다.
- `http://127.0.0.1:<expected-port>/...` 또는 `http://[::1]:<expected-port>/...` 외 redirect URL은 거부한다.
- `code`가 없거나 OAuth `error`가 있으면 명확한 `AUTH_ERROR`를 반환한다.
- access/refresh token 및 authorization code를 로그·JSON 결과에 출력하지 않는다.
- 성공 token은 legacy 및 named-account 경로에 기존 방식대로 암호화 저장된다.
- 재인증, 계정 선택, read-only scope 계산이 기존과 동일하게 동작한다.

---

## 4. Git Flow 작업 전략

현재 저장소에는 `main`만 있고 `develop`이 없다. 구현 시작 시 다음 순서를 따른다.

```bash
git switch main
git pull --ff-only origin main
git switch -c develop
git push -u origin develop
git switch -c feature/headless-oauth-auth
```

- 기능 개발: `feature/headless-oauth-auth`
- 완료 후: `feature/headless-oauth-auth` → `develop` PR/merge
- 릴리스 준비 시: `release/<version>`을 `develop`에서 생성
- 릴리스 검증 후: `main`과 `develop`에 병합 및 tag
- 계획 작성 단계에서는 브랜치를 생성하거나 변경하지 않는다.

---

## 5. 상세 구현 계획

### Task 1: 개발 환경과 기준선 확립

**Objective:** 개발 의존성을 준비하고 변경 전 테스트·lint·type-check 기준선을 기록한다.

**Files:**
- No source changes
- Reference: `pyproject.toml`
- Reference: `TESTING.md`

**Step 1: Git Flow 브랜치 생성**

위 4절 명령으로 `develop`과 `feature/headless-oauth-auth`를 생성한다.

**Step 2: 개발 의존성 설치**

```bash
uv sync --extra dev
```

현재 조사 시 `uv run pytest`와 `uv run ruff`는 dev dependency가 설치되지 않아 `program not found`로 실행되지 않았다. 구현 전에 반드시 해결한다.

**Step 3: 기준선 실행**

```bash
uv run pytest -q
uv run ruff check .
uv run mypy src/
```

Expected: 기존 실패가 있다면 기능 작업과 무관한 실패를 별도로 기록하고, 신규 변경으로 악화시키지 않는다.

**Step 4: Commit**

환경 준비만으로 파일 변경이 없으면 commit하지 않는다.

---

### Task 2: LocalAuthProvider headless flow의 실패 테스트 작성

**Objective:** local mode headless 인증의 보안·동작 계약을 테스트로 먼저 고정한다.

**Files:**
- Create: `tests/test_headless_auth.py`
- Reference: `src/gws/auth/oauth.py`

**Step 1: provider fixture 작성**

- 임시 config/token 경로 사용
- `GWS_ENCRYPTION=none`으로 단위 테스트 격리
- encrypted client config load를 mock
- `InstalledAppFlow.from_client_config()`과 Flow 객체를 mock

**Step 2: 다음 failing tests 작성**

1. `headless=True`에서 `run_local_server()`를 호출하지 않음
2. `webbrowser.open()`을 호출하지 않음
3. authorization URL을 출력함
4. 전체 redirect URL 입력 시 `fetch_token(authorization_response=<url>)` 호출
5. 성공 시 `flow.credentials`를 provider에 설정하고 `_save_credentials()` 호출
6. `state` 불일치 시 `fetch_token()` 호출 전 `AuthError`
7. `code` 누락 시 `AuthError`
8. `error=access_denied` 입력 시 Google 오류를 비밀정보 없이 요약한 `AuthError`
9. 비-loopback host, HTTPS, 예상치 않은 port 거부
10. 빈 입력/EOF를 취소로 처리
11. 입력 URL·code·token을 출력하지 않음
12. 기본 모드에서는 기존 `run_local_server()` 경로 유지

**Step 3: 실패 확인**

```bash
uv run pytest tests/test_headless_auth.py -v
```

Expected: `--headless` 구현이 없어 관련 테스트가 FAIL.

**Step 4: Commit**

```bash
git add tests/test_headless_auth.py
git commit -m "test(auth): define headless OAuth flow behavior"
```

---

### Task 3: LocalAuthProvider에 안전한 headless OAuth flow 구현

**Objective:** callback HTTP server 없이 URL 출력 → redirect URL 입력 → token 교환을 구현한다.

**Files:**
- Modify: `src/gws/auth/oauth.py:19-170`
- Test: `tests/test_headless_auth.py`

**Step 1: 공개 호출 계약 확장**

다음 중 한 가지 일관된 형태를 사용한다.

```python
def get_credentials(
    self,
    force_refresh: bool = False,
    headless: bool = False,
) -> Credentials:
    ...
```

`headless`는 새 OAuth flow가 필요한 경우에만 영향을 미치며, 유효한 기존 token 로드와 refresh 동작은 바꾸지 않는다.

**Step 2: 일반 flow와 headless flow 분리**

```python
def _run_auth_flow(self, scopes: list[str], headless: bool = False) -> None:
    if headless:
        self._run_headless_auth_flow(scopes)
        return
    self._run_local_server_auth_flow(scopes)
```

기존 코드는 `_run_local_server_auth_flow()`로 이동하되 동작을 변경하지 않는다.

**Step 3: headless flow 생성**

- 기존 encrypted `client_config` 로드 재사용
- `_find_available_port()`로 redirect port 선택
- `InstalledAppFlow.from_client_config(..., scopes=scopes, autogenerate_code_verifier=True)` 사용 여부를 라이브러리 버전과 테스트로 확인
- `flow.redirect_uri = f"http://127.0.0.1:{port}/"`
- `authorization_url(prompt="consent" 필요 여부는 기존 refresh-token 회귀 테스트 후 결정)` 호출
- URL과 사용자 절차를 stderr에 출력
- `typer.prompt`에 결합하지 말고 auth layer에서는 `input()` 또는 주입 가능한 reader helper를 사용하여 단위 테스트 가능하게 구성
- 입력 전체 URL을 파싱·검증
- `flow.fetch_token(authorization_response=redirect_url)` 실행
- `flow.credentials`를 `_credentials`에 저장
- 기존 `_save_credentials()` 호출

**Step 4: redirect 검증 helper 추가**

예상 인터페이스:

```python
def _validate_headless_redirect(
    redirect_url: str,
    expected_redirect_uri: str,
    expected_state: str,
) -> None:
    ...
```

검증 사항:

- URL이 절대 URL인지
- scheme은 `http`
- hostname은 `127.0.0.1` 또는 `::1`
- port와 path가 발급한 redirect URI와 동일한지
- query의 `state`가 `secrets.compare_digest()`로 일치하는지
- `code`가 정확히 하나 존재하는지
- `error`가 있으면 교환 중단
- fragment나 중복 보안 파라미터는 거부

**Step 5: 예외 정규화**

- `OAuth2Error`, `ValueError`, malformed URL을 `AuthError`로 변환
- 상세 메시지에 full URL, code, token을 포함하지 않음
- retry가 필요한 경우 명령을 다시 실행하라는 안내 제공

**Step 6: 단위 테스트 통과**

```bash
uv run pytest tests/test_headless_auth.py -v
```

Expected: PASS.

**Step 7: Commit**

```bash
git add src/gws/auth/oauth.py tests/test_headless_auth.py
git commit -m "feat(auth): add local headless OAuth flow"
```

---

### Task 4: AuthProvider와 CLI에 `--headless` 연결

**Objective:** 사용자 옵션을 provider까지 전달하고 기존 CLI JSON 계약을 유지한다.

**Files:**
- Modify: `src/gws/commands/auth.py:24-78`
- Modify: `src/gws/auth/provider.py:13-44` if protocol signature changes
- Modify: `src/gws/auth/server.py:121-152,395-475` for explicit browser suppression in server mode
- Create or Modify: `tests/test_auth_commands.py`
- Modify: `tests/test_auth_provider.py` as needed

**Step 1: CLI failing tests 작성**

`CliRunner`와 mocked provider로 다음을 검증한다.

- `gws-cli auth --headless`가 provider에 `headless=True` 전달
- `--force --headless -a work` 조합 전달
- 성공 stdout JSON에 token/code가 없고 기존 `operation=auth` 유지
- `AuthError`는 exit code `AUTH_ERROR`와 기존 JSON error 형식 유지
- `auth --help`에 headless/SSH 설명 표시

**Step 2: Typer option 추가**

```python
headless: Annotated[
    bool,
    typer.Option(
        "--headless",
        help="Authenticate without opening a browser; paste the full loopback redirect URL.",
    ),
] = False,
```

`provider.get_credentials(force_refresh=force, headless=headless)`로 전달한다.

**Step 3: Provider protocol 정합성 유지**

- `AuthProvider.get_credentials()`에 `headless: bool = False` 추가
- `LocalAuthProvider`와 `ServerAuthProvider` 모두 동일 signature 제공
- 기존 positional/keyword 호출은 그대로 호환

**Step 4: Server mode 처리**

server mode는 이미 callback이 relay server에 도착하므로 원격 브라우저 사용이 가능하다. `headless=True`일 때는 URL만 출력하고 `webbrowser.open()`을 호출하지 않게 한다. server token 자동 login 경로에도 같은 의도를 전달할지 테스트로 고정한다.

**Step 5: 테스트 실행**

```bash
uv run pytest tests/test_auth_commands.py tests/test_auth_provider.py tests/test_server_auth.py -v
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src/gws/commands/auth.py src/gws/auth/provider.py src/gws/auth/server.py tests/
git commit -m "feat(cli): expose headless authentication option"
```

---

### Task 5: 계정 명령과 자동 인증 경로의 일관성 검토

**Objective:** named account와 `account add` 흐름에서 headless 인증을 명확히 지원한다.

**Files:**
- Modify: `src/gws/commands/account.py:15-95` only if `account add --headless` is included
- Modify: `tests/test_account_commands.py`
- Modify: CLI help/docs

**Decision:** 최소 요구사항은 `account add work --no-auth` 후 `gws-cli auth --headless -a work`로 충족된다. YAGNI 원칙상 `account add --headless`는 필수는 아니다.

**Step 1: 최소 경로 테스트**

- `account add work --no-auth`
- `auth --headless -a work`
- account-specific token path에 저장

**Step 2: UX 판단**

반복 사용성이 충분히 높다고 판단될 때만 `account add --headless`를 추가한다. 추가한다면 `resolve_auth_provider(...).get_credentials(headless=True)`로 동일 구현을 재사용하고 별도 OAuth 코드를 만들지 않는다.

**Step 3: Tests**

```bash
uv run pytest tests/test_auth_accounts.py tests/test_account_commands.py -v
```

**Step 4: Commit**

```bash
git add src/gws/commands/account.py tests/test_account_commands.py
git commit -m "feat(account): support headless account authentication"
```

파일 변경이 없으면 commit하지 않는다.

---

### Task 6: 문서와 도움말 갱신

**Objective:** 사용자가 headless 인증, SSH tunnel, relay mode의 차이를 이해하고 안전하게 실행할 수 있게 한다.

**Files:**
- Modify: `README.md:62-85,136-168,185-198`
- Modify: `CLAUDE.md:109-182,202-229`
- Modify: `SKILL.md` authentication section
- Modify: `TESTING.md` if auth test procedure is documented there
- Modify: `LIVE_TESTING.md` only after actual live test

**Step 1: README에 Headless/SSH 섹션 추가**

포함 예시:

```bash
# Headless server
uvx gws-cli auth --headless

# Named account
uvx gws-cli auth --headless -a work
```

반드시 다음을 설명한다.

- redirect 연결 실패 화면은 예상 가능한 동작
- 주소창의 전체 URL을 복사해야 함
- URL에는 일회용 authorization code가 있으므로 채팅·로그·이메일로 공유하지 말 것
- CLI가 실행 중인 동일 터미널에만 즉시 붙여넣을 것
- OOB가 아니라 loopback + PKCE 방식임
- redirect URL/code는 짧은 시간 내 1회만 사용 가능

**Step 2: 대안 문서화**

- SSH port forwarding 예시
- oauth-token-relay server/device flow가 적절한 조직 배포 시나리오
- service account와 사용자 OAuth의 차이

**Step 3: 도움말 snapshot/문자열 테스트**

```bash
uv run gws-cli auth --help
```

Expected: `--headless` 설명 확인.

**Step 4: Commit**

```bash
git add README.md CLAUDE.md SKILL.md TESTING.md
git commit -m "docs(auth): document headless OAuth workflow"
```

---

### Task 7: 전체 품질·보안 검증

**Objective:** 기능·회귀·보안 검증을 완료한다.

**Files:**
- Modify tests only for genuine gaps

**Step 1: 전체 단위 테스트**

```bash
uv run pytest -q
```

Expected: all tests pass.

**Step 2: 정적 검사**

```bash
uv run ruff check .
uv run mypy src/
```

Expected: no new errors.

**Step 3: 패키지와 CLI smoke test**

```bash
uv build
uv run gws-cli auth --help
uv run gws-cli auth status
```

Expected: wheel/sdist build 성공, 도움말에 옵션 표시, status는 대화형 auth를 시작하지 않음.

**Step 4: 비밀정보 유출 검사**

테스트 capture output과 코드 검색으로 다음이 출력되지 않는지 확인한다.

- authorization code
- access token
- refresh token
- client secret
- 전체 pasted redirect URL

**Step 5: Commit**

테스트 보완이 있을 때만:

```bash
git add tests/
git commit -m "test(auth): cover headless OAuth security edge cases"
```

---

### Task 8: 실제 headless 환경 통합 테스트

**Objective:** 실제 Google Desktop OAuth client와 원격/격리 환경에서 end-to-end 동작을 검증한다.

**Files:**
- Modify: `LIVE_TESTING.md`

**Prerequisite:** 테스트 계정과 사용자가 승인한 OAuth client를 사용한다. 실제 token이나 계정 식별자는 문서·commit에 남기지 않는다.

**Step 1: 격리된 HOME 사용**

임시 VM/container/SSH 서버에서 별도 config directory로 테스트한다.

**Step 2: credentials import**

```bash
gws-cli auth import-credentials /secure/path/client_secret.json
gws-cli auth --headless
```

**Step 3: 별도 PC 브라우저 승인**

- URL을 로컬 브라우저에서 열기
- 승인 후 loopback 연결 실패 확인
- 전체 redirect URL을 서버 터미널에 직접 붙여넣기

**Step 4: 상태·API 검증**

```bash
gws-cli auth status
gws-cli drive list --max 1
```

Expected: token valid, 허용 scope 내 API 1회 조회 성공.

**Step 5: 회귀 테스트**

브라우저가 있는 컴퓨터에서 기존 명령 실행:

```bash
gws-cli auth --force
```

Expected: 기존 자동 브라우저 + callback server 방식 성공.

**Step 6: 부정 테스트**

- 잘못된 state URL
- 만료/재사용 code
- 사용자가 동의를 거부한 URL
- 잘못된 host/port
- Ctrl-D/빈 입력

Expected: token 미저장, 안전한 오류, exit code 1.

**Step 7: LIVE_TESTING 갱신**

민감정보 없이 날짜, 명령 형태, PASS/FAIL, 제한사항만 기록한다.

**Step 8: Commit**

```bash
git add LIVE_TESTING.md
git commit -m "test(auth): record live headless OAuth validation"
```

---

### Task 9: 리뷰와 Git Flow 통합

**Objective:** spec, 보안, 코드 품질을 검토하고 `develop`에 통합한다.

**Step 1: Diff review**

```bash
git diff develop...feature/headless-oauth-auth
```

**Step 2: 사전 코드 리뷰**

- OAuth state/PKCE 검증
- redirect URI 검증
- secret redaction
- backward compatibility
- account-specific path
- server mode 회귀
- exception/exit code 일관성

**Step 3: 최종 검증 재실행**

```bash
uv run pytest -q
uv run ruff check .
uv run mypy src/
uv build
```

**Step 4: PR**

`feature/headless-oauth-auth` → `develop` PR을 생성한다. PR 설명에 다음을 포함한다.

- 문제와 headless 사용자 흐름
- OOB를 사용하지 않는다는 점
- 보안 검증(state, PKCE, loopback URL)
- 자동/수동 테스트 결과
- 알려진 제한사항

---

## 6. 예상 변경 파일

| 파일 | 예상 변경 |
|---|---|
| `src/gws/auth/oauth.py` | local headless authorization flow, redirect URL 검증 |
| `src/gws/auth/provider.py` | `headless` 호출 계약 정합성 |
| `src/gws/auth/server.py` | server mode에서 명시적 browser suppression |
| `src/gws/commands/auth.py` | `--headless` Typer 옵션과 전달 |
| `src/gws/commands/account.py` | 선택적으로 `account add --headless` 연결 |
| `tests/test_headless_auth.py` | 신규 core/security tests |
| `tests/test_auth_commands.py` | CLI 옵션 및 JSON contract tests |
| `tests/test_auth_provider.py` | provider signature/dispatch 회귀 |
| `tests/test_server_auth.py` | server headless browser suppression 회귀 |
| `tests/test_auth_accounts.py` | named account token path 통합 |
| `README.md` | 사용자용 headless 인증 문서 |
| `CLAUDE.md` | 개발자용 OAuth 구조 갱신 |
| `SKILL.md` | 에이전트 사용 지침 갱신 |
| `LIVE_TESTING.md` | 실제 Google 통합 테스트 기록 |

---

## 7. 위험, 트레이드오프 및 완화책

### 7.1 Authorization code 노출

- redirect URL에는 일회용 code가 포함된다.
- 완화: 직접 터미널에만 붙여넣도록 안내하고, CLI는 입력값을 echo/log/JSON에 재출력하지 않는다. state+PKCE로 탈취 위험을 줄인다.

### 7.2 브라우저별 주소창 동작 차이

- 연결 실패 시 일부 브라우저가 URL을 축약하거나 error page로 바꿀 수 있다.
- 완화: Chrome/Firefox/Safari 실제 검증, SSH tunnel 및 relay mode 대안 문서화.

### 7.3 OOB 정책 오해

- manual paste라는 UX 때문에 OOB처럼 보일 수 있다.
- 완화: redirect URI는 정상 loopback URI이며 `urn:ietf:wg:oauth:2.0:oob`를 절대 사용하지 않는다는 것을 코드·문서·테스트로 명시한다.

### 7.4 Refresh token 미발급

- 기존 grant가 있거나 consent parameter에 따라 refresh token이 반환되지 않을 수 있다.
- 완화: 기존 `access_type=offline` 유지, `--force` 재동의 동작과 `prompt=consent` 필요성을 live test에서 확인하되 무조건 강제해 UX를 악화시키지 않는다.

### 7.5 Provider API 변경 회귀

- `get_credentials()` signature 변경이 서비스·account·server mode에 영향을 줄 수 있다.
- 완화: 기본값 `False`, keyword 전달, protocol과 두 provider를 동시에 변경, 전체 테스트 실행.

### 7.6 Port와 redirect 검증

- authorization URL 생성 후 다른 host/port URL을 받아들이면 code injection 또는 state 혼동 위험이 있다.
- 완화: expected redirect URI와 exact scheme/host/port/path 비교, state constant-time comparison.

---

## 8. 열린 질문 및 구현 시 결정 기준

1. **`account add --headless`를 함께 제공할지:** 최소 범위에서는 `--no-auth` 후 `auth --headless -a`로 충분하다. UX 이득이 명확할 때만 추가한다.
2. **IPv6 loopback 지원:** 첫 버전은 생성 URI를 `127.0.0.1`로 고정하고 입력도 exact match하는 것이 가장 단순하다. 기존/향후 IPv6 생성이 필요할 때만 `::1`을 허용한다.
3. **입력 재시도 횟수:** malformed URL은 1회 즉시 실패가 scripting에 명확하다. 사용자 편의를 위해 재입력을 허용하더라도 횟수 제한과 취소 방법을 둔다.
4. **server mode의 `--headless`:** local mode와 UX를 맞추기 위해 browser open 억제를 적용하되, relay 자체 callback/polling은 그대로 유지한다.
5. **timeout:** headless local paste flow는 callback server가 없으므로 blocking input timeout 구현이 플랫폼별로 복잡하다. 첫 버전은 Ctrl-C/EOF 취소를 제공하고, timeout은 YAGNI 원칙상 제외하는 것이 안전하다.

---

## 9. 완료 정의

- [ ] Git Flow의 `feature/headless-oauth-auth`에서 개발됨
- [ ] `gws-cli auth --headless`가 local mode에서 브라우저/callback server 없이 동작함
- [ ] named account와 `--force` 조합이 동작함
- [ ] state, PKCE, loopback URI 검증이 테스트됨
- [ ] secret/code/redirect URL이 출력에 유출되지 않음
- [ ] 기존 `gws-cli auth` 동작이 회귀하지 않음
- [ ] server mode가 회귀하지 않음
- [ ] unit/integration tests, Ruff, mypy, build가 통과함
- [ ] 실제 headless server에서 Google OAuth end-to-end 검증됨
- [ ] README/SKILL/개발 문서와 LIVE_TESTING이 갱신됨
- [ ] feature branch가 review 후 `develop`에 통합됨
