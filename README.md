# Ticket-Based Secure LLM Agent

사용자의 자연어 지시를 작업 계획으로 분석하고, 정책에 따라 발급한 Capability Ticket으로 도구 실행을 제한하는 프로젝트입니다.

현재는 **지시 해석, 권한 판단·티켓 발급, Worker 실행, 결과 평가**를 연결한 단일 프로세스 구현입니다.
특정 작업으로 범위를 한정하지 않습니다. 도구는 운영자가 등록하며, 기본 등록 목록은 비어 있습니다.
LLM은 OpenAI 호환 Chat Completions 엔드포인트에 연결합니다. 실제 Qwen 서버 검증은 아직 하지 않았습니다.

## 파일 구성

```text
SecureAgent/
├── README.md       # DFD, 통신 용어, 데이터 계약
├── main.py         # Entrypoint: 사용자 지시 입력
└── src/
    ├── core.py     # UserInstruction, ConversationHistory, TaskPlan
    └── logging.py  # 공통 로그 구조와 레벨 가이드 (아직 미연결)
```

## DFD: 전체 시스템의 논리적 데이터 흐름

E는 외부 주체, P는 처리 단위, D는 데이터 저장소, F는 이름이 붙은 데이터 흐름입니다.
아래는 설계이며 현재 실행 가능한 컴포넌트 목록이 아닙니다.

```text
[E1 User]
  │ 새 사용자 메시지 / 복원할 대화 JSONL
  ▼
(P1 Entrypoint)
  │ F1 UserInstruction（턴마다 1개）
  ▼
(P2 Instruction Analyzer)
  │ F2 TaskPlan
  ▼
(P3 Policy Engine) ◀── PolicyConfiguration ── || D1 Policy Store ||
  │ F3 PolicyDecision
  ▼
(P4 Ticket Issuer) ── F4 CapabilityTicket ──▶ || D2 Ticket Store ||
  │ F5 ExecutionAssignment
  ▼
(P5 Worker)
  │ F6 ToolCallRequest
  ▼
(P6 Function Call Gateway) ◀── F4 CapabilityTicket ── || D2 Ticket Store ||
  │ F7 AuthorizedToolCall（검증 통과 시에만）
  ▼
(P7 Tool Executor) ◀── 도구별 요청·응답 ──▶ [E2 Sandbox / External API]
  │ F8 ToolExecutionResult
  ▼
(P6 Function Call Gateway)
  │ F9 ToolCallResponse（실행 결과 또는 거부 사유）
  ▼
(P5 Worker)
  │ F10 AgentResponse
  ▼
(P1 Entrypoint) ── 최종 응답 ──▶ [E1 User]

P2~P7 ── F11 AuditEvent ──▶ (P8 Audit Logger) ──▶ || D3 Audit Store ||

P1 ── UserInstruction 기록 ──▶ || D4 ConversationHistory（세션별）||
P1 ── Managed Prompt 초기 설정 ──▶ || D4 ConversationHistory ||
P2/P5 ── assistant·도구 호출·결과 기록 ──▶ || D4 ConversationHistory ||
|| D4 ConversationHistory || ── 세션 이력 조회 ──▶ P2/P5
```

## 통신 용어

| 흐름 | 송신 → 수신 | 데이터 이름 | 의미 |
|---|---|---|---|
| F1 | Entrypoint → Instruction Analyzer | `UserInstruction` | 이번 사용자 턴: 세션·턴 식별자, 지시 원문, 조합된 작업 식별자 |
| F2 | Instruction Analyzer → Policy Engine | `TaskPlan` | 목표, 작업 단계, 요청 Role·도구·리소스. 아직 실행 권한이 없는 분석 결과 |
| F3 | Policy Engine → Ticket Issuer | `PolicyDecision` | 허용·거부 결정, 실제 허용 범위, 제약과 사유. 심사한 계획을 함께 전달하며, 거부된 경우 티켓 발급 금지 |
| F4 | Ticket Issuer → Ticket Store; Ticket Store → Gateway | `CapabilityTicket` | 서버에 저장하는 권한 원본. 사용자·세션·작업 바인딩, 허용 범위, 만료, 횟수, 승인 상태, 정책 버전 |
| F5 | Ticket Issuer → Worker | `ExecutionAssignment` | 실행하도록 확정한 계획과 발급된 티켓의 식별자 |
| F6 | Worker → Gateway | `ToolCallRequest` | 티켓 식별자, 작업·단계 식별자, 도구 이름, 호출 인자. Worker가 제안한 호출 |
| F7 | Gateway → Tool Executor | `AuthorizedToolCall` | 서버 티켓과 정책으로 검증을 통과한 호출. Worker가 직접 전달할 수 없음 |
| F8 | Tool Executor → Gateway | `ToolExecutionResult` | 실제 도구의 성공·실패와 반환 데이터 |
| F9 | Gateway → Worker | `ToolCallResponse` | 검증 거부 또는 도구 실행 결과를 구분한 응답 |
| F10 | Worker → Entrypoint | `AgentResponse` | 사용자에게 반환할 최종 작업 응답 |
| F11 | 각 처리 단위 → Audit Logger | `AuditEvent` | 작업·티켓·호출 식별자와 처리 결과에 대한 감사 기록 |

인증된 사용자·세션 정보는 신뢰된 실행 환경이 제공하는 `ExecutionContext`로 구분합니다.
JSONL의 `session_id`는 대화 식별용 입력이며 그 자체로 인증을 증명하지 않습니다.
사용자 지시문이나 모델 출력에서 인증 정보를 추출하여 신뢰하지 않습니다.
Policy Engine은 이 실행 문맥과 Policy Store를 사용하고, Gateway도 호출의 바인딩을 검사합니다.
외부 문서와 도구 응답은 F8/F9의 데이터이며 F1의 새 사용자 지시나 정책 변경으로 취급하지 않습니다.

## 이번 단계에서 코드로 정의하는 계약

F1, F2와 세션별 `ConversationHistory`를 정의합니다. 나머지 계약의 필드와 처리 로직은 해당 단계 구현 시 구체화합니다.

### F1: UserInstruction

| 필드 | 타입 | 생성 주체 | 의미 |
|---|---|---|---|
| `session_id` | `str` | Entrypoint / 복원한 이력 | 새 대화·fork에서 UUID 생성, 일반 복원에서는 기존 ID 유지 |
| `turn_id` | `int` | Entrypoint / 복원한 이력 | 세션 안의 사용자 턴 번호. 새 메시지는 기존 최대 사용자 턴 번호 + 1 |
| `task_id` | `str` | UserInstruction에서 계산 | `session_id:turn_id` 형식. 별도로 입력받거나 무작위 생성하지 않음 |
| `text` | `str` | User | 이번 사용자 턴의 자연어 지시 원문 |

`UserInstruction.from_jsonl()`은 전체 입력을 하나의 text로 합치지 않고, 각 JSON 객체를
한 턴의 `UserInstruction`으로 변환하는 iterator입니다. 같은 세션의 여러 턴과 서로 다른 세션을
입력 순서대로 처리합니다. 턴 번호는 입력 생산자가 부여하며 파서가 재번호화하지 않습니다.
동일한 세션·턴 쌍은 동일한 task_id를 만듭니다. 중복 실행 방지는 향후 런타임의 책임입니다.
사용자 턴 안에서 반복되는 Worker의 도구 호출은 새 사용자 턴이 아니므로 같은 task_id를 유지합니다.

### ConversationHistory: 세션에 누적된 대화 이력

`UserInstruction`은 이번 턴의 새 입력이고, `ConversationHistory`는 해당 세션의 누적 기록입니다.
현재 입력도 `add_user()`로 이력에 한 번 추가합니다. 이후 컨텍스트를 구성할 때 이력에 이미
들어간 현재 입력을 다시 중복 추가하지 않아야 합니다.

| 구간 | 기록 방법 | 기록 내용 |
|---|---|---|
| Entrypoint → 이력 | `add_managed_prompt(text)` | 새 대화 첫 위치의 에이전트 Managed Prompt |
| Entrypoint → 이력 | `add_user(instruction)` | 사용자 턴과 원문 |
| Analyzer/Worker → 이력 | `add_assistant(turn_id, text)` | 해당 턴에서 생성된 assistant 메시지 |
| Worker → 이력 | `add_tool_call(turn_id, call_id, tool_name, arguments)` | 모델이 요청한 도구 호출. 실행 승인을 뜻하지 않음 |
| Gateway 응답을 받은 Worker → 이력 | `add_tool_result(turn_id, call_id, content, is_error=...)` | 호출 결과 또는 오류·거부 내용 |
| 이력 → 조회자 | `entries` | 발생 순서대로 보관된 기록의 복사본 |

각 `ConversationEntry`는 `turn_id`와 `kind`를 가지며, 메시지는 `content`, 도구 호출은
`call_id`·`tool_name`·`arguments`, 도구 결과는 `call_id`·`content`·`is_error`를 사용합니다.
도구 결과의 content는 문자열로 보관하며 구조화된 결과는 JSON 문자열로 표현할 수 있습니다.
세션 ID는 이력 객체에 있으며 각 기록의 task_id는 `history.session_id:entry.turn_id`로 연결됩니다.
기록은 턴 번호로 재정렬하지 않고 추가된 순서를 유지합니다.
Managed Prompt는 `kind="managed"`, `turn_id=null`이며 사용자 작업이 아니므로 task_id도 null입니다.
Managed Prompt가 있으면 기록 순서는 1번 Managed Prompt, 2번 첫 사용자 입력입니다.
사용자 턴 번호와 기록 순서는 구분하며, 첫 사용자 입력의 turn_id는 1입니다.

다른 세션의 입력, 중복 사용자 턴, 중복 호출 ID, 대응하는 호출이 없는 결과와 중복 결과를 거부합니다.
도구 호출은 같은 사용자 턴 안에서 여러 번 발생할 수 있으며 `call_id`로 구별합니다.

```python
history = ConversationHistory(session_id="s1")
history.add_user(UserInstruction(session_id="s1", turn_id=1, text="첫 번째 요청"))
history.add_assistant(turn_id=1, text="첫 번째 답변")
history.add_user(UserInstruction(session_id="s1", turn_id=2, text="이전 답변에 대한 후속 요청"))
```

`to_jsonl()`은 Managed Prompt·사용자·assistant·도구 호출·결과를 순서대로 내보냅니다.
`ConversationHistory.from_jsonl()`은 한 세션의 전체 이력을 복원합니다. 기존 사용자 입력 전용
`session_id`, `turn_id`, `text` 형식도 읽을 수 있습니다. 여러 세션이 섞인 대화 파일은 거부합니다.
`UserInstruction.from_jsonl()`은 기존 사용자 입력 스트림용 함수로 유지하며 전체 이력 복원과 구별합니다.

`fork()`는 이력과 도구 호출·결과 연결을 독립적으로 복사하고 새 UUID 세션 ID를 부여합니다.
기존 turn_id와 call_id는 유지하고, task_id는 새 세션 ID와 기존 turn_id의 조합으로 출력합니다.
이는 대화 맥락만 복사하며 도구를 다시 실행하거나 과거 권한·티켓을 재발급하지 않습니다.
원본 메모리 이력과 입력 파일은 변경하지 않습니다.

자동 저장은 하지 않습니다. CLI의 JSONL 출력을 저장해 다음 실행에서 복원할 수 있습니다.
별도의 `LLMRequest`·`LLMResponse` 클래스는 추가하지 않았습니다.
`call_llm()`이 OpenAI 호환 메시지 객체를 받고 응답 메시지 객체를 반환합니다.

### F2: TaskPlan

| 필드 | 타입 | 생성 주체 | 의미 |
|---|---|---|---|
| `task_id` | `str` | Analyzer가 F1에서 보존 | 어떤 사용자 지시를 분석한 계획인지 연결 |
| `objective` | `str` | Analyzer | 분석한 작업 목표 |
| `steps` | `tuple[PlannedStep, ...]` | Analyzer | 수행 순서대로 나열한 작업 단계 |
| `clarification_questions` | `tuple[str, ...]` | Analyzer | 계획 확정 전에 해소해야 할 질문. 남아 있으면 실행 계획으로 확정하지 않음 |

`PlannedStep`은 별도 통신 메시지가 아니라 `TaskPlan`에 포함되는 항목입니다.

| 필드 | 타입 | 의미 |
|---|---|---|
| `step_id` | `str` | 계획 안의 단계 식별자 |
| `description` | `str` | 해당 단계에서 수행하려는 일 |
| `requested_tool` | `str` | 정책에 심사를 요청하는 도구 이름 |
| `requested_resources` | `tuple[str, ...]` | 해당 도구로 접근하려는 리소스 식별자 목록 |

리소스는 파일 경로로 고정하지 않습니다. 구체적인 형식과 유효성 검사는 도구별 정책에서 정의합니다.
계획의 도구·리소스 요청과 실제 Function Calling 인자는 구분합니다. 실행 인자는 F6에서 다룹니다.
`frozen=True`와 tuple은 데이터 재할당·변경을 줄이기 위한 구조이며 권한 검증 수단은 아닙니다.
Analyzer의 JSON을 검증한 뒤 권한 요청을 `TaskPlan`으로 구성합니다.
현재 단계 목록은 도구별 권한 요청 단위이며, 전체 작업을 세밀하게 분해하는 스케줄러는 아닙니다.
도구 없이 대화에 응답하는 작업은 빈 steps로 표현합니다.

## 현재 실행 범위

`main()`이 새 메시지로 `UserInstruction`을 만들고 `process_turn()`을 호출합니다.
입력의 이력 추가는 `process_turn()`에서 한 번만 수행합니다.

```text
사용자 입력 → 이력에 추가
                  ↓
          ANALYZE: 지시 해석
                  ↓
          AUTHORIZE: 권한 판단·티켓 발급
                  ↓
          EXECUTE: Worker 실행
                  ↓
          EVALUATE: 결과 평가
             ├─ 완료 → COMPLETED
             ├─ 실행 부족 → EXECUTE
             ├─ 권한 재심사 필요 → AUTHORIZE
             └─ 지시 재검토 필요 → ANALYZE

각 단계 → 질문 필요 / 취소 / 실패 → 응답 반환
반복 한도 도달 → LIMIT_REACHED
```

바깥쪽 `while`문은 `TurnState`를 보고 해당 `TurnStages` 메서드를 호출합니다.
각 메서드는 `StageResult(next_state, message)`로 다음 단계나 종료 상태를 돌려줍니다.
지시 해석은 추가 맥락 확인을 위해 자기 단계로 돌아갈 수 있습니다.
일반 대화 응답도 빈 권한 티켓을 발급받아 Worker가 답변하고 결과 평가를 거칩니다.
지시·권한 재검토는 결과 평가의 판정으로 요청합니다.
완료 상태는 결과 평가에서만 반환할 수 있고, 지시 해석에서 Worker 실행으로 바로 건너뛸 수는 없습니다.

| 데이터 | 전달 구간 | 역할 |
|---|---|---|
| `TurnContext` | process_turn → 각 단계 | 이번 입력, 이력, 분석 결과, 티켓, 작업 결과, 직전 단계의 피드백 |
| `StageResult` | 각 단계 → process_turn | 다음 단계와 재진입 이유 또는 사용자에게 전달할 메시지 |
| `TurnResult` | process_turn → main | task_id, 종료 상태, 사용자 메시지, 수행한 단계 수 |

analysis는 검증한 지시 해석 JSON, plan은 `TaskPlan`, ticket은 메모리 저장소의 티켓 식별자,
work_result는 Worker의 응답입니다. 지시 해석·권한 재심사 재진입과 턴 종료 시 이전 티켓을 폐기합니다.

`main.py`의 전역 `max_steps`는 기본 20이며 **바깥 루프에서 단계 함수를 호출하는 총횟수**입니다.
사용자 turn_id, LLM 호출 횟수, 도구 실행 횟수와 다릅니다. 한도는 재진입해도 초기화되지 않습니다.
`should_cancel` 콜백은 단계 사이에서 확인하고 Ctrl+C도 취소 종료로 처리합니다.
LLM 요청의 네트워크 타임아웃은 기본 60초입니다. API 오류·잘못된 응답은 재시도 없이 현재 턴을 실패 종료합니다.
이는 전체 작업 시간 제한이 아닙니다. 등록된 도구의 자체 시간 제한·격리는 해당 도구 구현의 책임입니다.

네 단계 모두 구현되어 있습니다. LLM 연결 정보가 없으면 설정 안내와 함께 FAILED로 종료합니다.
정상 완료, 질문, 실패, 중단, 한도 도달 안내 메시지는 assistant 기록으로 추가합니다.
이는 런타임이 반환하는 안내를 포함하며 전부 LLM이 생성한 메시지라는 뜻은 아닙니다.
질문 대기는 현재 호출을 종료하고 새 사용자 입력을 받는 방식입니다. 중단 지점의 자동 복원은 아직 없습니다.

JSONL을 지정하지 않으면 새 세션 ID를 생성하고 입력 메시지로 대화를 시작합니다.

```sh
python main.py "프로젝트의 요구사항을 정리해줘"
```

Managed Prompt는 `main.py`의 전역 변수 `managed_prompt`로 설정합니다.
기본값 `None`이면 첫 기록은 사용자 입력입니다. 문자열을 설정하면 새 대화에서
Managed Prompt가 첫 번째 기록, 사용자 입력이 두 번째 기록으로 추가됩니다.
새 대화에는 첫 사용자 메시지가 필요합니다.

대화를 복원해 메시지를 추가하거나, `--fork`로 같은 맥락에서 새 세션을 시작합니다.

```sh
python main.py --jsonl conversation.jsonl "앞서 정리한 요구사항에 우선순위를 붙여줘"
python main.py --jsonl conversation.jsonl --fork "이번에는 다른 기준으로 정리해줘"
python main.py --jsonl conversation.jsonl --fork
```

일반 복원은 세션 ID를 유지합니다. fork는 새 ID를 생성하며 새 메시지 없이 분기만 할 수도 있습니다.
복원·fork에서는 이력에 포함된 Managed Prompt를 그대로 유지합니다.
`--fork`는 복원할 `--jsonl`을 필요로 합니다. `--jsonl -`는 표준 입력에서 이력을 읽습니다.

표준 출력은 전체 ConversationHistory의 JSONL이고, 처리 상태·응답은 표준 오류에도 표시합니다.
각 줄에는 session_id,
계산된 task_id와 ConversationEntry 필드가 들어갑니다. JSONL 안의 줄바꿈은 문자열의 `\n`으로 표현합니다.
빈 줄은 건너뛰며 잘못된 기록은 줄 번호와 함께 오류를 냅니다. 복원을 완료한 후에만 결과를 출력합니다.

PowerShell에서 UTF-8로 저장하는 예:

```powershell
python -X utf8 main.py "첫 요청" | Set-Content -Encoding utf8 conversation.jsonl
python -X utf8 main.py --jsonl conversation.jsonl --fork "후속 요청" | Set-Content -Encoding utf8 fork.jsonl
```

## 네 단계의 처리

| 단계 | 실제 처리 | 다음 경로 |
|---|---|---|
| `analyze_instruction` | LLM으로 입력 목적, 우선순위 순 지시 목록, 사용자 턴 출처, 최우선 수행 지시, 완료 조건, 요청 권한을 분석 | 맥락 재조회 / 사용자 질문 / 취소 / 권한 판단 |
| `authorize_task` | 요청 도구·리소스를 에이전트 고정 정책 및 사용자 권한과 비교하고 메모리 티켓 발급 | 권한 거부 / Worker |
| `execute_task` | 티켓에 허용된 도구 정의를 LLM에 제공하고, 도구 호출 검사·실행·결과 기록·LLM 재호출 반복 | 후보 답변 평가 / 한도 종료 |
| `evaluate_result` | LLM이 완료 조건, 후보 답변, 이번 턴의 실제 도구 기록을 비교 | 완료 / 추가 실행 / 티켓 갱신 / 지시 재해석 / 질문 / 실패 |

Analyzer는 모든 사용자 지시와 최근 8개 기록을 먼저 봅니다. 이전 assistant·도구 맥락이 필요하면
`action=context`와 turn_ids를 반환하여 해당 턴의 기록을 추가한 후 다시 분석합니다.
지시 목록은 우선순위 순으로 반환하며 각 지시의 사용자 턴 출처를 포함합니다.
우선순위·의미 해석 자체의 정확성은 모델 판단에 의존합니다. Managed Prompt는 system 메시지에 넣고,
외부 기록은 kind가 표시된 데이터로 전달합니다. 모델의 해석 결과가 정책 상한을 변경하지는 못합니다.

Evaluator의 authorize는 기존 계획의 티켓 갱신입니다. 새로운 도구나 리소스가 필요하면 analyze로 돌아가
요청 권한을 다시 산출하고 정책 검사를 거칩니다. Worker 후보 응답과 최종 평가 응답은 이력에 남기며,
같은 답변이 연속되면 마지막 반환 단계에서 중복 기록하지 않습니다. 내부 Analyzer·Evaluator 프롬프트와
중간 JSON은 대화 이력에 저장하지 않습니다. 전체 감사 로그·분석 상태의 영구 저장은 후속 구현입니다.

## LLM 전역 설정

`main.py`에서 다음 값을 설정합니다. 환경변수를 지정하면 초기값으로 읽습니다.

| 변수 | 환경변수 | 의미 |
|---|---|---|
| `llm_base_url` | `LLM_BASE_URL` | API 기본 주소. 예: `http://localhost:8000/v1` |
| `llm_model` | `LLM_MODEL` | 서버가 실제로 제공하는 Qwen 모델 ID |
| `llm_api_key` | `LLM_API_KEY` | 서버가 인증을 요구할 때 사용 |
| `llm_timeout` | 없음 | 네트워크 요청 타임아웃, 기본 60초 |
| `llm_extra_body` | 없음 | 서버별 추가 요청 설정 |

`/chat/completions`는 코드가 기본 주소 뒤에 붙입니다. Qwen 3.8 27B라는 모델 설명만으로
서빙 ID를 추측하지 않았습니다. 서버에 등록된 정확한 이름을 llm_model에 넣어야 합니다.
Analyzer·Evaluator는 `response_format={"type":"json_object"}`, Worker는 등록 도구가 있으면
`tools`와 `tool_choice=auto`를 사용합니다. 해당 기능을 지원하는 서빙 설정이 필요합니다.
응답 크기와 finish_reason은 별도로 검사하지 않으며, JSON 파싱 오류는 그대로 전파합니다. 모델의 추론 전용 필드는 재전송하지 않으므로,
추론 기록 재전송이 필요한 모드는 별도 어댑터가 필요합니다.

## 도구·권한 전역 설정

`main.py`의 `tools`, `agent_permissions`, `user_permissions`에서 설정합니다. 현재 에이전트의 고정 도구 권한은 비어 있습니다.
`ToolDefinition`은 설명, JSON Schema, 인자 검증 함수, 실제 접근 리소스 추출 함수, 실행 함수로 구성합니다.
도구 이름은 연결할 서버의 function name 규칙에 맞게 등록합니다. 구체적인 파일·웹·쉘 도구를 임의로 추가하지 않았습니다.

인자 검증 함수는 검증·정규화한 dict를, 리소스 추출 함수는 정확한 식별자의 tuple을 반환해야 합니다.
JSON Schema를 LLM에 제공하는 것만으로 인자 검증을 대체하지 않습니다. 실제 검사는 등록한 validate 함수가 담당합니다.
정책은 `agent_permissions[tool]`, `user_permissions[tool]`에 지정한 정확한 리소스 식별자의 교집합을 사용합니다.
와일드카드나 경로 prefix 권한은 지원하지 않습니다. 리소스 없는 순수 계산 도구는 빈 tuple을 사용합니다.

티켓 원본은 `TurnStages`의 메모리 저장소에 보관합니다. 호출 시 작업·세션 바인딩, 만료,
허용 도구·리소스, 횟수를 확인합니다. 권한 위반은 실행하지 않고 PermissionError를 전파합니다.
단계 실행 중 Exception은 feedback에 단계·실패 상태·예외 종류를 기록하고 같은 단계를 다시 실행합니다. KeyboardInterrupt는 티켓 정리 후 그대로 전파합니다.
동기 단일 실행용이며 악성 Python 플러그인 격리·동시 실행·SQLite 저장소는 구현하지 않았습니다.

## 반복 제한과 검증

| 전역 변수 | 기본값 | 제한 대상 |
|---|---|---|
| `max_steps` | 20 | 바깥 단계 호출 총횟수 |
| `max_analysis_calls` | 3 | 이번 사용자 턴의 지시 분석 LLM 호출 |
| `max_worker_calls` | 8 | 이번 사용자 턴의 Worker LLM 호출 |
| `max_tool_calls` | 12 | 이번 사용자 턴의 도구 시도와 개별 티켓 실행 한도 |
| `ticket_ttl` | 300초 | 티켓 수명 |

지시 재해석·티켓 갱신 시에도 사용자 턴의 분석·Worker·도구 카운터를 초기화하지 않습니다.
질문 대기는 사용자에게 질문을 반환하고 호출을 끝냅니다. 실제 사용자 응답은 다음 turn_id로 처리합니다.
하위 에이전트는 아직 없고, 맥락 재조회 및 Worker 내부 루프로 먼저 구현했습니다.

검증에는 가짜 모델 응답과 테스트 전용 도구를 사용했습니다. 네 단계 완료, 맥락 재조회,
추가 실행·재심사·재해석, 질문·취소·LLM 실패 종료, 권한 거부, 리소스 범위·작업 바인딩,
티켓 만료·폐기, 호출 한도, JSONL 복원과 HTTP 요청 형식을 확인했습니다.
실제 Qwen 서버의 출력 품질·호환성 및 실제 외부 도구의 부작용은 검증하지 않았습니다.

## 공통 로그 구조

`src/logging.py`의 `LogEvent`는 UTC 시각, 레벨, 이벤트명, 메시지와 선택적인
세션·턴, 단계, 도구 호출 ID, 도구명, 소요 시간(ms), 오류 종류, 상세 정보를 담습니다.
`task_id`는 session_id와 turn_id에서 계산하며 `to_json()`은 JSONL 한 줄에 쓸 JSON 문자열을 반환합니다.
`event`는 `turn.started`, `llm.failed`, `tool.completed`처럼 검색용으로 고정된 이름을 사용합니다.
`stage`는 analyze, authorize, execute, evaluate 중 해당 단계를 기록합니다.
상세 정보에는 API 키나 원문 대화·도구 결과를 기본으로 넣지 않습니다.

레벨은 코드의 가이드를 따릅니다. 동일한 타임아웃도 재시도할 수 있으면 WARNING,
턴을 실패 종료하면 ERROR입니다. 단일 턴 실패는 CRITICAL로 분류하지 않습니다.
표준 logging용 JsonFormatter는 LogRecord의 pathname·lineno·funcName과 exc_info를 직렬화합니다.
주요 인자는 extra={"arguments": {...}}로 필요한 값만 명시합니다. 로컬 변수 전체를 자동 수집하지 않습니다.
logger.exception() 또는 exc_info=True로 traceback을 기록하며, 래퍼에서는 stacklevel로 호출 위치를 지정할 수 있습니다.
main.py·core.py에는 아직 연결하지 않았으며 출력 대상과 저장 방식도 아직 지정하지 않았습니다.

내부 데이터 타입·계획 존재 여부·단계 반환 형식은 정상 동작을 전제로 합니다.
외부 API 오류·타임아웃·JSON 파싱 오류는 단계 내부에서 전파되며, process_turn 루프에서 실패 feedback과 함께 같은 단계를 재시도합니다. 실제 권한·티켓 제한 처리는 유지합니다.

코드에서 만든 중단·실패·한도 안내 문구는 사용하지 않습니다. 취소 콜백과 반복 한도는 상태로 반환하며, 빈 응답을 대화 이력에 추가하지 않습니다.

## 데이터 클래스 상속

`TaskRecord`는 공통 작업 식별자 `task_id`를 정의합니다.
`UserInstruction`, `TaskPlan`, `CapabilityTicket`, `TurnResult`가 이를 상속합니다.
`UserInstruction`은 기존처럼 session_id와 turn_id로 task_id를 계산합니다.

`ProcessingResult`는 공통 응답 `message`를 정의합니다.
`StageResult`와 `TurnResult`가 이를 상속하며 message는 키워드 인자로 전달합니다.
`TurnResult`는 작업 식별자와 처리 결과 두 부모를 함께 상속합니다.
모든 데이터 부모·자식 클래스의 frozen 설정을 유지합니다.

단계 실패 시 이미 증가한 steps는 유지하며 반복 한도 안에서 같은 단계를 다시 실행합니다. 기존 이력이나 도구의 외부 효과를 되돌리지는 않습니다. 예외 로그 연결은 아직 하지 않았습니다.

도구 호출 실패는 오류 결과를 이력에 남긴 뒤 루프에 전달합니다. 분석·Worker·평가 LLM은 feedback을 입력으로 받습니다. 명시적인 FAILED 반환은 턴 종료로 유지합니다.
