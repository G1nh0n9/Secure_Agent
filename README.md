# Secure_Agent_attach

Secure_Agent(`~/safeAIsystem/Secure_Agent`)의 **원본을 수정하지 않고** 바깥에서 붙이는 안전 계층이다. 원본(`src/core.py`)의 모든 보안기능과 기능명세를 FRETish 요구로 쓰고, 공식 FRET 파서와 Kind2(realizability)와 NuSMV로 검사하며, 같은 요구를 실제 코드의 실행 관찰에도 적용한다. 프론트엔드는 범위 밖이다.

## 두 층의 요구

| 층 | 파일 | 내용 |
|---|---|---|
| 초기 8개 (SR-01..08) | `requirements/core_requirements.json` | 턴 상태기계의 안전 성질. NuSMV 모델과 6개 시나리오의 트레이스에서 검사 (`all`) |
| 코어 전체 명세 | `requirements/core_spec.json` | core.py의 모든 함수를 12개 컴포넌트, 요구 125개(보안기능요구 SEC 72, 기능명세 FUN 53), 보안기능 10개로 옮긴 카탈로그. 초기 8개는 여기의 `sr` 필드로 연결된다 |

읽기 쉬운 형태는 `docs/CORE_SPEC.md`(생성물)와 `docs/core_spec.csv`다. 직접 고치지 않고 `doc` 명령으로 만든다.

## 붙이는 방식 (원본 파일은 읽기만 한다)

| 수단 | 하는 일 | 위치 |
|---|---|---|
| 읽기 전용 import와 고정 | 원본을 import만 하고 바이트코드도 쓰지 않는다. 커밋과 파일 해시를 `pin/ORIGINAL.json`에 고정하고 실행마다 대조한다 | `pin.py`, `loader.py` |
| 서브클래스 관찰기 | `TurnStages`를 상속해 반복(process_turn 루프 1회)마다 신호 틱을 기록한다. 동작은 바꾸지 않는다 | `observe.py` |
| 서브클래스 가드 (선택) | 최소 권한 절삭, 만료 시 재인가, 복원 이력 정리, 거부된 턴의 메시지 보충 | `guard.py` |
| 이름 재바인딩 | 원본 `main.py`를 그대로 실행하되 실행 중에 `TurnStages` 등의 이름을 바꿔 끼운다 | `scenarios.cli_smoke` |

가드는 attach 진입점(`GuardedStages`, `TrustedHistory`, `attached_process_turn`)으로 실행할 때만 적용된다. 원본 `main.py`를 직접 실행하면 적용되지 않는다.

## 구성

```
pin/ORIGINAL.json                     원본 커밋과 파일 해시
pin/VENDOR.json                       vendor 스크립트의 해시 (nl2fret_tool에서 변경 없이 복사)
requirements/core_requirements.json   초기 FRETish 요구 8개와 신호 어휘 (모델과 트레이스용)
requirements/core_spec.json           코어 전체 명세 카탈로그 (단일 원천)
model/core_turn.smv.tpl               process_turn 상태기계의 NuSMV 모델 (guard=FALSE 원본, TRUE 가드 포함)
vendor/fretjs/                        FRET 파서와 가져오기 스크립트 (변경 없이 복사)
secure_agent_attach/                  ptl, fret_nusmv, observe, guard, scenarios, selftest (초기 층)
                                      spec, rlz, probes (코어 전체 명세 층)
docs/                                 CORE_SPEC.md, core_spec.csv (생성물)
runs/                                 실행 기록 (git에서 제외)
```

## 실행

```
cd ~/safeAIsystem/Secure_Agent_attach
PYTHONDONTWRITEBYTECODE=1 ~/.pyenv/versions/3.12.14/bin/python3 -m secure_agent_attach full
```

필요한 것: Python 3.10 이상(원본 요구), Docker 이미지 `fret-lab:latest`(FRET 파서, Kind2, NuSMV 2.7.1). 도커는 CPU 1개로 제한해 순서대로 돈다.

| 명령 | 하는 일 | 시간 |
|---|---|---|
| `full` | 아래를 모두 | 약 5분 |
| `all` | 초기 층: pin, 컴파일, 모델 검사, 평가기 자체 시험, 트레이스, CLI 시험 | 5초 |
| `spec` | 카탈로그 검사: 공식 파서, 신호 선언, 정수와 불리언 사용, 응답에 Output, 보안기능 분류, core.py 문장 커버리지 | 몇 초 |
| `rlz [컴포넌트]` | 컴포넌트마다 realizability(Kind2), 결함을 요구로 써서 넣는 민감도 검사 | 약 4분 |
| `probe [컴포넌트]` | 요구를 실제 코드의 관찰에 적용 (가짜 LLM, 가짜 도구, 가짜 시계). 컴포넌트를 지정하지 않으면 가드를 켠 스택에서도 돈다 | 몇 초 |
| `mutate` | 원본 복사본에 결함을 하나씩 넣고 프로브가 잡는지 확인 | 15초 |
| `doc` | `docs/CORE_SPEC.md`와 `docs/core_spec.csv` 생성 | 1초 |
| `pin`, `compile`, `mc`, `selftest`, `traces` | 초기 층의 부분 실행 | |

## 검사 체인

초기 층 (SR-01..08):
1. FRETish 요구 → 공식 FRET 파서 → `ltl_pt`
2. `ltl_pt` → NuSMV `LTLSPEC G`: 모델은 LLM 4단계와 TTL을 비결정 환경으로 둔다
3. `ltl_pt` → 실제 코드의 트레이스: 적대적 스텁 LLM으로 시나리오를 돌리고 같은 공식을 틱마다 평가한다
4. 자체 시험: 트레이스 평가기를 NuSMV와 무작위 트레이스로 대조한다

코어 전체 명세 층:
1. **카탈로그** (`spec`): core.py의 모든 함수와 보안 동작이 요구에 연결된다. 문장 316개 중 305개가 요구에 연결되고, 11개(import와 프롬프트 글)는 사유와 함께 제외하며, 어디에도 없는 문장은 0개다. 모든 보안기능요구는 보안기능 10개 중 하나에 속한다.
2. **realizability** (`rlz`): 컴포넌트마다 Input을 모두 제약 없이 두고 Kind2로 확인한다. realizable은 "모든 입력 순서에서 모든 요구를 지키는 구현이 존재한다"는 뜻이다. 공격 범위를 모를 때는 외부에서 오는 값을 전부 Input으로 두는 것이 가장 보수적인 가정이다.
3. **민감도 검사 1** (`rlz`): 결함을 요구로 써서 컴포넌트에 넣으면 unrealizable로 바뀌어야 한다. 원본의 알려진 빈틈 7개와 원본에는 없는 가상 결함 8개를 쓴다. 원본 동작은 충돌해야 하는 요구를 빼면 다시 realizable이 되어야 한다.
4. **프로브** (`probe`): 같은 `ltl_pt`를 진짜 원본 코드의 관찰에 대입한다. 게이트는 입력 9개의 모든 조합 512개를 전수로 돌리고, 나머지는 요구를 가르는 경우(모든 action, 모든 decision, 모든 종류의 복원 기록, 인가 검사의 모든 조합 등)를 돌린다. `asis: ok`인 요구는 모든 관찰에서 성립해야 하고, `asis: gap`인 요구는 위반이 재현되어야 한다. 프로브가 core.py 함수 본문 문장을 얼마나 실행했는지도 잰다. 컴포넌트를 지정하지 않으면 같은 프로브를 가드를 켠 스택(`GuardedStages`, `TrustedHistory`)에서도 돌려 원본이 어기던 요구가 닫히는지 본다. Turn은 대본대로 움직이는 단계로 돌리므로 이 비교에서 빼고, 가드가 루프에 주는 효과는 `all`의 종단 시나리오(SR-05, SR-06)로 본다.
5. **민감도 검사 2** (`mutate`): 원본 복사본에 결함을 하나씩 넣고 같은 프로브를 돌려 잡는지 본다.

한 시점(tick)의 뜻은 컴포넌트마다 다르며(게이트는 도구 호출 1회, 턴은 루프 반복 1회 등) 카탈로그의 `tick_ko`에 있다. 요구는 모두 "모든 시점에서 성립" 형태다. FRETish의 `when`은 상승 에지에서만 걸리므로 쓰지 않았다.

## 새 요구를 넣는 법

1. `requirements/core_spec.json`의 컴포넌트에 신호(역할 Input 또는 Output, 형 boolean 또는 integer)와 요구를 더한다. 요구마다 코드 줄 참조(`code`), 한국어 설명(`ko`), 원본 준수 여부(`asis`: ok 또는 gap)가 필요하다. 보안기능요구는 `security_functions`의 하나에 넣는다.
2. `spec`이 오류 0이어야 한다. 파서가 거부하거나, 선언 안 한 신호를 쓰거나, 응답에 Output이 없거나(환경만 제약하는 요구), 보안기능에 속하지 않으면 실패한다.
3. `rlz 컴포넌트`가 realizable이어야 한다. unrealizable이면 요구끼리 모순이거나 입력의 독립을 잘못 가정한 것이다. 격리 조건(다른 플래그는 거짓)을 넣어 원인을 가른다.
4. 원본이 어기는 요구는 `asis: gap`과 `asis_ko`를 쓰고, 그 원본 동작을 쓴 변이(`mutants`)를 하나 둔다.

## 한계

- realizable은 "규칙끼리 모순이 없고 규칙을 지키는 구현이 존재한다"이다. 원본 코드가 그 구현이라는 뜻이 아니다. 그것은 프로브(실제 코드 관찰)가 확인한다.
- 프로브의 입력은 불리언 추상이다. 게이트만 전수이고 나머지는 요구를 가르는 경우를 골라 돌린다. 도구는 가짜이고 LLM은 대본대로 답한다.
- 요구가 코드의 모든 행동을 담았는지는 증명하지 못한다. 문장 연결(305/316 + 제외 11)과 프로브의 문장 실행, 코드 변이 검출로 간접 확인할 뿐이다.
- 요구 수준 변이와 코드 수준 변이의 목록은 제가 정한 것이다. 목록 밖의 결함은 잡는다고 말할 수 없다.
- 프롬프트의 권고(검증, 작업, 평가, 분석, managed 프롬프트)는 강제가 아니다. 카탈로그의 `advisory`에 N-01부터 N-05로 적었다.
- 도구 구현(validate, resources, execute)은 신뢰하는 코드라고 가정한다(A-02). 게이트는 도구가 계산한 자원 이름을 믿는다.
- 초기 층의 한계도 남는다: 모델은 코드를 읽고 손으로 옮긴 것이고 시나리오 6개의 결과와 일치하는 수준에서 확인했다. 관찰기와 가드는 원본의 내부 이름(`_execute_tool`, `_tickets`, `_ticket_calls`)에 기대므로 원본이 바뀌면 pin이 불일치로 알린다. 복원 가드는 user와 assistant 항목의 위조를 서명 없이는 막지 못한다. 취소 콜백의 늦은 확인, 동시 턴, 프론트엔드는 다루지 않는다.
