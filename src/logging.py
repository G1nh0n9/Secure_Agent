from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
import json
import logging
import traceback


class LogLevel(IntEnum):
    # DEBUG: 맥락 조회, 단계 분기, 반복 횟수 등 개발 중 추적할 세부 정보.
    DEBUG = 10
    # INFO: 턴·단계 시작과 완료, 티켓 발급, 사용자 응답 대기 등 정상 진행.
    INFO = 20
    # WARNING: 도구 실행 거부·실패, 재시도, 반복 한도 도달 등 복구 또는 개입이 필요한 상황.
    WARNING = 30
    # ERROR: LLM 연결 실패·타임아웃 등 현재 턴을 완료할 수 없는 오류.
    ERROR = 40
    # CRITICAL: 초기화 실패 등 프로세스 전체가 더 이상 동작할 수 없는 오류.
    CRITICAL = 50


@dataclass(frozen=True)
class LogEvent:
    level: LogLevel
    event: str
    message: str
    session_id: str | None = None
    turn_id: int | None = None
    stage: str | None = None
    call_id: str | None = None
    tool_name: str | None = None
    duration_ms: float | None = None
    error_type: str | None = None
    pathname: str | None = None
    lineno: int | None = None
    func_name: str | None = None
    arguments: dict[str, object] = field(default_factory=dict)
    exception: str | None = None
    details: dict[str, object] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def task_id(self) -> str | None:
        if self.session_id is not None and self.turn_id is not None:
            return f"{self.session_id}:{self.turn_id}"
        return None

    def to_json(self) -> str:
        record = {**asdict(self), "level": self.level.name, "task_id": self.task_id}
        return json.dumps(record, ensure_ascii=False)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        context = {
            name: getattr(record, name)
            for name in (
                "session_id", "turn_id", "stage", "call_id", "tool_name",
                "duration_ms", "arguments", "details",
            )
            if hasattr(record, name)
        }
        error = record.exc_info
        return LogEvent(
            level=LogLevel(record.levelno),
            event=getattr(record, "event", record.name),
            message=record.getMessage(),
            pathname=record.pathname,
            lineno=record.lineno,
            func_name=record.funcName,
            timestamp=datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            error_type=error[0].__name__ if error and error[0] else None,
            exception="".join(traceback.format_exception(*error)) if error and error[0] else None,
            **context,
        ).to_json()
