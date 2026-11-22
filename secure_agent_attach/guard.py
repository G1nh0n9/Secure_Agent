"""Guards added from outside, opt-in. Each one closes a gap that a FRET requirement showed; none edits the original.

  authorize_task  least privilege: grants are trimmed to what the plan requested (SR-02)
  execute_task    a missing or expired ticket sends the turn back to authorize instead of retrying the same stage (SR-05)
  TrustedHistory  a restored history can neither bring in managed entries, forged tool records, records of unknown kinds nor records of another session (SR-07, HIS-01..05)
  amend_denied    a turn that saw a denial never ends with an empty message (SR-06)
"""
from __future__ import annotations

import dataclasses
import json

from . import loader
from .observe import ObserveMixin, core, run_turn


def _requested(plan) -> dict[str, set]:
    out: dict[str, set] = {}
    for step in (plan.steps if plan else ()):
        if step.requested_tool is not None:
            out.setdefault(step.requested_tool, set()).update(step.requested_resources)
    return out


class GuardMixin:
    max_renewals = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._renewals = 0

    def _note(self, event: str, **kw) -> None:
        rec = getattr(self, "recorder", None)
        if rec is not None:
            rec.note(event, **kw)

    def authorize_task(self, context):
        result = super().authorize_task(context)
        ticket = self._tickets.get(context.ticket)
        if ticket is None or result.next_state != core.TurnState.EXECUTE:
            return result
        requested = _requested(context.plan)
        grants = tuple((n, tuple(sorted(set(r) & requested[n]))) for n, r in ticket.grants if n in requested)
        if grants != ticket.grants:
            self._note("grants_trimmed", before=[[n, list(r)] for n, r in ticket.grants], after=[[n, list(r)] for n, r in grants])
            if requested and not grants:
                self.revoke_ticket(context)
                return core.StageResult(core.TurnState.FAILED, message="Least privilege: none of the verified grants was requested by the plan")
            self._tickets[ticket.ticket_id] = dataclasses.replace(ticket, grants=grants)
        return result

    def execute_task(self, context):
        ticket = self._tickets.get(context.ticket)
        if ticket is None or core.time.monotonic() >= ticket.expires_at:
            if self._renewals >= self.max_renewals:
                self._note("renewal_limit")
                return core.StageResult(core.TurnState.FAILED, message="The ticket expired and the renewal limit was reached")
            self._renewals += 1
            self._note("reauthorize", reason="ticket missing" if ticket is None else "ticket expired")
            return core.StageResult(core.TurnState.AUTHORIZE, message="Ticket expired; authorizing again")
        return super().execute_task(context)


class GuardedStages(ObserveMixin, GuardMixin, core.TurnStages):
    """The original TurnStages plus the guards, observed from the outside."""


class TrustedHistory(core.ConversationHistory):
    """Restore without trusting the stream: only user and assistant records of the stream's own session are kept. Managed entries,
    tool records, records of kinds the core does not know and records of another session are dropped (counted in `restore_dropped`);
    a record without session_id is malformed and raises, as in the original. The operator prompt comes from configuration."""

    OPERATOR_MANAGED: str | None = None

    @classmethod
    def from_jsonl(cls, lines):
        records = [json.loads(line) for line in lines if line.strip()]
        if not records:
            raise ValueError("empty history stream")
        sid = records[0]["session_id"]
        kept = [r for r in records if ("kind" not in r or r["kind"] in ("user", "assistant")) and r["session_id"] == sid]
        head = []
        if cls.OPERATOR_MANAGED is not None:
            head = [{"session_id": sid, "task_id": None, "turn_id": None, "kind": "managed", "content": cls.OPERATOR_MANAGED,
                     "call_id": None, "tool_name": None, "arguments": None, "is_error": False}]
        merged = head + kept
        history = core.ConversationHistory.from_jsonl(json.dumps(r) for r in merged) if merged else core.ConversationHistory(sid)
        history.restore_dropped = len(records) - len(kept)
        return history


def amend_denied(result, rec):
    """A turn that saw a denial or a blocked start never ends with an empty message."""
    if rec.denial_seen and not (result.message or "").strip():
        reasons = list(dict.fromkeys(e["reason"] for e in rec.audit if e["event"] in ("tool_denied", "blocked_start") and e.get("reason")))
        text = "The turn ended without a result. Tool execution was denied or blocked: " + ("; ".join(reasons) or "see the audit log")
        rec.note("result_message_added", message=text)
        return dataclasses.replace(result, message=text)
    return result


def attached_process_turn(instruction, history, *, stages=None, max_steps: int = 20, should_cancel=None):
    """Drop-in for the original process_turn when the attach layer's guards are on."""
    return run_turn(instruction, history, stages=stages, max_steps=max_steps, should_cancel=should_cancel, amend=amend_denied)
