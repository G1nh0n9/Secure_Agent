"""Layer 4 (Logging & Monitoring) wired into the ticket-based agent, without changing core.py.

MonitoredTurnStages extends TurnStages at four points:

  analyze_instruction  -> the monitor learns the user's instruction and the planned tools
  authorize_task       -> every issued CapabilityTicket is registered (and logged)
  _execute_tool        -> BEFORE the ticket check: Monitor.check() decides allow / confirm / block;
                          AFTER execution: the tool result is registered as untrusted context
  execute_task         -> "confirm" ends the turn as WAITING_FOR_USER; an exhausted risk budget
                          ends it as FAILED and revokes the ticket, instead of retrying until
                          max_steps

The ticket check in core.py still runs unchanged; the monitor adds a session-wide view on top.
Every decision goes to the hash-chained audit log and, as a structured record, to the Python
logger "secure_agent.monitor" (format it with src.logging.JsonFormatter).
"""
import json
import logging
from copy import deepcopy

from monitor import Monitor, ToolCall
from monitor.tickets import Ticket
from src.core import StageResult, TurnStages, TurnState

log = logging.getLogger("secure_agent.monitor")


class MonitorBlocked(PermissionError):
    def __init__(self, decision):
        super().__init__("; ".join(decision.reasons) or "blocked by monitor")
        self.decision = decision


class MonitorConfirm(PermissionError):
    def __init__(self, decision, tool, arguments):
        super().__init__("; ".join(decision.reasons))
        self.decision, self.tool, self.arguments = decision, tool, arguments


class MonitoredTurnStages(TurnStages):
    def __init__(self, call_llm=None, *, monitor: Monitor, user: str = "user@local",
                 contacts=(), **kwargs) -> None:
        super().__init__(call_llm, **kwargs)
        self.monitor, self.user, self.contacts = monitor, user, tuple(contacts)
        self._turns = set()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _sid(context):
        return context.instruction.session_id

    def _ensure_turn(self, context):
        if context.instruction.task_id not in self._turns:
            self._turns.add(context.instruction.task_id)
            self.monitor.begin_turn(self._sid(context), self.user, context.instruction.text, contacts=self.contacts)

    def _halted(self, context):
        s = self.monitor.sessions.get(self._sid(context))
        return bool(s and s.halted)

    def _emit(self, context, level, event, message, **details):
        log.log(level, message, extra={
            "event": event, "session_id": context.instruction.session_id,
            "turn_id": context.instruction.turn_id, "stage": "monitor", "details": details})

    # ------------------------------------------------------------------ stage hooks
    def analyze_instruction(self, context):
        self._ensure_turn(context)
        result = super().analyze_instruction(context)
        if context.plan is not None:
            self.monitor.set_plan(self._sid(context),
                                  {s.requested_tool for s in context.plan.steps if s.requested_tool})
        return result

    def authorize_task(self, context):
        self._ensure_turn(context)
        if self._halted(context):
            return StageResult(TurnState.FAILED, message="Session halted by the Layer 4 monitor (risk budget exhausted).")
        result = super().authorize_task(context)
        if context.ticket:
            t = self.monitor.on_ticket_issued(self._sid(context),
                                              Ticket.from_capability_ticket(self._tickets[context.ticket]))
            self._emit(context, logging.INFO, "ticket_issued", "capability ticket issued",
                       ticket_id=t.ticket_id, grants={k: sorted(v) for k, v in t.grants.items()})
        return result

    def revoke_ticket(self, context):
        if context.ticket:
            self.monitor.on_ticket_revoked(self._sid(context), context.ticket, reason="turn stage")
        super().revoke_ticket(context)

    def execute_task(self, context):
        if self._halted(context):
            return StageResult(TurnState.FAILED, message="Session halted by the Layer 4 monitor (risk budget exhausted).")
        try:
            return super().execute_task(context)
        except MonitorConfirm as e:
            msg = (f"Confirmation needed before '{e.tool}' with {json.dumps(e.arguments, ensure_ascii=False)}. "
                   f"Reasons: {e}")
            return StageResult(TurnState.WAITING_FOR_USER, message=msg)
        except MonitorBlocked as e:
            if self._halted(context):
                return StageResult(TurnState.FAILED,
                                   message=f"Session halted by the Layer 4 monitor. Last reasons: {e}")
            raise                                   # ordinary block: same path as a ticket denial

    def _execute_tool(self, context, name, arguments):
        sid = self._sid(context)
        resources = None
        tool = self.tools.get(name)
        if tool is not None:
            try:
                resources = tuple(tool.resources(tool.validate(deepcopy(arguments))))
            except Exception:
                resources = None
        call = ToolCall(name, deepcopy(arguments), ticket_id=context.ticket, resources=resources)
        d = self.monitor.check(sid, call)
        level = {"allow": logging.INFO, "confirm": logging.WARNING, "block": logging.WARNING}[d.action]
        self._emit(context, level, "monitor_decision", f"{name}: {d.action}", decision=d.action,
                   risk=f"{d.used}/{d.budget}", reasons=d.reasons, revoke=d.revoke)
        if context.ticket in d.revoke:
            super().revoke_ticket(context)
        if d.action == "block":
            self.monitor.record_outcome(sid, d.call_id, executed=False, call=call)
            raise MonitorBlocked(d)
        if d.action == "confirm":
            self.monitor.record_outcome(sid, d.call_id, executed=False, user_confirmed=None, call=call)
            raise MonitorConfirm(d, name, arguments)
        try:
            value = super()._execute_tool(context, name, arguments)
        except Exception:
            self.monitor.record_outcome(sid, d.call_id, executed=False, call=call)
            raise
        self.monitor.record_outcome(sid, d.call_id, executed=True, call=call)
        # whatever a tool returns (an email, a web page) is data from outside: untrusted context
        self.monitor.observe_context(sid, f"tool:{name}", json.dumps(value, ensure_ascii=False, default=str))
        return value
