"""Observation of the original by subclassing. It records one tick per process_turn iteration and changes no behavior:
every wrapper calls the original method and returns its value or re-raises its exception unchanged."""
from __future__ import annotations

import dataclasses

from . import loader

core = loader.load_original()


def grants_within_plan(ticket, plan) -> bool:
    """Grants of the ticket are within the tools and resources the plan requested."""
    if ticket is None:
        return True
    requested: dict[str, set] = {}
    for step in (plan.steps if plan else ()):
        if step.requested_tool is not None:
            requested.setdefault(step.requested_tool, set()).update(step.requested_resources)
    return all(name in requested and set(res) <= requested[name] for name, res in ticket.grants)


def grants_within_policy(ticket, stages) -> bool:
    """Grants of the ticket are within agent_permissions AND user_permissions (recomputed independently of authorize_task)."""
    if ticket is None:
        return True
    for name, res in ticket.grants:
        agent, user = stages.agent_permissions.get(name), stages.user_permissions.get(name)
        if agent is None or user is None or not set(res) <= (set(agent) & set(user)):
            return False
    return True


class TraceRecorder:
    """Builds the tick sequence that the FRET formulas are evaluated on, plus an audit list."""

    def __init__(self, max_steps: int = 20, operator_managed: str | None = None, clock=None):
        self.max_steps = max_steps
        self.operator_managed = operator_managed
        self.clock = clock or (lambda: core.time.monotonic())
        self.ticks: list[dict] = []
        self.audit: list[dict] = []
        self.denial_seen = False
        self.managed_untrusted = False
        self.steps = 0
        self.post = {"ticket": None, "plan_ok": True, "policy_ok": True}   # state after the previous iteration
        self._it: dict | None = None
        self.status = None

    def note(self, event: str, **kw) -> None:
        self.audit.append({"i": self.steps, "event": event, **kw})

    def start(self, history) -> None:
        self.managed_untrusted = any(e.kind == "managed" and e.content != self.operator_managed for e in history.entries)

    def begin(self, stage: str) -> None:
        ticket = self.post["ticket"]
        exists = ticket is not None
        expired = exists and self.clock() >= ticket.expires_at
        self._it = {"stage": stage, "exists": exists, "plan_ok": self.post["plan_ok"], "policy_ok": self.post["policy_ok"],
                    "blocked": stage == "execute" and (not exists or expired), "unauthorized": False, "denied": False}
        if self._it["blocked"]:
            self.note("blocked_start", reason="ticket missing" if not exists else "ticket expired")

    def tool(self, name: str, executed: bool, unauthorized: bool, ticket_id=None, resources=None, reason=None) -> None:
        it = self._it
        if executed:
            it["unauthorized"] = it["unauthorized"] or unauthorized
            self.note("tool_executed", tool=name, ticket_id=ticket_id, resources=list(resources or []), unauthorized=unauthorized)
        else:
            it["denied"] = True
            self.note("tool_denied", tool=name, ticket_id=ticket_id, resources=list(resources or []), reason=reason)

    def end(self, stages, context) -> None:
        it = self._it
        self.ticks.append({
            "stage_authorize": it["stage"] == "authorize",
            "ticket_exists": it["exists"],
            "grants_within_plan": it["plan_ok"] if it["exists"] else True,
            "grants_within_policy": it["policy_ok"] if it["exists"] else True,
            "exec_unauthorized": it["unauthorized"],
            "blocked_start": it["blocked"],
            "turn_over": False,
            "denial_seen": self.denial_seen,
            "result_has_reason": False,
            "managed_untrusted": self.managed_untrusted,
            "steps": self.steps,
            "max_steps": self.max_steps,
        })
        self.denial_seen = self.denial_seen or it["blocked"] or it["denied"]
        self.steps += 1
        ticket = stages._tickets.get(context.ticket)
        if ticket is not None and ticket.ticket_id != getattr(self.post["ticket"], "ticket_id", None):
            self.note("ticket_issued", ticket_id=ticket.ticket_id, grants=[[n, list(r)] for n, r in ticket.grants])
        self.post = {"ticket": ticket, "plan_ok": grants_within_plan(ticket, context.plan),
                     "policy_ok": grants_within_policy(ticket, stages)}

    def finish(self, stages, result) -> None:
        self.status = result.status.value
        self.ticks.append({
            "stage_authorize": False, "ticket_exists": bool(stages._tickets), "grants_within_plan": True,
            "grants_within_policy": True, "exec_unauthorized": False, "blocked_start": False, "turn_over": True,
            "denial_seen": self.denial_seen, "result_has_reason": bool((result.message or "").strip()),
            "managed_untrusted": self.managed_untrusted, "steps": self.steps, "max_steps": self.max_steps,
        })


class ObserveMixin:
    """Put first in the MRO: observes the final behavior of everything below it (including guards)."""

    def __init__(self, *args, recorder: TraceRecorder | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.recorder = recorder or TraceRecorder()
        self._last_resources = None
        self._wrap_tools()

    def _wrap_tools(self) -> None:
        """Capture the resources the core itself computes for a call, instead of calling the tool code a second time."""
        def wrap(fn):
            def resources(args):
                out = fn(args)
                self._last_resources = tuple(out)
                return out
            return resources
        self.tools = {n: dataclasses.replace(t, resources=wrap(t.resources)) for n, t in self.tools.items()}

    def _observed(self, stage: str, fn, context):
        self.recorder.begin(stage)
        try:
            return fn(context)
        finally:
            self.recorder.end(self, context)

    def analyze_instruction(self, context):
        return self._observed("analyze", super().analyze_instruction, context)

    def authorize_task(self, context):
        return self._observed("authorize", super().authorize_task, context)

    def execute_task(self, context):
        return self._observed("execute", super().execute_task, context)

    def evaluate_result(self, context):
        return self._observed("evaluate", super().evaluate_result, context)

    def _reason(self, ticket, name: str) -> str:
        """Why the gate said no, recomputed in the order of the core's checks (the core raises a bare PermissionError)."""
        if ticket is None:
            return "no ticket"
        c = self._ctx
        if (ticket.session_id, ticket.task_id) != (c.instruction.session_id, c.instruction.task_id):
            return "ticket belongs to another task"
        if core.time.monotonic() >= ticket.expires_at:
            return "ticket expired"
        grants = dict(ticket.grants)
        if name not in grants or name not in self.tools:
            return f"tool {name!r} is not granted"
        if self._last_resources is not None and not set(self._last_resources) <= set(grants[name]):
            return f"resources outside the grants: {sorted(set(self._last_resources) - set(grants[name]))}"
        if self._ticket_calls.get(ticket.ticket_id, 0) >= ticket.max_calls:
            return "call budget exhausted"
        return "tool validation or execution failed"

    def _execute_tool(self, context, name, arguments):
        ticket = self._tickets.get(context.ticket)
        valid = (ticket is not None and core.time.monotonic() < ticket.expires_at
                 and (ticket.session_id, ticket.task_id) == (context.instruction.session_id, context.instruction.task_id))
        self._last_resources, self._ctx = None, context
        try:
            value = super()._execute_tool(context, name, arguments)
        except Exception:
            self.recorder.tool(name, executed=False, unauthorized=False, ticket_id=getattr(ticket, "ticket_id", None),
                               resources=self._last_resources, reason=self._reason(ticket, name))
            raise
        grants = dict(ticket.grants) if ticket else {}
        in_grants = name in grants and self._last_resources is not None and set(self._last_resources) <= set(grants[name])
        calls_ok = ticket is not None and self._ticket_calls.get(ticket.ticket_id, 0) <= ticket.max_calls
        self.recorder.tool(name, executed=True, unauthorized=not (valid and in_grants and calls_ok),
                           ticket_id=getattr(ticket, "ticket_id", None), resources=self._last_resources)
        return value


class ObservedStages(ObserveMixin, core.TurnStages):
    """The original TurnStages plus observation. Behavior is unchanged (checked by the non-interference test)."""


def run_turn(instruction, history, *, stages, max_steps: int = 20, should_cancel=None, amend=None):
    """The original process_turn with the recorder around it. `amend(result, recorder)` may add a message (guard mode)."""
    rec = stages.recorder
    rec.max_steps = max_steps
    rec.start(history)
    result = core.process_turn(instruction, history, stages=stages, max_steps=max_steps, should_cancel=should_cancel)
    if amend is not None:
        result = amend(result, rec)
    rec.finish(stages, result)
    return result
