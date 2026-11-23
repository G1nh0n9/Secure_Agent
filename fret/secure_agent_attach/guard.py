"""Guards added from outside the original, all opt-in.

Each guard closes a gap that a requirement of ``core_spec.json``
showed.  Nothing here edits the original.  The guards subclass
``TurnStages`` and wrap the objects the original is configured with:
the tools and the call to the model.  The original gate
(``_execute_tool``) therefore stays the only path to a tool, which
keeps complete mediation [Saltzer1975]; the reference-monitor argument
depends on it [Anderson1972].

=========================  =========================================
Requirement                Guard
=========================  =========================================
AUT-06, AUT-10, AUT-11     least privilege at authorization
TRN-09                     re-authorization when a ticket is gone
HIS-01 to HIS-05           ``TrustedHistory`` on restore
TRN-10                     ``amend_denied``
GATE-17                    shape check of the arguments, before the
                           tool's own ``validate``
GATE-18                    operator content rules
GATE-19, GATE-21           order rules on the ``CallLedger``
EXE-15                     unparsable tool calls are recorded
EXE-16                     long tool results are cut
EVA-11                     ``completed`` needs an executed call
LLM-10, LLM-11, TRN-13/14  per-turn budget at the provider call
=========================  =========================================

The turn in progress, the budget and the context of the running gate
call are instance attributes (assumption A-11).
"""

from __future__ import annotations

import dataclasses
import json
from typing import Optional

from .ledger import CallLedger, UsageMeter
from .observe import ObserveMixin, core, run_turn
from .policy import (
    BudgetExceeded,
    GuardDenied,
    GuardPolicy,
    argument_violation,
    content_violation,
    measure,
    over_budget,
    sequence_violation,
    truncate_result,
)

__all__ = [
    "GuardMixin",
    "GuardedStages",
    "TrustedHistory",
    "amend_denied",
    "amend_budget",
    "attached_process_turn",
]


def _requested(plan) -> dict:
    """Return the resources the plan requested, per tool."""
    out: dict = {}
    for step in (plan.steps if plan else ()):
        if step.requested_tool is not None:
            out.setdefault(step.requested_tool, set()).update(
                step.requested_resources
            )
    return out


class GuardMixin:
    """Guards for the four stages and for the gate of ``TurnStages``.

    Put after ``ObserveMixin`` and before ``core.TurnStages`` in the
    list of base classes, so that the observer sees the final
    behaviour.

    Attributes:
        policy: The :class:`GuardPolicy` in force.
        ledger: The :class:`CallLedger` of executed tool calls.
        call_record: The ledger's entries (the probes read this).
        max_renewals: How often one turn may be sent back to
            authorization because its ticket expired.
    """

    max_renewals = 2

    def __init__(
        self, *args, policy: Optional[GuardPolicy] = None, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.policy = policy or GuardPolicy()
        self.ledger = CallLedger()
        self.call_record = self.ledger.entries
        self._renewals = 0
        self._meter = UsageMeter(started=core.time.monotonic())
        self._turn = None  # context of the turn in progress
        self._call_context = None  # (context, tool) of the gate call
        self._worker_response = None  # last answer of the worker model
        self._evidence_tries = 0
        # The tool code is reached only through the gate.  Wrapping it
        # here lets the original gate stay the point of mediation.
        self.tools = {
            name: self._guard_tool(name, tool)
            for name, tool in self.tools.items()
        }
        if self.call_llm is not None:
            self.call_llm = self._metered(self.call_llm)

    @property
    def usage(self) -> dict:
        """Calls and characters spent by the turn in progress."""
        return self._meter.snapshot()

    def _note(self, event: str, **detail) -> None:
        recorder = getattr(self, "recorder", None)
        if recorder is not None:
            recorder.note(event, **detail)

    # -- per-turn state ---------------------------------------------

    def _enter_turn(self, context) -> None:
        """Reset the per-turn state if ``context`` is a new turn.

        ``process_turn`` builds one ``TurnContext`` per turn and hands
        it to every stage, so a new object means a new turn.  The
        budget is reset here and nowhere else: re-entering a stage must
        not renew it, and an earlier turn must not use up a later one
        (TRN-14).
        """
        if context is not self._turn:
            self._turn = context
            self._meter.reset(core.time.monotonic())
            self._evidence_tries = 0
            self._note("usage_reset")

    def _stage(self, run, context):
        """Run a stage; turn a spent budget into a visible result."""
        self._enter_turn(context)
        try:
            return run(context)
        except BudgetExceeded as spent:
            return self._budget_stop(spent.reason)

    def _budget_stop(self, reason: str):
        """End the turn with a message that says why (TRN-13)."""
        self._note("budget_stop", reason=reason)
        message = (
            "The usage budget of this turn is exhausted ("
            + reason
            + "), so the turn was stopped without a "
            "result."
        )
        return core.StageResult(core.TurnState.LIMIT_REACHED, message=message)

    # -- stages -----------------------------------------------------

    def analyze_instruction(self, context):
        """Run the analysis stage under the per-turn budget."""
        return self._stage(super().analyze_instruction, context)

    def authorize_task(self, context):
        """Run the authorization stage with least privilege."""
        return self._stage(self._authorize_least_privilege, context)

    def execute_task(self, context):
        """Run the execution stage under the guards."""
        return self._stage(self._execute_guarded, context)

    def evaluate_result(self, context):
        """Run the evaluation stage; completion needs evidence."""
        return self._stage(self._evaluate_with_evidence, context)

    def _authorize_least_privilege(self, context):
        """Trim the grants to what the plan asked for (AUT-06/10/11).

        Least privilege: a subject gets the privileges its task needs
        and no more [Saltzer1975]; [NIST800-53r5, AC-6].
        """
        result = super().authorize_task(context)
        ticket = self._tickets.get(context.ticket)
        if ticket is None or result.next_state != core.TurnState.EXECUTE:
            return result
        requested = _requested(context.plan)
        grants = tuple(
            (name, tuple(sorted(set(resources) & requested[name])))
            for name, resources in ticket.grants
            if name in requested
        )
        if grants == ticket.grants:
            return result
        self._note(
            "grants_trimmed",
            before=[[n, list(r)] for n, r in ticket.grants],
            after=[[n, list(r)] for n, r in grants],
        )
        if requested and not grants:
            self.revoke_ticket(context)
            return core.StageResult(
                core.TurnState.FAILED,
                message="Least privilege: none of the verified grants "
                "was requested by the plan",
            )
        self._tickets[ticket.ticket_id] = dataclasses.replace(
            ticket, grants=grants
        )
        return result

    def _execute_guarded(self, context):
        """Renew a missing ticket, then run the stage (TRN-09)."""
        ticket = self._tickets.get(context.ticket)
        if ticket is None or core.time.monotonic() >= ticket.expires_at:
            if self._renewals >= self.max_renewals:
                self._note("renewal_limit")
                return core.StageResult(
                    core.TurnState.FAILED,
                    message="The ticket expired and the renewal limit "
                    "was reached",
                )
            self._renewals += 1
            self._note(
                "reauthorize",
                reason=(
                    "ticket missing" if ticket is None else "ticket expired"
                ),
            )
            return core.StageResult(
                core.TurnState.AUTHORIZE,
                message="Ticket expired; authorizing again",
            )
        self._worker_response = None
        try:
            return super().execute_task(context)
        except json.JSONDecodeError as error:
            self._record_unparsable_call(context, error)
            raise

    def _evaluate_with_evidence(self, context):
        """Do not accept ``completed`` without an executed call.

        This is requirement EVA-11.  Evidence is a call that the gate
        executed and that returned normally, taken from the ledger and
        not from the history.  The turn gets
        ``evidence_retries`` chances to execute; after that it fails
        with a message the user can read.
        """
        result = super().evaluate_result(context)
        if (
            result.next_state is not core.TurnState.COMPLETED
            or self._has_evidence(context)
        ):
            return result
        self._note("completion_without_evidence", tries=self._evidence_tries)
        if self._evidence_tries < self.policy.evidence_retries:
            self._evidence_tries += 1
            return core.StageResult(
                core.TurnState.EXECUTE,
                message="No successful tool execution is recorded for "
                "this task. Execute the planned tools, or "
                "report that the task cannot be completed.",
            )
        return core.StageResult(
            core.TurnState.FAILED,
            message="The assistant reported completion, but no "
            "successful tool execution was recorded for this "
            "task, so it is not marked as completed.",
        )

    def _has_evidence(self, context) -> bool:
        plan = context.plan
        if plan is None or all(
            step.requested_tool is None for step in plan.steps
        ):
            return True  # the plan needed no tool
        instruction = context.instruction
        return self.ledger.succeeded(
            instruction.session_id, instruction.turn_id
        )

    def _record_unparsable_call(self, context, error) -> None:
        """Record a tool call whose arguments are not JSON (EXE-15).

        The original raises before it writes the call to the history,
        so the attempt would leave no trace.  The offending call is
        found by matching the text that failed to parse.  It is
        recorded and counted exactly like a call that reached the
        gate, and the original's exception then propagates as before.
        """
        response = self._worker_response or {}
        for call in response.get("tool_calls") or []:
            function = call.get("function") if isinstance(call, dict) else None
            if not isinstance(function, dict):
                continue
            if function.get("arguments") != error.doc:
                continue
            name = function.get("name")
            name = name if isinstance(name, str) else "<unnamed>"
            turn = context.instruction.turn_id
            call_id = str(core.uuid4())
            context.history.add_tool_call(turn, call_id, name, {})
            context.tool_attempts += 1
            context.history.add_tool_result(
                turn,
                call_id,
                json.dumps(
                    {"error_type": type(error).__name__}, ensure_ascii=False
                ),
                is_error=True,
            )
            self._note(
                "malformed_tool_call", tool=name, excerpt=error.doc[:200]
            )
            return

    # -- the gate ---------------------------------------------------

    def _execute_tool(self, context, name, arguments):
        """Tell the wrapped tool which call it serves, then gate it."""
        self._call_context = (context, name)
        try:
            return super()._execute_tool(context, name, arguments)
        finally:
            self._call_context = None

    def _require_gate(self):
        """Return the context of the running gate call, or refuse."""
        if self._call_context is None:
            raise GuardDenied("tool code was reached outside the gate")
        return self._call_context[0]

    def _guard_tool(self, name: str, tool):
        """Wrap the three functions of a tool with the call guards.

        The original gate calls ``validate``, ``resources`` and
        ``execute`` in this order and checks grants, resources and the
        call budget in between.  Each wrapper adds one check at the
        matching point, so a refused call never reaches the next step
        and never uses up the ticket's call budget (GATE-17 to
        GATE-19).
        """
        policy = self.policy

        def validate(arguments):
            self._require_gate()
            reason = argument_violation(
                arguments, tool.parameters, policy.arguments
            )
            if reason:
                raise GuardDenied(reason)
            return tool.validate(arguments)

        def resources(checked):
            context = self._require_gate()
            touched = tool.resources(checked)
            instruction = context.instruction
            reason = content_violation(
                policy.content_rules, name, checked, touched
            )
            reason = reason or sequence_violation(
                policy.sequence,
                name,
                self.ledger.tools_run(instruction.session_id),
                self.ledger.calls(
                    instruction.session_id, instruction.turn_id, name
                ),
            )
            if reason:
                raise GuardDenied(reason)
            return touched

        def execute(checked):
            instruction = self._require_gate().instruction
            entry = self.ledger.begin(
                instruction.session_id, instruction.turn_id, name
            )
            value = tool.execute(checked)
            self.ledger.succeed(entry)
            return truncate_result(value, policy.result_max_chars)

        return dataclasses.replace(
            tool, validate=validate, resources=resources, execute=execute
        )

    # -- the call to the model --------------------------------------

    def _metered(self, provider):
        """Wrap the provider call with the per-turn budget.

        A call that would pass a limit is not made and raises
        :class:`BudgetExceeded`; the stage wrapper turns that into the
        end of the turn.  The call and what is sent are counted before
        the call, the answer after it (LLM-10, LLM-11).  A failing
        provider still costs a call.
        """

        def call(messages, tools, json_output):
            meter, budget = self._meter, self.policy.budget
            sent = measure(messages) + measure(tools)
            elapsed = core.time.monotonic() - meter.started
            reason = over_budget(
                budget, meter.calls, meter.chars, sent, elapsed
            )
            if reason:
                self._note(
                    "budget_refused",
                    reason=reason,
                    calls=meter.calls,
                    chars=meter.chars,
                    sent=sent,
                    elapsed=elapsed,
                )
                raise BudgetExceeded(reason)
            meter.calls += 1
            meter.chars += sent
            response = provider(messages, tools, json_output)
            meter.chars += measure(response)
            if not json_output:
                self._worker_response = response
            return response

        return call


class GuardedStages(ObserveMixin, GuardMixin, core.TurnStages):
    """The original ``TurnStages`` plus the guards, observed.

    Example:
        stages = GuardedStages(call_llm, tools=tools,
                               policy=GuardPolicy(budget=Budget(10)))
    """


class TrustedHistory(core.ConversationHistory):
    """Restore a history without trusting the stream (HIS-01 to HIS-05).

    Only user and assistant records of the stream's own session are
    kept.  Managed entries, tool records, records of kinds the core
    does not know and records of another session are dropped and
    counted in ``restore_dropped``.  A record without a session id is
    malformed and raises, as in the original.  The operator prompt
    comes from configuration, not from the stream.
    """

    OPERATOR_MANAGED: Optional[str] = None

    @classmethod
    def from_jsonl(cls, lines):
        """Build a history from JSON lines, dropping untrusted ones."""
        records = [json.loads(line) for line in lines if line.strip()]
        if not records:
            raise ValueError("empty history stream")
        session = records[0]["session_id"]
        kept = [
            r
            for r in records
            if ("kind" not in r or r["kind"] in ("user", "assistant"))
            and r["session_id"] == session
        ]
        head = []
        if cls.OPERATOR_MANAGED is not None:
            head = [
                {
                    "session_id": session,
                    "task_id": None,
                    "turn_id": None,
                    "kind": "managed",
                    "content": cls.OPERATOR_MANAGED,
                    "call_id": None,
                    "tool_name": None,
                    "arguments": None,
                    "is_error": False,
                }
            ]
        merged = head + kept
        if merged:
            history = core.ConversationHistory.from_jsonl(
                json.dumps(r) for r in merged
            )
        else:
            history = core.ConversationHistory(session)
        history.restore_dropped = len(records) - len(kept)
        return history


def amend_denied(result, rec):
    """Make a turn that saw a denial end with a message (TRN-10)."""
    if rec.denial_seen and not (result.message or "").strip():
        reasons = list(
            dict.fromkeys(
                e["reason"]
                for e in rec.audit
                if e["event"] in ("tool_denied", "blocked_start")
                and e.get("reason")
            )
        )
        text = (
            "The turn ended without a result. Tool execution was "
            "denied or blocked: " + ("; ".join(reasons) or "see the audit log")
        )
        rec.note("result_message_added", message=text)
        return dataclasses.replace(result, message=text)
    return result


def amend_budget(result, rec):
    """Add a message if a budget stop was swallowed on the way.

    The stage wrapper already returns the message (TRN-13); this is a
    safety net, so that a budget stop never ends without one.
    """
    stopped = any(
        e["event"] in ("budget_refused", "budget_stop") for e in rec.audit
    )
    if stopped and not (result.message or "").strip():
        text = (
            "The usage budget of this turn is exhausted, so the "
            "turn was stopped without a result."
        )
        rec.note("result_message_added", message=text)
        return dataclasses.replace(result, message=text)
    return result


def attached_process_turn(
    instruction,
    history,
    *,
    stages=None,
    max_steps: int = 20,
    should_cancel=None,
):
    """Run the original ``process_turn`` with the guards on."""

    def amend(result, rec):
        return amend_budget(amend_denied(result, rec), rec)

    return run_turn(
        instruction,
        history,
        stages=stages,
        max_steps=max_steps,
        should_cancel=should_cancel,
        amend=amend,
    )
