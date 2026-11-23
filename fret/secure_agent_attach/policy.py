"""Policy of the attach guards: configuration types and pure checks.

The guards in :mod:`secure_agent_attach.guard` wrap the unmodified
original and decide, for every call, whether a tool may run and whether
the model may be called.  The decisions live here, in functions without
state, so that each one can be judged against an independent oracle
(:mod:`secure_agent_attach.oracles`).

Design sources (keys resolve in ``docs/REFERENCES.md``):

* Every check denies when in doubt: fail-safe defaults, and every access
  goes through the checks: complete mediation [Saltzer1975].
* The checks are run-time enforcement of safety properties, the class of
  policies an execution monitor can enforce [Schneider2000].  A denial
  suppresses the action and may insert a message, as an edit automaton
  does [Ligatti2005].
* Limits on the size and the nesting depth of JSON are explicitly
  permitted for a parser [RFC8259, Sec. 9].
* Quotas on a shared resource: [CC2022-2, FRU_RSA.1]; consumption
  without limits is a named risk: [OWASP-LLM2025, LLM10].
"""

from __future__ import annotations

import dataclasses
import json
import types
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Optional

# A content rule receives the tool name, the validated arguments and the
# resources the tool says it will touch.  It returns the reason for a
# denial, or None to allow the call.
ContentRule = Callable[[str, Mapping[str, Any], Sequence[str]], Optional[str]]


class GuardDenied(PermissionError):
    """A guard refused a tool call.

    A subclass of the exception the original gate raises, so that the
    original's handling (the call is recorded as an error and the stage
    fails) applies unchanged.

    Attributes:
        reason: Why the call was refused.  It goes to the audit trail
            and to the user, never to the model.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class BudgetExceeded(Exception):
    """Raised instead of calling the model once a turn budget is spent.

    Attributes:
        reason: Which limit was reached.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


@dataclasses.dataclass(frozen=True)
class ArgumentLimits:
    """Structural limits for the arguments of one tool call.

    Attributes:
        max_bytes: Upper bound of the UTF-8 length of the JSON text.
        max_depth: Upper bound of the nesting depth of objects and
            arrays.  A flat object has depth 1.
    """

    max_bytes: int = 16 * 1024
    max_depth: int = 8

    def __post_init__(self) -> None:
        _require(self.max_bytes > 0, "max_bytes must be positive")
        _require(self.max_depth > 0, "max_depth must be positive")


@dataclasses.dataclass(frozen=True)
class SequenceRules:
    """Rules on the order and the number of tool calls.

    Both rules are history-based, in the sense of a Chinese-wall policy
    [Brewer1989]: what is allowed now depends on what already ran.

    Attributes:
        forbidden_after: Pairs ``(earlier, later)``.  Tool ``later`` may
            not run in a session in which tool ``earlier`` has run.
        max_calls_per_turn: Mapping from a tool name to the number of
            times the tool may run in one turn.
    """

    forbidden_after: frozenset = frozenset()
    max_calls_per_turn: Mapping[str, int] = dataclasses.field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "forbidden_after", frozenset(self.forbidden_after)
        )
        caps = dict(self.max_calls_per_turn)
        _require(
            all(cap >= 0 for cap in caps.values()),
            "a call cap must not be negative",
        )
        object.__setattr__(
            self, "max_calls_per_turn", types.MappingProxyType(caps)
        )


@dataclasses.dataclass(frozen=True)
class Budget:
    """Consumption limits of one turn for calls to the model.

    Sizes are counted in characters of the JSON text, a stand-in for
    tokens that needs no tokenizer (assumption A-09).  The defaults sit
    above what the original's own step and call limits allow in normal
    use, so they act on runaway turns only.

    Attributes:
        max_calls: Calls that may reach the provider in one turn.
        max_chars: Characters sent plus characters received in a turn.
        max_seconds: Seconds from the first stage of the turn.
    """

    max_calls: int = 40
    max_chars: int = 400_000
    max_seconds: float = 300.0

    def __post_init__(self) -> None:
        _require(self.max_calls > 0, "max_calls must be positive")
        _require(self.max_chars > 0, "max_chars must be positive")
        _require(self.max_seconds > 0, "max_seconds must be positive")


@dataclasses.dataclass(frozen=True)
class GuardPolicy:
    """Everything an operator can set for the guards.

    Attributes:
        arguments: Limits on the arguments of a tool call.
        result_max_chars: Longest serialized tool result that enters
            the conversation history; longer results are cut.
        sequence: Order and count rules for tool calls.
        content_rules: Operator rules that look at a call's content.
        budget: Per-turn consumption limits.
        evidence_retries: How often the evaluator may send a turn back
            to execution when it claims completion without evidence.
    """

    arguments: ArgumentLimits = dataclasses.field(
        default_factory=ArgumentLimits
    )
    result_max_chars: int = 16_000
    sequence: SequenceRules = dataclasses.field(default_factory=SequenceRules)
    content_rules: tuple = ()
    budget: Budget = dataclasses.field(default_factory=Budget)
    evidence_retries: int = 1

    def __post_init__(self) -> None:
        _require(
            self.result_max_chars >= 256,
            "result_max_chars must leave room for the cut notice",
        )
        _require(
            self.evidence_retries >= 0, "evidence_retries must not be negative"
        )


def measure(value: Any) -> int:
    """Return the size of ``value`` in characters of its JSON text.

    This is the unit of the budget (assumption A-09).  Values that JSON
    cannot encode are measured by their string form.
    """
    return len(json.dumps(value, ensure_ascii=False, default=str))


def nesting_depth(value: Any) -> int:
    """Return the nesting depth of the objects and arrays in ``value``.

    A scalar has depth 0 and a flat object has depth 1.  The walk is
    iterative, so that an adversarial depth cannot exhaust the stack.
    """
    deepest = 0
    stack = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, Mapping):
            children = node.values()
        elif isinstance(node, (list, tuple)):
            children = node
        else:
            continue
        deepest = max(deepest, depth + 1)
        stack.extend((child, depth + 1) for child in children)
    return deepest


_JSON_TYPES = {
    "object": lambda v: isinstance(v, Mapping),
    "array": lambda v: isinstance(v, (list, tuple)),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: (
        isinstance(v, (int, float)) and not isinstance(v, bool)
    ),
    "null": lambda v: v is None,
}


def schema_violation(
    value: Any, schema: Any, path: str = "arguments"
) -> Optional[str]:
    """Return why ``value`` breaks ``schema``, or None if it conforms.

    Only a subset of JSON Schema is enforced: ``type``, ``enum``,
    ``properties``, ``required``, ``additionalProperties`` (a boolean or
    a schema), ``items``, ``maxLength``, ``minimum`` and ``maximum``.
    Other keywords are ignored, as the specification allows
    [JSONSchema2020-12]; the tool's own ``validate`` still runs after
    this check.  A schema that is not an object constrains nothing.

    Args:
        value: The decoded JSON value to check.
        schema: The schema, normally ``ToolDefinition.parameters``.
        path: Name of ``value`` in the reason, for readability.

    Returns:
        A short reason, or None.
    """
    if not isinstance(schema, Mapping):
        return None
    wanted = schema.get("type")
    if wanted is not None:
        names = [wanted] if isinstance(wanted, str) else list(wanted)
        known = [_JSON_TYPES[n] for n in names if n in _JSON_TYPES]
        if known and not any(test(value) for test in known):
            return f"{path} must be of type {'/'.join(names)}"
    if "enum" in schema and value not in list(schema["enum"]):
        return f"{path} is not one of the allowed values"
    if isinstance(value, str) and "maxLength" in schema:
        if len(value) > schema["maxLength"]:
            return f"{path} is longer than {schema['maxLength']} characters"
    if _JSON_TYPES["number"](value):
        if "minimum" in schema and value < schema["minimum"]:
            return f"{path} is below {schema['minimum']}"
        if "maximum" in schema and value > schema["maximum"]:
            return f"{path} is above {schema['maximum']}"
    if isinstance(value, Mapping):
        return _object_violation(value, schema, path)
    if isinstance(value, (list, tuple)) and "items" in schema:
        for index, item in enumerate(value):
            reason = schema_violation(
                item, schema["items"], f"{path}[{index}]"
            )
            if reason:
                return reason
    return None


def _object_violation(
    value: Mapping, schema: Mapping, path: str
) -> Optional[str]:
    properties = schema.get("properties") or {}
    for name in schema.get("required") or ():
        if name not in value:
            return f"{path} lacks the required field {name!r}"
    extra = schema.get("additionalProperties", True)
    for name, item in value.items():
        if name in properties:
            reason = schema_violation(item, properties[name], f"{path}.{name}")
            if reason:
                return reason
        elif extra is False:
            return f"{path} has the unexpected field {name!r}"
        elif isinstance(extra, Mapping):
            reason = schema_violation(item, extra, f"{path}.{name}")
            if reason:
                return reason
    return None


def argument_violation(
    arguments: Any, schema: Any, limits: ArgumentLimits
) -> Optional[str]:
    """Return why the arguments of a tool call are refused, or None.

    The arguments must be a JSON object, within the size and depth
    limits, and conform to the tool's declared parameter schema.  The
    check runs before any tool code sees the arguments (GATE-17).
    """
    if not isinstance(arguments, Mapping):
        return "the arguments are not a JSON object"
    try:
        text = json.dumps(arguments, ensure_ascii=False)
    except (TypeError, ValueError):
        return "the arguments cannot be encoded as JSON"
    if len(text.encode("utf-8")) > limits.max_bytes:
        return f"the arguments exceed {limits.max_bytes} bytes"
    if nesting_depth(arguments) > limits.max_depth:
        return f"the arguments nest deeper than {limits.max_depth} levels"
    return schema_violation(arguments, schema)


def content_violation(
    rules: Sequence[ContentRule],
    tool: str,
    arguments: Mapping[str, Any],
    resources: Sequence[str],
) -> Optional[str]:
    """Return the first reason an operator rule gives, or None.

    A rule that raises refuses the call: when a check cannot be carried
    out, access is denied [Saltzer1975, fail-safe defaults] (GATE-18).
    """
    for rule in rules:
        try:
            reason = rule(tool, arguments, tuple(resources))
        except Exception as error:  # noqa: BLE001 - fail closed
            name = getattr(rule, "__name__", "a content rule")
            return f"{name} failed with {type(error).__name__}"
        if reason:
            return reason
    return None


def sequence_violation(
    rules: SequenceRules,
    tool: str,
    ran_in_session: frozenset,
    calls_this_turn: int,
) -> Optional[str]:
    """Return why the order rules refuse the call, or None (GATE-19).

    Args:
        rules: The rules in force.
        tool: Name of the tool about to run.
        ran_in_session: Tools that have run in this session so far, in
            any turn.
        calls_this_turn: How often ``tool`` has run in this turn.
    """
    for earlier in sorted(ran_in_session):
        if (earlier, tool) in rules.forbidden_after:
            return (
                f"tool {tool!r} may not run in a session in which "
                f"{earlier!r} has run"
            )
    cap = rules.max_calls_per_turn.get(tool)
    if cap is not None and calls_this_turn >= cap:
        return f"tool {tool!r} reached its limit of {cap} calls per turn"
    return None


def over_budget(
    budget: Budget, calls: int, chars: int, new_chars: int, elapsed: float
) -> Optional[str]:
    """Return which limit a call to the model would break, or None.

    Args:
        budget: The limits of the turn.
        calls: Calls made so far in this turn.
        chars: Characters sent and received so far in this turn.
        new_chars: Size of the call about to be made.
        elapsed: Seconds since the turn started.
    """
    if calls >= budget.max_calls:
        return f"the limit of {budget.max_calls} model calls is reached"
    if chars + new_chars > budget.max_chars:
        return f"the limit of {budget.max_chars} characters would be passed"
    if elapsed > budget.max_seconds:
        return f"the time limit of {budget.max_seconds:g} seconds is over"
    return None


def truncate_result(value: Any, cap: int) -> Any:
    """Return ``value``, or a cut text of it if it exceeds ``cap``.

    The result enters the history as ``{"result": value}`` and is sent
    to the model on every later call, so its size is a cost
    (EXE-16).  A value that fits is returned unchanged.  A longer value
    is replaced by a string: the start of its JSON text and a notice
    that says how long the whole was.  A value that JSON cannot encode
    is returned unchanged; the original then reports the error itself.
    """
    try:
        text = json.dumps(value, ensure_ascii=False)
        if len(json.dumps({"result": value}, ensure_ascii=False)) <= cap:
            return value
    except (TypeError, ValueError):
        return value
    notice = f" ...[cut: {len(text)} characters in all]"
    keep = max(cap - len(notice) - 16, 0)
    while True:
        candidate = text[:keep] + notice
        if len(json.dumps({"result": candidate}, ensure_ascii=False)) <= cap:
            return candidate
        keep = keep * 3 // 4
