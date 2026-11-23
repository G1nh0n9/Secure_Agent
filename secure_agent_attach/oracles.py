"""Reference oracles for the extension requirements.

The requirements GATE-17 to GATE-21, EXE-15, EXE-16, EVA-11, TRN-13,
TRN-14 and LLM-10 to LLM-12 ask for behaviour that the original does not
have.  An oracle states what a correct implementation must decide.  It
is written independently of the guards in
:mod:`secure_agent_attach.guard`: it shares no code with
:mod:`secure_agent_attach.policy`, so that a mistake in one is not
repeated in the other.  The probes feed the same calls to the stack
under test and compare its behaviour with the oracle.

The oracles judge by the properties of a reference monitor: it is
invoked on every access, and its decision does not depend on the
implementation of the thing it guards [Anderson1972]; the properties
enforced are safety properties [Schneider2000].

Sizes are counted in characters (assumption A-09).
"""

from __future__ import annotations

import json

# Parameter schema of the probes' tool.  A string-only object with one
# required field; unknown fields are refused [JSONSchema2020-12].
SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string"},
        "note": {"type": "string"},
        "meta": {"type": "object"},
    },
    "required": ["target"],
    "additionalProperties": False,
}
MAX_ARG_BYTES = 2000  # UTF-8 bytes of the arguments' JSON text
MAX_ARG_DEPTH = 4  # nesting depth of objects and arrays
RESULT_CAP = 16000  # characters of a result entering the history
SEQ_FORBID = frozenset({("a", "t")})  # t may not run once a has run
SEQ_CAP = {"c": 2}  # tool c runs at most twice per turn

# Per-turn budgets: model calls, characters sent and received, seconds.
# The prompts of the real stages are thousands of characters long, so
# the whole-turn scenarios use budgets with a character limit out of
# reach.
BUDGET = {"calls": 3, "chars": 2000, "seconds": 30.0}
BUDGET_RUNAWAY = {"calls": 3, "chars": 100_000, "seconds": 30.0}
BUDGET_ROOMY = {"calls": 6, "chars": 100_000, "seconds": 30.0}


def _depth(node) -> int:
    """Return the nesting depth of objects and arrays in ``node``."""
    if isinstance(node, dict):
        return 1 + max((_depth(v) for v in node.values()), default=0)
    if isinstance(node, list):
        return 1 + max((_depth(v) for v in node), default=0)
    return 0


def oracle_shape_ok(arguments) -> bool:
    """Say whether the arguments are an acceptable JSON object.

    Acceptable means: an object that fits :data:`SCHEMA` (``target``
    present, only the declared fields, each of its declared type), and
    whose JSON text and nesting stay within the limits.  The size limit
    is bounded by the parser's freedom to refuse large texts [RFC8259,
    Sec. 9].
    """
    if not isinstance(arguments, dict):
        return False
    allowed = SCHEMA["properties"]
    if any(key not in allowed for key in arguments):
        return False
    if any(key not in arguments for key in SCHEMA["required"]):
        return False
    for key, value in arguments.items():
        kind = allowed[key]["type"]
        if kind == "string" and not isinstance(value, str):
            return False
        if kind == "object" and not isinstance(value, dict):
            return False
    text = json.dumps(arguments, ensure_ascii=False)
    return (
        len(text.encode("utf-8")) <= MAX_ARG_BYTES
        and _depth(arguments) <= MAX_ARG_DEPTH
    )


def oracle_content_ok(arguments) -> bool:
    """Say whether the probes' content policy allows the call.

    The policy of the probes refuses a note that reads ``EVIL``.
    """
    return not (
        isinstance(arguments, dict) and arguments.get("note") == "EVIL"
    )


def evil_note_rule(tool, arguments, resources):
    """Content rule that realizes :func:`oracle_content_ok` as policy.

    It is the operator rule handed to the guard in the probes.  The
    oracle above is the independent statement of what the rule must do.
    """
    if arguments.get("note") == "EVIL":
        return "the note is refused by the content policy"
    return None


def oracle_sequence_ok(ran, session: str, turn: int, tool: str) -> bool:
    """Say whether the order rules allow ``tool`` to run now.

    Args:
        ran: Triples ``(session, turn, tool)`` of the calls that ran.
        session: Session of the call.
        turn: Turn of the call.
        tool: Tool about to run.

    The ban applies to a whole session, the call cap to one turn, as in
    the history-based policies of [Brewer1989].
    """
    for seen_session, _, earlier in ran:
        if seen_session == session and (earlier, tool) in SEQ_FORBID:
            return False
    cap = SEQ_CAP.get(tool)
    if cap is None:
        return True
    return sum(1 for entry in ran if entry == (session, turn, tool)) < cap


def oracle_budget_over(
    calls: int, chars: int, new_chars: int, elapsed: float, budget=BUDGET
) -> bool:
    """Say whether a model call would break the budget of the turn.

    Args:
        calls: Calls that reached the provider so far in the turn.
        chars: Characters sent and received so far in the turn.
        new_chars: Characters the call would send.
        elapsed: Seconds since the turn began.
        budget: Mapping with ``calls``, ``chars`` and ``seconds``.
    """
    return (
        calls >= budget["calls"]
        or chars + new_chars > budget["chars"]
        or elapsed > budget["seconds"]
    )
