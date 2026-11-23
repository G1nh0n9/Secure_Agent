"""State the guards keep between calls: executed calls and usage.

Both records are written by the guards themselves.  Neither is read back
from the conversation history, which a restored stream can forge
(HIS-01 to HIS-05).  A record of what was done is the basis of
accountability [Saltzer1975, "compromise recording"]; the audit data of
[CC2022-2, FAU_GEN.1] has the same purpose.
"""

from __future__ import annotations

import dataclasses


class CallLedger:
    """Append-only record of the tool calls that reached ``execute``.

    An entry is written before the tool runs and marked successful when
    it returns, so a tool that fails halfway still counts as a call.
    The order rules [Brewer1989] and the completion check read this
    record (GATE-19, GATE-21, EVA-11).

    Attributes:
        entries: One dict per call with the keys ``session``, ``turn``,
            ``tool`` and ``ok``.  The guards expose this list as
            ``call_record``.
    """

    def __init__(self) -> None:
        self.entries: list = []
        self._tools: dict = {}
        self._calls: dict = {}
        self._successes: dict = {}

    def begin(self, session: str, turn: int, tool: str) -> dict:
        """Record that ``tool`` is about to run and return its entry."""
        entry = {"session": session, "turn": turn, "tool": tool, "ok": False}
        self.entries.append(entry)
        self._tools.setdefault(session, set()).add(tool)
        key = (session, turn, tool)
        self._calls[key] = self._calls.get(key, 0) + 1
        return entry

    def succeed(self, entry: dict) -> None:
        """Mark the call of ``entry`` as having returned normally."""
        if entry["ok"]:
            return
        entry["ok"] = True
        key = (entry["session"], entry["turn"])
        self._successes[key] = self._successes.get(key, 0) + 1

    def tools_run(self, session: str) -> frozenset:
        """Return the tools that ran in ``session``, in any turn."""
        return frozenset(self._tools.get(session, ()))

    def calls(self, session: str, turn: int, tool: str) -> int:
        """Return how often ``tool`` has run in the given turn."""
        return self._calls.get((session, turn, tool), 0)

    def succeeded(self, session: str, turn: int) -> bool:
        """Return whether any call of the turn returned normally."""
        return self._successes.get((session, turn), 0) > 0


@dataclasses.dataclass
class UsageMeter:
    """Calls to the model and characters spent by the turn in progress.

    Attributes:
        started: Monotonic time at which the turn began.
        calls: Calls that were made (or tried) in this turn.
        chars: Characters sent plus characters received so far.
    """

    started: float = 0.0
    calls: int = 0
    chars: int = 0

    def reset(self, now: float) -> None:
        """Start a new turn at monotonic time ``now`` (TRN-14)."""
        self.started, self.calls, self.chars = now, 0, 0

    def snapshot(self) -> dict:
        """Return the totals as a dict with ``calls`` and ``chars``."""
        return {"calls": self.calls, "chars": self.chars}
