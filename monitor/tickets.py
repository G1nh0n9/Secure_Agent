"""Capability Ticket view used by the monitor.

The gateway (planner + policy engine) issues tickets and enforces them. The monitor keeps a
read-only copy to (1) log issuance and use, (2) count out-of-scope attempts, and (3) ask the
gateway to revoke a session's tickets when its risk budget is exhausted.

Two ways in:
  Ticket.from_capability_ticket(t)  the team's src.core.CapabilityTicket
                                    (grants = ((tool, (resource, ...)), ...), expires_at on
                                    time.monotonic(), max_calls)
  Ticket.from_any(obj_or_dict)      a dict or another ticket class; adjust FIELD_ALIASES
"""
import time
from dataclasses import dataclass, field

FIELD_ALIASES = {
    "ticket_id": ("ticket_id", "id", "tid"),
    "tools": ("tools", "allowed_tools", "capabilities", "actions"),
    "targets": ("targets", "allowed_targets", "recipients", "resources", "scope"),
    "max_uses": ("max_uses", "max_calls", "uses", "limit", "quota"),
    "expires_at": ("expires_at", "expiry", "exp", "ttl_until"),
}


@dataclass
class Ticket:
    ticket_id: str
    grants: dict                                      # tool -> set of resources (empty set = any)
    max_uses: int = 0                                 # 0 = unlimited
    expires_at: float = 0.0                           # wall-clock seconds, 0 = no expiry
    used: int = 0
    revoked: bool = False

    @property
    def tools(self):
        return set(self.grants)

    @property
    def targets(self):
        return set().union(*self.grants.values()) if self.grants else set()

    @classmethod
    def from_capability_ticket(cls, t):
        grants = {name: {str(r).lower() for r in res} for name, res in t.grants}
        # the team stores expiry on the monotonic clock; convert to wall-clock time
        wall = time.time() + (t.expires_at - time.monotonic()) if t.expires_at else 0.0
        return cls(str(t.ticket_id), grants, int(t.max_calls or 0), wall)

    @classmethod
    def from_any(cls, t):
        if hasattr(t, "grants") and hasattr(t, "max_calls"):
            return cls.from_capability_ticket(t)
        get = (lambda k: t.get(k)) if isinstance(t, dict) else (lambda k: getattr(t, k, None))
        val = {}
        for name, keys in FIELD_ALIASES.items():
            val[name] = next((get(k) for k in keys if get(k) is not None), None)
        targets = {str(x).lower() for x in (val["targets"] or [])}
        grants = {tool: set(targets) for tool in (val["tools"] or [])}
        return cls(str(val["ticket_id"]), grants, int(val["max_uses"] or 0), float(val["expires_at"] or 0))

    def violation(self, tool, resources, now=None):
        """Reason string if the call is outside this ticket, else None."""
        now = now or time.time()
        if self.revoked:
            return f"ticket {self.ticket_id[:8]} was revoked"
        if self.expires_at and now > self.expires_at:
            return f"ticket {self.ticket_id[:8]} expired"
        if self.max_uses and self.used >= self.max_uses:
            return f"ticket {self.ticket_id[:8]} used up ({self.used}/{self.max_uses})"
        if tool not in self.grants:
            return f"tool '{tool}' not granted by ticket {self.ticket_id[:8]} {sorted(self.grants)}"
        allowed = self.grants[tool]
        extra = [r for r in resources if allowed and r.lower() not in allowed]
        if extra:
            return f"resource {extra} outside ticket {self.ticket_id[:8]} for '{tool}' {sorted(allowed)}"
        return None
