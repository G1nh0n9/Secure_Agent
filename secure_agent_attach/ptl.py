"""Past-time LTL in the notation of FRET's ``ltl_pt`` strings.

A parser, a finite-trace evaluator and a NuSMV printer.  This is an
own implementation that needs no other tool; ``selftest`` checks the
evaluator against NuSMV on random traces.

Semantics, as in NuSMV: Y is strong yesterday (false at the first
tick), Z is weak yesterday (true at the first tick), ``a S b`` is
strong since (b must have held) and ``a T b`` is its dual.
"""

from __future__ import annotations

import re

TOK = re.compile(
    r"\s*([HOFG]\[[^\]]*\]|<->|->|<=|>=|!=|[A-Za-z_][A-Za-z0-9_]*"
    r"|\d+\.\d+|\d+|[()!&|<>=+\-*/,])"
)
UNARY = {"!", "H", "O", "Y", "Z", "X", "F", "G"}
CMP = {"<", "<=", ">", ">=", "=", "!="}
ARI = {"+", "-", "*"}
BOOL2 = {"&", "|", "->", "<->"}
WIN = re.compile(r"^([HO])\[(?:(<=|<)\s*(\d+)|(\d+)\s*,\s*(\d+))\]$")


class Unsupported(Exception):
    """Raised for a formula the evaluator does not support."""


def lex(s: str) -> list[str]:
    """Split a formula into tokens."""
    out, p, s = [], 0, s.strip()
    while p < len(s):
        m = TOK.match(s, p)
        if not m:
            raise ValueError("cannot lex: " + s[p : p + 24])
        out.append(m.group(1))
        p = m.end()
    return out


def _window(op: str) -> tuple[str, int, int]:
    m = WIN.match(op)
    if not m:
        raise Unsupported("window operator " + op)
    if m.group(2):
        return (
            m.group(1),
            0,
            int(m.group(3)) - (0 if m.group(2) == "<=" else 1),
        )
    return m.group(1), int(m.group(4)), int(m.group(5))


def parse(s: str):
    """Parse fully parenthesised formulas: (op a), (a op b), (a)."""
    toks, pos = lex(s), [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def nxt():
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def expect(t):
        got = nxt()
        if got != t:
            raise ValueError(f"expected {t!r}, got {got!r}")

    def is_unary(t):
        return t in UNARY or bool(t and re.match(r"^[HOFG]\[", t))

    def atom():
        t = nxt()
        if t == "(":
            if is_unary(peek()):
                op = nxt()
                a = atom()
                expect(")")
                if "[" in op:
                    kind, lo, hi = _window(op)
                    return ("win", kind, lo, hi, a)
                return (op, a)
            a = atom()
            if peek() == ")":
                nxt()
                return a
            op = nxt()
            b = atom()
            expect(")")
            return (op, a, b)
        if t in ("TRUE", "FALSE"):
            return ("const", t == "TRUE")
        if re.fullmatch(r"\d+\.\d+", t):
            return ("num", float(t))
        if re.fullmatch(r"\d+", t):
            return ("num", int(t))
        if t == "-":
            return ("neg", atom())
        if re.fullmatch(r"[A-Za-z_]\w*", t):
            return ("var", t)
        raise ValueError("unexpected token " + t)

    ast = atom()
    if pos[0] != len(toks):
        raise ValueError("trailing tokens after formula")
    return ast


def variables(node, acc=None) -> set[str]:
    """Return the names of the variables a formula mentions."""
    acc = acc if acc is not None else set()
    if node[0] == "var":
        acc.add(node[1])
    for x in node[1:]:
        if isinstance(x, tuple):
            variables(x, acc)
    return acc


def evaluate(ast, ticks: list[dict]) -> list:
    """Return the value of the formula at every tick of a trace.

    ``ticks`` is a list of ``{signal: bool or int}`` dicts.
    """
    n = len(ticks)
    memo: dict[int, list] = {}

    def ev(node):
        key = id(node)
        if key in memo:
            return memo[key]
        k = node[0]
        if k == "var":
            name = node[1]
            try:
                out = [t[name] for t in ticks]
            except KeyError:
                raise KeyError(
                    f"signal {name!r} is missing in the trace"
                ) from None
        elif k in ("const", "num"):
            out = [node[1]] * n
        elif k == "neg":
            out = [-x for x in ev(node[1])]
        elif k == "!":
            out = [not x for x in ev(node[1])]
        elif k in BOOL2:
            a, b = ev(node[1]), ev(node[2])
            f = {
                "&": lambda x, y: x and y,
                "|": lambda x, y: x or y,
                "->": lambda x, y: (not x) or y,
                "<->": lambda x, y: bool(x) == bool(y),
            }[k]
            out = [bool(f(x, y)) for x, y in zip(a, b)]
        elif k in CMP:
            a, b = ev(node[1]), ev(node[2])
            f = {
                "<": lambda x, y: x < y,
                "<=": lambda x, y: x <= y,
                ">": lambda x, y: x > y,
                ">=": lambda x, y: x >= y,
                "=": lambda x, y: x == y,
                "!=": lambda x, y: x != y,
            }[k]
            out = [bool(f(x, y)) for x, y in zip(a, b)]
        elif k in ARI:
            a, b = ev(node[1]), ev(node[2])
            f = {
                "+": lambda x, y: x + y,
                "-": lambda x, y: x - y,
                "*": lambda x, y: x * y,
            }[k]
            out = [f(x, y) for x, y in zip(a, b)]
        elif k == "Y":
            out = [False] + [bool(x) for x in ev(node[1])[:-1]]
        elif k == "Z":
            out = [True] + [bool(x) for x in ev(node[1])[:-1]]
        elif k == "O":
            out, seen = [], False
            for x in ev(node[1]):
                seen = seen or bool(x)
                out.append(seen)
        elif k == "H":
            out, ok = [], True
            for x in ev(node[1]):
                ok = ok and bool(x)
                out.append(ok)
        elif k == "S":
            a, b = ev(node[1]), ev(node[2])
            out, prev = [], False
            for x, y in zip(a, b):
                prev = bool(y) or (bool(x) and prev)
                out.append(prev)
        elif k == "T":  # a T b  ==  !( !a S !b )
            a, b = ev(node[1]), ev(node[2])
            out, prev = [], False
            for x, y in zip(a, b):
                prev = (not y) or ((not x) and prev)
                out.append(not prev)
        elif k == "win":
            _, kind, lo, hi, sub = node
            v = [bool(x) for x in ev(sub)]
            out = []
            for t in range(n):
                cells = [v[t - j] for j in range(lo, hi + 1) if t - j >= 0]
                out.append(
                    any(cells) if kind == "O" else all(cells)
                )  # O: strong at the start, H: weak at the start
        else:
            raise Unsupported("operator " + str(k))
        memo[key] = out
        return out

    return ev(ast)


def check(formula, ticks: list[dict]) -> dict:
    """Check ``G formula`` on a finite trace.

    Returns the first tick where the formula is false, if any.
    """
    ast = parse(formula) if isinstance(formula, str) else formula
    vals = evaluate(ast, ticks)
    bad = next((i for i, v in enumerate(vals) if not v), None)
    return {"ok": bad is None, "first_violation": bad}


def _rep(op: str, x: str, n: int) -> str:
    for _ in range(n):
        x = f"({op} {x})"
    return x


def to_smv(node) -> str:
    """Return the NuSMV text of a formula.

    Windowed operators are expanded into chains of Y (O) or Z (H).
    """
    k = node[0]
    if k == "var":
        return node[1]
    if k == "const":
        return "TRUE" if node[1] else "FALSE"
    if k == "num":
        return str(node[1])
    if k == "neg":
        return f"(- {to_smv(node[1])})"
    if k == "!":
        return f"(! {to_smv(node[1])})"
    if k in ("H", "O", "Y", "Z"):
        return f"({k} {to_smv(node[1])})"
    if k in ("S", "T") or k in BOOL2 or k in CMP or k in ARI:
        return f"({to_smv(node[1])} {k} {to_smv(node[2])})"
    if k == "win":
        _, kind, lo, hi, sub = node
        inner = to_smv(sub)
        if kind == "O":
            return (
                "("
                + " | ".join(_rep("Y", inner, j) for j in range(lo, hi + 1))
                + ")"
            )
        return (
            "("
            + " & ".join(_rep("Z", inner, j) for j in range(lo, hi + 1))
            + ")"
        )
    raise Unsupported("smv " + str(k))
