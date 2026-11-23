"""Mechanical style check for the modules written under the code rules.

The rules follow PEP 8 for layout [PEP8], PEP 257 for docstrings
[PEP257] with the section headings of the Google Python Style Guide
(Args, Returns, Raises, Attributes) [GoogleStyle], and PEP 484 for type
hints [PEP484].  Comments and docstrings are in English and cite their
sources by key; the keys are resolved in ``docs/REFERENCES.md``.

The module uses the standard library only and checks:

* lines of at most 79 characters, comment and docstring lines of at most
  72 [PEP8, "Maximum Line Length"];
* no tabs, no trailing blanks, a newline at the end of the file;
* ASCII only in code, comments, docstrings and strings, so that they
  are plain English;
* a docstring on every public module, class, function and method
  (``__init__`` excepted, the class docstring covers it) [PEP257];
* a docstring summary that is one line ending in a period, followed by a
  blank line if the docstring goes on [PEP257, "One-line docstrings"];
* every ``[Key]`` cited in a docstring or comment is defined in
  ``docs/REFERENCES.md``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MODULES = tuple(sorted(p.name for p in HERE.glob("*.py")))
CODE_LIMIT, TEXT_LIMIT = 79, 72
CITATION = re.compile(
    r"\[([A-Za-z][A-Za-z0-9-]*\d[A-Za-z0-9.-]*)" r"(?:,[^\]]*)?\]"
)


def defined_keys() -> set:
    """Return the citation keys defined in ``docs/REFERENCES.md``."""
    text = (ROOT / "docs" / "REFERENCES.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\*\*\[([^\]]+)\]\*\*", text, re.MULTILINE))


def _docstring_lines(tree: ast.AST) -> set:
    """Return the numbers of the lines that belong to a docstring."""
    lines = set()
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                lines.update(range(body[0].lineno, body[0].end_lineno + 1))
    return lines


def _api_nodes(tree: ast.AST):
    """Yield the module, its classes and the functions of the API.

    Functions defined inside other functions are implementation detail
    and need no docstring.
    """
    yield tree
    stack = [(child, False) for child in ast.iter_child_nodes(tree)]
    while stack:
        node, inside_function = stack.pop()
        if isinstance(node, ast.ClassDef):
            yield node
            stack.extend(
                (c, inside_function) for c in ast.iter_child_nodes(node)
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not inside_function:
                yield node
            stack.extend((c, True) for c in ast.iter_child_nodes(node))


def _docstring_problems(tree: ast.AST) -> list:
    problems = []
    for node in _api_nodes(tree):
        name = getattr(node, "name", "module")
        where = f"line {getattr(node, 'lineno', 1)} {name}"
        doc = ast.get_docstring(node, clean=True)
        public = not name.startswith("_")
        if doc is None:
            if public or name == "module":
                problems.append(f"{where}: no docstring")
            continue
        lines = doc.splitlines()
        if not lines[0].rstrip().endswith("."):
            problems.append(f"{where}: the summary line must end in a period")
        if len(lines) > 1 and lines[1].strip():
            problems.append(f"{where}: a blank line must follow the summary")
    return problems


def check_file(path: Path, keys: set) -> list:
    """Return the style problems of one file as readable strings."""
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    in_doc = _docstring_lines(tree)
    problems = []
    if not text.endswith("\n"):
        problems.append("no newline at the end of the file")
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        is_text = number in in_doc or stripped.startswith("#")
        limit = TEXT_LIMIT if is_text else CODE_LIMIT
        if len(line) > limit:
            problems.append(f"line {number}: {len(line)} > {limit} characters")
        if "\t" in line:
            problems.append(f"line {number}: tab")
        if line != line.rstrip():
            problems.append(f"line {number}: trailing blanks")
        if not line.isascii():
            problems.append(f"line {number}: a non-ASCII character")
        if is_text:
            for key in CITATION.findall(line):
                if key not in keys:
                    problems.append(f"line {number}: unknown citation {key}")
    problems.extend(_docstring_problems(tree))
    return problems


def check_all() -> dict:
    """Check every module of :data:`MODULES`; return the problems."""
    keys = defined_keys()
    return {name: check_file(HERE / name, keys) for name in MODULES}
