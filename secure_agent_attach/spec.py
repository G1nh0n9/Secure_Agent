"""Requirement catalog of the core (requirements/core_spec.json): load, validate, compile, coverage, readable document.

load()           reads the catalog and expands the {MACRO} shorthand of every requirement
compile_texts()  official FRET parser (docker image fret-lab), cached on disk (runs/spec_compile_cache.json)
validate()       declared signals, role and type use, an Output in every response, unique ids
coverage()       every statement of the pinned core.py is cited by a requirement or by an explained exclusion (AST, read-only)
render_doc()     docs/CORE_SPEC.md and docs/core_spec.csv, readable summary of catalog, coverage and the latest check results"""
from __future__ import annotations

import ast
import csv
import json
import re
import subprocess
from pathlib import Path

from . import fret_nusmv as fn
from . import pin, ptl

ROOT = fn.ROOT
RUNS = fn.RUNS
SPEC_FILE = ROOT / "requirements" / "core_spec.json"
CACHE = RUNS / "spec_compile_cache.json"
DOCS = ROOT / "docs"
MACRO = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")
BOOL_OPS = {"&", "|", "->", "<->"}
CMP_OPS = set(ptl.CMP)
ARI_OPS = {"+", "-", "*"}


# ---------------------------------------------------------------- load

def _expand(text: str, macros: dict, where: str, seen: tuple = ()) -> str:
    def rep(m):
        name = m.group(1)
        if name not in macros:
            raise SystemExit(f"{where}: unknown macro {{{name}}}")
        if name in seen:
            raise SystemExit(f"{where}: macro {name} refers to itself")
        return _expand(macros[name], macros, where, seen + (name,))
    out = MACRO.sub(rep, text)
    if "{" in out or "}" in out:
        raise SystemExit(f"{where}: unexpanded brace in {out!r}")
    return out


def load() -> dict:
    spec = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
    for cname, comp in spec["components"].items():
        macros = comp.get("macros", {})
        for r in comp["requirements"]:
            r["component"] = cname
            r["expanded"] = _expand(r["text"], macros, r["id"])
    for m in spec["mutants"]:
        m["expanded"] = _expand(m["text"], spec["components"][m["component"]].get("macros", {}), m["id"])
    return spec


def requirements(spec: dict) -> list[dict]:
    return [r for comp in spec["components"].values() for r in comp["requirements"]]


# ---------------------------------------------------------------- compile (official FRET parser)

def compile_texts(texts: list[str]) -> dict[str, dict]:
    RUNS.mkdir(exist_ok=True)
    cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    todo = list(dict.fromkeys(t for t in texts if t not in cache))
    if todo:
        inp = RUNS / "spec_fret_in.json"
        inp.write_text(json.dumps(todo, ensure_ascii=False), encoding="utf-8")
        js = ROOT / "vendor" / "fretjs"
        cmd = ["docker", "run", "--rm", "--cpus", "1", "--entrypoint", "node", "-e", "NODE_PATH=/stub:/opt/fret/fret-electron/app/node_modules",
               "-v", f"{js}:/tools:ro", "-v", f"{js / 'stub'}:/stub:ro", "-v", f"{inp}:/in.json:ro", fn.IMAGE, "/tools/fret_parse_full.js", "/in.json"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        try:
            res = json.loads(r.stdout)
        except json.JSONDecodeError:
            raise SystemExit(f"FRET parser run failed: rc={r.returncode} stderr={r.stderr[-400:]!r}")
        if len(res) != len(todo):
            raise SystemExit("FRET parser returned a different number of results")
        for t, x in zip(todo, res):
            cache[t] = {"ok": bool(x.get("ok")), "error": x.get("error"), "ltl_ft": x.get("ltl_ft"), "ltl_pt": x.get("ltl_pt"), "sem": x.get("sem")}
        CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        inp.unlink(missing_ok=True)
    return {t: cache[t] for t in texts}


# ---------------------------------------------------------------- validate

def signal_types(spec: dict, cname: str) -> dict[str, str]:
    types = {n: "integer" for n in spec["constants"]}
    types.update({n: s[1] for n, s in spec["components"][cname]["signals"].items()})
    return types


def _ctx(node, want: str, types: dict, errors: list, where: str) -> str:
    """Type check of a formula tree: want is 'bool' or 'num'; returns the type of the node."""
    k = node[0]
    if k == "var":
        t = "bool" if types.get(node[1]) == "boolean" else "num"
        if node[1] not in types:
            errors.append(f"{where}: undeclared signal {node[1]}")
        elif t != want:
            errors.append(f"{where}: {node[1]} is {types[node[1]]} but is used as {'a truth value' if want == 'bool' else 'a number'}")
        return t
    if k == "num":
        if want != "num":
            errors.append(f"{where}: number {node[1]} used as a truth value")
        return "num"
    if k == "const":
        if want != "bool":
            errors.append(f"{where}: TRUE or FALSE used as a number")
        return "bool"
    if k == "!":
        _ctx(node[1], "bool", types, errors, where)
        return "bool"
    if k in BOOL_OPS:
        _ctx(node[1], "bool", types, errors, where)
        _ctx(node[2], "bool", types, errors, where)
        return "bool"
    if k in CMP_OPS:
        _ctx(node[1], "num", types, errors, where)
        _ctx(node[2], "num", types, errors, where)
        return "bool"
    if k in ARI_OPS:
        _ctx(node[1], "num", types, errors, where)
        _ctx(node[2], "num", types, errors, where)
        return "num"
    if k == "neg":
        _ctx(node[1], "num", types, errors, where)
        return "num"
    if k in ("H", "O", "Y", "Z"):
        _ctx(node[1], "bool", types, errors, where)
        return "bool"
    errors.append(f"{where}: operator {k} is not expected in a state requirement")
    return want


def _response_side(body):
    """The part of a requirement that the component must make true: the right side of an implication, else the whole formula."""
    return body[2] if body[0] == "->" else body


def _conjuncts(node) -> list:
    """FRET writes `always satisfy (A & B)` as a top-level conjunction of H formulas."""
    return _conjuncts(node[1]) + _conjuncts(node[2]) if node[0] == "&" else [node]


def validate(spec: dict, comp: dict[str, dict]) -> dict:
    errors, warnings = [], []
    consts = spec["constants"]
    seen_ids, seen_sig = set(), {}
    for cname, c in spec["components"].items():
        for key in ("title_ko", "tick_ko", "signals", "requirements"):
            if key not in c:
                errors.append(f"{cname}: missing {key}")
        for n, s in c["signals"].items():
            if len(s) != 4 or s[0] not in ("Input", "Output") or s[1] not in ("boolean", "integer"):
                errors.append(f"{cname}.{n}: signal entry must be [Input|Output, boolean|integer, ko, code]")
            if n in seen_sig:
                errors.append(f"signal {n} is declared in {seen_sig[n]} and {cname}")
            seen_sig[n] = cname
            if n in consts:
                errors.append(f"{cname}.{n}: signal name equals a constant")
        types = signal_types(spec, cname)
        used, positive = set(), set()
        for r in c["requirements"]:
            where = r["id"]
            if where in seen_ids:
                errors.append(f"duplicate id {where}")
            seen_ids.add(where)
            if r["kind"] not in ("SEC", "FUN"):
                errors.append(f"{where}: kind must be SEC or FUN")
            if r.get("asis") not in ("ok", "gap"):
                errors.append(f"{where}: asis must be ok or gap")
            if r.get("asis") == "gap" and not r.get("asis_ko"):
                errors.append(f"{where}: a gap needs asis_ko")
            if not r["text"].startswith(f"{cname} shall "):
                errors.append(f"{where}: text must start with '{cname} shall '")
            if not r.get("code"):
                errors.append(f"{where}: no code reference")
            if not r.get("ko"):
                errors.append(f"{where}: no Korean description")
            res = comp[r["expanded"]]
            if not res["ok"]:
                errors.append(f"{where}: the FRET parser rejected the text: {res['error']}")
                continue
            sem_vars = set(res["sem"].get("variables") or [])
            for v in sem_vars:
                if v not in types:
                    errors.append(f"{where}: undeclared signal {v}")
                elif v in c["signals"]:
                    used.add(v)
            try:
                ast_ = ptl.parse(res["ltl_pt"])
            except Exception as e:  # noqa: BLE001
                errors.append(f"{where}: the evaluator cannot read ltl_pt: {e}")
                continue
            for part in _conjuncts(ast_):
                if part[0] != "H":
                    errors.append(f"{where}: expected a state requirement (always), got {part[0]}")
                    continue
                body = part[1]
                _ctx(body, "bool", types, errors, where)
                outputs = {v for v in ptl.variables(body) if v in c["signals"] and c["signals"][v][0] == "Output"}
                if not outputs:
                    errors.append(f"{where}: the formula mentions no Output signal (it would only constrain the environment)")
                positive |= {v for v in ptl.variables(_response_side(body)) if v in c["signals"] and c["signals"][v][0] == "Output"}
        for n, s in c["signals"].items():
            if n not in used:
                warnings.append(f"{cname}.{n}: declared but used by no requirement")
            elif s[0] == "Output" and n not in positive:
                warnings.append(f"{cname}.{n}: this Output appears only as a condition, so the spec is satisfied by never producing it (add a requirement that demands it)")
    for kind in ("assumptions", "advisory", "observations", "security_functions"):
        ids = [x["id"] for x in spec[kind]]
        if len(ids) != len(set(ids)):
            errors.append(f"duplicate id in {kind}")
    classified = set()
    for sf in spec["security_functions"]:
        for rid in sf["reqs"]:
            if rid not in seen_ids:
                errors.append(f"{sf['id']}: unknown requirement {rid}")
            classified.add(rid)
    for c in spec["components"].values():
        for r in c["requirements"]:
            if r["kind"] == "SEC" and r["id"] not in classified:
                errors.append(f"{r['id']}: a security requirement that belongs to no security function")
    for m in spec["mutants"]:
        if not comp[m["expanded"]]["ok"]:
            errors.append(f"{m['id']}: the FRET parser rejected the text")
        for rid in m["conflicts_with"]:
            if rid not in seen_ids:
                errors.append(f"{m['id']}: conflicts_with names unknown requirement {rid}")
    return {"errors": errors, "warnings": warnings}


# ---------------------------------------------------------------- coverage of the code

def _ranges(items) -> set[int]:
    out: set[int] = set()
    for item in items:
        for part in str(item).split(","):
            m = re.fullmatch(r"\s*L(\d+)(?:-(\d+))?\s*", part)
            if not m:
                raise SystemExit(f"bad code reference {part!r}")
            a, b = int(m.group(1)), int(m.group(2) or m.group(1))
            out.update(range(a, b + 1))
    return out


def coverage(spec: dict) -> dict:
    p = pin.check()
    core_hash = p["now"]["sha256"]["src/core.py"]
    pinned = pin.load_pin()["sha256"]["src/core.py"]
    path = pin.original_root() / spec["source"]["file"]
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    tree = ast.parse(text)
    stmts = sorted({n.lineno for n in ast.walk(tree) if isinstance(n, ast.stmt)})
    by_req: dict[int, list[str]] = {}
    for r in requirements(spec):
        for ln in _ranges(r["code"]):
            by_req.setdefault(ln, []).append(r["id"])
    excl: dict[int, str] = {}
    for e in spec["exclusions"]:
        for ln in _ranges([e["lines"]]):
            excl[ln] = e["reason"]
    covered = [ln for ln in stmts if ln in by_req]
    excluded = [ln for ln in stmts if ln not in by_req and ln in excl]
    uncovered = [ln for ln in stmts if ln not in by_req and ln not in excl]
    beyond = sorted(ln for ln in by_req if ln > len(lines))
    funcs = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = [s for s in stmts if n.lineno <= s <= n.end_lineno]
            funcs.append({"name": n.name, "lines": [n.lineno, n.end_lineno], "statements": len(inner),
                          "covered": sum(1 for s in inner if s in by_req), "excluded": sum(1 for s in inner if s not in by_req and s in excl)})
    funcs.sort(key=lambda f: f["lines"][0])
    return {"core_sha256_matches_pin": core_hash == pinned, "statements": len(stmts), "covered_by_requirement": len(covered),
            "covered_by_exclusion": len(excluded), "uncovered": [{"line": ln, "text": lines[ln - 1].strip()[:100]} for ln in uncovered],
            "references_beyond_file_end": beyond, "functions": funcs, "n_lines": len(lines)}


# ---------------------------------------------------------------- readable document

def _link(code: list[str]) -> str:
    out = []
    for c in code:
        m = re.fullmatch(r"L(\d+)(?:-(\d+))?", c.strip())
        if m:
            a, b = m.group(1), m.group(2)
            out.append(f"[{c}](../../Secure_Agent/src/core.py#L{a}" + (f"-L{b}" if b else "") + ")")
        else:
            out.append(c)
    return ", ".join(out)


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def render_doc(spec: dict, cov: dict, check: dict | None = None) -> None:
    DOCS.mkdir(exist_ok=True)
    rlz = _load_json(RUNS / "rlz" / "latest.json")
    probe = _load_json(RUNS / "probe" / "latest.json")
    cmut = _load_json(RUNS / "probe" / "mutants.json")
    traces = (_load_json(RUNS / "latest.json") or {}).get("traces") or {}
    guarded = (probe or {}).get("guarded") or {}
    closed = set(guarded.get("closed_gaps") or [])

    def sr_status(sr):
        if not traces or not sr or any(sr not in r["original"] for r in traces.values()):
            return ""
        orig = [n for n, r in traces.items() if not r["original"][sr]["ok"]]
        guard = [n for n, r in traces.items() if not r["guarded"][sr]["ok"]]
        return (f"; 종단 시나리오 {len(traces)}개에서 {sr}: 원본 " + (f"{', '.join(orig)}에서 위반" if orig else "모두 성립")
                + ", 가드 " + (f"{', '.join(guard)}에서 위반" if guard else "모두 성립"))
    reqs = requirements(spec)
    n_sec = sum(1 for r in reqs if r["kind"] == "SEC")
    gaps = [r for r in reqs if r["asis"] == "gap"]
    obs = lambda cname, rid: ((probe or {}).get("components", {}).get(cname, {}).get("requirements", {}).get(rid))   # noqa: E731
    L: list[str] = []
    L.append(f"# {spec['title']}\n")
    L.append("이 문서는 `requirements/core_spec.json`과 마지막 검사 결과(`runs/`)에서 `python -m secure_agent_attach doc`으로 생성한다. 직접 고치지 않는다.\n")
    L.append("## 읽는 법\n")
    L.append(spec["how_to_read_ko"] + "\n")
    L.append(spec["role_policy_ko"] + "\n")
    L.append(spec["constants_ko"] + "\n")
    L.append("## 요약\n")
    L.append(f"- 요구 {len(reqs)}개 (보안기능요구 SEC {n_sec}, 기능명세 FUN {len(reqs) - n_sec}), 컴포넌트 {len(spec['components'])}개, 보안기능 {len(spec['security_functions'])}개")
    L.append(f"- 원본이 어기는 요구(gap) {len(gaps)}개: " + ", ".join(r["id"] for r in gaps))
    L.append(f"- core.py 문장 {cov['statements']}개 중 요구에 연결 {cov['covered_by_requirement']}, 제외 사유 있음 {cov['covered_by_exclusion']}, 어디에도 없음 {len(cov['uncovered'])}")
    if check:
        L.append(f"- 카탈로그 검사: 오류 {len(check['errors'])}, 경고 {len(check['warnings'])}")
    if rlz:
        res = rlz["components"]
        L.append(f"- realizability(Kind2, 모든 입력 무제약): 컴포넌트 {sum(v['result'] == 'realizable' for v in res.values())}/{len(res)}개 realizable")
        mut = rlz.get("mutants") or {}
        if mut:
            L.append(f"- 요구 수준 변이(결함을 요구로 써서 넣기): {sum(v['result'] == 'unrealizable' for v in mut.values())}/{len(mut)}개가 unrealizable로 바뀜")
    if probe:
        ec = probe.get("exec_coverage") or {}
        pc = probe["counts"]
        n_probe = sum(len(v["requirements"]) for v in probe["components"].values())
        L.append(f"- 실제 코드 프로브: 관찰 {pc['ticks']}건, 요구 {n_probe}개 중 {pc['holds']}개가 모든 관찰에서 성립, {pc['violated']}개 위반, 관찰하지 못한 것 {pc['not_checked']}개, 카탈로그의 asis 열과 다른 것 {len(probe['mismatch'])}개")
        if ec:
            L.append(f"- 프로브가 실행한 core.py 함수 본문 문장: {ec['executed']}/{ec['statements_in_function_bodies']}")
        if guarded:
            n_g = sum(len(v["requirements"]) for v in guarded["components"].values())
            L.append(f"- 가드를 켠 스택(GuardedStages, TrustedHistory)의 프로브, Turn 제외: 요구 {n_g}개 중 위반 {len(guarded['still_violated'])}개, 원본이 어기던 요구 {len(closed)}개가 성립 ({', '.join(sorted(closed))}). Turn의 TRN-09, TRN-10은 종단 시나리오로 확인한다""")
    if cmut:
        L.append(f"- 코드 수준 변이(원본 복사본에 결함 하나씩 넣기): {sum(1 for v in cmut.values() if v.get('caught'))}/{len(cmut)}개를 프로브가 잡음")
    L.append("")
    L.append("## 보안기능과 요구의 대응\n")
    L.append("| 보안기능 | 내용 | 요구 | 원본이 어기는 것 |\n|---|---|---|---|")
    gapset = {r["id"] for r in gaps}
    for sf in spec["security_functions"]:
        L.append(f"| {sf['id']} {sf['name_ko']} | {sf['ko']} | {', '.join(sf['reqs'])} | {', '.join(x for x in sf['reqs'] if x in gapset) or '없음'} |")
    L.append("\n## 가정 (Core 밖에서 보장해야 하는 것)\n")
    for a in spec["assumptions"]:
        L.append(f"- **{a['id']}** {a['ko']}")
    L.append("\n## 권고일 뿐 강제되지 않는 통제 (프롬프트 글)\n")
    for a in spec["advisory"]:
        L.append(f"- **{a['id']}** ({_link([a['code']])}) {a['ko']}")
    L.append("\n## 관찰 (요구로 세우지 않은 사실)\n")
    for a in spec["observations"]:
        code = f" ({_link(a['code'].split(', '))})" if a.get("code") else ""
        L.append(f"- **{a['id']}**{code} {a['ko']}")
    L.append("\n## 컴포넌트별 요구\n")
    for cname, c in spec["components"].items():
        L.append(f"### {cname}: {c['title_ko']}\n")
        L.append(f"한 시점 = {c['tick_ko']}\n")
        if rlz and cname in rlz["components"]:
            v = rlz["components"][cname]
            L.append(f"realizability: **{v['result']}** ({v.get('time_s', '?')} s)\n")
        L.append("| 신호 | 역할 | 형 | 뜻 | 코드 |\n|---|---|---|---|---|")
        for n, s_ in c["signals"].items():
            L.append(f"| `{n}` | {s_[0]} | {s_[1]} | {s_[2]} | {s_[3]} |")
        if c.get("macros"):
            L.append("\n매크로 (요구 글의 `{이름}`은 아래 식으로 바뀐다):\n")
            for k, v in c["macros"].items():
                L.append(f"- `{{{k}}}` = `{v}`")
        L.append("")
        for r in c["requirements"]:
            tag = f"{r['kind']}" + (f", {r['sr']}" if r.get("sr") else "")
            asis = "원본 준수" if r["asis"] == "ok" else "**원본이 어김**: " + r["asis_ko"]
            o = obs(cname, r["id"])
            seen = "" if not o else (f"; 실제 코드 관찰 {o['checked']}건 모두 성립" if o["status"] == "holds" else f"; 실제 코드 관찰 {o['checked']}건 중 {o['violations']}건 위반" if o["status"] == "violated" else "; 관찰 없음")
            closed_note = "; 가드를 켜면 프로브에서 성립" if r["id"] in closed else ""
            L.append(f"- **{r['id']}** ({tag}; {asis}{seen}{closed_note}{sr_status(r.get('sr'))}) {r['ko']}  ")
            L.append(f"  `{r['text']}`  ")
            L.append(f"  코드: {_link(r['code'])}")
        L.append("")
    L.append("## 코드 커버리지 (core.py의 모든 문장)\n")
    L.append(f"문장 {cov['statements']}개: 요구에 연결 {cov['covered_by_requirement']}, 제외 {cov['covered_by_exclusion']}, 없음 {len(cov['uncovered'])}\n")
    L.append("| 함수 | 줄 | 문장 | 요구에 연결 | 제외 |\n|---|---|---|---|---|")
    for f in cov["functions"]:
        L.append(f"| {f['name']} | {f['lines'][0]}-{f['lines'][1]} | {f['statements']} | {f['covered']} | {f['excluded']} |")
    L.append("\n제외한 줄과 사유:\n")
    for e in spec["exclusions"]:
        L.append(f"- {e['lines']}: {e['reason']}")
    if cov["uncovered"]:
        L.append("\n어디에도 연결되지 않은 문장:\n")
        for u in cov["uncovered"]:
            L.append(f"- L{u['line']}: `{u['text']}`")
    if probe and probe.get("exec_coverage") and probe["exec_coverage"]["not_executed"]:
        L.append("\n프로브가 실행하지 못한 문장:\n")
        for u in probe["exec_coverage"]["not_executed"]:
            L.append(f"- L{u['line']}: `{u['text']}`")
    if rlz and rlz.get("mutants"):
        L.append("\n## 민감도 검사 1: 결함을 요구로 써서 넣으면 realizability가 깨지는가\n")
        L.append("원본 동작(as_is)은 충돌해야 하는 요구를 빼면 다시 realizable이 되어야 한다(귀속). 가상 결함(hypothetical)은 원본에 없는 퇴행이다.\n")
        L.append("| 변이 | 종류 | 컴포넌트 | 내용 | 충돌해야 하는 요구 | 결과 | 요구를 빼면 | FRET 진단 |\n|---|---|---|---|---|---|---|---|")
        for m in spec["mutants"]:
            r = rlz["mutants"].get(m["id"], {})
            dg = (r.get("diagnosis_run") or {}).get("diagnosis") or []
            found = sorted({q for d in dg for ce in d.get("Counterexamples", []) for q in ce["requirements"]})
            w = r.get("without_expected", {}).get("result", "")
            L.append(f"| {m['id']} | {m.get('origin', '')} | {m['component']} | {m['ko']} | {', '.join(m['conflicts_with'])} | {r.get('result', '미실행')} | {w} | {', '.join(found)} |")
    if cmut:
        L.append("\n## 민감도 검사 2: 코드에 결함을 넣으면 프로브가 잡는가\n")
        L.append("원본 core.py의 복사본에 결함을 하나씩 넣고 같은 프로브를 돌린다. 원본에서 성립하던 요구가 하나라도 위반되면 잡은 것이다.\n")
        L.append("| 변이 | 넣은 결함 | 잡았나 | 위반된 요구 |\n|---|---|---|---|")
        for mid, v in cmut.items():
            L.append(f"| {mid} | {v['ko']} | {'예' if v.get('caught') else '**아니오**'} | {', '.join(v.get('violated', []))} |")
    (DOCS / "CORE_SPEC.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    sf_of: dict[str, list[str]] = {}
    for sf in spec["security_functions"]:
        for rid in sf["reqs"]:
            sf_of.setdefault(rid, []).append(sf["id"])
    with open(DOCS / "core_spec.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "component", "kind", "security_function", "sr", "asis", "asis_note", "observed_on_real_code", "description_ko", "fretish", "code"])
        for r in reqs:
            o = obs(r["component"], r["id"])
            w.writerow([r["id"], r["component"], r["kind"], " ".join(sf_of.get(r["id"], [])), r.get("sr", ""), r["asis"], r.get("asis_ko", ""),
                        "" if not o else f"{o['status']} ({o['checked']} observations)", r["ko"], r["expanded"], ", ".join(r["code"])])
