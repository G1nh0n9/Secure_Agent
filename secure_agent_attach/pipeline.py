"""Run the checks as stages and keep the result of every stage.

One run writes a directory ``runs/<run id>/`` with one subdirectory per
stage, ``NN_stage/``: the log of what the stage printed (``stage.log``),
the data it returned (``result.json``) and the raw files the stage wrote
under ``runs/`` (``artifacts/``, same relative paths).  Two summaries
sit beside the subdirectories: ``summary.md`` for people and
``summary.json`` for programs.  ``runs/last`` points to the latest run.

A stage ends with one of three verdicts:

* PASS: the outcome is the one the design expects (a guarded variant
  holds, a planted defect is noticed, the original is unchanged);
* FAIL: the stage ran and the outcome is not the expected one;
* ERROR: the stage stopped with an exception.

The requirements that the original violates are expected findings and
are reported, not counted as FAIL.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import sys
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import fret_nusmv as fn

RUNS = fn.RUNS


@dataclass
class Stage:
    """One stage of the pipeline.

    Attributes:
        key: Short name used on the command line and in file names.
        title: One line for the summary.
        purpose: What the stage checks, in one sentence.
        judge: Function from the stage's result to ``(ok, headline,
            details)``.
    """

    key: str
    title: str
    purpose: str
    judge: Callable[[object], tuple[bool, str, list[str]]]


@dataclass
class Outcome:
    """The recorded outcome of one stage."""

    key: str
    verdict: str
    headline: str
    details: list[str] = field(default_factory=list)
    seconds: float = 0.0
    files: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)


class _Tee(io.TextIOBase):
    """Write to several streams."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, text: str) -> int:
        """Write ``text`` to every stream."""
        for stream in self.streams:
            stream.write(text)
        return len(text)

    def flush(self) -> None:
        """Flush every stream."""
        for stream in self.streams:
            stream.flush()


RUN_DIR = re.compile(r"\d{8}-\d{6}")
# Not results of a stage: a cache, and the combined record that the
# document builder reads.
SKIPPED = {"spec_compile_cache.json", "latest.json"}  # paths below runs


def _snapshot() -> dict[str, tuple[int, int]]:
    """Return ``{path below runs: (mtime, size)}`` of result files."""
    seen = {}
    for path in RUNS.rglob("*"):
        rel = path.relative_to(RUNS)
        if not path.is_file() or path.is_symlink():
            continue
        if RUN_DIR.fullmatch(rel.parts[0]) or rel.parts[0] == "last":
            continue
        if rel.as_posix() in SKIPPED:
            continue
        stat = path.stat()
        seen[rel.as_posix()] = (stat.st_mtime_ns, stat.st_size)
    return seen


def _keep_artifacts(before: dict, target: Path) -> list[str]:
    """Copy the files written since ``before`` into ``target``."""
    kept = []
    for rel, mark in _snapshot().items():
        if before.get(rel) != mark:
            destination = target / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(RUNS / rel, destination)
            kept.append(rel)
    return sorted(kept)


def _count(items, test) -> int:
    return sum(1 for item in items if test(item))


def _judge_pin(res) -> tuple[bool, str, list[str]]:
    ok = res["ok"] and res["vendor"]["ok"]
    head = (
        f"pinned commit {res['pinned_commit'][:12]}; pinned files "
        f"{'unchanged' if res['ok'] else 'CHANGED'}; vendored scripts "
        f"{'unchanged' if res['vendor']['ok'] else 'CHANGED'}"
    )
    return ok, head, list(res["problems"])


def _judge_compile(res) -> tuple[bool, str, list[str]]:
    ok = all(c["ok"] for c in res)
    head = f"{_count(res, lambda c: c['ok'])}/{len(res)} sentences parsed"
    return ok, head, [f"{c['id']}: {c['fretish']}" for c in res]


def _judge_model(res) -> tuple[bool, str, list[str]]:
    reqs = {k: v for k, v in res.items() if not k.startswith("V")}
    seen = {k: v for k, v in res.items() if k.startswith("V")}
    guarded = _count(reqs.values(), lambda v: v["guarded"]["holds"] is True)
    attacks = _count(reqs.values(), lambda v: v["original"]["holds"] is False)
    reach = _count(
        seen.values(),
        lambda v: v["original"]["holds"] is False
        and v["guarded"]["holds"] is False,
    )
    ok = guarded == len(reqs) and reach == len(seen)
    head = (
        f"guarded holds {guarded}/{len(reqs)}; the original fails "
        f"{attacks} (counterexamples); situations reachable "
        f"{reach}/{len(seen)}"
    )
    word = {True: "holds", False: "FAILS", None: "no verdict"}
    details = [
        f"{k}: original {word[v['original']['holds']]}, guarded "
        f"{word[v['guarded']['holds']]}"
        for k, v in sorted(reqs.items())
    ]
    return ok, head, details


def _judge_selftest(res) -> tuple[bool, str, list[str]]:
    ok = res["agree"] == res["total"] and not res["mismatches"]
    head = f"evaluator and NuSMV agree on {res['agree']}/{res['total']}"
    return ok, head, [f"mismatch: {m}" for m in res["mismatches"][:10]]


def _judge_traces(res) -> tuple[bool, str, list[str]]:
    quiet = all(all(r["non_interference"].values()) for r in res.values())
    bad = [
        f"{name}: {rid}"
        for name, r in res.items()
        for rid, e in r["guarded"].items()
        if not e["ok"]
    ]
    hit = []
    for name, r in res.items():
        broken = [rid for rid, e in r["original"].items() if not e["ok"]]
        if broken:
            hit.append(f"{name}: {', '.join(broken)}")
    head = (
        f"{len(res)} scenarios; observer changes nothing: {quiet}; "
        f"guarded violations: {len(bad)}; scenarios in which the original "
        f"violates a requirement: {len(hit)}"
    )
    details = [f"original violates in {line}" for line in hit]
    return quiet and not bad, head, details + [f"GUARDED {b}" for b in bad]


def _judge_cli(res) -> tuple[bool, str, list[str]]:
    ok = "completed" in res["status_line"] and bool(res["executed"])
    head = f"{res['status_line']}; {len(res['executed'])} tool call(s)"
    return ok, head, [f"{k}: {v}" for k, v in res.items()]


def _judge_calls(res) -> tuple[bool, str, list[str]]:
    model = {k: v for k, v in res["model"].items() if not k.startswith("V")}
    guard_ok = all(v["guarded"]["holds"] is True for v in model.values())
    rz = res["realizability"]
    rz_ok = rz["components"]["Monitor"]["result"] == "realizable" and all(
        m["result"] == "unrealizable" and m["attributed"]
        for m in rz["mutants"].values()
    )
    sess = res["sessions"]
    sess_ok = not sess["guarded"]["violations"]
    st = res["selftest"]
    head = (
        f"model: guarded holds {guard_ok}; realizability {rz_ok}; "
        f"sessions: original broke "
        f"{sum(sess['original']['violations'].values())} times, guarded "
        f"{sum(sess['guarded']['violations'].values())}; evaluator "
        f"{st['agree']}/{st['total']}"
    )
    details = [
        f"{k}: original {'holds' if v['original']['holds'] else 'FAILS'}, "
        f"guarded {'holds' if v['guarded']['holds'] else 'FAILS'}"
        for k, v in sorted(model.items())
    ]
    for name, run in sess.items():
        broken = ", ".join(f"{r} x{n}" for r, n in run["violations"].items())
        details.append(
            f"{run['runs']} sessions, {name}: {broken or 'no violation'}"
        )
    ok = guard_ok and rz_ok and sess_ok and st["agree"] == st["total"]
    return ok, head, details


def _judge_catalog(res) -> tuple[bool, str, list[str]]:
    chk, cov = res["check"], res["coverage"]
    ok = (
        not chk["errors"]
        and not cov["uncovered"]
        and cov["core_sha256_matches_pin"]
    )
    head = (
        f"{res['n_requirements']} requirements; errors "
        f"{len(chk['errors'])}; core.py statements {cov['statements']}, "
        f"cited {cov['covered_by_requirement']}, excluded "
        f"{cov['covered_by_exclusion']}, uncovered {len(cov['uncovered'])}"
    )
    return ok, head, [f"ERROR {e}" for e in chk["errors"][:20]]


def _judge_rlz(res) -> tuple[bool, str, list[str]]:
    comps = res["components"]
    real = _count(comps.values(), lambda v: v["result"] == "realizable")
    muts = res["mutants"]
    noticed = _count(muts.values(), lambda v: v["result"] == "unrealizable")
    attributed = _count(
        muts.values(), lambda v: v.get("attributed", True) is not False
    )
    ok = real == len(comps) and noticed == attributed == len(muts)
    head = (
        f"components realizable {real}/{len(comps)}; defects noticed "
        f"{noticed}/{len(muts)}; attributed {attributed}/{len(muts)}"
    )
    details = [
        f"{name}: {v['result']} ({v.get('time_s')} s)"
        for name, v in comps.items()
    ]
    return ok, head, details


def _judge_probe(res) -> tuple[bool, str, list[str]]:
    cnt, guarded = res["counts"], res["guarded"]
    ok = (
        not res["mismatch"]
        and cnt["not_checked"] == 0
        and not guarded["unexpected_violations"]
        and not guarded["pending_guard"]
        and not res["exec_coverage"]["not_executed"]
    )
    ec = res["exec_coverage"]
    head = (
        f"{cnt['ticks']} observations; hold {cnt['holds']}, violated "
        f"{cnt['violated']} (the original's gaps); guarded stack: gaps "
        f"closed {len(guarded['closed_gaps'])}, unexpected "
        f"{len(guarded['unexpected_violations'])}; core.py statements "
        f"executed {ec['executed']}/{ec['statements_in_function_bodies']}"
    )
    details = [
        f"{c}: " + ", ".join(r for r, e in v["requirements"].items()
                             if e["status"] == "violated")
        for c, v in res["components"].items()
        if any(e["status"] == "violated" for e in v["requirements"].values())
    ]
    return ok, head, details


def _judge_mutants(res) -> tuple[bool, str, list[str]]:
    caught = _count(res.values(), lambda v: v.get("caught"))
    errors = _count(res.values(), lambda v: "error" in v)
    ok = caught == len(res) and not errors
    head = f"code mutants caught {caught}/{len(res)}; errors {errors}"
    details = [
        f"{mid}: {'caught' if v.get('caught') else 'MISSED'}: "
        f"{v.get('desc', v.get('error'))}"
        for mid, v in res.items()
    ]
    return ok, head, details


def _judge_untouched(res) -> tuple[bool, str, list[str]]:
    head = "original unchanged, no bytecode caches" if res["ok"] else "CHANGED"
    return res["ok"], head, [res["git_status"]] if res["git_status"] else []


def _judge_docs(res) -> tuple[bool, str, list[str]]:
    return True, "documents written", []


def _judge_style(res) -> tuple[bool, str, list[str]]:
    total = sum(len(v) for v in res.values())
    head = f"{total} problems in {len(res)} modules"
    details = [f"{m}: {p}" for m, v in res.items() for p in v[:5]]
    return total == 0, head, details


STAGES = (
    Stage(
        "pin",
        "Original pinned",
        "The original project is the pinned version and the vendored "
        "FRET scripts are unchanged.",
        _judge_pin,
    ),
    Stage(
        "compile",
        "FRETish to LTL (turn state machine)",
        "The official FRET parser accepts every requirement of the turn "
        "state machine (SR-01..08).",
        _judge_compile,
    ),
    Stage(
        "model_check",
        "NuSMV on the turn model",
        "Model check of SR-01..08 on the original and on the guarded "
        "variant; every situation the requirements talk about is "
        "reachable.",
        _judge_model,
    ),
    Stage(
        "selftest",
        "Evaluator against NuSMV",
        "The Python evaluator of the formulas gives the NuSMV verdict on "
        "random traces.",
        _judge_selftest,
    ),
    Stage(
        "traces",
        "End-to-end scenarios",
        "Adversarial scenarios on the real core; the observer changes "
        "nothing; the guarded run keeps every requirement.",
        _judge_traces,
    ),
    Stage(
        "cli_smoke",
        "Unmodified CLI with the attach layer",
        "The original main.py runs with the attach layer and completes "
        "a turn.",
        _judge_cli,
    ),
    Stage(
        "calls",
        "Tool-call monitor (CM-01..05)",
        "Attacker-controlled model: NuSMV on the monitor model, Kind2 "
        "realizability, the formulas on generated real sessions.",
        _judge_calls,
    ),
    Stage(
        "catalog",
        "Requirement catalog",
        "Parser, signal declarations, types and coverage of every "
        "statement of core.py.",
        _judge_catalog,
    ),
    Stage(
        "realizability",
        "Realizability of the core (Kind2)",
        "Every component is realizable and every planted defect makes "
        "its component unrealizable.",
        _judge_rlz,
    ),
    Stage(
        "probes",
        "Probes on the real code",
        "The requirements evaluated on observations of the real core, "
        "with and without the guards.",
        _judge_probe,
    ),
    Stage(
        "mutants",
        "Code mutants",
        "A defect put into a copy of core.py is noticed by the probes.",
        _judge_mutants,
    ),
    Stage(
        "untouched",
        "Original after the run",
        "The original has no changes and no bytecode caches left by "
        "the run.",
        _judge_untouched,
    ),
    Stage(
        "docs",
        "Documents",
        "docs/CORE_SPEC.md, docs/core_spec.csv and docs/REQUIREMENTS.md "
        "are built from the requirement files and the latest results.",
        _judge_docs,
    ),
    Stage(
        "style",
        "Code style",
        "PEP 8, PEP 257 and citation keys of the modules.",
        _judge_style,
    ),
)
KEYS = tuple(stage.key for stage in STAGES)


def _write_latest(results: dict) -> None:
    """Write the record that the document builder reads."""
    needed = ("pin", "compile", "model_check", "selftest", "traces")
    if not all(key in results for key in needed):
        return
    data = {
        "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pin": results["pin"],
        "compiled": [
            {k: c[k] for k in ("id", "fretish", "ok", "ltl_pt")}
            for c in results["compile"]
        ],
        "model_check": results["model_check"],
        "selftest": results["selftest"],
        "traces": results["traces"],
        "cli_smoke": results.get("cli_smoke"),
        "untouched": results.get("untouched"),
    }
    (RUNS / "latest.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=1, default=str),
        encoding="utf-8",
    )


def _summary(run_id: str, outcomes: list[Outcome], seconds: float) -> str:
    by_key = {stage.key: stage for stage in STAGES}
    total = len(outcomes)
    passed = _count(outcomes, lambda o: o.verdict == "PASS")
    lines = [
        f"# Run {run_id}",
        "",
        f"Result: **{'PASS' if passed == total else 'NOT PASSED'}** "
        f"({passed} of {total} stages passed), {round(seconds)} s.",
        "",
        "| # | Stage | Verdict | Result | Time | Files |",
        "|---|---|---|---|---|---|",
    ]
    for number, out in enumerate(outcomes, 1):
        files = ", ".join(f"[{Path(f).name}]({f})" for f in out.files)
        if out.artifacts:
            folder = Path(out.files[0]).parent.as_posix()
            files += f", [artifacts]({folder}/artifacts/)"
        lines.append(
            f"| {number} | {by_key[out.key].title} | {out.verdict} | "
            f"{out.headline.replace('|', '/')} | {round(out.seconds)} s | "
            f"{files} |"
        )
    for number, out in enumerate(outcomes, 1):
        stage = by_key[out.key]
        lines += ["", f"## {number}. {stage.title}", "", stage.purpose, ""]
        lines.append(f"**{out.verdict}**: {out.headline}")
        if out.details:
            lines.append("")
            lines += [f"- {d}" for d in out.details[:60]]
            if len(out.details) > 60:
                lines.append(f"- ... {len(out.details) - 60} more in the log")
    return "\n".join(lines) + "\n"


def _link_last(run_dir: Path) -> None:
    last = RUNS / "last"
    with contextlib.suppress(OSError):
        if last.is_symlink() or last.exists():
            last.unlink()
        last.symlink_to(run_dir.name)


def run(functions: dict, selected: list[str] | None = None) -> bool:
    """Run the stages and write the run directory.

    Args:
        functions: Stage key to a function that takes the dict of the
            results so far and returns the result of the stage.
        selected: Stage keys to run, in pipeline order; all if empty.

    Returns:
        True if every stage that ran passed.
    """
    chosen = [s for s in STAGES if not selected or s.key in selected]
    unknown = set(selected or []) - set(KEYS)
    if unknown:
        raise SystemExit(f"unknown stage: {', '.join(sorted(unknown))}")
    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True)
    results: dict = {}
    outcomes: list[Outcome] = []
    started = time.time()
    for number, stage in enumerate(chosen, 1):
        name = f"{number:02d}_{stage.key}"
        stage_dir = run_dir / name
        stage_dir.mkdir()
        before = _snapshot()
        print(f"[{number}/{len(chosen)}] {stage.title}", flush=True)
        log = io.StringIO()
        t0 = time.time()
        out = Outcome(stage.key, "ERROR", "")
        tee = _Tee(sys.stdout, log)
        try:
            with contextlib.redirect_stdout(tee):
                result = functions[stage.key](results)
            results[stage.key] = result
            ok, out.headline, out.details = stage.judge(result)
            out.verdict = "PASS" if ok else "FAIL"
            (stage_dir / "result.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=1, default=str),
                encoding="utf-8",
            )
            out.files.append(f"{name}/result.json")
        except (Exception, SystemExit) as error:  # noqa: BLE001
            out.headline = f"{type(error).__name__}: {error}"
            log.write(traceback.format_exc())
        _write_latest(results)
        out.seconds = time.time() - t0
        (stage_dir / "stage.log").write_text(log.getvalue(), encoding="utf-8")
        out.files.insert(0, f"{name}/stage.log")
        out.artifacts = _keep_artifacts(before, stage_dir / "artifacts")
        outcomes.append(out)
        print(f"  -> {out.verdict}: {out.headline}\n", flush=True)
    seconds = time.time() - started
    (run_dir / "summary.md").write_text(
        _summary(run_id, outcomes, seconds), encoding="utf-8"
    )
    (run_dir / "summary.json").write_text(
        json.dumps(
            {
                "run": run_id,
                "seconds": round(seconds, 1),
                "stages": [o.__dict__ for o in outcomes],
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )
    _link_last(run_dir)
    print(f"summary: runs/{run_id}/summary.md")
    return all(o.verdict == "PASS" for o in outcomes)
