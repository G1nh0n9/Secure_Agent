"""python -m secure_agent_attach <pin|compile|mc|selftest|traces|all|spec|rlz|probe|doc|full>   (Python 3.10+, docker image fret-lab for FRET and NuSMV)"""
from __future__ import annotations

import json
import sys
import time

sys.dont_write_bytecode = True

from . import fret_nusmv as fn  # noqa: E402
from . import pin  # noqa: E402

FMT = {True: "holds", False: "FAILS", None: "NO VERDICT"}


def cmd_pin() -> dict:
    p = pin.check()
    print(f"original: {p['root']}\n  pinned commit {p['pinned_commit'][:12]}  now {p['now']['commit'][:12]}  clean={not p['now']['dirty']}  ->",
          "OK" if p["ok"] else "MISMATCH: " + "; ".join(p["problems"]))
    v = pin.vendor_check()
    print("  vendored FRET scripts (pin/VENDOR.json):", "unchanged" if v["ok"] else f"CHANGED: {v['changed']}")
    p["vendor"] = v
    return p


def cmd_compile() -> list[dict]:
    spec = fn.load_requirements()
    comp = fn.compile_requirements(spec["requirements"])
    for c in comp:
        print(f"  {c['id']}  {'parsed' if c['ok'] else 'PARSE ERROR ' + str(c['error'])}  {c['fretish']}")
    if not all(c["ok"] for c in comp):
        raise SystemExit("some requirement was rejected by the FRET parser")
    return comp


def cmd_mc(comp: list[dict]) -> dict:
    res = fn.model_check(comp)
    print(f"  {'':34s}{'original':12s}guarded")
    for rid in sorted(res):
        o, g = res[rid]["original"], res[rid]["guarded"]
        if rid.startswith("V"):
            print(f"  {rid:34s}{'reachable' if o['holds'] is False else 'NOT reachable':12s}{'reachable' if g['holds'] is False else 'NOT reachable'}")
        else:
            extra = f"   (counterexample of {o['n_states']} states)" if o["holds"] is False else ""
            print(f"  {rid:34s}{FMT[o['holds']]:12s}{FMT[g['holds']]}{extra}")
    return res


def cmd_selftest(comp: list[dict]) -> dict:
    from . import selftest
    r = selftest.run(comp)
    print(f"  trace evaluator vs NuSMV: {r['agree']}/{r['total']} verdicts agree, mismatches: {len(r['mismatches'])}")
    for rid, e in sorted(r["per_requirement"].items()):
        print(f"    {rid}: {e['agree']}/{e['traces']} agree  (verdict true {e['true']}, false {e['false']})")
    return r


def cmd_traces(comp: list[dict]) -> dict:
    from . import scenarios
    res = scenarios.run_all(comp)
    ids = [c["id"] for c in comp]
    print("  non-interference (plain vs observed, every compared field):")
    for n, r in res.items():
        print(f"    {n:16s}", "identical" if all(r["non_interference"].values()) else "DIFFERS " + str([k for k, v in r["non_interference"].items() if not v]))
    print(f"\n  {'scenario':16s}{'':10s}" + " ".join(f"{i[3:]:>4s}" for i in ids) + "     (number = first tick where the requirement fails)")
    for n, r in res.items():
        for mode in ("original", "guarded"):
            row = " ".join(f"{'ok':>4s}" if r[mode][i]["ok"] else f"{'@' + str(r[mode][i]['first_violation']):>4s}" for i in ids)
            print(f"  {n:16s}{mode:10s}{row}")
    print("\n  what the guards changed (original -> guarded):")
    for n, r in res.items():
        o, g = r["plain"], r["guarded_run"]
        print(f"    {n:16s} {o['status']:13s} executed={len(o['executed'])}  ->  {g['status']:13s} executed={len(g['executed'])}  changed fields: {r['guard_changes'] or 'none'}")
    return res


def cmd_spec() -> dict:
    """Requirement catalog: official parser, declared signals and types, code coverage."""
    from . import spec as sp
    s = sp.load()
    reqs = sp.requirements(s)
    comp = sp.compile_texts([r["expanded"] for r in reqs] + [m["expanded"] for m in s["mutants"]])
    chk = sp.validate(s, comp)
    cov = sp.coverage(s)
    print(f"  requirements {len(reqs)} (SEC {sum(r['kind'] == 'SEC' for r in reqs)}, FUN {sum(r['kind'] == 'FUN' for r in reqs)}) in {len(s['components'])} components, "
          f"{sum(r['asis'] == 'gap' for r in reqs)} that the original violates, {len(s['mutants'])} mutants")
    for cname, c in s["components"].items():
        rr = c["requirements"]
        print(f"    {cname:12s} {len(rr):3d} requirements, {len(c['signals']):3d} signals "
              f"({sum(v[0] == 'Input' for v in c['signals'].values())} in, {sum(v[0] == 'Output' for v in c['signals'].values())} out)")
    print(f"  security functions: {len(s['security_functions'])}, every one of the {sum(r['kind'] == 'SEC' for r in reqs)} security requirements belongs to one"
          f" (checked: {not any('belongs to no security function' in e for e in chk['errors'])})")
    print(f"  parser: {sum(r['ok'] for r in comp.values())}/{len(comp)} sentences accepted")
    print(f"  catalog check: {len(chk['errors'])} errors, {len(chk['warnings'])} warnings")
    for e in chk["errors"][:40]:
        print("    ERROR", e)
    for w in chk["warnings"][:20]:
        print("    warn ", w)
    print(f"  core.py coverage: {cov['statements']} statements = {cov['covered_by_requirement']} cited by a requirement + {cov['covered_by_exclusion']} excluded with a reason + {len(cov['uncovered'])} uncovered"
          f"  (core.py equals the pin: {cov['core_sha256_matches_pin']})")
    for u in cov["uncovered"][:40]:
        print(f"    uncovered L{u['line']}: {u['text']}")
    out = {"check": chk, "coverage": cov, "n_requirements": len(reqs)}
    (fn.RUNS / "spec_check.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return out


def cmd_rlz(only: list[str] | None = None) -> dict:
    """FRET realizability (Kind2) per component, plus the sensitivity check with the original behaviour of the known gaps."""
    from . import rlz
    from . import spec as sp
    s = sp.load()
    comp = sp.compile_texts([r["expanded"] for r in sp.requirements(s)] + [m["expanded"] for m in s["mutants"]])
    out = rlz.run(s, comp, only=only or None)
    (fn.RUNS / "rlz").mkdir(exist_ok=True)
    (fn.RUNS / "rlz" / "latest.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"  {'component':14s}{'result':14s}{'time':>8s}   (Kind2, every Input unconstrained)")
    for c, v in out["components"].items():
        print(f"  {c:14s}{v['result']:14s}{str(v.get('time_s', v.get('wall_s'))):>8s}   {v.get('error') or v.get('detail') or ''}")
    if out["mutants"]:
        print("  sensitivity: a requirement that states a defect, added to its component, must make it unrealizable")
        print("  as_is = the original behaviour of a known gap (must be realizable again once the requirements it conflicts with are removed)")
        print("  hypothetical = a regression that the original does not have, to show that the spec would catch it")
        for mid, v in out["mutants"].items():
            m = next(x for x in s["mutants"] if x["id"] == mid)
            dg = v.get("diagnosis_run") or {}
            found = sorted({r for d in (dg.get("diagnosis") or []) for ce in d.get("Counterexamples", []) for r in ce["requirements"]})
            tail = (f"without {', '.join(m['conflicts_with'])}: {v['without_expected']['result']:12s}attributed: {v['attributed']}   FRET diagnosis: {', '.join(found) if found else 'none returned'}"
                    if "without_expected" in v else f"expected conflict: {', '.join(m['conflicts_with'])}")
            print(f"    {mid} {v.get('origin', ''):12s}{m['component']:10s} with: {v['result']:13s}{tail}")
    print(f"  batch wall time {out.get('batch_wall_s')} s")
    return out


def cmd_probe(only: list[str] | None = None) -> dict:
    """The catalog's requirements evaluated on observations of the REAL original code (scripted LLMs, fake tools, fake clock)."""
    from . import probes
    from . import spec as sp
    s = sp.load()
    comp = sp.compile_texts([r["expanded"] for r in sp.requirements(s)] + [m["expanded"] for m in s["mutants"]])
    out = probes.run_traced(s, comp, only=only or None)
    if not only:
        out["guarded"] = probes.run_guarded(s, comp)
    (fn.RUNS / "probe").mkdir(exist_ok=True)
    (fn.RUNS / "probe" / "latest.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"  {'component':14s}{'ticks':>7s}{'hold':>6s}{'violated':>10s}{'not seen':>10s}   violated requirements")
    for cname, v in out["components"].items():
        ev = v["requirements"]
        cnt = {k: sum(e["status"] == k for e in ev.values()) for k in ("holds", "violated", "not_checked")}
        print(f"  {cname:14s}{v['ticks']:7d}{cnt['holds']:6d}{cnt['violated']:10d}{cnt['not_checked']:10d}   {', '.join(r for r, e in ev.items() if e['status'] == 'violated')}")
    print("  " + out["summary"])
    ec = out["exec_coverage"]
    print(f"  the probes executed {ec['executed']} of {ec['statements_in_function_bodies']} statements inside function bodies of core.py")
    for u in ec["not_executed"][:25]:
        print(f"    not executed L{u['line']}: {u['text']}")
    for m in out["mismatch"]:
        print(f"    MISMATCH {m['id']}: observed {m['status']}, catalog says asis={m['asis']}; examples: {m['examples']}")
    g = out.get("guarded")
    if g:
        n = sum(len(v["requirements"]) for v in g["components"].values())
        print(f"  with the attach guards (GuardedStages, TrustedHistory; all components except Turn): {n} requirements, "
              f"{len(g['closed_gaps'])} gaps closed ({', '.join(g['closed_gaps'])}), still violated: {', '.join(g['still_violated']) or 'none'}")
        print("    " + g["summary"])
    return out


def cmd_mutate() -> dict:
    """Code mutants: one defect at a time is put into a COPY of core.py and the probes must notice it."""
    from . import probes
    from . import spec as sp
    s = sp.load()
    comp = sp.compile_texts([r["expanded"] for r in sp.requirements(s)] + [m["expanded"] for m in s["mutants"]])
    out = probes.mutate(s, comp)
    (fn.RUNS / "probe").mkdir(exist_ok=True)
    (fn.RUNS / "probe" / "mutants.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    caught = sum(1 for v in out.values() if v.get("caught"))
    print(f"  code mutants caught: {caught}/{len(out)}")
    for mid, v in out.items():
        if "error" in v:
            print(f"    {mid} ERROR {v['error']}")
        else:
            print(f"    {mid} {'caught ' if v['caught'] else 'MISSED '} {v['ko']}   violated: {', '.join(v['violated'][:6])}{' ...' if len(v['violated']) > 6 else ''}{'  crash: ' + v['crash'] if v.get('crash') else ''}")
    return out


def cmd_doc() -> None:
    from . import spec as sp
    s = sp.load()
    chk = json.loads((fn.RUNS / "spec_check.json").read_text(encoding="utf-8")) if (fn.RUNS / "spec_check.json").exists() else None
    cov = sp.coverage(s)
    sp.render_doc(s, cov, chk["check"] if chk else None)
    print("  docs/CORE_SPEC.md and docs/core_spec.csv written")


def cmd_full() -> None:
    """Everything: the earlier checks (SR-01..08), the requirement catalog, realizability, probes, code mutants, the document."""
    t0 = time.time()
    print("[A] earlier checks: model check, traces, evaluator self-test (SR-01..08)")
    cmd_all()
    print("\n[B] requirement catalog of the whole core: parser, signals, coverage of core.py")
    cmd_spec()
    print("\n[C] realizability (Kind2): every component, then the defects written as requirements")
    cmd_rlz()
    print("\n[D] probes: the requirements evaluated on the real code")
    cmd_probe()
    print("\n[E] code mutants: a defect in a copy of core.py must be noticed")
    cmd_mutate()
    print("\n[F] document")
    cmd_doc()
    print("\n[G] original after everything")
    u = pin.untouched()
    print("  ", "unchanged, no bytecode caches" if u["ok"] else f"CHANGED: {u}")
    print(f"\nfull run {round(time.time() - t0)} s")


def cmd_all() -> None:
    t0 = time.time()
    out: dict = {"when": time.strftime("%Y-%m-%d %H:%M:%S")}
    print("[1] pin of the original")
    out["pin"] = cmd_pin()
    print("\n[2] FRETish -> official FRET parser (ltl_pt)")
    comp = cmd_compile()
    out["compiled"] = [{k: c[k] for k in ("id", "fretish", "ok", "ltl_pt")} for c in comp]
    print("\n[3] NuSMV on the core model (original / with guards)")
    out["model_check"] = cmd_mc(comp)
    print("\n[4] self-test: trace evaluator against NuSMV")
    out["selftest"] = cmd_selftest(comp)
    print("\n[5] adversarial scenarios on the real core")
    out["traces"] = cmd_traces(comp)
    from . import scenarios
    print("\n[6] unmodified CLI (main.py) running with the attach layer")
    out["cli_smoke"] = scenarios.cli_smoke()
    print("  ", json.dumps(out["cli_smoke"]))
    print("\n[7] original after the run")
    out["untouched"] = pin.untouched()
    print("  ", "unchanged, no bytecode caches" if out["untouched"]["ok"] else f"CHANGED: {out['untouched']}")
    out["wall_s"] = round(time.time() - t0, 1)
    (fn.RUNS / "latest.json").write_text(json.dumps(out, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print(f"\nrecord: runs/latest.json  ({out['wall_s']} s)")


def main(argv: list[str]) -> None:
    cmd = argv[0] if argv else "all"
    if cmd == "pin":
        cmd_pin()
    elif cmd == "compile":
        cmd_compile()
    elif cmd == "mc":
        cmd_mc(fn.load_compiled())
    elif cmd == "selftest":
        cmd_selftest(fn.load_compiled())
    elif cmd == "traces":
        cmd_traces(fn.load_compiled())
    elif cmd == "spec":
        cmd_spec()
    elif cmd == "rlz":
        cmd_rlz(argv[1:])
    elif cmd == "probe":
        cmd_probe(argv[1:])
    elif cmd == "mutate":
        cmd_mutate()
    elif cmd == "doc":
        cmd_doc()
    elif cmd == "all":
        cmd_all()
    elif cmd == "full":
        cmd_full()
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
