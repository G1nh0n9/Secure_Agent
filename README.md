# Secure_Agent_FRET

A formal-verification layer for Secure_Agent. The original is never modified; it is pinned to a commit and verified from the outside. Requirements are written in FRETish, compiled by the official FRET parser to past-time LTL, and checked with NuSMV (model checking) and Kind2 (realizability). The same formulas are evaluated on the behaviour of the real code.

## Approach

The LLM is treated as a worst-case, nondeterministic attacker: any plan, any tool call, any extra grant from the verifier, any clock jump. Only properties that must hold for every model output are specified. A NuSMV counterexample is a concrete attack.

| Layer | Files | Content |
|---|---|---|
| **Tool-call monitor** (core) | `requirements/call_requirements.json`, `model/call_monitor.smv.tpl` | Five requirements (CM-01..05) for four attack classes: privilege escalation, exfiltration chain, resource exhaustion, false completion. Model-checked on an abstract session model; the same formulas are evaluated on generated sessions of the real system (`calls`). Realizability is checked with Kind2. |
| Turn state machine | `requirements/core_requirements.json`, `model/core_turn.smv.tpl` | Eight requirements (SR-01..08): stage order, ticket lifetime, denial messages. NuSMV model and six end-to-end scenarios (`all`). |
| Core catalog | `requirements/core_spec.json` | 138 requirements over 12 components covering every statement of `core.py`. Kind2 realizability per component; the same formulas evaluated on real-code observations (`spec`, `rlz`, `probe`, `mutate`). |

Generated reports: `docs/CORE_SPEC.md` and `docs/core_spec.csv` (built by `doc`; do not edit). Assumptions (A-xx), observations (O-xx) and the signal vocabulary are defined there.

## Attachment

| Mechanism | Purpose | Module |
|---|---|---|
| Read-only import and pin | Imports the original without writing bytecode; `pin/ORIGINAL.json` holds the pinned commit and file hashes, and every run checks that the pinned files are unchanged and the pinned commit is in the history | `pin.py`, `loader.py` |
| Observer (subclass) | Subclasses `TurnStages`; records one signal tick per `process_turn` iteration; behaviour unchanged | `observe.py` |
| Guards (subclass, opt-in) | Reference implementation of the guarded variant: least privilege, re-authorization, restored-history sanitizing, denial messages, call shape/content/order checks, result truncation, completion evidence, per-turn budget | `guard.py`, `policy.py`, `ledger.py` |
| Name rebinding | Runs the original `main.py` unchanged, rebinding `TurnStages` and related names at run time | `scenarios.cli_smoke` |

Guards apply through the attach entry points (`GuardedStages`, `TrustedHistory`, `attached_process_turn`).

## Layout

```
pin/                     ORIGINAL.json (commit, file hashes), VENDOR.json (vendor script hashes)
requirements/            call_requirements, call_realizability, core_requirements, core_spec (JSON)
model/                   call_monitor.smv.tpl, core_turn.smv.tpl (guard=FALSE original, TRUE guarded)
vendor/fretjs/           FRET parser and import scripts (copied unchanged from nl2fret_tool)
secure_agent_attach/     callcheck, generator      tool-call monitor and session generation
                         spec, rlz, probes         core catalog, realizability, probes, code mutants
                         policy, ledger, guard     guards
                         oracles                   independent reference decisions for the guards
                         ptl, fret_nusmv, observe, scenarios, selftest, style
docs/                    CORE_SPEC.md, core_spec.csv (generated), REFERENCES.md
runs/                    run records (git-ignored)
```

## Usage

Requires Python 3.10+ and the Docker image `fret-lab:latest` (FRET, Kind2, NuSMV 2.7.1). Containers run on a single CPU, sequentially.

Run from the root of this project. The original is found in the parent directory when this project lies in a subdirectory of the Secure_Agent repository, otherwise in the sibling directory `../Secure_Agent`; `SECURE_AGENT_ORIGINAL` overrides both.

```
PYTHONDONTWRITEBYTECODE=1 python3 -m secure_agent_attach full
```

| Command | Action | Time |
|---|---|---|
| `full` | All of the below | ~13 min |
| `calls [N]` | Tool-call monitor: FRET compile, NuSMV on original and guarded models, Kind2 realizability, evaluation on N generated sessions (default 2000) | ~1 min |
| `all` | Turn state machine: pin, compile, model check, evaluator self-test, traces, CLI smoke test | 5 s |
| `spec` | Catalog check: parser, signal declarations, types, security-function classification, `core.py` statement coverage | seconds |
| `rlz [component]` | Kind2 realizability per component; sensitivity check with defects written as requirements | ~5 min |
| `probe [component]` | Evaluate requirements on observations of the real code (scripted LLM, fake tools, fake clock); also on the guarded stack when no component is given | seconds |
| `mutate` | Inject one defect at a time into a copy of `core.py`; the probes must catch each | ~5 min |
| `style` | PEP 8 / PEP 257 and citation-key check | 1 s |
| `doc` | Generate `docs/CORE_SPEC.md` and `docs/core_spec.csv` | 1 s |
| `pin`, `compile`, `mc`, `selftest`, `traces` | Parts of the first layer | |

## Verification chain

1. **Compile.** FRETish → official FRET parser → `ltl_pt`.
2. **Model check.** `ltl_pt` → NuSMV `LTLSPEC G` on the abstract models; the environment (LLM stages, plan, grants, clock) is unconstrained. The original fails where the guarded variant holds; the counterexample is the attack.
3. **Realizability.** Kind2 per component with all inputs unconstrained. Defects written as requirements must make a component unrealizable and be attributable to the conflicting requirement.
4. **Probe.** The same `ltl_pt` is evaluated on ticks observed from the real code. The gate is enumerated over all 2^12 Boolean input combinations, plus malformed-argument cases and all call sequences up to length three; other components use the cases that decide each requirement. `asis: ok` requirements must hold on every tick; `asis: gap` requirements must be violated at least once.
5. **Mutate.** Defects injected into a copy of `core.py` must be caught by the probes.
6. **Self-test.** The Python past-time LTL evaluator (`ptl.py`) is compared with NuSMV on random traces.

All requirements have the form "always satisfy"; FRETish `when` triggers on rising edges only and is not used. The meaning of a tick is per component and is listed in the catalog (`tick`).

## Reference guards

The guards implement the guarded model variant and close the gaps found in the original (`asis: gap`): call shape and content (GATE-17, 18, 20), call order (GATE-19, 21), per-turn budget (LLM-10, 11, TRN-13, 14, EXE-16), completion evidence (EVA-11) and audit of unparsable calls (EXE-15). The original gate `_execute_tool` remains the only path to a tool: the tools' `validate`, `resources` and `execute` are wrapped, and `call_llm` is wrapped for the budget.

`GuardPolicy` defaults: arguments 16 KiB and depth 8, results 16,000 characters, 40 model calls / 400,000 characters / 300 s per turn. Sequence and content rules are empty by default and set by the operator (A-10).

```python
from secure_agent_attach.guard import GuardedStages
from secure_agent_attach.policy import GuardPolicy, SequenceRules

policy = GuardPolicy(sequence=SequenceRules(
    forbidden_after={("read_secret", "send_mail")},   # within a session
    max_calls_per_turn={"send_mail": 1}))
stages = GuardedStages(call_llm, tools=tools, policy=policy)
```

Independent reference decisions live in `oracles.py` (`oracle_shape_ok`, `oracle_content_ok`, `oracle_sequence_ok`, `oracle_budget_over`); the probes feed the same calls to the guarded stack and compare. Observation channels exposed by the guards: `call_record` and `usage`.

## Code style

Code and comments in `secure_agent_attach/*.py` are English and follow PEP 8 (79 columns, 72 for comments and docstrings), PEP 257, the Google docstring sections (Args, Returns, Raises, Attributes) and PEP 484. Design sources are cited by key, for example `[Saltzer1975]`, and defined in `docs/REFERENCES.md`. `style` checks line length, whitespace, ASCII, docstrings and citation keys; it is part of `full`.

## Adding a requirement

1. Add signals (role `Input` or `Output`, type boolean or integer) and the requirement to a component of `requirements/core_spec.json`. Each requirement needs a code reference (`code`), a description (`desc`) and `asis` (`ok` or `gap`); security requirements belong to one of `security_functions`.
2. `spec` must report 0 errors: the parser accepts the sentence, every signal is declared, the response contains an Output, and the requirement belongs to a security function.
3. `rlz <component>` must be realizable. If not, the requirements conflict or an input was assumed independent that is not; add isolation conditions to find the cause.
4. For a gap, set `asis: gap` and `asis_desc`, and add a mutant (`mutants`) that states the original behaviour. Mark requirements the guards do not yet close with `guard: pending`.
