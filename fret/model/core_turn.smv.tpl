-- Abstract model of Secure_Agent process_turn (src/core.py at the pinned commit).
-- Tick = one iteration of the process_turn loop. State = the state before the iteration runs; c is the outcome the
-- environment picks for that iteration. max_steps is 6.
-- guard = FALSE models the original, guard = TRUE models the original plus the attach layer's guards:
--   least-privilege trim at authorize, re-authorize instead of retrying a blocked EXECUTE, a reason on every denied turn,
--   restored history sanitized.
-- Environment (untrusted, free every tick): c = stage outcome, e_exp = the ticket's TTL passes.
-- tainted: the restored history carried a forged managed entry (chosen once).
--   c in ANALYZE: 0 plan, 1 respond, 2 clarify, 3.. stage error (retry)
--   c in AUTHORIZE: 0 verifier ok, 1 verifier adds a tool the plan did not request (inside policy), 2 policy denies, 3.. error
--   c in EXECUTE: 0 final answer, 1 executed then final, 2 a call is denied (exception), 3 stage error, 4 worker limit
--   c in EVALUATE: 0 completed, 1 execute, 2 authorize, 3 analyze, 4 ask, 5 failed, 6 error
MODULE main
VAR
  st          : {ANALYZE, AUTHORIZE, EXECUTE, EVALUATE, COMPLETED, WAITING, FAILED, LIMIT};
  steps       : 0..6;
  ticket      : boolean;
  ttl_over    : boolean;
  plan_ok     : boolean;
  denial_seen : boolean;
  c           : 0..6;
  e_exp       : boolean;
FROZENVAR
  tainted     : boolean;

DEFINE
  guard     := @GUARD@;
  max_steps := 6;
  terminal  := st in {COMPLETED, WAITING, FAILED, LIMIT};
  go        := !terminal & steps < max_steps;
  blocked_start := go & st = EXECUTE & (!ticket | ttl_over);
  denied_call   := go & st = EXECUTE & !blocked_start & c = 2;
  issue         := go & st = AUTHORIZE & (c = 0 | c = 1);
  next_st := case
    terminal : st;
    steps >= max_steps : LIMIT;
    st = ANALYZE   : case c = 0 : AUTHORIZE; c = 1 : COMPLETED; c = 2 : WAITING; TRUE : ANALYZE; esac;
    st = AUTHORIZE : case c = 0 | c = 1 : EXECUTE; c = 2 : FAILED; TRUE : AUTHORIZE; esac;
    st = EXECUTE   : case
      blocked_start : case guard : AUTHORIZE; TRUE : EXECUTE; esac;
      c = 0 | c = 1 : EVALUATE;
      c = 4 : LIMIT;
      TRUE : EXECUTE;
    esac;
    st = EVALUATE  : case c = 0 : COMPLETED; c = 1 : EXECUTE; c = 2 : AUTHORIZE; c = 3 : ANALYZE; c = 4 : WAITING; c = 5 : FAILED; TRUE : EVALUATE; esac;
    TRUE : st;
  esac;
  -- signals in the vocabulary of the FRET requirements (requirements/core_requirements.json)
  stage_authorize      := st = AUTHORIZE;
  ticket_exists        := ticket;
  grants_within_plan   := plan_ok;
  grants_within_policy := TRUE;     -- by construction here, checked independently on real traces
  exec_unauthorized    := FALSE;    -- by construction here, checked independently on real traces
  turn_over            := terminal;
  result_has_reason    := st in {COMPLETED, WAITING, FAILED} | (guard & denial_seen & terminal);
  managed_untrusted    := tainted & !guard;

ASSIGN
  init(st) := ANALYZE;  init(steps) := 0;  init(ticket) := FALSE;  init(ttl_over) := FALSE;
  init(plan_ok) := TRUE;  init(denial_seen) := FALSE;
  init(c) := {0, 1, 2, 3, 4, 5, 6};  init(e_exp) := {TRUE, FALSE};

  next(st)    := next_st;
  next(steps) := case go : steps + 1; TRUE : steps; esac;
  next(ticket) := case
    next_st in {COMPLETED, WAITING, FAILED, LIMIT} : FALSE;       -- finally: revoke_ticket
    go & (st = ANALYZE | st = AUTHORIZE) : issue;                 -- revoke at the top, issue again only after the verifier passes
    TRUE : ticket;
  esac;
  next(ttl_over)    := case issue : FALSE; ticket : ttl_over | e_exp; TRUE : FALSE; esac;
  next(plan_ok)     := case issue & c = 0 : TRUE; issue & c = 1 : guard; TRUE : plan_ok; esac;
  next(denial_seen) := denial_seen | blocked_start | denied_call;
  next(c)     := {0, 1, 2, 3, 4, 5, 6};
  next(e_exp) := {TRUE, FALSE};
