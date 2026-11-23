-- Abstract model of the tool-call monitor of Secure_Agent over a whole session, from src/core.py
-- (gate _execute_tool, tickets, authorize_task) and the attach guards (attach layer, guard.py).
-- Tick = one event of the session. State = the state before the event; the environment picks the event.
-- Tools are abstracted to three classes: SENS (reads sensitive data), SEND (sends data out), OTHER.
-- guard = FALSE models the original, guard = TRUE the original plus the guards:
--   least privilege (grants = plan only), no SEND once a SENS has run in the session, a call cap per turn for the
--   model, a completion needs a successful tool call when the plan asked for one.
-- Environment (untrusted, free every tick): ev (the event), e_p_* (what the plan requests), e_x_* (extra grants the
-- verifier adds), the clock (TTL_PASS). The policy pol_* is chosen once, for every possible policy.
-- The model-call cap is 3.
MODULE main
VAR
  ev       : {NEW_TURN, CALL_SENS, CALL_SEND, CALL_OTHER, TTL_PASS, LLM_CALL, COMPLETE};
  e_p_sens : boolean;  e_p_send : boolean;  e_p_other : boolean;
  e_x_sens : boolean;  e_x_send : boolean;  e_x_other : boolean;
  in_turn  : boolean;
  ticket   : boolean;
  p_sens   : boolean;  p_send   : boolean;  p_other   : boolean;
  g_sens   : boolean;  g_send   : boolean;  g_other   : boolean;
  tainted  : boolean;
  ok_turn  : boolean;
  llm_calls : 0..4;
FROZENVAR
  pol_sens : boolean;  pol_send : boolean;  pol_other : boolean;

DEFINE
  guard := @GUARD@;
  cap   := 3;
  call  := ev in {CALL_SENS, CALL_SEND, CALL_OTHER};
  granted := case ev = CALL_SENS : g_sens; ev = CALL_SEND : g_send; ev = CALL_OTHER : g_other; TRUE : FALSE; esac;
  planned := case ev = CALL_SENS : p_sens; ev = CALL_SEND : p_send; ev = CALL_OTHER : p_other; TRUE : FALSE; esac;
  order_ok := !(guard & ev = CALL_SEND & tainted);
  exec := call & ticket & granted & order_ok;
  plan_tool := p_sens | p_send | p_other;
  llm_done := ev = LLM_CALL & in_turn & (!guard | llm_calls < cap);
  complete_ok := ev = COMPLETE & in_turn & (!guard | ok_turn | !plan_tool);
  -- signals in the vocabulary of requirements/call_requirements.json
  exec_sens             := exec & ev = CALL_SENS;
  exec_send             := exec & ev = CALL_SEND;
  exec_outside_plan     := exec & !planned;
  exec_unauthorized     := FALSE;   -- by construction here (a grant is within the policy), checked on real traces
  llm_over_cap          := llm_done & llm_calls >= cap;
  completed_no_evidence := complete_ok & plan_tool & !ok_turn;

ASSIGN
  init(in_turn) := FALSE;  init(ticket) := FALSE;
  init(p_sens) := FALSE;  init(p_send) := FALSE;  init(p_other) := FALSE;
  init(g_sens) := FALSE;  init(g_send) := FALSE;  init(g_other) := FALSE;
  init(tainted) := FALSE;  init(ok_turn) := FALSE;  init(llm_calls) := 0;

  next(ev)       := {NEW_TURN, CALL_SENS, CALL_SEND, CALL_OTHER, TTL_PASS, LLM_CALL, COMPLETE};
  next(e_p_sens) := {TRUE, FALSE};  next(e_p_send) := {TRUE, FALSE};  next(e_p_other) := {TRUE, FALSE};
  next(e_x_sens) := {TRUE, FALSE};  next(e_x_send) := {TRUE, FALSE};  next(e_x_other) := {TRUE, FALSE};

  next(in_turn) := case ev = NEW_TURN : TRUE; complete_ok : FALSE; TRUE : in_turn; esac;
  next(ticket)  := case ev = NEW_TURN : TRUE; ev = TTL_PASS | complete_ok : FALSE; TRUE : ticket; esac;
  next(p_sens)  := case ev = NEW_TURN : e_p_sens;  TRUE : p_sens;  esac;
  next(p_send)  := case ev = NEW_TURN : e_p_send;  TRUE : p_send;  esac;
  next(p_other) := case ev = NEW_TURN : e_p_other; TRUE : p_other; esac;
  -- a grant is the verified request inside the policy; the original also lets the verifier add tools
  next(g_sens)  := case ev = NEW_TURN : (e_p_sens  | (!guard & e_x_sens))  & pol_sens;  TRUE : g_sens;  esac;
  next(g_send)  := case ev = NEW_TURN : (e_p_send  | (!guard & e_x_send))  & pol_send;  TRUE : g_send;  esac;
  next(g_other) := case ev = NEW_TURN : (e_p_other | (!guard & e_x_other)) & pol_other; TRUE : g_other; esac;
  next(tainted) := tainted | exec_sens;
  next(ok_turn) := case ev = NEW_TURN : FALSE; exec : TRUE; TRUE : ok_turn; esac;
  next(llm_calls) := case ev = NEW_TURN : 0; llm_done & llm_calls < 4 : llm_calls + 1; TRUE : llm_calls; esac;
