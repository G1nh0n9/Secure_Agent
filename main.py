import argparse
import json
import os
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from src.core import ConversationHistory, TurnStages, UserInstruction, process_turn


managed_prompt: str | None = None
max_steps = 20
llm_base_url = os.environ.get("LLM_BASE_URL", "")
llm_model = os.environ.get("LLM_MODEL", "")
llm_api_key = os.environ.get("LLM_API_KEY", "")
llm_timeout = 60
llm_extra_body = {}
tools = {}
agent_permissions = {}
user_permissions = {}
max_analysis_calls = 3
max_worker_calls = 8
max_tool_calls = 12
ticket_ttl = 300


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call_llm(messages: list[dict], tool_schemas: list[dict], json_output: bool) -> dict:
    if not llm_base_url:
        raise RuntimeError("LLM_BASE_URL is not set. Run: export LLM_BASE_URL=https://your-endpoint/v1")
    payload = {**llm_extra_body, "model": llm_model, "messages": messages, "stream": False}
    if tool_schemas:
        payload["tools"] = tool_schemas
        payload["tool_choice"] = "auto"
    if json_output:
        payload["response_format"] = {"type": "json_object"}
    headers = {"Content-Type": "application/json"}
    if llm_api_key:
        headers["Authorization"] = f"Bearer {llm_api_key}"
    request = Request(llm_base_url.rstrip("/") + "/chat/completions", json.dumps(payload).encode("utf-8"), headers)
    with build_opener(NoRedirect).open(request, timeout=llm_timeout) as response:
        data = json.load(response)
    return data["choices"][0]["message"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create, restore, or fork conversations and process instructions using capability tickets"
    )
    parser.add_argument("message", nargs="?", help="New user message")
    parser.add_argument("--jsonl", help="Path to conversation JSONL to restore; use - for standard input")
    parser.add_argument("--fork", action="store_true", help="Copy existing conversation context and create a new session ID")
    parser.add_argument("--monitor", metavar="AUDIT_JSONL",
                        help="Enable the Layer 4 monitor and append its hash-chained audit log to this file")
    args = parser.parse_args()

    if args.jsonl is None:
        history = ConversationHistory(str(uuid4()))
        if managed_prompt is not None:
            history.add_managed_prompt(managed_prompt)
    else:
        if args.jsonl == "-":
            history = ConversationHistory.from_jsonl(sys.stdin)
        else:
            with open(args.jsonl, encoding="utf-8-sig") as stream:
                history = ConversationHistory.from_jsonl(stream)
        if args.fork:
            history = history.fork()
    if args.message is not None:
        instruction = UserInstruction(history.session_id, history.next_turn_id, args.message)
        options = dict(
            tools=tools, agent_permissions=agent_permissions, user_permissions=user_permissions,
            max_analysis_calls=max_analysis_calls, max_worker_calls=max_worker_calls,
            max_tool_calls=max_tool_calls, ticket_ttl=ticket_ttl,
        )
        if args.monitor:
            from monitor import Monitor
            from src.monitored_stages import MonitoredTurnStages
            stages = MonitoredTurnStages(call_llm, monitor=Monitor(args.monitor), **options)
        else:
            stages = TurnStages(call_llm, **options)
        result = process_turn(instruction, history, stages=stages, max_steps=max_steps)
        print(f"[{result.status.value}] {result.message}", file=sys.stderr)
    for line in history.to_jsonl():
        print(line, flush=True)


if __name__ == "__main__":
    main()
