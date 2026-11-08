"""Embedded by agmi; native Hermes OAuth only, never a MinePOA credential reader.

The launcher supplies bootstrap source as data. Only its literal source-directory
insertion is accepted; launcher code is not evaluated. Unsupported embedding APIs
fail before inference. The Rust owner controls deadline, pipes and process group.
"""
import asyncio
import ast
import contextlib
import inspect
import json
import logging
import os
import sys
from pathlib import Path

STARTED = False
PRELAUNCH_CODE = 78


class NativeFailure(Exception):
    def __init__(self, kind):
        self.kind = kind


def main():
    global STARTED, PRELAUNCH_CODE
    payload = json.load(sys.stdin)
    tree = ast.parse(sys.argv[1])
    roots = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute)
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "sys"
                and node.func.value.attr == "path" and node.func.attr == "insert"
                and len(node.args) == 2 and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == 0 and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)):
            roots.append(node.args[1].value)
    if len(roots) != 1 or not os.path.isabs(roots[0]):
        raise RuntimeError("unsupported Hermes launcher bootstrap")
    sys.path.insert(0, roots[0])
    logging.disable(logging.CRITICAL)
    # Keep third-party diagnostics out of the sole machine-readable result.
    with contextlib.redirect_stdout(sys.stderr):
        import hermes_bootstrap  # noqa: F401
        from hermes_cli.runtime_provider import resolve_runtime_provider
        from run_agent import AIAgent
        from hermes_state import SessionDB
        required = {"skip_context_files", "skip_memory", "skip_background_review",
                    "fallback_model", "enabled_toolsets", "run_budget_seconds",
                    "session_db", "side_agent", "cwd", "requested_provider"}
        if not required <= set(inspect.signature(AIAgent).parameters):
            raise RuntimeError("unsupported Hermes embedding isolation API")
        if "system_message" not in inspect.signature(AIAgent.run_conversation).parameters:
            raise RuntimeError("unsupported Hermes privileged policy API")
        PRELAUNCH_CODE = 79
        runtime = resolve_runtime_provider(requested="openai-codex", target_model=payload["model"])
        PRELAUNCH_CODE = 80
        expected = ("openai-codex", "codex_responses", payload["hermes_api_url"])
        if tuple(runtime.get(k) for k in ("provider", "api_mode", "base_url")) != expected:
            raise RuntimeError("native OAuth route mismatch")
        if runtime.get("source") not in ("hermes-auth-store", "manual:device_code", "device_code"):
            raise RuntimeError("native OAuth credentials unavailable")
        PRELAUNCH_CODE = 78
        db = SessionDB(Path.cwd() / "session.db")
        agent = None
        try:
            agent = AIAgent(
                model=payload["model"], provider=expected[0], requested_provider=expected[0],
                api_mode=expected[1], base_url=expected[2], api_key=runtime["api_key"],
                credential_pool=runtime.get("credential_pool"), enabled_toolsets=["bot_room"],
                fallback_model=[], max_iterations=1, run_budget_seconds=payload["timeout_seconds"],
                reasoning_config={"enabled": True, "effort": payload["reasoning"]},
                quiet_mode=True, save_trajectories=False, verbose_logging=False,
                skip_context_files=True, skip_memory=True, skip_background_review=True,
                session_db=db, side_agent=True, platform="subagent", cwd=os.getcwd(),
                ephemeral_system_prompt="No tools or external actions. Return only the requested JSON artifact.")
            for attribute in ("compression_enabled", "codex_responses_native_compaction", "_skip_mcp_refresh"):
                if not hasattr(agent, attribute):
                    raise RuntimeError("unsupported Hermes isolation diagnostics")
            agent.compression_enabled = False
            agent.codex_responses_native_compaction = False
            agent._skip_mcp_refresh = True
            if agent.tools or agent.valid_tool_names or agent._fallback_chain:
                raise RuntimeError("tools or fallback enabled")
            if (agent.provider, agent.api_mode, agent.base_url) != expected or agent.model != payload["model"]:
                raise RuntimeError("model route mismatch")
            if agent.reasoning_config != {"enabled": True, "effort": payload["reasoning"]}:
                raise RuntimeError("reasoning setting changed")
            STARTED = True
            # Policy uses the inspected native privileged channel. The user
            # message contains only the envelope; this is not semantic validation
            # or a claim that model prompt injection is solved.
            result = agent.run_conversation(payload["prompt"], system_message=payload["policy"])
            if (result.get("completed") is not True or result.get("partial")
                    or result.get("interrupted") or result.get("failed")):
                raise NativeFailure("incomplete")
            if agent.model != payload["model"] or agent.provider != expected[0]:
                raise NativeFailure("provenance")
            output = result.get("final_response")
            if not isinstance(output, str) or len(output.encode("utf-8")) > 65536:
                raise NativeFailure("output")
            envelope = {"provider": agent.provider, "model": agent.model,
                        "run_id": agent.session_id, "reasoning_effort": payload["reasoning"],
                        "output": output}
        finally:
            if agent is not None:
                agent.close()
            db.close()
    print(json.dumps(envelope, ensure_ascii=True))


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except (Exception, asyncio.CancelledError, KeyboardInterrupt) as error:
        # Only static categories cross the boundary, never exception text/tracebacks.
        if STARTED:
            kind = "exception"
            if isinstance(error, NativeFailure):
                kind = error.kind
            elif isinstance(error, TimeoutError):
                kind = "timeout"
            elif isinstance(error, (asyncio.CancelledError, KeyboardInterrupt)):
                kind = "cancelled"
            print(json.dumps({"ok": False, "error": {"kind": kind}}))
        raise SystemExit(1 if STARTED else PRELAUNCH_CODE)
