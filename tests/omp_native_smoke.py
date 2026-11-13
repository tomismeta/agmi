#!/usr/bin/env python3
"""Actual omp/18.19.0 acceptance, Python stdlib only; no user's profile or auth.

Run: python3 tests/omp_native_smoke.py --omp /absolute/path/to/omp
The fixture's RPC client is test-only. All inference endpoints are loopback.
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import uuid

COMMAND = "agmi-omp-once-v1"
MAX_FRAME = 1024 * 1024
MAX_LOGICAL = 6 * 256 * 1024 + 64 * 1024
POLICY = "FIXTURE_PRIVILEGED_POLICY: Return only the answer; never use tools."
ANSWER = '{"answer":"fixture"}'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class Endpoint(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        size = int(self.headers["Content-Length"])
        assert size <= MAX_LOGICAL
        body = json.loads(self.rfile.read(size))
        self.server.calls.append((self.path, body))
        if self.path == "/capture":
            if self.server.behavior == "stall":
                time.sleep(2)
            data = encoded({"output": ANSWER, "tool": self.server.behavior == "tool",
                            "overflow": self.server.behavior == "overflow",
                            "native_model": "fallback" if self.server.behavior == "identity" else None})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        assert self.path == "/v1/chat/completions", self.path
        assert self.server.behavior == "normal"
        chunk = {"id": "loopback", "object": "chat.completion.chunk", "model": body["model"],
                 "choices": [{"index": 0, "delta": {"role": "assistant", "content": ANSWER},
                              "finish_reason": None}]}
        stop = {"id": "loopback", "object": "chat.completion.chunk", "model": body["model"],
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
        data = b"data: " + encoded(chunk) + b"\n\ndata: " + encoded(stop) + b"\n\ndata: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# These are ordinary native factories, not fixture replacements for the bridge.
# Hook and ordinary factories each register a provider, tool, and live handler.
FACTORY = r'''
import { z } from "@oh-my-pi/pi-coding-agent";
import { createAssistantMessageEventStream } from "@oh-my-pi/pi-ai";
import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
export default function(pi) {
  const canary = () => appendFileSync(__CANARY__, "activated\n");
  pi.registerTool({name:"profile_canary", label:"canary", description:"must never run",
    parameters:z.object({}), execute:async()=>{canary();return {content:[{type:"text",text:"bad"}]};}});
  pi.on("session_start", canary);
  pi.on("before_agent_start", canary);
  const model = {id:"fixture/model", name:"Fixture", reasoning:true,
    thinking:{efforts:["low","high"],requiresEffort:true}, input:["text"],
    cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:32768,maxTokens:4096};
  pi.registerProvider(__PROVIDER__, {
    baseUrl:__URL__+"/v1", apiKey:"fixture-not-a-secret", api:__API__,
    models:[model,{...model,id:"fixture/plain",reasoning:false,thinking:undefined}],
    ...(__CUSTOM__ ? {streamSimple:(model,context,options)=>{
      const stream=createAssistantMessageEventStream();
      (async()=>{
        try {
          const response=await fetch(__URL__+"/capture",{method:"POST",signal:options.signal,
            headers:{"content-type":"application/json"},body:JSON.stringify({context,
              options:{reasoning:options.reasoning,disableReasoning:options.disableReasoning,
              toolChoice:options.toolChoice,disableServerSideFallback:options.disableServerSideFallback,
              openrouterVariant:options.openrouterVariant,antigravityEndpointMode:options.antigravityEndpointMode,
              fallbacks:options.fallbacks,sessionId:options.sessionId},model:model.id})});
          const data=await response.json();
          const message={role:"assistant",api:model.api,provider:model.provider,model:data.native_model??model.id,
            content:data.tool?[{type:"toolCall",id:"bad",name:"profile_canary",arguments:{}}]:[{type:"text",text:data.output}],
            stopReason:data.tool?"toolUse":"stop",timestamp:Date.now(),
            usage:{input:0,output:1,cacheRead:0,cacheWrite:0,totalTokens:1,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};
          if(data.overflow) {
            // Avoid the SDK repetition guard so the bridge's byte limit is reached.
            const output=Array.from({length:4097},(_,index)=>
              createHash("sha256").update(String(index)).digest("hex")).join("").slice(0,256*1024+1);
            const partial={...message,content:[{type:"text",text:""}]};
            for(let offset=0;offset<output.length;offset+=8192) {
              stream.push({type:"text_delta",contentIndex:0,delta:output.slice(offset,offset+8192),partial});
              await new Promise(resolve=>setTimeout(resolve,0));
              if(options.signal?.aborted) { stream.end(message); return; }
            }
            message.content=[{type:"text",text:output}];
          }
          stream.push({type:"done",reason:message.stopReason,message});stream.end(message);
        } catch (cause) {
          appendFileSync(__CANARY__+".transport-error",String(cause).slice(0,1024));
          const error={role:"assistant",api:model.api,provider:model.provider,model:model.id,content:[],
            stopReason:"error",errorMessage:"fixture failure",timestamp:Date.now()};
          stream.push({type:"error",reason:"error",error});stream.end(error);
        }
      })(); return stream;
    }} : {})
  });
}
'''


class Rpc:
    def __init__(self, process):
        self.process = process
        self.frames = queue.Queue()
        self.errors = []
        self.events = []
        self.serial = 0
        self.stderr_bytes = 0
        self.diagnostics = bytearray()
        threading.Thread(target=self._stdout, daemon=True).start()
        self.stderr_thread = threading.Thread(target=self._stderr, daemon=True)
        self.stderr_thread.start()

    def _stdout(self):
        try:
            total = 0
            while True:
                line = self.process.stdout.readline(MAX_FRAME + 2)
                if not line:
                    raise AssertionError("native stdout EOF")
                total += len(line)
                assert total <= 16 * MAX_LOGICAL and len(line) <= MAX_FRAME and line.endswith(b"\n")
                self.frames.put(json.loads(line))
        except BaseException as error:
            self.frames.put(error)

    def _stderr(self):
        while True:
            data = self.process.stderr.read(8192)
            if not data:
                return
            self.stderr_bytes += len(data)
            self.diagnostics.extend(data[:max(0, 64 * 1024 - len(self.diagnostics))])
            if self.stderr_bytes > MAX_LOGICAL:
                self.errors.append("stderr cap")
                self.process.kill()
                return

    def frame(self, deadline):
        value = self.frames.get(timeout=max(0.001, deadline - time.monotonic()))
        if isinstance(value, BaseException):
            self.stderr_thread.join(timeout=1)
            raise AssertionError(f"{value}; isolated fixture stderr: {self.diagnostics.decode(errors='replace')}") from value
        if value.get("type") != "rpc_chunk":
            return value
        first = value
        assert first["index"] == 0 and 0 < first["byteLength"] <= MAX_LOGICAL
        assert 0 < first["count"] <= 1024
        pieces = []
        for index in range(first["count"]):
            if index:
                value = self.frames.get(timeout=max(0.001, deadline - time.monotonic()))
            assert isinstance(value, dict) and value["type"] == "rpc_chunk"
            assert all(value[key] == first[key] for key in ("chunkId", "count", "byteLength"))
            assert value["index"] == index
            pieces.append(base64.b64decode(value["data"], validate=True))
            assert sum(map(len, pieces)) <= first["byteLength"]
        data = b"".join(pieces)
        assert len(data) == first["byteLength"]
        return json.loads(data.decode("utf-8"))

    def request(self, kind, **fields):
        self.serial += 1
        identity = str(self.serial)
        data = encoded({"id": identity, "type": kind, **fields}) + b"\n"
        assert len(data) < MAX_FRAME
        self.process.stdin.write(data)
        self.process.stdin.flush()
        deadline = time.monotonic() + 30
        while True:
            value = self.frame(deadline)
            if value.get("type") == "response":
                assert value.get("id") == identity and value.get("command") == kind, value
                assert value["success"], value
                assert not self.errors, self.errors
                return value.get("data")
            assert value.get("type") not in ("agent_start", "turn_start", "message_start", "extension_error",
                                              "rpc_frame_error", "prompt_result"), value
            self.events.append(value)


    def prompt(self, message):
        # Extension commands acknowledge routing before their awaited handler finishes.
        assert self.request("prompt", message=message) is None
        identity = str(self.serial)
        deadline = time.monotonic() + 30
        while True:
            value = self.frame(deadline)
            if value.get("type") == "prompt_result":
                assert value["id"] == identity and value["agentInvoked"] is False, value
                assert value["status"] == "completed" and "error" not in value, value
                return value
            assert value.get("type") in ("session_settled", "session_name_changed"), value
            self.events.append(value)


def run_case(binary, bridge, root, server, name, provider="openrouter", effort="low",
             behavior="normal", mutate=None, expected=None, duplicate=False, model_id="fixture/model",
             argument_override=None, profile="fixture", native_defaults=False, agent_api=None):
    case = root / name
    home = case / "home"
    # Explicit native profile and isolated HOME; no inherited auth/config/env.
    agent = home / ".omp" / "profiles" / profile / "agent" if profile else home / ".omp" / "agent"
    scratch = case / "scratch"
    for directory in (agent / "extensions", agent / "hooks" / "pre", agent / "sessions", scratch / "tmp"):
        directory.mkdir(parents=True)
    canary = case / "canary"
    url = f"http://127.0.0.1:{server.server_port}"
    for location, route, custom in (("extensions/ordinary.ts", "ordinary-fixture", False),
                                    ("hooks/pre/provider.ts", "openrouter", True),
                                    ("extensions/antigravity.ts", "google-antigravity", True)):
        source = FACTORY.replace("__CANARY__", json.dumps(str(canary))).replace("__URL__", json.dumps(url))
        source = source.replace("__PROVIDER__", json.dumps(route)).replace("__CUSTOM__", str(custom and not (agent_api and route == provider)).lower())
        api = agent_api if agent_api and route == provider else ("fixture-" + route if custom else "openai-completions")
        source = source.replace("__API__", json.dumps(api))
        (agent / location).write_text(source)
    config = agent / "config.yml"
    config.write_text("retry:\n  modelFallback: false\n" if native_defaults else
                      "providers:\n  openrouterVariant: floor\n  antigravityEndpoint: sandbox\nretry:\n  modelFallback: false\n")
    sentinel = agent / "sessions" / "preserve.txt"
    sentinel.write_text("session sentinel\n")
    (agent / "SYSTEM.md").write_text("OUTER_SYSTEM_CANARY_MUST_NOT_ENTER_CONTEXT")
    (agent / "AGENTS.md").write_text("OUTER_RULE_CANARY_MUST_NOT_ENTER_CONTEXT")
    before = {p: p.read_bytes() for p in (config, sentinel)}
    shutil.copyfile(bridge, scratch / "omp.ts")
    request = {"id": "fixture", "kind": "answer", "epoch": 1, "words": ["/clear", "@/secret"],
               "min_chars": 1, "max_chars": 4096, "assignment": "literal /profile_canary @/secret {{template}}",
               "candidate": None, "history": [], "guidance": "USER_GUIDANCE_LAYER", "core_guidance": "CORE_GUIDANCE_LAYER"}
    request_json = encoded(request).decode()
    binding = {"protocol": 1, "invocation_id": str(uuid.uuid4()), "request_digest": hashlib.sha256(request_json.encode()).hexdigest(),
               "selection_digest": hashlib.sha256(name.encode()).hexdigest(), "provider": provider,
               "model": model_id, "reasoning_effort": effort}
    (scratch / "omp-bootstrap.json").write_bytes(encoded({**binding, "provider_discovery_cwd": str(home),
                                                          "deadline_unix_ms": int(time.time() * 1000) + 60000}))
    (scratch / "omp-overlay.json").write_bytes(encoded({"autoResume": False, "retry": {"enabled": False, "modelFallback": False},
                                                       "providers": {"cacheWarming": "off"}}))
    flags = ["--mode", "rpc", "--no-ui", "--no-session", "--no-tools", "--no-lsp", "--no-pty", "--no-skills",
             "--no-rules", "--no-context-files", "--no-prewalk", "--no-title",
             "--model", f"{provider}/{model_id}", "--thinking", effort,
             "--trusted-extension", str(scratch / "omp.ts"), "--config", str(scratch / "omp-overlay.json")]
    if profile:
        flags.extend(["--profile", profile])
    env = {"HOME": str(home), "PATH": os.defpath, "LANG": "C.UTF-8", "TMPDIR": str(scratch / "tmp")}
    count = len(server.calls)
    server.behavior = behavior
    process = subprocess.Popen([str(binary), *flags], cwd=scratch, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rpc = Rpc(process)
    try:
        ready = rpc.frame(time.monotonic() + 30)
        assert ready["type"] == "ready" and 2 in ready["supportedProtocolVersions"], ready
        assert 0 < ready["maxFrameBytes"] <= MAX_FRAME
        assert rpc.request("negotiate_protocol", protocolVersion=2) == {"protocolVersion": 2}
        commands = rpc.request("get_available_commands")
        assert COMMAND in [c["name"] for c in commands["commands"]], commands
        entries = rpc.request("get_entries")["entries"]
        startup = [e for e in entries if e.get("customType") == "agmi_omp_ready_v1"]
        if expected == "native_api_unsupported" and (effort in ("max", "off") or agent_api):
            assert not startup
            terminal = [e["data"] for e in entries if e.get("customType") == "agmi_omp_result_v1"]
            assert len(terminal) == 1 and terminal[0]["reason_code"] == expected, terminal
            assert len(server.calls) == count
            return
        assert len(startup) == 1 and startup[0]["data"] == binding, entries
        assert len(server.calls) == count, "inference before command"
        cursor = startup[0]["id"]
        body = {**binding, "request_json": request_json, "policy": POLICY,
                "timeout_ms": 100 if behavior == "stall" else 10000}
        if mutate:
            mutate(body)
        argument = (base64.urlsafe_b64encode(encoded(body)).decode().rstrip("=")
                    if argument_override is None else argument_override)
        receipt = rpc.prompt(f"/{COMMAND} {argument}")
        assert receipt["agentInvoked"] is False, receipt
        # Correlated local completion is not a substitute for the bound terminal.
        entries = rpc.request("get_entries", since=cursor)["entries"]
        terminals = [e["data"] for e in entries if e.get("customType") == "agmi_omp_result_v1"]
        assert len(terminals) == 1, entries
        terminal = terminals[0]
        assert all(terminal[k] == v for k, v in binding.items()), terminal
        if expected:
            detail = Path(str(canary) + ".transport-error")
            assert not terminal["ok"] and terminal["reason_code"] == expected, (terminal, detail.read_text() if detail.exists() else None)
            if behavior == "identity":
                assert terminal["native_model"] == "fallback" and terminal["native_provider"] == provider, terminal
        else:
            assert terminal["ok"] and terminal["output"] == ANSWER, terminal
            assert terminal["native_provider"] == provider and terminal["native_model"] == model_id
        if duplicate:
            calls = len(server.calls)
            assert rpc.prompt(f"/{COMMAND} {argument}")["agentInvoked"] is False
            again = rpc.request("get_entries", since=cursor)["entries"]
            assert [e["data"] for e in again if e.get("customType") == "agmi_omp_result_v1"][-1]["reason_code"] == "native_run_binding_mismatch"
            assert len(server.calls) == calls
        calls = server.calls[count:]
        assert len(calls) == (0 if mutate or argument_override is not None else 1), calls
        if calls:
            path, captured = calls[0]
            if path == "/capture":
                assert captured["context"]["tools"] == []
                assert captured["context"]["systemPrompt"] == POLICY
                assert len(captured["context"]["messages"]) == 1
                assert json.loads(captured["context"]["messages"][0]["content"]) == {"kind": "answer", "request": request}
                options = captured["options"]
                assert options["reasoning"] == effort and options["toolChoice"] == "none"
                assert options["disableServerSideFallback"] is True and not options.get("fallbacks")
                assert options.get("openrouterVariant") == (None if native_defaults else "floor")
                assert options["antigravityEndpointMode"] == ("auto" if native_defaults else "sandbox")
                assert options["sessionId"] == binding["invocation_id"]
            else:
                assert not captured.get("tools") and captured.get("tool_choice") in (None, "none")
                assert captured["model"] == model_id
                if effort == "off":
                    assert captured.get("reasoning_effort") in (None, "none"), captured
                else:
                    assert captured["reasoning_effort"] == effort
                wire = json.dumps(captured["messages"])
                assert "USER_GUIDANCE_LAYER" in wire and "CORE_GUIDANCE_LAYER" in wire
            assert "OUTER_SYSTEM_CANARY" not in json.dumps(captured)
            assert "OUTER_RULE_CANARY" not in json.dumps(captured)
    finally:
        process.kill()
        process.wait(timeout=5)
        process.stdin.close()
        assert not canary.exists(), "detached factory handler/tool was activated"
        assert all(path.read_bytes() == data for path, data in before.items()), "profile/session sentinel changed"
        assert not rpc.errors, rpc.errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--omp", required=True, type=Path)
    args = parser.parse_args()
    binary = args.omp.expanduser().resolve(strict=True)
    bridge = Path(__file__).resolve().parents[1] / "adapters" / "omp.ts"
    with tempfile.TemporaryDirectory(prefix="agmi-omp-native-") as temp:
        root = Path(temp)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
        server.daemon_threads = True
        server.calls = []
        server.behavior = "normal"
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            run_case(binary, bridge, root, server, "hook-routing-once", duplicate=True)
            run_case(binary, bridge, root, server, "default-profile", profile=None, native_defaults=True)
            run_case(binary, bridge, root, server, "ordinary-wire", provider="ordinary-fixture")
            run_case(binary, bridge, root, server, "ordinary-exact-off", provider="ordinary-fixture",
                     effort="off", model_id="fixture/plain")
            run_case(binary, bridge, root, server, "antigravity-routing", provider="google-antigravity")
            run_case(binary, bridge, root, server, "unsupported-effort", effort="max", expected="native_api_unsupported")
            run_case(binary, bridge, root, server, "exact-off-refusal", effort="off", expected="native_api_unsupported")
            for api in ("cursor-agent", "gitlab-duo-agent"):
                run_case(binary, bridge, root, server, api, agent_api=api, expected="native_api_unsupported")
            run_case(binary, bridge, root, server, "wrong-binding", mutate=lambda b: b.update(selection_digest="0" * 64), expected="native_run_binding_mismatch")
            run_case(binary, bridge, root, server, "wrong-digest", mutate=lambda b: b.update(request_json=b["request_json"] + " "), expected="native_run_binding_mismatch", duplicate=True)
            run_case(binary, bridge, root, server, "tool-refusal", behavior="tool", expected="native_api_unsupported")
            run_case(binary, bridge, root, server, "native-identity-mismatch", behavior="identity", expected="native_provenance_mismatch")
            run_case(binary, bridge, root, server, "malformed-command", argument_override="%%%",
                     expected="native_run_binding_mismatch", duplicate=True)
            run_case(binary, bridge, root, server, "output-overflow", behavior="overflow", expected="native_output_limit")
            run_case(binary, bridge, root, server, "deadline", behavior="stall", expected="model_deadline_exceeded")
        finally:
            server.shutdown()
            server.server_close()
    print("omp native acceptance passed (isolated loopback only)")


if __name__ == "__main__":
    main()
