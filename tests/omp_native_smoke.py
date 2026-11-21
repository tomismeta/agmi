#!/usr/bin/env python3
"""Actual omp/19.0.1 acceptance, Python stdlib only; no user's profile or auth.

Run: python3 tests/omp_native_smoke.py --omp /absolute/path/to/omp
The fixture's RPC client is test-only. All inference endpoints are loopback.
"""
import argparse
import base64
from contextlib import suppress
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
GO_PROVIDER, GO_KEY = "opencode-go", "agmi-loopback-fixture"
GO_WRONG_KEY = "fixture-private-wrong-key"


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class Endpoint(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_CONNECT(self):
        # Factory's isolated profile can try auxiliary requests. This loopback
        # proxy never forwards them and does not send an error page to a closing socket.
        self.send_response_only(403)
        self.send_header("Connection", "close")
        with suppress(BrokenPipeError, ConnectionResetError):
            self.end_headers()

    def do_GET(self):
        if self.server.go_model is None or self.path != "/v1/models":
            self.send_error(404)
            return
        data = encoded({"object": "list", "data": [{"object": "model", "id": self.server.go_model}]})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        with suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(data)

    def do_POST(self):
        # Count ingress before parsing, even if validation fails.
        call = [self.path.split("?", 1)[0], None]
        self.server.calls.append(call)
        size = int(self.headers["Content-Length"])
        assert size <= MAX_LOGICAL
        body = json.loads(self.rfile.read(size))
        path = call[0]
        call[1] = body
        if self.server.go_model is not None:
            assert self.headers.get("Authorization") == f"Bearer {GO_KEY}"
        if path.startswith("/api/llm/"):
            # Only the actual Factory transport supplies its native route headers.
            wire, path = path.removeprefix("/api/llm/").split("/", 1)
            path = "/" + path
            assert self.headers["x-factory-client"] == "cli"
            assert (wire, path, self.headers["x-api-provider"]) in (
                ("a", "/v1/messages", "anthropic"), ("o", "/v1/chat/completions", "fireworks")
            )
        if path == "/capture":
            if self.server.behavior == "stall":
                time.sleep(2)
            data = encoded({"output": ANSWER, "tool": self.server.behavior == "tool",
                            "stream_error": self.server.behavior == "stream-error",
                            "overflow": self.server.behavior == "overflow",
                            "native_model": "fallback" if self.server.behavior == "identity" else None,
                            "upstream_model": {"served": "fixture/model", "served-other": "fixture/served-other"}.get(self.server.behavior),
                            "phase_behavior": self.server.behavior})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if path == "/v1/responses":
            phase = self.server.behavior
            assert phase in ("wire-phase-final", "wire-phase-commentary"), phase
            response = {"id": "resp_fixture", "object": "response", "model": body["model"]}
            events = [{"type": "response.created", "response": {**response, "status": "in_progress"}}]
            items = []
            texts = (
                (("commentary", "NOT_ARTIFACT"), ("final_answer", ANSWER))
                if phase == "wire-phase-final" else (("commentary", ANSWER),)
            )
            for index, (text_phase, text) in enumerate(texts):
                item = {"id": f"msg_fixture_{index}", "type": "message", "role": "assistant", "phase": text_phase}
                items.append({**item, "status": "completed", "content": [
                    {"type": "output_text", "text": text, "annotations": []}
                ]})
                events.extend([
                    {"type": "response.output_item.added", "output_index": index,
                     "item": {**item, "status": "in_progress", "content": []}},
                    {"type": "response.output_item.done", "output_index": index, "item": items[-1]},
                ])
            events.append({"type": "response.completed", "response": {
                **response, "status": "completed", "output": items,
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }})
            data = b"".join(b"data: " + encoded(event) + b"\n\n" for event in events)
        elif path == "/v1/messages":
            stop_reason = self.server.behavior.removeprefix("anthropic-")
            retry = stop_reason.startswith("retry-")
            empty = retry and len(self.server.calls) == self.server.case_start + 1
            stop_reason = "end_turn" if empty else stop_reason.removeprefix("retry-")
            delta = {"stop_sequence": "fixture-stop" if stop_reason == "stop_sequence" else None}
            if stop_reason != "missing":
                delta["stop_reason"] = None if stop_reason == "null" else stop_reason
            events = [
                {"type": "message_start", "message": {
                    "id": "msg_fixture", "type": "message", "role": "assistant", "model": body["model"],
                    "content": [], "stop_reason": None, "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 0},
                }},
            ]
            if not empty:
                events.extend([
                    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": ANSWER}},
                    {"type": "content_block_stop", "index": 0},
                ])
            if not (retry and stop_reason == "missing"):
                events.append({"type": "message_delta", "delta": delta, "usage": {"output_tokens": int(not empty)}})
            events.append({"type": "message_stop"})
            data = b"".join(b"event: " + event["type"].encode() + b"\ndata: " + encoded(event) + b"\n\n"
                            for event in events)
        else:
            assert path == "/v1/chat/completions", self.path
            effort = body.get("reasoning_effort")
            rejected = "max" if body["model"] == "glm-5.3" else "low"
            supported = "high" if rejected == "max" else "medium"
            if self.server.behavior == "effort-rejected" and effort == rejected:
                data = encoded({"error": {"type": "invalid_request_error", "param": "reasoning_effort",
                                          "message": f"Unsupported reasoning_effort '{rejected}'. Supported values are: '{supported}'."}})
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            assert self.server.behavior in ("normal", "wire-model-change", "wire-model-omitted", "effort-rejected")
            chunk = {"id": "loopback", "object": "chat.completion.chunk",
                     "choices": [{"index": 0, "delta": {"role": "assistant", "content": ANSWER},
                                  "finish_reason": None}]}
            stop = {"id": "loopback", "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            if self.server.behavior != "wire-model-omitted":
                stop["model"] = body["model"]
                chunk["model"] = "fixture/served-other" if self.server.behavior == "wire-model-change" else body["model"]
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
    baseUrl:__URL__+(__API__==="anthropic-messages"?"":"/v1"), apiKey:"fixture-not-a-secret", api:__API__,
    models:[model,{...model,id:"fixture/plain",reasoning:false,thinking:undefined},
      ...["fixture/model:free:online","perplexity/sonar","sonar","gpt-5-search-api"].map(id=>({...model,id}))],
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
          if (data.stream_error) throw new Error("fixture private provider error");
          const message={role:"assistant",api:model.api,provider:model.provider,model:data.native_model??model.id,
            content:data.tool?[{type:"toolCall",id:"bad",name:"profile_canary",arguments:{}}]:[{type:"text",text:data.output}],
            stopReason:data.tool?"toolUse":"stop",timestamp:Date.now(),
            usage:{input:0,output:1,cacheRead:0,cacheWrite:0,totalTokens:1,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};
          if (data.upstream_model) {
            message.upstreamModel=data.upstream_model;
            message.upstreamProvider="fixture-upstream";
          }
          const phaseText=(phase,text,id=phase)=>({type:"text",text,
            textSignature:JSON.stringify({v:1,id,phase})});
          switch(data.phase_behavior) {
            case "commentary": message.content=[phaseText("commentary",data.output)]; break;
            case "partial": message.content=[phaseText("partial_answer",data.output)]; break;
            case "phase-final": message.content=[phaseText("commentary","NOT_ARTIFACT"),
              phaseText("partial_answer","ALSO_NOT_ARTIFACT"),phaseText("final_answer",data.output)]; break;
            case "phase-ambiguous": message.content=[{type:"text",text:data.output},
              phaseText("final_answer",data.output)]; break;
            case "phase-out-of-order": message.content=[phaseText("final_answer",data.output),
              phaseText("partial_answer","incomplete follow-on")]; break;
            case "stop-conflict": message.stopReason="length"; break;
          }
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
          stream.push({type:"done",reason:data.phase_behavior==="stop-conflict"?"stop":message.stopReason,message});
          stream.end(message);
        } catch (cause) {
          appendFileSync(__CANARY__+".transport-error",String(cause).slice(0,1024));
          const error={role:"assistant",api:model.api,provider:model.provider,model:model.id,content:[],
            stopReason:"error",errorMessage:String(cause),timestamp:Date.now()};
          stream.push({type:"error",reason:"error",error});stream.end(error);
        }
      })(); return stream;
    }} : {})
  });
}
'''


# The pinned native model declaration plus a loopback gateway and a fake bearer.
# No custom stream, fetch override, authentication flow, or live discovery.
DROID_PROFILE = r'''
import { factoryDroidRegistry } from "@oh-my-pi/pi-catalog/compat/factory-droid";
import { buildFactoryDroidModel } from "@oh-my-pi/pi-catalog/discovery";
export default function(pi) {
  const entry = factoryDroidRegistry().find(({spec}) => spec.id === __MODEL__);
  if (!entry) throw new Error("Factory fixture model absent from the native catalogue");
  const model = buildFactoryDroidModel(entry);
  const baseUrl = __URL__ + (entry.policy.wire === "anthropic-messages" ? "/api/llm/a" : "/api/llm/o/v1");
  pi.registerProvider(model.provider, {api:model.api, apiKey:"fixture-not-a-secret", baseUrl,
    models:[{...model, baseUrl}]});
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


# Applied only to a scratch copy of the extension: the actual native encoder
# still builds the request, then this stand-in for an incompatible SDK alters it.
GO_TRANSPORT_FAULT = r'''
import { streamSimple as nativeStreamSimple } from "@oh-my-pi/pi-ai";
import { writeFileSync } from "node:fs";
const streamSimple: typeof nativeStreamSimple = (model, context, options) => {
  const fault = __FAULT__;
  let hookRan = false;
  return nativeStreamSimple(model, context, {
    ...options,
    onPayload(payload, ...rest) {
      if (fault === "missing-model" || fault === "caught-hook" || fault === "agreeing-model-alias") {
        const input = { ...(payload as Record<string, unknown>) };
        if (fault === "missing-model") delete input.model;
        else input.model = "fixture/wrong-model";
        try { options!.onPayload!(input, ...rest); } catch { /* SDK catches the rejection. */ }
        hookRan = true;
        return;
      }
      const result = options!.onPayload!(payload, ...rest);
      hookRan = true;
      return result;
    },
    fetch(url, init) {
      if (!hookRan || typeof init?.body !== "string") throw new Error("fixture transport was not reached");
      const payload = JSON.parse(init.body);
      const headers = new Headers(init.headers);
      switch (fault) {
        case "wire-model": case "agreeing-model-alias": payload.model = "fixture/wrong-model"; break;
        case "wire-effort": payload.reasoning_effort = "high"; break;
        case "wire-tool": payload.tools = [{ type: "web_search" }]; break;
        case "wire-fallback": payload.fallbacks = ["fixture/wrong-model"]; break;
        case "wire-prompt": payload.messages[0].content = "Replaced privileged prompt"; break;
        case "wire-auth": headers.set("Authorization", "Bearer " + __WRONG_KEY__); break;
      }
      const body = fault === "wire-duplicate" ? '{"model":"fixture/wrong-model",' + init.body.slice(1) : JSON.stringify(payload);
      writeFileSync(__MARKER__, "reached\n");
      return options!.fetch!(url, { ...init, headers, body });
    },
  });
};
'''


def run_case(binary, bridge, root, server, name, provider="openrouter", effort="low",
             behavior="normal", mutate=None, expected=None, duplicate=False, model_id="fixture/model",
             argument_override=None, profile="fixture", native_defaults=False, agent_api=None, expected_calls=1,
             startup_refusal=False, openrouter_variant="floor", shell_model_id=None, extra_body=None,
             wire_mode=None, wire_id=None, go_fault=None):
    case = root / name
    home = case / "home"
    # Explicit native profile and isolated HOME; no inherited auth/config/env.
    agent = home / ".omp" / "profiles" / profile / "agent" if profile else home / ".omp" / "agent"
    scratch = case / "scratch"
    for directory in (agent / "extensions", agent / "hooks" / "pre", agent / "sessions", scratch / "tmp"):
        directory.mkdir(parents=True)
    canary = case / "canary"
    url = f"http://127.0.0.1:{server.server_port}"
    stock_go = provider == GO_PROVIDER
    if stock_go:
        (agent / "models.yml").write_text(json.dumps({"providers": {provider: {
            "baseUrl": url + "/v1", "apiKey": GO_KEY,
        }}}))
    if provider == "factory-droid":
        source = DROID_PROFILE.replace("__MODEL__", json.dumps(model_id)).replace("__URL__", json.dumps(url))
        (agent / "extensions" / "factory-droid.ts").write_text(source)
    if extra_body is not None or wire_mode is not None:
        model = dict(id=model_id, name="Configured fixture", reasoning=effort != "off", input=["text"],
                     contextWindow=32768, maxTokens=4096,
                     cost=dict(input=0, output=0, cacheRead=0, cacheWrite=0))
        (agent / "models.yml").write_text(json.dumps({"providers": {provider: {
            "baseUrl": url + "/v1", "apiKey": "fixture-not-a-secret", "api": "openai-completions",
            "compat": ({"extraBody": extra_body} if extra_body is not None else {"wireModelIdMode": wire_mode}),
            "models": [model],
        }}}))
    for location, route, custom in (("extensions/ordinary.ts", "ordinary-fixture", False),
                                    ("hooks/pre/provider.ts", "openrouter", True),
                                    ("extensions/antigravity.ts", "google-antigravity", True)):
        if stock_go:
            continue
        if (extra_body is not None or wire_mode is not None) and route == provider:
            continue
        source = FACTORY.replace("__CANARY__", json.dumps(str(canary))).replace("__URL__", json.dumps(url))
        source = source.replace("__PROVIDER__", json.dumps(route)).replace("__CUSTOM__", str(custom and not (agent_api and route == provider)).lower())
        api = agent_api if agent_api and route == provider else ("fixture-" + route if custom else "openai-completions")
        source = source.replace("__API__", json.dumps(api))
        (agent / location).write_text(source)
    config = agent / "config.yml"
    config.write_text("retry:\n  modelFallback: false\n" if native_defaults else
                      f"providers:\n  openrouterVariant: {openrouter_variant}\n  antigravityEndpoint: sandbox\nretry:\n  modelFallback: false\n")
    sentinel = agent / "sessions" / "preserve.txt"
    sentinel.write_text("session sentinel\n")
    (agent / "SYSTEM.md").write_text("OUTER_SYSTEM_CANARY_MUST_NOT_ENTER_CONTEXT")
    (agent / "AGENTS.md").write_text("OUTER_RULE_CANARY_MUST_NOT_ENTER_CONTEXT")
    before = {p: p.read_bytes() for p in (config, sentinel)}
    fault_marker = case / "transport-reached"
    if go_fault:
        assert stock_go
        source = bridge.read_text()
        original = 'import { streamSimple } from "@oh-my-pi/pi-ai";'
        assert source.count(original) == 1
        shim = (GO_TRANSPORT_FAULT.replace("__FAULT__", json.dumps(go_fault))
                .replace("__MARKER__", json.dumps(str(fault_marker)))
                .replace("__WRONG_KEY__", json.dumps(GO_WRONG_KEY)))
        if go_fault == "agreeing-model-alias":
            # Simulate a native resolver that agrees with the wrong hook and final wire ID.
            helper = 'import { requireSupportedEffort, resolveWireModelId } from "@oh-my-pi/pi-catalog";'
            assert source.count(helper) == 1
            source = source.replace(helper, '''import { requireSupportedEffort } from "@oh-my-pi/pi-catalog";
const resolveWireModelId = () => "fixture/wrong-model";''')
        (scratch / "omp.ts").write_text(source.replace(original, shim))
    else:
        shutil.copyfile(bridge, scratch / "omp.ts")
    request = {"id": "fixture", "kind": "answer", "epoch": 1, "words": ["/clear", "@/secret"],
               "min_chars": 1, "max_chars": 4096, "assignment": "literal /profile_canary @/secret {{template}}",
               "candidate": None, "history": [], "guidance": "USER_GUIDANCE_LAYER", "core_guidance": "CORE_GUIDANCE_LAYER"}
    request_json = encoded(request).decode()
    binding = {"protocol": 1, "invocation_id": str(uuid.uuid4()), "request_digest": hashlib.sha256(request_json.encode()).hexdigest(),
               "selection_digest": hashlib.sha256(name.encode()).hexdigest(), "provider": provider,
               "model": model_id, "reasoning_effort": effort}
    bootstrap = {**binding, "provider_discovery_cwd": str(home), "deadline_unix_ms": int(time.time() * 1000) + 60000}
    if stock_go:
        bootstrap["go_mode"] = "fixture"
    (scratch / "omp-bootstrap.json").write_bytes(encoded(bootstrap))
    (scratch / "omp-overlay.json").write_bytes(encoded({"autoResume": False, "retry": {"enabled": False, "modelFallback": False},
                                                       "providers": {"cacheWarming": "off"}}))
    flags = ["--mode", "rpc", "--no-ui", "--no-session", "--no-tools", "--no-lsp", "--no-pty", "--no-skills",
             "--no-rules", "--no-context-files", "--no-prewalk", "--no-title",
             "--model", f"{provider}/{shell_model_id or model_id}", "--thinking", effort,
             "--trusted-extension", str(scratch / "omp.ts"), "--config", str(scratch / "omp-overlay.json")]
    if profile:
        flags.extend(["--profile", profile])
    env = {"HOME": str(home), "PATH": os.defpath, "LANG": "C.UTF-8", "TMPDIR": str(scratch / "tmp")}
    if provider == "factory-droid" or stock_go:
        # No proxy forwarding if a native profile override stops applying.
        env.update(HTTP_PROXY=url, HTTPS_PROXY=url, NO_PROXY="127.0.0.1")
    count = server.case_start = len(server.calls)
    server.go_model = model_id if stock_go else None
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
        if startup_refusal:
            assert not startup
            terminal = [e["data"] for e in entries if e.get("customType") == "agmi_omp_result_v1"]
            assert terminal == [{**binding, "ok": False, "stage": "startup", "reason_code": expected}], terminal
            assert not any(e.get("customType") == "agmi_omp_dispatch_v1" for e in entries), entries
            assert len(server.calls) == count
            return
        assert len(startup) == 1, entries
        data = startup[0]["data"]
        if stock_go:
            digest = data["route_digest"]
            assert len(digest) == 64 and int(digest, 16) >= 0, data
            assert data == {**binding, "route_digest": digest, "route_url": url + "/v1"}, data
        else:
            assert data == binding, entries
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
        if stock_go:
            dispatched = [e["data"] for e in entries if e.get("customType") == "agmi_omp_dispatch_v1"]
            assert dispatched == ([binding] if expected_calls == 1 else []), entries
            if go_fault:
                assert fault_marker.read_text() == "reached\n", name
                assert GO_WRONG_KEY not in json.dumps(entries)
        terminals = [e["data"] for e in entries if e.get("customType") == "agmi_omp_result_v1"]
        assert len(terminals) == 1, entries
        terminal = terminals[0]
        assert all(terminal[k] == v for k, v in binding.items()), terminal
        if expected:
            detail = Path(str(canary) + ".transport-error")
            assert not terminal["ok"] and terminal["reason_code"] == expected, (name, terminal, detail.read_text() if detail.exists() else None)
            assert "fixture private provider error" not in json.dumps(terminal)
            if behavior == "identity":
                assert terminal["native_model"] == "fallback" and terminal["native_provider"] == provider, terminal
            if behavior == "wire-model-change":
                assert terminal["native_model"] == model_id and terminal["wire_model"] == "fixture/served-other", terminal
            if behavior == "served-other":
                assert terminal["native_model"] == model_id and terminal["upstream_model"] == "fixture/served-other", terminal
            if behavior in ("anthropic-missing", "anthropic-retry-missing"):
                assert terminal["native_provider"] == provider and terminal["native_model"] == model_id, terminal
        else:
            assert terminal["ok"] and terminal["output"] == ANSWER, terminal
            assert terminal["native_provider"] == provider and terminal["native_model"] == model_id
            phase = "final_answer" if behavior in ("phase-final", "wire-phase-final") else None
            assert terminal["output_phase"] == phase, terminal
            expected_wire = ((wire_id or model_id) if provider in ("ordinary-fixture", "factory-droid", GO_PROVIDER)
                             and behavior != "wire-model-omitted" else None)
            assert terminal["wire_model"] == expected_wire, terminal
            assert terminal["upstream_model"] == ("fixture/model" if behavior == "served" else None), terminal
            assert terminal["upstream_provider"] == ("fixture-upstream" if behavior == "served" else None), terminal
        if duplicate:
            calls = len(server.calls)
            assert rpc.prompt(f"/{COMMAND} {argument}")["agentInvoked"] is False
            again = rpc.request("get_entries", since=cursor)["entries"]
            assert [e["data"] for e in again if e.get("customType") == "agmi_omp_result_v1"][-1]["reason_code"] == "native_run_binding_mismatch"
            assert len(server.calls) == calls
        calls = server.calls[count:]
        assert len(calls) == (0 if mutate or argument_override is not None else expected_calls), calls
        for path, captured in calls:
            if path == "/capture":
                assert captured["context"]["tools"] == []
                assert captured["context"]["systemPrompt"] == [POLICY]
                assert len(captured["context"]["messages"]) == 1
                assert json.loads(captured["context"]["messages"][0]["content"]) == {"kind": "answer", "request": request}
                options = captured["options"]
                assert options["reasoning"] == effort and options["toolChoice"] == "none"
                assert options["disableServerSideFallback"] is True and not options.get("fallbacks")
                expected_variant = None if native_defaults or openrouter_variant == "online" else openrouter_variant
                assert options.get("openrouterVariant") == expected_variant
                assert options["antigravityEndpointMode"] == ("auto" if native_defaults else "sandbox")
                assert options["sessionId"] == binding["invocation_id"]
            else:
                assert not captured.get("tools"), captured
                assert captured.get("tool_choice") in (None, "none", {"type": "none"}), captured
                if extra_body is not None:
                    assert all(captured[key] == value for key, value in extra_body.items()), captured
                assert captured["model"] == (wire_id or model_id)
                if path == "/api/llm/a/v1/messages":
                    assert captured["thinking"]["type"] == "adaptive", captured
                    assert captured["output_config"]["effort"] == effort, captured
                elif effort == "off":
                    assert captured.get("reasoning_effort") in (None, "none"), captured
                else:
                    assert captured["reasoning_effort"] == effort
                wire = json.dumps(captured["input"] if path == "/v1/responses" else captured["messages"])
                assert "USER_GUIDANCE_LAYER" in wire and "CORE_GUIDANCE_LAYER" in wire
                assert POLICY in json.dumps(captured), captured
                if provider == "factory-droid":
                    assert path.startswith("/api/llm/") and not captured.get("fallbacks"), captured
            assert "OUTER_SYSTEM_CANARY" not in json.dumps(captured)
            assert "OUTER_RULE_CANARY" not in json.dumps(captured)
    finally:
        process.kill()
        process.wait(timeout=5)
        process.stdin.close()
        assert not canary.exists(), "detached factory handler/tool was activated"
        assert all(path.read_bytes() == data for path, data in before.items()), "profile/session sentinel changed"
        assert not rpc.errors, rpc.errors
        # Standalone omp extracts a native addon into each isolated home.
        shutil.rmtree(case)


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
            go = dict(provider=GO_PROVIDER, model_id="glm-5.3", effort="max", profile=None, native_defaults=True)
            run_case(binary, bridge, root, server, "go-wire-native", **go)
            for fault, reason in (
                ("wire-model", "native_provenance_mismatch"),
                ("wire-effort", "native_api_unsupported"),
                ("wire-tool", "native_api_unsupported"),
                ("wire-fallback", "native_api_unsupported"),
                ("wire-prompt", "native_provenance_mismatch"),
                ("wire-duplicate", "native_provenance_mismatch"),
                ("wire-auth", "native_auth_unavailable"),
                ("missing-model", "native_provenance_mismatch"),
                ("caught-hook", "native_provenance_mismatch"),
                ("agreeing-model-alias", "native_provenance_mismatch"),
            ):
                run_case(binary, bridge, root, server, "go-" + fault, go_fault=fault,
                         expected=reason, expected_calls=0, **go)
            run_case(binary, bridge, root, server, "ordinary-no-effort-fallback", provider="ordinary-fixture",
                     behavior="effort-rejected", expected="native_api_unsupported")
            run_case(binary, bridge, root, server, "ordinary-native-wire-namespace", provider="ordinary-fixture",
                     effort="off", model_id="fixture/plain", wire_mode="cline-pass", wire_id="cline-pass/fixture/plain")
            run_case(binary, bridge, root, server, "factory-glm-max", provider="factory-droid",
                     model_id="glm-5.3", effort="max")
            run_case(binary, bridge, root, server, "factory-glm-no-effort-fallback", provider="factory-droid",
                     model_id="glm-5.3", effort="max", behavior="effort-rejected", expected="native_api_unsupported")
            run_case(binary, bridge, root, server, "ordinary-exact-off", provider="ordinary-fixture",
                     effort="off", model_id="fixture/plain")
            run_case(binary, bridge, root, server, "native-paused-provider", provider="google-antigravity",
                     expected="native_failure", expected_calls=0)
            run_case(binary, bridge, root, server, "unsupported-effort", effort="max",
                     expected="native_api_unsupported", startup_refusal=True)
            run_case(binary, bridge, root, server, "exact-off-refusal", effort="off",
                     expected="native_api_unsupported", startup_refusal=True)
            for api in ("cursor-agent", "gitlab-duo-agent"):
                run_case(binary, bridge, root, server, api, agent_api=api,
                         expected="native_api_unsupported", startup_refusal=True)
            run_case(binary, bridge, root, server, "online-variant", openrouter_variant="online",
                     expected="native_api_unsupported", startup_refusal=True)
            run_case(binary, bridge, root, server, "online-unrelated-route", provider="ordinary-fixture",
                     openrouter_variant="online")
            for model_id in ("fixture/model:free:online", "perplexity/sonar"):
                # The outer CLI can interpret colon suffixes as selector syntax.
                # Start the inert shell on a known model to exercise the
                # invocation bootstrap's independent catalog and tool fence.
                run_case(binary, bridge, root, server, "tool-enabled-" + model_id.replace("/", "-").replace(":", "-"),
                         model_id=model_id, shell_model_id="fixture/model",
                         expected="native_api_unsupported", startup_refusal=True)
            for model_id in ("sonar", "gpt-5-search-api"):
                run_case(binary, bridge, root, server, "direct-search-" + model_id,
                         provider="ordinary-fixture", model_id=model_id,
                         expected="native_api_unsupported", startup_refusal=True)
            run_case(binary, bridge, root, server, "plain-router-model-variant", openrouter_variant="exacto")
            for key, value in (("model", "fixture/served-other"), ("plugins", [{"id": "web"}]),
                               ("messages", [{"role": "user", "content": "replacement"}]),
                               ("reasoning_effort", "max")):
                run_case(binary, bridge, root, server, "override-" + key,
                         provider="ordinary-fixture", model_id="fixture/plain", effort="off",
                         extra_body={key: value}, expected="native_api_unsupported", startup_refusal=True)
            run_case(binary, bridge, root, server, "safe-tuning", provider="ordinary-fixture",
                     model_id="fixture/plain", effort="off", extra_body={"temperature": 0.3})
            run_case(binary, bridge, root, server, "wrong-binding", mutate=lambda b: b.update(selection_digest="0" * 64), expected="native_run_binding_mismatch")
            run_case(binary, bridge, root, server, "wrong-digest", mutate=lambda b: b.update(request_json=b["request_json"] + " "), expected="native_run_binding_mismatch", duplicate=True)
            run_case(binary, bridge, root, server, "tool-refusal", behavior="tool", expected="native_api_unsupported")
            run_case(binary, bridge, root, server, "native-identity-mismatch", behavior="identity", expected="native_provenance_mismatch")
            run_case(binary, bridge, root, server, "known-upstream-model", behavior="served")
            run_case(binary, bridge, root, server, "wrong-upstream-model", behavior="served-other",
                     expected="native_provenance_mismatch")
            run_case(binary, bridge, root, server, "ordinary-wire-model-change", provider="ordinary-fixture",
                     behavior="wire-model-change", expected="native_provenance_mismatch")
            run_case(binary, bridge, root, server, "ordinary-wire-model-omitted", provider="ordinary-fixture",
                     behavior="wire-model-omitted")
            run_case(binary, bridge, root, server, "final-phase-only", behavior="phase-final")
            run_case(binary, bridge, root, server, "responses-final-phase-only", behavior="wire-phase-final",
                     provider="ordinary-fixture", agent_api="openai-responses", effort="off", model_id="fixture/plain")
            run_case(binary, bridge, root, server, "responses-commentary-only", behavior="wire-phase-commentary",
                     provider="ordinary-fixture", agent_api="openai-responses", effort="off", model_id="fixture/plain",
                     expected="native_api_unsupported")
            for reason in ("end_turn", "stop_sequence", "pause_turn", "unrecognized_stop", "missing", "null"):
                behavior = "anthropic-" + reason
                run_case(binary, bridge, root, server, behavior, behavior=behavior,
                         provider="ordinary-fixture", agent_api="anthropic-messages",
                         effort="off", model_id="fixture/plain",
                         expected=None if reason in ("end_turn", "stop_sequence") else "native_api_unsupported")
            # Deliberately reuse the message id: the artifact must have its own
            # supported stop even if the empty first request had one.
            for stop in ("missing", "end_turn"):
                run_case(binary, bridge, root, server, "anthropic-retry-" + stop, behavior="anthropic-retry-" + stop,
                         provider="ordinary-fixture", agent_api="anthropic-messages", effort="off",
                         model_id="fixture/plain", expected_calls=2,
                         expected="native_api_unsupported" if stop == "missing" else None)
            for stop, calls in (("end_turn", 1), ("missing", 1), ("retry-missing", 2)):
                run_case(binary, bridge, root, server, "factory-messages-" + stop, behavior="anthropic-" + stop,
                         provider="factory-droid", model_id="claude-sonnet-5", expected_calls=calls,
                         expected=None if stop == "end_turn" else "native_api_unsupported")
            for behavior in ("commentary", "partial", "phase-ambiguous", "phase-out-of-order", "stop-conflict"):
                run_case(binary, bridge, root, server, behavior, behavior=behavior, expected="native_api_unsupported")
            run_case(binary, bridge, root, server, "malformed-command", argument_override="%%%",
                     expected="native_run_binding_mismatch", duplicate=True)
            run_case(binary, bridge, root, server, "output-overflow", behavior="overflow", expected="native_output_limit")
            run_case(binary, bridge, root, server, "deadline", behavior="stall", expected="model_deadline_exceeded")
            run_case(binary, bridge, root, server, "upstream-stream-error",
                     behavior="stream-error", expected="native_stream_failed")
        finally:
            server.shutdown()
            server.server_close()
    print("omp native acceptance passed (isolated loopback only)")


if __name__ == "__main__":
    main()
