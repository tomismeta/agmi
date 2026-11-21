#!/usr/bin/env python3
"""Qualify packaged agmi -> pinned standalone omp -> loopback inference -> MinePOA.

The binary under test owns RPC negotiation and the embedded bridge. Only the
native profile/provider and hosted service are fixtures; no real credentials.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import time

from participation_smoke import ANSWER, Fixture

MODEL = "fixture/model"
PROVIDER = "openrouter"
WIRE_PROVIDER = "ordinary-fixture"
ARTIFACT = json.dumps(dict(answer=ANSWER, score=None, reasoning=None))
COMMENTARY = json.dumps(dict(answer=ANSWER + " This is not the final answer.",
                             score=None, reasoning=None))

# A native SDK factory, not a replacement agmi bridge, RPC shell or solver.
# Use the SDK's actual textSignature shape and separate upstreamModel field.
FACTORY = r'''
import { createAssistantMessageEventStream } from "@oh-my-pi/pi-ai";
export default function (pi) {
    const model = {id: "fixture/model", name: "Release fixture", reasoning: true,
        thinking: {efforts: ["low", "high"], requiresEffort: true}, input: ["text"],
        cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0},
        contextWindow: 1048576, maxTokens: 4096};
    function streamSimple(model, context, options) {
        const stream = createAssistantMessageEventStream();
        void (async () => {
            const message = {role: "assistant", api: model.api, provider: model.provider,
                model: model.id, content: [], stopReason: "stop", timestamp: Date.now(),
                usage: {input: 0, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 1,
                    cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0}}};
            try {
                const response = await fetch(__URL__ + "/inference", {method: "POST",
                    signal: options.signal, headers: {"content-type": "application/json"},
                    body: JSON.stringify({context, pid: process.pid, cwd: process.cwd(),
                        model: model.id, reasoning: options.reasoning,
                        toolChoice: options.toolChoice, sessionId: options.sessionId})});
                const result = await response.json();
                message.content = result.parts;
                if (result.upstreamModel) message.upstreamModel = result.upstreamModel;
                stream.push({type: "done", reason: "stop", message});
            } catch (error) {
                message.stopReason = "error";
                message.errorMessage = String(error);
                stream.push({type: "error", reason: "error", error: message});
            } finally {
                stream.end(message);
            }
        })();
        return stream;
    }
    pi.registerProvider(__PROVIDER__, {
        baseUrl: __URL__ + "/v1", apiKey: "fixture-not-a-secret",
        api: __WIRE__ ? "openai-completions" : "fixture-release",
        models: [model],
        ...(__WIRE__ ? {} : {streamSimple}),
    });
}
'''


def text_part(text, phase=None):
    part = {"type": "text", "text": text}
    if phase:
        part["textSignature"] = json.dumps({"v": 1, "id": "msg_" + phase, "phase": phase})
    return part


class Inference(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        assert self.path in ("/inference", "/v1/chat/completions"), self.path
        size = int(self.headers["Content-Length"])
        assert 0 < size <= 2 * 1024 * 1024, size
        body = json.loads(self.rfile.read(size))
        self.server.calls.append(body)
        if self.path == "/v1/chat/completions":
            common = {"id": "fixture", "object": "chat.completion.chunk",
                      "model": self.server.wire_model or body["model"]}
            chunks = [{**common, "choices": [{"index": 0, "finish_reason": None,
                      "delta": {"role": "assistant", "content": ARTIFACT}}]},
                      {**common, "choices": [{"index": 0, "finish_reason": "stop", "delta": {}}]}]
            data = b"".join(b"data: " + json.dumps(chunk).encode() + b"\n\n" for chunk in chunks)
            data += b"data: [DONE]\n\n"
            content_type = "text/event-stream"
        elif self.server.stall:
            # Never send a result in this scenario. Only teardown releases us.
            self.server.release.wait(60)
            self.close_connection = True
            return
        else:
            data = json.dumps(self.server.response).encode()
            content_type = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def model_attempts(fixture):
    return [(row["state"], json.loads(row["model_attempt"])) for row in fixture.rows(
        "SELECT o.state, e.model_attempt FROM operations o JOIN operation_evidence e "
        "ON e.operation_id = o.id WHERE e.model_attempt IS NOT NULL ORDER BY o.id")]


def wait_for(fixture, predicate, label, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if fixture.child.poll() is not None:
            break
        if predicate():
            return
        time.sleep(0.05)
    stderr = (fixture.root / "runtime.stderr").read_text(errors="replace")[-8192:]
    raise AssertionError((label, model_attempts(fixture), stderr))


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True

def large_guidance(label, char):
    # Valid UTF-8 and individually bounded, with worst-case JSON escapes.
    return label + char * (64 * 1024 - len(label))


def run_case(agmi, omp, root, case, output, code, execution, outcome, *,
             effort="low", upstream_model=None, wire=False, wire_model=None,
             large=False, stall=False, cancel=False):
    root.mkdir()
    fixture = Fixture(agmi, root)
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Inference)
    provider.calls = []
    provider.stall = stall
    provider.release = threading.Event()
    provider.response = {"parts": output, "upstreamModel": upstream_model}
    provider.wire_model = wire_model
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    try:
        home = root / "home"
        agent = home / ".omp/profiles/fixture/agent"
        factories = agent / ("extensions" if wire else "hooks/pre")
        factories.mkdir(parents=True)
        route = WIRE_PROVIDER if wire else PROVIDER
        source = FACTORY.replace("__URL__", json.dumps(f"http://127.0.0.1:{provider.server_port}"))
        source = source.replace("__PROVIDER__", json.dumps(route)).replace("__WIRE__", str(wire).lower())
        (factories / "provider.ts").write_text(source)
        (agent / "config.yml").write_text("retry:\n  modelFallback: false\n")
        scratch = root / "tmp"
        scratch.mkdir(mode=0o700)
        fixture.env = dict(HOME=str(home), PATH=os.defpath, LANG="C.UTF-8",
                           TMPDIR=str(scratch), XDG_CONFIG_HOME=str(home / ".config"),
                           XDG_DATA_HOME=str(home / ".local/share"),
                           XDG_CACHE_HOME=str(home / ".cache"), AGMI_UPDATE_CHECKS="0",
                           NO_PROXY="127.0.0.1,localhost")
        guidance = large_guidance("fixture user: ", "\u0001") if large else "fixture user"
        core = large_guidance("fixture core: ", "\u0002") if large else "fixture core"
        guide = root / "user-guidance.md"
        guide.write_text(guidance)
        guide.chmod(0o600)
        fixture.core.write_text(core)
        lane = fixture.lanes["answer"]
        lane["model"] = dict(harness="omp", executable=str(omp), model=f"{route}/{MODEL}",
                             reasoning=effort, core_guidance_file=str(fixture.core),
                             guidance_file=str(guide),
                             omp=dict(profile="fixture", provider_discovery_cwd=str(home)))
        # One accounted attempt makes acceptance/absence of replay deterministic.
        lane["preparation"]["max_attempts_per_work"] = 1
        lane["timeouts"]["model_seconds"] = 12 if stall and not cancel else 30
        fixture.answer_response = "included"
        fixture.receipt_state = "final"
        fixture.configure()
        fixture.invoke("config", "check")
        fixture.start(resume=True)

        if stall:
            wait_for(fixture, lambda: len(provider.calls) == 1, "held inference was never dispatched")
            held = provider.calls[0]
            assert pid_alive(held["pid"]) and Path(held["cwd"]).is_dir(), held["pid"]
            assert not fixture.writes and not fixture.dispatched()
            assert not any(record.get("completion") for _, record in model_attempts(fixture))
        if cancel:
            # Deliver SIGTERM only after the actual native request, not after a sleep.
            fixture.child.terminate()
            assert fixture.child.wait(timeout=10) == 0, (root / "runtime.stderr").read_text()
            # Stop tore down the process; allow the OS to finish reaping it.
            deadline = time.monotonic() + 5
            while pid_alive(held["pid"]) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not pid_alive(held["pid"]), "controller shutdown leaked standalone omp"
            assert not Path(held["cwd"]).exists(), "controller shutdown leaked the native workspace"
        else:
            wait_for(fixture, lambda: any(record.get("completion")
                                          for _, record in model_attempts(fixture)),
                     "terminal model evidence was not recorded")
            if stall:
                wait_for(fixture, lambda: not pid_alive(held["pid"]) and not Path(held["cwd"]).exists(),
                         "model deadline leaked standalone omp or its workspace", seconds=5)
            if outcome == "captured":
                wait_for(fixture, lambda: len(fixture.writes) == 1, "captured result was not submitted")
                wait_for(fixture, lambda: any(row["state"] == "final" for row in fixture.operations()),
                         "hosted acceptance was not recorded")
            fixture.stop()

        attempts = model_attempts(fixture)
        assert len(attempts) == 1, attempts
        state, record = attempts[0]
        completion = record["completion"]
        assert (completion["reason_code"], completion["execution"], completion["outcome"]) == (
            code, execution, outcome), completion
        if stall:
            cancellation = completion["cancellation"]
            assert cancellation["requested_at"] is not None, cancellation
            assert cancellation["remote_run_stop"] == "unknown", cancellation
        if effort == "max":
            assert state == "prelaunch_failed" and not provider.calls, (state, completion)
            assert completion["inference_spawned_at"] is not None, completion
        elif wire:
            assert len(provider.calls) == 1, f"{case}: fixture inference count {len(provider.calls)}"
            call = provider.calls[0]
            assert call["model"] == MODEL and call["reasoning_effort"] == "low"
            assert not call.get("tools") and call.get("tool_choice") in (None, "none")
            assert "No tools or external actions" in json.dumps(call["messages"])
            reported = completion["reported"]
            assert reported["model"]["value"] == (wire_model or MODEL), reported
        else:
            assert len(provider.calls) == 1, f"{case}: fixture inference count {len(provider.calls)}"
            call = provider.calls[0]
            assert (call["model"], call["reasoning"], call["toolChoice"]) == (MODEL, "low", "none")
            context = call["context"]
            policy = context["systemPrompt"]
            assert context["tools"] == [] and len(policy) == 1 and "No tools or external actions" in policy[0]
            assert len(context["messages"]) == 1 and context["messages"][0]["role"] == "user"
            envelope = json.loads(context["messages"][0]["content"])
            request = envelope["request"]
            assert envelope["kind"] == "answer" and request["words"] == ["clock", "bridge"]
            assert request["guidance"] == guidance and request["core_guidance"] == core
            if large:
                # The Rust prompt carries the base64 of an outer JSON body with
                # request_json as a string. Even that field alone exceeds 1 MiB.
                request_json = json.dumps(request, separators=(",", ":"))
                assert (4 * len(json.dumps(request_json))) // 3 > 1024 * 1024
            if outcome == "captured" or upstream_model:
                reported = completion["reported"]
                assert reported["provider"]["value"] == route, reported
                assert reported["model"] is None, reported
                assert reported["run_id"]["value"] == call["sessionId"]
                if upstream_model:
                    assert reported["winner_model"]["value"] == upstream_model, reported
        if outcome == "captured":
            assert state == "final", state
            assert len(fixture.writes) == len(fixture.dispatched()) == 1, fixture.writes
            write = fixture.writes[0]
            assert write["route"].endswith("/api/hosted/answer") and write["body"]["answer"] == ANSWER, write
        else:
            assert not fixture.writes and not fixture.dispatched(), fixture.writes
        print(f"PASS packaged omp {case}", flush=True)
    finally:
        provider.release.set()
        fixture.close()
        provider.shutdown()
        provider.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agmi", type=Path)
    parser.add_argument("--omp", required=True, type=Path)
    args = parser.parse_args()
    agmi, omp = args.agmi.resolve(strict=True), args.omp.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="agmi-packaged-omp-") as temp:
        root = Path(temp).resolve()

        def check(name, *args, **settings):
            run_case(agmi, omp, root / name, name, *args, **settings)

        unphased = [text_part(ARTIFACT)]
        commentary = text_part(COMMENTARY, "commentary")
        check("unphased-success", unphased, "captured", "completed", "captured")
        check("wire-success", unphased, "captured", "completed", "captured", wire=True)
        check("wire-model-contradiction", unphased, "native_provenance_mismatch",
              "unknown", "unknown", wire=True, wire_model="fixture/served-other")
        check("bind-refusal", unphased, "native_api_unsupported", "not_started", "not_started", effort="max")
        check("served-model-contradiction", unphased, "native_provenance_mismatch",
              "unknown", "unknown", upstream_model="fixture/served-other")
        check("commentary-only", [text_part(ARTIFACT, "commentary")], "native_api_unsupported",
              "unknown", "unknown")
        check("final-phase-large-input", [commentary, text_part(ARTIFACT, "final_answer")],
              "captured", "completed", "captured", large=True)
        check("deadline", unphased, "model_deadline_exceeded", "unknown", "unknown", stall=True)
        check("shutdown-cancellation", unphased, "interrupted", "unknown", "unknown", stall=True, cancel=True)


if __name__ == "__main__":
    main()
