#!/usr/bin/env python3
"""Exercise OpenCode Go qualification with a standalone Linux omp, offline.

For real synthetic inference use a controller built with --features omp-go-fixture:
  python3 tests/omp_go_qualification_smoke.py /absolute/agmi-fixture --omp /absolute/omp
Use --judge-only --model MODEL to exercise grade validation on a catalog route.
Use --expect-production-refusal for exact artifacts without the fixture feature.
Use --expect-refusal only for a separately known incompatible omp executable.
Use --stock-gate for the packaged binary with a clean native auth store.
Run with no external network (CI uses --network=none); both servers are loopback.
Uses a fresh HOME and no user credentials, extension, or replacement RPC client.
"""
import argparse
from contextlib import suppress
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading

from packaged_omp_smoke import ARTIFACT, model_attempts, wait_for
from participation_smoke import ANSWER, Fixture

PROVIDER, EFFORT = 'opencode-go', 'max'
KEY = 'agmi-loopback-fixture'
MODEL_SECONDS = 120
REFUSALS = ('native_qualification_failed', 'native_qualification_unavailable')
REJECTED_TEXT = 'synthetic-rejected-grade-secret-canary'
GRADE = json.dumps(dict(answer=None, score=2,
                       reasoning='The clock and the bridge impose a measurable delay.'))


class Inference(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, content_type, data):
        with suppress(BrokenPipeError, ConnectionResetError):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def do_GET(self):
        self.reply(404, 'text/plain', b'no discovery')

    def do_POST(self):
        # Count ingress *before* parsing or validating it. A malformed second
        # request or a POST to an unexpected path is still an extra request.
        call = {'path': self.path, 'test_key': self.headers.get('Authorization') == f'Bearer {KEY}',
                'body': None}
        self.server.calls.append(call)
        if self.path != '/v1/chat/completions':
            self.reply(404, 'text/plain', b'not the provider endpoint')
            return
        try:
            size = int(self.headers.get('Content-Length', 0))
            if not 0 < size <= 2 * 1024 * 1024:
                raise ValueError('invalid size')
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError('expected object')
        except (ValueError, UnicodeDecodeError):
            self.reply(400, 'text/plain', b'invalid request')
            return
        call['body'] = body
        if self.server.reject_max and body.get('reasoning_effort') == 'max':
            error = {'error': {'type': 'invalid_request_error', 'param': 'reasoning_effort',
                               'message': "Unsupported reasoning_effort 'max'. Supported values are: 'high'."}}
            self.reply(400, 'application/json', json.dumps(error).encode())
            return
        # A high retry would genuinely succeed here: only the adapter may
        # prevent it. Return a structurally valid artifact for the current lane.
        common = {'id': 'go-test', 'object': 'chat.completion.chunk', 'model': self.server.model}
        chunks = [{**common, 'choices': [{'index': 0, 'finish_reason': None,
                  'delta': {'role': 'assistant', 'content': self.server.output}}]},
                  {**common, 'choices': [{'index': 0, 'finish_reason': 'stop', 'delta': {}}]}]
        data = b''.join(b'data: ' + json.dumps(chunk).encode() + b'\n\n' for chunk in chunks)
        self.reply(200, 'text/event-stream', data + b'data: [DONE]\n\n')


def profile(path, origin, downgrade_model=None):
    route = {'baseUrl': origin + '/v1', 'apiKey': KEY}
    if downgrade_model:
        # Both native effort mappings agree, without changing model or API.
        route['modelOverrides'] = {downgrade_model: {
            'thinking': {'mode': 'effort', 'efforts': ['high', 'max'], 'effortMap': {'max': 'high'}},
            'compat': {'reasoningEffortMap': {'max': 'high'}},
        }}
    pending = path.with_suffix('.new')
    pending.write_text(json.dumps({'providers': {PROVIDER: route}}))
    pending.chmod(0o600)
    pending.replace(path)


def terminal(fixture, nth, task):
    def ready():
        attempts = model_attempts(fixture)
        return len(attempts) >= nth and attempts[nth - 1][1]['completion'] is not None

    wait_for(fixture, ready, f'missing terminal {nth} ({task})', seconds=MODEL_SECONDS + 20)
    attempts = model_attempts(fixture)
    assert len(attempts) == nth, ('unexpected model attempt', attempts)
    state, record = attempts[-1]
    producer = record['producer']
    assert producer['task_kind'] == task, producer
    requested = producer['requested']
    model = fixture.lanes['judge' if task == 'grade' else 'answer']['model']['model'].split('/', 1)[1]
    assert tuple(requested[k] for k in ('harness', 'provider', 'model', 'reasoning_effort')) == (
        'omp', PROVIDER, model, EFFORT), requested
    assert requested['native_route'] == str(fixture.root / 'omp'), requested
    return state, record


def counts(fixture, server, attempts, posts, writes):
    assert len(model_attempts(fixture)) == attempts, model_attempts(fixture)
    assert len(server.calls) == posts, ('inference fixture POSTs', server.calls)
    assert len(fixture.writes) == len(fixture.dispatched()) == writes, fixture.writes


def budget(fixture, lane, record, used, unknown):
    model = fixture.status()['work'][lane]['model']
    assert model['operation_id'] == record['producer']['operation']['operation_id'], model
    assert (model['budget_used'], model['unresolved_attempts'], model['reserved_attempts']) == (
        used, unknown, 0), model
    if used:
        assert model['blocker'] == 'model_budget_exhausted' and not model['retry_eligible'], model


def refused(fixture, nth):
    state, record = terminal(fixture, nth, 'answer')
    completion = record['completion']
    assert state == 'prelaunch_failed' and record['launch'] is None, (state, record)
    assert completion['reason_code'] in REFUSALS, completion
    assert (completion['execution'], completion['outcome'], completion['inference_spawned_at']) == (
        'not_started', 'not_started', None), completion
    budget(fixture, 'answer', record, 0, 0)
    return completion['reason_code']


def wire(call, record, kind):
    assert call['path'] == '/v1/chat/completions' and call['test_key'], call
    body = call['body']
    expected_model = record['producer']['requested']['model']
    assert (body['model'], body['reasoning_effort'], body['stream']) == (expected_model, EFFORT, True), body
    assert not body.get('tools') and body.get('tool_choice') in (None, 'none', {'type': 'none'}), body
    assert not any(body.get(k) for k in ('functions', 'plugins', 'fallbacks', 'web_search_options')), body
    messages = body['messages']
    assert 'No tools or external actions' in json.dumps(messages), messages
    users = [message['content'] for message in messages if message['role'] == 'user']
    assert len(users) == 1, users
    content = users[0]
    if isinstance(content, list):
        assert all(part['type'] == 'text' for part in content), content
        content = ''.join(part['text'] for part in content)
    envelope = json.loads(content)
    assert envelope['kind'] == kind and envelope['request']['kind'] == kind, envelope
    assert envelope['request']['id'] == record['producer']['request_id'], envelope
    assert envelope['request']['words'] == ['clock', 'bridge'], envelope


def exercise(fixture, server, native, expect_refusal, production, judge_only, stock_gate):
    root = fixture.root
    home, scratch, candidate = root / 'home', root / 'tmp', root / 'omp'
    scratch.mkdir(mode=0o700)
    models = home / '.omp/agent/models.yml'
    models.parent.mkdir(parents=True)
    # Exercise the stock settings shape Agmigo actually uses. OMP may return
    # these settings grouped or as dotted keys, depending on the executable.
    (models.parent / 'config.yml').write_text(
        'update:\n  auto: true\nretry:\n  enabled: false\n  modelFallback: false\n')
    origin = f'http://127.0.0.1:{server.server_port}'
    if not stock_gate:
        profile(models, origin)
    # agmigo's default OMP profile coexists with ambient Pi extensions.
    # Trusted stock Go must not load them while resolving the catalog route.
    ambient = home / '.pi/agent/extensions'
    ambient.mkdir(parents=True)
    (ambient / 'must-not-load.ts').write_text('throw new Error("ambient extension loaded");\n')
    # Replacing this private copy cannot overwrite the supplied executable.
    shutil.copy2(native, candidate)
    fixture.env = dict(HOME=str(home), TMPDIR=str(scratch), PATH=os.defpath, LANG='C.UTF-8',
                       XDG_CONFIG_HOME=str(home / '.config'), XDG_DATA_HOME=str(home / '.local/share'),
                       XDG_CACHE_HOME=str(home / '.cache'), AGMI_UPDATE_CHECKS='0',
                       AGMI_OMP_TEST_LOOPBACK='1')
    if stock_gate:
        del fixture.env['AGMI_OMP_TEST_LOOPBACK']
    for kind in ('answer', 'judge'):
        lane = fixture.lanes[kind]
        lane['mode'] = 'off' if kind == 'answer' and judge_only else 'active'
        lane['participation']['mode'] = 'participation_first'
        lane['model'] = dict(harness='omp', executable=str(candidate), model=f'{PROVIDER}/{server.model}',
                             reasoning=EFFORT, core_guidance_file=str(fixture.core))
        lane['timeouts']['model_seconds'] = MODEL_SECONDS
        # One possible execution per work item. Prelaunch refusals consume no
        # budget, so give them a cooldown while we change opportunities.
        lane['preparation'].update(max_attempts_per_work=1, retry_uncertain=False,
                                   max_uncertain_replacements_per_work=0)
        lane['schedule']['retry_seconds'] = 300
    fixture.answer_response, fixture.receipt_state = 'included', 'final'
    fixture.configure()
    fixture.invoke('config', 'check')
    if judge_only:
        judge_participation(fixture, server)
        return
    fixture.start(resume=True)
    if stock_gate:
        state, attempt = terminal(fixture, 1, 'answer')
        result = attempt['completion']
        # Reaching the native stream with an empty auth store proves traversal
        # of the Rust stock descriptor gate, not just a ready RPC entry.
        assert (state, result['phase'], result['execution']) == (
            'model_unknown', 'inference', 'unknown'), result
        assert result['reason_code'] in ('native_failure', 'native_stream_failed'), result
        assert result['inference_spawned_at'] is not None
        assert result['reported']['run_id']['source'] == 'adapter_contract', result
        fixture.stop()
        counts(fixture, server, 1, 0, 0)
        print(f'PASS real stock {server.model} route crossed qualification; empty auth, no hosted write',
              flush=True)
        return
    if expect_refusal or production:
        reason = refused(fixture, 1)
        if production:
            assert reason == 'native_qualification_unavailable', reason
        fixture.cycles(2)
        fixture.stop()
        counts(fixture, server, 1, 0, 0)
        what = 'production binary rejected enabled fixture override' if production else 'incompatible standalone'
        print(f'PASS {what}: {reason}, no provider POST, model budget or hosted write', flush=True)
        return

    _, answer = terminal(fixture, 1, 'answer')
    result = answer['completion']
    assert (result['reason_code'], result['execution'], result['outcome']) == (
        'captured', 'completed', 'captured'), result
    assert answer['launch'] and result['inference_spawned_at'] is not None, result
    assert result['reported']['model']['value'] == server.model, result
    assert result['reported']['provider']['value'] == PROVIDER, result
    wait_for(fixture, lambda: any(op['state'] == 'final' for op in fixture.operations('answer')),
             'captured answer was not accepted by the hosted fixture')
    counts(fixture, server, 1, 1, 1)
    wire(server.calls[0], answer, 'answer')
    write = fixture.writes[0]
    assert write['route'].endswith('/api/hosted/answer') and write['body']['answer'] == ANSWER, write
    budget(fixture, 'answer', answer, 1, 0)
    print('PASS real OpenCode Go answer: one max request, no tools, one accepted answer', flush=True)
    print('PASS private preflight refused the wrong resolved bearer with zero POSTs', flush=True)

    # The successful Answer left a qualification warm. Atomically replace
    # the same configured pathname with an executable that passes the ELF
    # magic check but cannot serve the native OMP contract.
    incompatible = Path('/bin/false').resolve(strict=True)
    with incompatible.open('rb') as image:
        assert image.read(4) == b'\x7fELF', incompatible
    check = subprocess.run([str(incompatible), 'config', 'list', '--scope=global', '--json'],
                           env=fixture.env, capture_output=True, timeout=5)
    assert (check.returncode, check.stdout) == (1, b''), check
    pending = candidate.with_suffix('.new')
    shutil.copy2(incompatible, pending)
    pending.replace(candidate)
    fixture.rollover(11)
    refused(fixture, 2)
    counts(fixture, server, 2, 1, 1)
    print('PASS warm-cache same-path ELF replacement: no provider POST, budget or hosted write', flush=True)
    shutil.copy2(native, pending)
    pending.replace(candidate)

    # A positive proof must not admit a subsequently modified native profile.
    profile(models, origin, downgrade_model=server.model)
    fixture.rollover(12)
    refused(fixture, 3)
    counts(fixture, server, 3, 1, 1)
    print('PASS changed profile effort override: no provider POST or budget spent', flush=True)

    # Close that Answer opportunity before restoring the native profile. The
    # separate Judge lane now takes one real 400, with a valid high retry on offer.
    fixture.rollover(13, answered=True)
    profile(models, origin)
    server.output = GRADE
    server.reject_max = True
    with fixture.lock:
        fixture.assignments = True
    state, judge = terminal(fixture, 4, 'grade')
    result = judge['completion']
    assert state == 'model_unknown' and judge['launch'] and result['inference_spawned_at'] is not None, judge
    assert (result['reason_code'], result['execution'], result['outcome']) == (
        'native_api_unsupported', 'unknown', 'unknown'), result
    budget(fixture, 'judge', judge, 1, 1)
    fixture.cycles(2)
    counts(fixture, server, 4, 2, 1)
    wire(server.calls[1], judge, 'judge')
    print('PASS real OpenCode Go judge: 400 offered high, one max POST, no replay or grade', flush=True)

    # A previously qualified source must stay executable by the service user.
    with fixture.lock:
        fixture.assignments = False
    server.reject_max = False
    original_mode = candidate.stat().st_mode & 0o777
    candidate.chmod(0o600)
    fixture.rollover(14)
    assert refused(fixture, 5) == 'native_qualification_unavailable'
    counts(fixture, server, 5, 2, 1)
    candidate.chmod(original_mode)
    print('PASS installed executable disabled: no provider POST or budget spent', flush=True)

    # Only executable content/identity changes at the configured pathname.
    marker = root / 'replacement-canaries'
    pending.write_text(f'#!/bin/sh\ntouch "{marker}"\nexec "{native}" "$@"\n')
    pending.chmod(0o700)
    pending.replace(candidate)
    fixture.rollover(15)
    reason = refused(fixture, 6)
    assert reason == 'native_qualification_unavailable', reason
    assert not marker.exists(), 'an unqualified wrapper started'
    fixture.cycles(2)
    counts(fixture, server, 6, 2, 1)
    print('PASS wrapper replacement: no process launch or provider POST', flush=True)
    fixture.stop()
    shutil.copy2(native, candidate)
    fixture.env.pop('AGMI_OMP_TEST_LOOPBACK')
    fixture.start()
    # Rollover waits for the running controller to persist the observation.
    fixture.rollover(16)
    assert refused(fixture, 7) == 'native_qualification_unavailable'
    counts(fixture, server, 7, 2, 1)
    print('PASS fixture build without opt-in: no provider POST, model budget or hosted write', flush=True)

class JudgeFixture(Fixture):
    def handler(self):
        parent = super().handler()
        fixture = self

        class Hosted(parent):
            def do_POST(self):
                if self.path.endswith('/api/hosted/grade'):
                    with fixture.lock:
                        fixture.assignments = False
                        super().do_POST()
                else:
                    super().do_POST()

        return Hosted


def judge_participation(fixture, server):
    server.output = json.dumps(dict(answer=None, score='2', reasoning=REJECTED_TEXT))
    fixture.queued_grades = fixture.assignments = True
    fixture.start(resume=True)
    state, rejected = terminal(fixture, 1, 'grade')
    result = rejected['completion']
    assert (state, result['reason_code'], result['execution'], result['outcome'], result['grade_failure']) == (
        'rejected', 'artifact_grade_invalid', 'completed', 'invalid', 'score_not_integer'), rejected
    op, = fixture.operations('judge')
    assert op['result'] is None and op['payload'] is None and op['job_id'] is None and op['txid'] is None
    assert REJECTED_TEXT not in json.dumps(op) + json.dumps(rejected)
    budget(fixture, 'judge', rejected, 1, 0)
    counts(fixture, server, 1, 1, 0)
    wire(server.calls[0], rejected, 'judge')
    compact = subprocess.run(fixture.command + ['doctor'], env=fixture.env, timeout=10,
                             text=True, capture_output=True)
    detail = json.loads(compact.stdout)['data']['work']['judge']['model']
    assert detail['grade_failure'] == 'score_not_integer', detail
    plain = subprocess.run(fixture.command[:-1] + ['doctor'], env=fixture.env,
                           timeout=10, text=True, capture_output=True)
    assert '(score_not_integer)' in plain.stdout, plain.stdout
    assert all(REJECTED_TEXT not in stream
               for stream in (compact.stdout, compact.stderr, plain.stdout, plain.stderr))

    # A completed invalid grade exhausts only its own seat, not the lane.
    server.output = GRADE
    with fixture.lock:
        fixture.assignment_number += 1
    state, accepted = terminal(fixture, 2, 'grade')
    assert accepted['completion']['reason_code'] == 'captured', (state, accepted)
    assert 'grade_failure' not in accepted['completion']
    wire(server.calls[1], accepted, 'judge')
    wait_for(fixture, lambda: len(fixture.writes) == 1, 'fresh grade was never submitted to the fixture')
    write, = fixture.writes
    assert write['body'] == dict(assignment=f'{11:064x}', score=2, reasoning=json.loads(GRADE)['reasoning'])
    counts(fixture, server, 2, 2, 1)
    print(f'PASS {server.model}: invalid grade diagnosed privately; fresh seat graded at max', flush=True)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('agmi', type=Path)
    parser.add_argument('--omp', type=Path, required=True)
    parser.add_argument('--model', default='glm-5.3', help='stock OpenCode Go model ID')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--judge-only', action='store_true', help='exercise invalid and fresh Judge seats')
    mode.add_argument('--expect-production-refusal', action='store_true',
                      help='require the exact production binary to refuse the enabled fixture override')
    mode.add_argument('--stock-gate', action='store_true',
                      help='prove packaged stock pre-prompt gate with no native credentials')
    mode.add_argument('--expect-refusal', action='store_true',
                        help='require prelaunch refusal on the supplied incompatible executable')
    args = parser.parse_args()
    agmi, omp = args.agmi.resolve(strict=True), args.omp.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='agmi-go-qualification-') as temp:
        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Inference) as server:
            server.daemon_threads, server.reject_max, server.calls = True, False, []
            server.model, server.output = args.model, ARTIFACT
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                fixture_type = JudgeFixture if args.judge_only else Fixture
                fixture = fixture_type(agmi, Path(temp).resolve())
                try:
                    exercise(fixture, server, omp, args.expect_refusal,
                             args.expect_production_refusal, args.judge_only, args.stock_gate)
                finally:
                    fixture.close()
            finally:
                server.shutdown()
                thread.join()


if __name__ == '__main__':
    main()
