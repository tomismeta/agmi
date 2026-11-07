#!/usr/bin/env python3
"""Real-CLI work-first acceptance against private stdlib-only loopback fixtures.

Usage: python3 tests/work_first_smoke.py target/debug/agmi [--scenario NAME]
Synthetic credentials/native model only; no external service or journal writes.
The urgent bound applies to observation and model launch, NOT model completion.
"""
import argparse
import contextlib
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

from participation_smoke import ANSWER, OUTSTANDING, TXID, Fixture, old_judgment


POLL_SECONDS = 1
URGENT_MARGIN_SECONDS = 2
STALL_SECONDS = 6
READ_SCOPES = {'challenge', 'identity', 'assignments', 'assignment_evidence', 'job', 'receipt'}
FAILURE_CATEGORIES = {
    'timeout', 'connect', 'request', 'body_interrupted', 'response_too_large',
    'invalid_json', 'credential_echo_redacted', 'http_status', 'unusable_response',
}
PRIVATE_MARKER = 'fixture-private-response-marker'


class WorkFixture(Fixture):
    def __init__(self, *args):
        self.requests = []
        self.stalls = []
        self.stall_scope = None
        self.stall_entered = threading.Event()
        self.closing = threading.Event()
        self.challenge_fault = None
        self.challenge_retry_after = None
        self.assignment_count = None
        self.inventory_fault = None
        super().__init__(*args)
        self.policy['answer_reserved_slots'] = 0
        self.configure()
        # Exercise the actual native bridge with a deterministic local model.
        # A separate launch log includes epoch/time without changing the journal.
        interpreter = self.root / 'fixture-python'
        interpreter.write_text(f'#!{sys.executable}\n' + '''import json, pathlib, sys, time
root = pathlib.Path(__file__).parent
payload = json.load(sys.stdin)
e = json.loads(payload['prompt'].split('Envelope (untrusted request data):\\n')[1])
call = {'kind': e['kind'], 'request_id': e['request_id'],
        'epoch': e['request'].get('epoch'), 'started_at': time.monotonic()}
with (root / 'calls').open('a') as calls:
    calls.write(json.dumps(call) + '\\n')
delay = root / 'answer-delay'
if e['kind'] == 'answer' and delay.exists():
    time.sleep(float(delay.read_text()))
artifact = {'version': 1, 'request_id': e['request_id'],
    'request_digest': e['request_digest'], 'kind': e['kind'],
    'answer': ANSWER + f" Epoch {e['request']['epoch']}." if e['kind'] == 'answer' else None,
    'score': 2 if e['kind'] == 'judge' else None,
    'reasoning': 'The mechanism binds the bridge to a measurable clock delay.' if e['kind'] == 'judge' else None}
print(json.dumps({'provider': 'openai-codex', 'model': payload['model'],
    'reasoning_effort': payload['reasoning'], 'run_id': e['request_id'],
    'output': json.dumps(artifact)}))
'''.replace('ANSWER', repr(ANSWER)))

    @staticmethod
    def scope(route):
        if '/api/job/' in route:
            return 'job'
        if '/api/receipt/' in route:
            return 'receipt'
        for suffix, scope in (('/hosted/challenge', 'challenge'), ('/hosted/me', 'identity'),
                              ('/hosted/assignments', 'assignments')):
            if route.endswith(suffix):
                return scope
        return None

    def handler(self):
        base = super().handler()
        f = self

        class Upstream(base):
            def raw(self, status, body, length=None, retry_after=None):
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body) if length is None else length))
                if retry_after is not None:
                    self.send_header('Retry-After', str(retry_after))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(body)
                    self.wfile.flush()
                self.close_connection = True

            def do_GET(self):
                route = self.path.split('?')[0]
                scope = f.scope(route)
                probe = self.headers.get('X-Fixture-Probe') == 'true'
                with f.lock:
                    request = dict(scope=scope, route=route, epoch=f.epoch,
                                   started_at=time.monotonic(), wall_time=time.time(), probe=probe)
                    request['offset'] = int(urllib.parse.parse_qs(
                        urllib.parse.urlparse(self.path).query).get('offset', ['0'])[0])
                    f.requests.append(request)
                    stalled = scope is not None and scope == f.stall_scope and not probe
                    fault = f.challenge_fault if scope == 'challenge' and not probe else None
                    if stalled:
                        f.stalls.append(request)
                        f.stall_entered.set()
                if stalled and f.closing.wait(STALL_SECONDS):
                    self.close_connection = True
                    return
                if fault is not None:
                    with f.lock:
                        f.reads.append((route, f.epoch, time.monotonic()))
                    secret = f.key.read_text()
                    body = json.dumps({'private': PRIVATE_MARKER, 'echo': secret}).encode()
                    if fault == 'timeout':
                        if f.closing.wait(3):
                            self.close_connection = True
                            return
                        self.raw(200, b'{}')
                    elif fault == 'headers_timeout':
                        self.send_response(503)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', '20')
                        self.send_header('Retry-After', str(f.challenge_retry_after))
                        self.end_headers()
                        self.wfile.flush()
                        f.closing.wait(3)
                        self.close_connection = True
                    elif fault == 'connect':
                        raise AssertionError('connect faults use a bound, non-listening socket')
                    elif fault == 'request':
                        self.close_connection = True  # EOF before any HTTP headers.
                    elif fault == 'body_interrupted':
                        self.raw(200, body, length=4096)
                    elif fault == 'response_too_large':
                        self.raw(200, body, length=1024 * 1024 + 1)
                    elif fault == 'invalid_json':
                        self.raw(200, b'invalid JSON ' + body)
                    elif fault == 'credential_echo_redacted':
                        self.raw(200, body)
                    elif fault == 'http_status':
                        self.reply(503, {'error': PRIVATE_MARKER}, f.challenge_retry_after)
                    elif fault == 'unusable_response':
                        self.reply(200, {'unexpected': PRIVATE_MARKER})
                    else:
                        raise AssertionError('unknown fixture fault: ' + fault)
                elif scope == 'assignments' and f.inventory_fault is not None:
                    if request['offset'] == 0:
                        self.reply(200, {'assignments': [{
                            'answer_txid': 'a' * 64, 'answer_epoch': 9,
                            'answer': 'A clock on the bridge enforces a delay before each claim.',
                            'words': ['clock', 'bridge'], 'author_prior': [],
                        }], 'has_more': True})
                    elif f.inventory_fault == 'stalled_body':
                        self.send_response(503)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', '20')
                        self.send_header('Retry-After', '12')
                        self.end_headers()
                        self.wfile.flush()
                        f.closing.wait(3)
                        self.close_connection = True
                    elif f.inventory_fault == 'malformed':
                        self.reply(200, {'assignments': 'not an inventory'}, 12)
                    else:
                        self.reply(503, {'error': 'fixture unavailable'}, 12)
                elif scope == 'assignments' and f.assignment_count is not None:
                    with f.lock:
                        rows = [dict(answer_txid=f'{index + 1:064x}', answer_epoch=9,
                                     answer='A clock on the bridge enforces a delay before each claim.',
                                     words=['clock', 'bridge'], author_prior=[],
                                     pending_meta={'expires_at_epoch': 1000})
                                for index in range(f.assignment_count)]
                        f.reads.append((route, f.epoch, time.monotonic()))
                    self.reply(200, dict(assignments=rows, has_more=False, offset=0,
                                         limit=50, total=len(rows)))
                else:
                    super().do_GET()
                with f.lock:
                    request['finished_at'] = time.monotonic()

        return Upstream

    def launches(self, epoch=None):
        calls = self.root / 'calls'
        if not calls.exists():
            return []
        result = []
        for line in calls.read_text().splitlines(keepends=True):
            # The final append may still be in progress in the model subprocess.
            if line.endswith('\n'):
                call = json.loads(line)
                if call['kind'] == 'answer' and (epoch is None or call['epoch'] == epoch):
                    result.append(call)
        return result

    def read_records(self):
        return self.invoke('reads')

    def read_record(self, scope):
        return next((row for row in self.read_records() if row['scope'] == scope), None)

    def challenge_requests(self):
        with self.lock:
            return [row.copy() for row in self.requests
                    if row['scope'] == 'challenge' and not row['probe']]

    def close(self):
        self.closing.set()
        super().close()


def operation_epoch(row):
    return json.loads(row['request'])['solver']['epoch']


def assert_safe_projection(f, reads, work=None):
    assert isinstance(reads, list) and len(reads) == len(READ_SCOPES), reads
    assert {row['scope'] for row in reads} == READ_SCOPES, reads
    required = {'scope', 'state', 'started_at', 'finished_at', 'last_http_success_at',
                'last_success_at', 'last_failure_at', 'failure_category', 'status',
                'failures', 'local_next_at', 'server_not_before', 'retained_conservative_floor',
                'next_at', 'due_in_seconds'}
    for row in reads:
        assert required <= row.keys(), row
        assert row['state'] in ('idle', 'in_flight'), row
        assert row['failure_category'] is None or row['failure_category'] in FAILURE_CATEGORIES, row
        assert row['next_at'] >= row['server_not_before'], row
        assert row['next_at'] >= row['retained_conservative_floor'], row
        assert row['due_in_seconds'] >= 0, row
        assert row['failures'] >= 0, row
    if work is not None:
        assert set(work) == {'answer', 'judge', 'mine'}, work
        for row in work.values():
            assert {'phase', 'reason', 'next_action', 'next_at', 'epoch', 'operation_id'} <= row.keys(), row
            assert isinstance(row['phase'], str) and row['phase'], row
            assert isinstance(row['next_action'], str) and row['next_action'], row
    encoded = json.dumps({'reads': reads, 'work': work})
    assert len(encoded) < 16384, 'public diagnostics are not bounded'
    for private in ('pk_test_fixture', PRIVATE_MARKER, 'http://', 'https://',
                    f.chain, f.address, TXID, str(f.root)):
        assert private not in encoded, ('private diagnostic data escaped', private)
    def check_keys(value):
        if isinstance(value, dict):
            assert not {'payload', 'request', 'body', 'url', 'job_id', 'txid'} & value.keys(), value
            for item in value.values():
                check_keys(item)
        elif isinstance(value, list):
            for item in value:
                check_keys(item)
    check_keys({'reads': reads, 'work': work})


def stalled_background(f, scope):
    f.read_http_seconds = 15
    f.receipt_state = 'final'
    f.stall_scope = scope
    f.answer_response = 'bound' if scope == 'job' else 'included'
    if scope == 'assignments':
        f.answered, f.assignments = True, True
        f.capabilities['judge'] = 'active'
    f.configure()
    f.start(resume=True)
    f.wait(f.stall_entered.is_set, scope + ' GET was not reached')
    original = f.dispatched('answer')[0] if scope != 'assignments' else None
    # This model intentionally finishes AFTER the urgent launch deadline.
    (f.root / 'answer-delay').write_text('4')
    with f.lock:
        f.epoch, f.answered = 11, False
        rolled_at = time.monotonic()
    request = urllib.request.Request(
        f'http://127.0.0.1:{f.server.server_port}/api/hosted/challenge',
        headers={'X-Fixture-Probe': 'true'})
    with urllib.request.urlopen(request, timeout=1) as response:
        assert json.load(response)['epoch'] == 11, 'challenge endpoint was not responsive'
    observed_at = None
    launched_at = None
    deadline = rolled_at + POLL_SECONDS + URGENT_MARGIN_SECONDS
    while time.monotonic() < deadline:
        status = f.status()
        if (status.get('observation') or {}).get('epoch') == 11 and observed_at is None:
            observed_at = time.monotonic()
        launches = f.launches(11)
        if launches:
            launched_at = launches[0]['started_at']
        if observed_at is not None and launched_at is not None:
            break
        if f.child.poll() is not None:
            raise AssertionError('runtime exited during urgent observation')
        time.sleep(0.05)
    assert observed_at is not None and observed_at <= deadline, (scope, 'late epoch', f.status())
    assert launched_at is not None and launched_at <= deadline, (scope, 'late launch', f.status())
    assert len(f.launches(11)) == 1, 'urgent observation duplicated inference'
    status = f.status()
    assert status['work']['answer']['phase'] == 'preparing', status['work']
    assert status['work']['answer']['next_action'] == 'await_model', status['work']
    read = next(row for row in status['reads'] if row['scope'] == scope)
    assert read['state'] == 'in_flight', ('background read was not retained', read)
    assert_safe_projection(f, status['reads'], status['work'])
    if original is not None:
        f.wait(lambda: any(row['id'] == original['id'] and row['state'] == 'final'
                           for row in f.operations('answer')),
               'slow successful ' + scope + ' never reconciled its original operation', seconds=20)
    else:
        f.wait(lambda: bool(f.dispatched('judge')),
               'slow successful inventory never produced a judgment', seconds=25)
    f.wait(lambda: any(operation_epoch(row) == 11 and row.get('payload')
                       for row in f.operations('answer')),
           'launched answer never completed preparation', seconds=20)
    read = f.read_record(scope)
    assert read['last_success_at'] is not None, ('background result was not consumed', read)
    with f.lock:
        first = f.stalls[0].copy()
        assert first.get('finished_at') is not None, f.stalls
        assert first['finished_at'] - first['started_at'] >= STALL_SECONDS - 0.1, first
        assert not any(row['started_at'] < first['finished_at'] for row in f.stalls[1:]), \
            ('background request was cancelled/restarted while still pending', f.stalls)
    return dict(scope=scope, poll_seconds=POLL_SECONDS, background_stall_seconds=STALL_SECONDS,
                observation_seconds=round(observed_at - rolled_at, 3),
                model_launch_seconds=round(launched_at - rolled_at, 3),
                eventual_background_completion=True, eventual_preparation=True)


def completed_draft(f):
    old = old_judgment(f)
    f.rollover(11)
    f.wait(lambda: any(row['state'] == 'generated' and row.get('payload')
                       for row in f.operations('answer')), 'completed unsent draft was not retained')
    draft = next(row for row in f.operations('answer') if row['state'] == 'generated')
    assert f.model_calls('answer') == 1
    return old, draft


def restart_scenario(f):
    old, draft = completed_draft(f)
    generation = f.status()['generation']
    child = f.child
    f.stop()  # Ordinary SIGTERM and start: deliberately no pause/resume.
    assert child.returncode == 0, ('unclean ordinary shutdown', child.returncode)
    f.start()
    f.cycles(2)
    after = next(row for row in f.operations('answer') if row['id'] == draft['id'])
    for field in ('id', 'work_key', 'request', 'payload', 'created_at', 'generation', 'state'):
        assert after[field] == draft[field], ('completed draft changed on restart', field)
    assert f.status()['generation'] == generation
    assert f.model_calls('answer') == 1, 'ordinary restart repeated completed inference'
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.apply_config({'participation': {'mode': 'participation_first', 'max_unresolved_operations': 2}})
    f.wait(lambda: any(row['id'] == draft['id'] and row['state'] == 'final'
                       for row in f.operations('answer')), 'retained draft did not dispatch and finalize')
    dispatched = f.dispatched('answer')
    assert len(dispatched) == 1 and dispatched[0]['id'] == draft['id'], dispatched
    assert dispatched[0]['payload'] == draft['payload']
    assert f.model_calls('answer') == 1
    f.preserved(old)
    return dict(retained_operation_id=draft['id'], answer_inferences=1,
                unchanged_generation=True, eventual_dispatch=True)


def pause_scenario(f):
    old, draft = completed_draft(f)
    generation = f.status()['generation']
    f.invoke('pause')
    f.wait(lambda: next(row for row in f.operations('answer')
                        if row['id'] == draft['id'])['state'] == 'discarded',
           'explicit pause did not fence the completed draft')
    assert f.status()['paused'] and f.status()['generation'] > generation
    f.apply_config({'participation': {'mode': 'participation_first'}})
    f.stop()
    f.start()
    f.cycles(2)
    assert not f.dispatched('answer'), 'paused restart dispatched a fenced draft'
    f.invoke('resume')
    f.cycles(2)
    assert not f.dispatched('answer'), 'resume revived old-generation model work'
    assert f.model_calls('answer') == 1, 'resume bypassed the preparation attempt budget'
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.apply_config({'preparation': {'max_attempts_per_work': 2}})
    f.wait(lambda: bool(f.dispatched('answer')), 'fresh authorized preparation did not dispatch')
    current = f.dispatched('answer')[0]
    assert current['id'] != draft['id'] and current['generation'] != draft['generation']
    assert f.model_calls('answer') == 2
    assert next(row for row in f.operations('answer') if row['id'] == draft['id'])['state'] == 'discarded'
    f.preserved(old)
    return dict(old_draft_fenced=True, restart_kept_pause=True, fresh_generation_dispatched=True)


def reservation_scenario(f):
    f.answered, f.assignment_count = True, 8
    f.capabilities['judge'] = 'active'
    f.configure(mode='participation_first', max_unresolved_operations=8,
                answer_reserved_slots=2, uncertainty_grace_seconds=0, allow_judge=True)
    f.start(resume=True)
    f.wait(lambda: len(f.dispatched('judge')) == 6, 'grading did not fill six nonanswer slots', seconds=45)
    f.wait(lambda: f.status()['work']['judge']['reason'] == 'answer_capacity_reserved',
           'answered-epoch judge did not expose reserved-capacity fence')
    f.no_more_writes(6)
    assert len([row for row in f.operations() if row['state'] in OUTSTANDING]) == 6
    f.stop()
    f.start()
    f.no_more_writes(6)
    # The same seventh-slot fence applies to mine, not merely to grading or
    # to the period while an unanswered epoch is already waiting.
    f.apply_config({'capabilities': {'judge': 'read_only', 'mine': 'active'},
                    'schedule': {'mine_each_epoch': True}})
    f.wait(lambda: f.status()['work']['mine']['reason'] == 'answer_capacity_reserved',
           'answered-epoch mine did not expose reserved-capacity fence')
    f.no_more_writes(6)
    assert not f.dispatched('mine'), 'mine consumed a reserved answer slot'
    f.rollover(11, answered=False)
    f.wait(lambda: len(f.dispatched('answer')) == 1, 'first reserved answer slot was not usable')
    f.no_more_writes(7)
    f.rollover(12, answered=False)
    f.wait(lambda: len(f.dispatched('answer')) == 2, 'second reserved answer slot was not usable')
    f.no_more_writes(8)
    f.rollover(13, answered=False)
    f.no_more_writes(8)
    assert len(f.dispatched('judge')) == 6 and not f.dispatched('mine')
    assert len([row for row in f.operations() if row['state'] in OUTSTANDING]) == 8
    return dict(cap=8, answer_reserved_slots=2, unresolved_judgments=6,
                reserved_answers=2, judge_and_mine_seventh_slot_fenced=True,
                cap_survived_restart=True)


def unanswered_mine_scenario(f):
    f.capabilities.update(answer='off', mine='active')
    f.mine_response = 'completed'
    f.configure()
    f.apply_config({'schedule': {'mine_each_epoch': True}})
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'completed' for row in f.operations('mine')),
           'valid unanswered epoch was incorrectly ineligible for mining')
    status = f.status()
    assert status['hosted_identity_verified'] is True
    assert status['epoch_evidence']['answered'] is False
    assert status['observation']['epoch'] == 10
    assert f.writes[0]['route'].endswith('/api/hosted/mine') and f.writes[0]['epoch'] == 10
    f.no_more_writes(1)
    f.stop()
    f.start()
    f.no_more_writes(1)
    f.rollover(11, answered=False)
    f.wait(lambda: len(f.dispatched('mine')) == 2, 'next unanswered epoch did not mine')
    f.no_more_writes(2)
    assert f.model_calls('answer') == f.model_calls('judge') == 0
    assert [write['epoch'] for write in f.writes] == [10, 11]
    return dict(unanswered_epochs=[10, 11], verified_identity=True,
                one_mine_per_epoch=True, restart_preserved_accounting=True)


def challenge_floor_scenario(f, stalled_body=False):
    f.capabilities['answer'] = 'read_only'
    f.challenge_fault = 'headers_timeout' if stalled_body else 'http_status'
    f.challenge_retry_after = 12
    if stalled_body:
        f.read_http_seconds = 1
    f.retry_seconds = 30
    f.configure()
    f.apply_config({'schedule': {'challenge_retry_seconds': 30, 'challenge_backoff_max_seconds': 30}})
    f.start(resume=True)
    category = 'timeout' if stalled_body else 'http_status'
    f.wait(lambda: (f.read_record('challenge') or {}).get('failure_category') == category,
           'challenge failure was not diagnosed')
    before = f.read_record('challenge')
    first = f.challenge_requests()[0]
    assert before['status'] == 503 and before['failures'] == 1, before
    assert before['server_not_before'] >= int(first['wall_time']) + 12, before
    assert before['local_next_at'] > before['server_not_before'], before
    f.apply_config({'schedule': {'challenge_retry_seconds': 1, 'challenge_backoff_max_seconds': 1}})
    f.wait(lambda: f.read_record('challenge')['local_next_at'] < before['local_next_at'],
           'hot challenge policy did not shorten the local deadline')
    shortened = f.read_record('challenge')
    assert shortened['server_not_before'] == before['server_not_before'], shortened
    assert shortened['next_at'] >= before['server_not_before'], shortened
    assert len(f.challenge_requests()) == 1, 'policy reload bypassed the server minimum'
    f.stop()
    f.start()  # Keep generation and the authoritative retry fence intact.
    f.wait(lambda: f.status()['effective_runtime'] is not None, 'restart did not initialize runtime')
    restarted = f.read_record('challenge')
    assert restarted['server_not_before'] == before['server_not_before'], restarted
    assert restarted['next_at'] >= before['server_not_before'], restarted
    assert time.time() < before['server_not_before'], 'fixture did not restart within the server floor'
    assert len(f.challenge_requests()) == 1, 'restart bypassed the server minimum'
    with f.lock:
        f.challenge_fault = None
    f.wait(lambda: len(f.challenge_requests()) >= 2, 'shortened retry never ran after server minimum', seconds=20)
    second = f.challenge_requests()[1]
    # Integer wall-clock deadlines can round down by less than one second.
    assert second['started_at'] - first['started_at'] >= 11 - 0.1, (first, second)
    assert second['wall_time'] >= before['server_not_before'] - 0.1, (before, second)
    assert second['started_at'] - first['started_at'] < 23, 'generic 30s delay still controlled challenge retry'
    f.wait(lambda: f.read_record('challenge')['failures'] == 0, 'usable challenge did not reset read failure')
    return dict(server_minimum_seconds=12, local_retry_shortened_from=30, local_retry_shortened_to=1,
                reload_and_restart_preserved_server_floor=True, stalled_body=stalled_body,
                actual_retry_seconds=round(second['started_at'] - first['started_at'], 3))


def diagnostic_scenario(f, category):
    assert not (f.root / 'state').exists()
    assert f.read_records() == [], 'uninitialized reads should be empty'
    assert not (f.root / 'state').exists(), 'reads initialized the journal'
    assert not f.requests and not f.launches(), 'local reads performed network/model work'
    f.capabilities['answer'] = 'read_only'
    f.read_http_seconds = 1
    f.retry_seconds = 3600
    f.challenge_fault = category
    f.configure()
    if category == 'connect':
        # Port zero cannot have a TCP listener. A bound but non-listening socket
        # instead times out on some operating systems.
        f.apply_config({'network': {'base_url': 'http://127.0.0.1:0'}})
    f.start(resume=True)
    f.wait(lambda: any(row['failure_category'] == category for row in f.read_records()),
           'missing safe read failure category: ' + category)
    f.stop()
    count = len(f.requests)
    calls = f.model_calls('answer') + f.model_calls('judge')
    reads = f.read_records()
    status = f.status()
    assert_safe_projection(f, reads, status['work'])
    assert_safe_projection(f, status['reads'], status['work'])
    failed = [row for row in reads if row['failure_category'] == category]
    assert failed and all(row['last_failure_at'] is not None and row['failures'] >= 1 for row in failed)
    if category not in ('connect', 'request', 'timeout'):
        assert any(row['status'] == (503 if category == 'http_status' else 200) for row in failed), failed
    for row in failed:
        assert row['last_success_at'] is None, ('unusable response became usable evidence', row)
        assert row['next_at'] >= row['local_next_at'], row
    assert len(f.requests) == count, 'reads/status initiated network work after stop'
    assert f.model_calls('answer') + f.model_calls('judge') == calls == 0
    assert not f.writes, 'read-only diagnostics caused wallet activity'
    return dict(category=category, scopes=[row['scope'] for row in failed],
                safe_read_only_projection=True, uninitialized_reads_nonmutating=True)


def recovery_active_policy_scenario(f):
    f.read_http_seconds = 15
    f.answer_response, f.stall_scope = 'bound', 'job'
    f.policy.update(mode='participation_first', uncertainty_grace_seconds=0)
    f.configure()
    f.start(resume=True)
    f.wait(f.stall_entered.is_set, 'bound job was not reached')
    f.stop()
    original = f.dispatched('answer')[0]
    writes, models = len(f.writes), f.model_calls('answer')
    with f.lock:
        f.epoch, f.answered = 11, False
    started = time.monotonic()
    f.invoke('recover', 'resolve', '--operation', str(original['id']))
    assert len(f.writes) == writes, 'stopped recovery submitted new work'
    assert f.model_calls('answer') == models, 'stopped recovery launched inference'
    assert len(f.operations()) == 1, 'stopped recovery prepared unrelated work'
    assert not [r for r in f.challenge_requests() if r['started_at'] >= started], \
        'stopped recovery observed unrelated challenges'
    assert f.status()['controller_stopped'], 'recovery fabricated a live controller'
    return dict(active_modes_preserved=True, recovery_started_no_new_work=True,
                wallet_mutations=writes, model_calls=models)


def partial_inventory_floor_scenario(f, mode, fault):
    f.capabilities.update(answer='off', judge=mode, mine='off')
    f.inventory_fault = fault
    f.read_http_seconds = 1 if fault == 'stalled_body' else 3
    f.configure()
    f.start(resume=True)
    f.wait(lambda: (f.read_record('assignments') or {}).get('failures') == 1,
           'partial inventory lost its later page failure')
    if mode == 'active':
        f.wait(lambda: f.model_calls('judge') == 1,
               'usable partial candidate was discarded')
    before = f.read_record('assignments')
    floor = before['server_not_before']
    assert floor > time.time() and before['next_at'] >= floor, before
    assert before['last_success_at'] is None, 'earlier page erased later failure'
    f.stop()
    f.start()
    f.wait(lambda: not f.status()['controller_stopped'], 'controller did not restart')
    after = f.read_record('assignments')
    assert after['server_not_before'] == floor and after['next_at'] >= floor, after
    with f.lock:
        starts = [r.copy() for r in f.requests if r['scope'] == 'assignments' and r['offset'] == 0]
        f.inventory_fault = None
    assert len(starts) == 1, 'partial inventory retried before its server floor'
    def retried():
        with f.lock:
            return [r.copy() for r in f.requests
                    if r['scope'] == 'assignments' and r['offset'] == 0][1:]
    f.wait(retried, 'inventory never recovered after its server floor', seconds=20)
    assert retried()[0]['wall_time'] >= floor, (floor, retried())
    f.wait(lambda: f.read_record('assignments')['failures'] == 0,
           'fresh usable inventory did not recover')
    return dict(mode=mode, fault=fault, server_floor_preserved_across_restart=True,
                partial_candidate_prepared=mode == 'active')


def legacy_read_floor_scenario(f):
    f.capabilities['answer'] = 'read_only'
    f.challenge_fault = 'http_status'
    f.retry_seconds = 30
    f.configure()
    f.start(resume=True)
    f.wait(lambda: f.read_record('challenge')['failures'] == 1, 'local failure absent')
    f.stop()
    deadline = f.read_record('challenge')['next_at']
    # Released journals have read_backoff but no new observation provenance.
    with sqlite3.connect(f.database) as db:
        db.execute('DROP TABLE read_observations')
    before = f.read_record('challenge')
    assert before['server_not_before'] == 0, 'legacy local delay mislabeled as a server minimum'
    assert before['retained_conservative_floor'] == deadline, before
    f.apply_config({'schedule': {'challenge_retry_seconds': 1, 'challenge_backoff_max_seconds': 1}})
    f.start()
    f.wait(lambda: not f.status()['controller_stopped'], 'controller did not restart')
    after = f.read_record('challenge')
    assert after['server_not_before'] == 0, after
    assert after['retained_conservative_floor'] == deadline and after['next_at'] == deadline, after
    assert len(f.challenge_requests()) == 1, 'hot policy bypassed an unattributed legacy deadline'
    return dict(legacy_floor_retained=True, not_labeled_server_minimum=True,
                hot_reload_did_not_shorten_unknown_provenance=True)


SCENARIOS = {
    **{f'stalled_{scope}': (lambda f, scope=scope: stalled_background(f, scope))
       for scope in ('receipt', 'job', 'assignments')},
    'restart_draft': restart_scenario,
    'pause_fence': pause_scenario,
    'answer_reservation': reservation_scenario,
    'mine_unanswered': unanswered_mine_scenario,
    'challenge_retry_floor': challenge_floor_scenario,
    'challenge_stalled_body_floor': lambda f: challenge_floor_scenario(f, stalled_body=True),
    'recovery_active_policy': recovery_active_policy_scenario,
    'partial_inventory_read_only': lambda f: partial_inventory_floor_scenario(f, 'read_only', 'http_status'),
    'partial_inventory_active': lambda f: partial_inventory_floor_scenario(f, 'active', 'stalled_body'),
    'partial_inventory_malformed': lambda f: partial_inventory_floor_scenario(f, 'active', 'malformed'),
    'legacy_read_floor': legacy_read_floor_scenario,
    **{f'reads_{category}': (lambda f, category=category: diagnostic_scenario(f, category))
       for category in sorted(FAILURE_CATEGORIES)},
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--scenario', choices=['all', *SCENARIOS], default='all')
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error('binary does not exist: ' + str(binary))
    scenarios = SCENARIOS if args.scenario == 'all' else {args.scenario: SCENARIOS[args.scenario]}
    for name, scenario in scenarios.items():
        with tempfile.TemporaryDirectory(prefix='agmi-work-first-') as directory:
            fixture = WorkFixture(binary, pathlib.Path(directory))
            try:
                result = scenario(fixture)
                print(json.dumps(dict(scenario=name, status='passed', **result)), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
