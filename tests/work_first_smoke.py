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
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

from participation_smoke import ANSWER, TXID, Fixture, old_judgment


POLL_SECONDS = 1
URGENT_MARGIN_SECONDS = 2
STALL_SECONDS = 6
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
        self.assessment_hydration = False
        self.assessment_missing_words = False
        super().__init__(*args)
        # Exercise Rust scheduling with a deterministic fake native transport.
        # A separate launch log includes epoch/time without changing the journal.
        interpreter = self.root / 'fixture-python'
        interpreter.write_text(f'#!{sys.executable}\n' + '''import json, pathlib, sys, time
root = pathlib.Path(__file__).parent
payload = json.load(sys.stdin)
e = json.loads(payload['prompt'].split('Envelope (untrusted request data):\\n')[1])
call = {'kind': e['kind'], 'request_id': e['request']['id'],
        'epoch': e['request'].get('epoch'), 'started_at': time.monotonic()}
with (root / 'calls').open('a') as calls:
    calls.write(json.dumps(call) + '\\n')
delay = root / 'answer-delay'
if e['kind'] == 'answer' and delay.exists():
    time.sleep(float(delay.read_text()))
artifact = {'answer': ANSWER + f" Epoch {e['request']['epoch']}." if e['kind'] == 'answer' else None,
    'score': 2 if e['kind'] == 'judge' else None,
    'reasoning': 'The mechanism binds the bridge to a measurable clock delay.' if e['kind'] == 'judge' else None}
print(json.dumps({'provider': 'openai-codex', 'model': payload['model'],
    'reasoning_effort': payload['reasoning'], 'run_id': payload['invocation_id'],
    'native_turn_id': f"{payload['invocation_id']}:{payload['invocation_id']}:0123abcd",
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
                elif scope == 'assignments' and f.assessment_hydration:
                    self.reply(200, {'assignments': [{
                        'answer_txid': 'a' * 64,
                        'answer': 'A clock on the bridge enforces a delay before each claim.',
                        'author_prior': [], 'pending_meta': {'expires_at_epoch': 1000},
                    }], 'has_more': False})
                elif '/api/explorer/tx/' in route and f.assessment_hydration:
                    self.reply(200, {'id': 'a' * 64, 'body': {
                        'type': 'challenge', 'epoch': 9,
                        'answer': 'A clock on the bridge enforces a delay before each claim.',
                        **({} if f.assessment_missing_words else {'words': ['clock', 'bridge']}),
                    }})
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
        projection = self.invoke('reads')
        assert projection['reads_truncated'] is False, 'fixture read evidence was truncated'
        return projection['reads']

    def read_record(self, owner, purpose, resource=None, operation_id=None):
        rows = [row for row in self.read_records()
                if row['owner'] == owner and row['purpose'] == purpose
                and (resource is None or row['resource'] == resource)
                and (operation_id is None or row['operation_id'] == operation_id)]
        assert len(rows) <= 1, ('ambiguous read key', owner, purpose, resource, rows)
        return rows[0] if rows else None

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
    assert isinstance(reads, list) and reads, reads
    assert len({(row['owner'], row['purpose'], row['resource']) for row in reads}) == len(reads), reads
    required = {'owner', 'purpose', 'resource', 'operation_id', 'binding_revision',
                'state', 'started_at', 'finished_at', 'last_http_success_at',
                'last_success_at', 'last_failure_at', 'failure_category', 'status',
                'failures', 'local_next_at', 'server_not_before', 'retained_conservative_floor',
                'next_at', 'due_in_seconds'}
    for row in reads:
        assert required <= row.keys(), row
        assert row['owner'] in ('account', 'answer', 'judge', 'mine'), row
        assert row['purpose'] in ('identity', 'discovery', 'assignment', 'job', 'receipt'), row
        if row['operation_id'] is not None:
            assert row['resource'] == f"{row['operation_id']}:{row['binding_revision']}", row
        assert row['state'] in ('idle', 'in_flight'), row
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
    public_work = json.loads(json.dumps(work))
    if public_work is not None:
        for row in public_work.values():
            for action in row.get('next_actions', []):
                argv = action.get('argv', [])
                # The caller-selected configuration is explicit CLI navigation,
                # not permission to expose any other private path or model data.
                if argv[:3] == ['agmi', '--config', str(f.config)]:
                    argv[2] = '<selected-config>'
    encoded = json.dumps({'reads': reads, 'work': public_work})
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
    f.lanes['answer']['timeouts']['read_http_seconds'] = 15
    f.lanes['judge']['timeouts']['read_http_seconds'] = 15
    f.receipt_state = 'final'
    f.stall_scope = scope
    f.answer_response = 'bound' if scope == 'job' else 'included'
    if scope == 'assignments':
        f.answered, f.assignments = True, True
        f.lanes['judge']['mode'] = 'active'
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
        if (status['observations'].get('answer') or {}).get('epoch') == 11 and observed_at is None:
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
    read = (f.read_record('judge', 'discovery', 'assignments') if scope == 'assignments'
            else f.read_record('answer', scope, operation_id=original['id']))
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
    read = (f.read_record('judge', 'discovery', 'assignments') if scope == 'assignments'
            else f.rows('SELECT * FROM read_state WHERE owner=? AND purpose=? AND operation_id=? '
                        'ORDER BY binding_revision DESC LIMIT 1', ('answer', scope, original['id']))[0])
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
    # Unlock retained work with a one-shot grant, not a lane revision change,
    # which correctly retires artifacts captured under the previous policy.
    f.lanes['answer']['participation']['mode'] = 'manual'
    old, draft = completed_draft(f)
    generation = f.status()['generation']
    child = f.child
    f.stop()  # Ordinary SIGTERM and start: deliberately no pause/resume.
    assert child.returncode == 0, ('unclean ordinary shutdown', child.returncode)
    f.start()
    f.cycles(2)
    after = next(row for row in f.operations('answer') if row['id'] == draft['id'])
    for field in ('id', 'work_key', 'request', 'payload', 'created_at', 'generation', 'revision', 'state'):
        assert after[field] == draft[field], ('completed draft changed on restart', field)
    assert f.status()['generation'] == generation
    assert f.model_calls('answer') == 1, 'ordinary restart repeated completed inference'
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.stop()
    grant = f.invoke('recover', 'authorize', '--epoch', '11', '--kind', 'answer')
    f.start()
    f.wait(lambda: any(row['id'] == draft['id'] and row['state'] == 'final'
                       for row in f.operations('answer')), 'retained draft did not dispatch and finalize')
    dispatched = f.dispatched('answer')
    assert len(dispatched) == 1 and dispatched[0]['id'] == draft['id'], dispatched
    assert dispatched[0]['payload'] == draft['payload']
    assert f.model_calls('answer') == 1
    assert f.status()['generation'] == generation
    assert dispatched[0]['revision'] == draft['revision']
    assert len(f.risks()) == 1 and f.risks()[0]['manual_grant_id'] == grant['grant_id']
    f.preserved(old)
    return dict(retained_operation_id=draft['id'], answer_inferences=1,
                unchanged_generation=True, eventual_dispatch=True)


def pause_scenario(f):
    f.lanes['answer']['preparation']['max_attempts_per_work'] = 1
    old, draft = completed_draft(f)
    generation = f.status()['generation']
    f.invoke('pause')
    f.wait(lambda: next(row for row in f.operations('answer')
                        if row['id'] == draft['id'])['state'] == 'discarded',
           'explicit pause did not fence the completed draft')
    assert f.status()['paused'] and f.status()['generation'] > generation
    f.apply_config({'capabilities': {'answer': {'participation': {'mode': 'participation_first'}}}})
    f.stop()
    f.start()
    f.cycles(2)
    assert not f.dispatched('answer'), 'paused restart dispatched a fenced draft'
    f.invoke('resume')
    f.cycles(2)
    assert not f.dispatched('answer'), 'resume revived old-generation model work'
    assert f.model_calls('answer') == 1, 'resume bypassed the preparation attempt budget'
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.apply_config({'capabilities': {'answer': {'preparation': {'max_attempts_per_work': 2}}}})
    f.wait(lambda: bool(f.dispatched('answer')), 'fresh authorized preparation did not dispatch')
    current = f.dispatched('answer')[0]
    assert current['id'] != draft['id'] and current['generation'] != draft['generation']
    assert f.model_calls('answer') == 2
    assert next(row for row in f.operations('answer') if row['id'] == draft['id'])['state'] == 'discarded'
    f.preserved(old)
    return dict(old_draft_fenced=True, restart_kept_pause=True, fresh_generation_dispatched=True)


def independent_caps_scenario(f):
    f.answered, f.assignment_count = True, 8
    f.lanes['judge']['mode'] = 'active'
    f.lanes['answer']['participation']['max_unresolved_operations'] = 1
    f.configure('judge', mode='participation_first', max_unresolved_operations=2,
                uncertainty_grace_seconds=0)
    f.start(resume=True)
    f.wait(lambda: len(f.dispatched('judge')) == 2, 'judge did not fill its own cap')
    f.wait(lambda: f.status()['work']['judge']['admission']['reason'] == 'lane_unresolved_capacity',
           'judge own-cap fence was not projected')
    originals = f.dispatched('judge')
    f.no_more_writes(2)
    f.stop()
    f.start()
    f.no_more_writes(2)
    f.rollover(11)
    f.wait(lambda: any(row['state'] == 'generated' for row in f.operations('answer')),
           'strict answer did not prepare behind shared uncertainty')
    admission = f.status()['work']['answer']['admission']
    assert admission['own_count'] == 0 and admission['own_limit'] == 1, admission
    assert admission['reason'] == 'account_uncertainty' and admission['scope'] == 'account', admission
    assert set(admission['blocker_ids']) == {row['id'] for row in originals}, admission
    f.no_more_writes(2)
    f.apply_config({'capabilities': {'answer': {'participation': {
        'mode': 'participation_first', 'uncertainty_grace_seconds': 0}}}})
    f.unknown('answer')
    f.no_more_writes(3)
    f.apply_config({'capabilities': {'mine': {'mode': 'active',
        'schedule': {'each_epoch': True}, 'participation': {
            'mode': 'participation_first', 'uncertainty_grace_seconds': 0,
            'max_unresolved_operations': 1}}}})
    f.unknown('mine')
    f.no_more_writes(4)
    f.rollover(12)
    f.no_more_writes(4)
    status = f.status()
    for lane, count in (('answer', 1), ('judge', 2), ('mine', 1)):
        admission = status['participation']['lanes'][lane]
        assert admission['own_count'] == admission['own_limit'] == count, admission
        assert admission['own_remaining'] == 0 and admission['required_release'] == 1, admission
        assert admission['reason'] == 'lane_unresolved_capacity' and admission['scope'] == 'lane', admission
        assert set(admission['blocker_ids']) == {row['id'] for row in f.dispatched(lane)}, admission
    assert status['participation']['unresolved_count'] == 4
    for original in originals:
        f.preserved(original)
    assert len(f.risks()) == 3
    return dict(own_caps=dict(answer=1, judge=2, mine=1), shared_uncertainty_retained=True,
                cross_lane_capacity_independent=True, caps_survived_restart=True)


def unanswered_mine_scenario(f):
    f.lanes['answer']['mode'] = 'off'
    f.lanes['mine']['mode'] = 'active'
    f.mine_response = 'completed'
    f.configure()
    f.apply_config({'capabilities': {'mine': {'schedule': {'each_epoch': True}}}})
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'completed' for row in f.operations('mine')),
           'valid unanswered epoch was incorrectly ineligible for mining')
    status = f.status()
    assert status['hosted_identity_verified'] is True
    assert status['observations']['mine']['answered'] is False
    assert status['observations']['mine']['epoch'] == 10
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
    f.lanes['answer']['mode'] = 'read_only'
    f.challenge_fault = 'headers_timeout' if stalled_body else 'http_status'
    f.challenge_retry_after = 12
    if stalled_body:
        f.lanes['answer']['timeouts']['read_http_seconds'] = 1
    f.lanes['answer']['schedule']['retry_seconds'] = 30
    f.configure()
    f.apply_config({'capabilities': {'answer': {'schedule': {'discovery_retry_seconds': 30, 'discovery_backoff_max_seconds': 30}}}})
    f.start(resume=True)
    f.wait(lambda: (f.read_record('answer', 'discovery', 'challenge') or {}).get('failures', 0) == 1,
           'challenge failure was not recorded')
    before = f.read_record('answer', 'discovery', 'challenge')
    first = f.challenge_requests()[0]
    assert before['status'] == 503 and before['failures'] == 1, before
    restriction = next(row for row in f.restrictions()
                       if row['scope'] == 'account_authenticated' and row['basis'] == 'server_retry_after')
    floor = restriction['not_before']
    assert floor >= int(first['wall_time']) + 12, restriction
    assert before['server_not_before'] == 0, 'shared restriction was broadcast into resource state'
    assert before['local_next_at'] > floor, before
    f.apply_config({'capabilities': {'answer': {'schedule': {'discovery_retry_seconds': 1, 'discovery_backoff_max_seconds': 1}}}})
    f.wait(lambda: f.read_record('answer', 'discovery', 'challenge')['local_next_at'] < before['local_next_at'],
           'hot challenge policy did not shorten the local deadline')
    shortened = f.read_record('answer', 'discovery', 'challenge')
    assert shortened['server_not_before'] == before['server_not_before'], shortened
    assert shortened['next_at'] == floor, shortened
    assert f.status()['work']['answer']['next_at'] == floor, 'work timing kept the obsolete retry clock'
    assert restriction in f.restrictions(), 'policy reload changed the shared minimum'
    assert len(f.challenge_requests()) == 1, 'policy reload bypassed the server minimum'
    authority = f.rows('SELECT authority_epoch FROM runtime_authority')[0]['authority_epoch']
    f.stop()
    f.start()  # Keep generation and the authoritative retry fence intact.
    f.wait(lambda: f.rows('SELECT authority_epoch FROM runtime_authority')[0]['authority_epoch'] != authority,
           'restart did not establish a new runtime authority')
    restarted = f.read_record('answer', 'discovery', 'challenge')
    assert restarted['server_not_before'] == before['server_not_before'], restarted
    assert restarted['next_at'] == floor, restarted
    assert f.status()['work']['answer']['next_at'] == floor, 'restart restored the obsolete retry clock'
    assert restriction in f.restrictions(), 'restart changed the shared minimum'
    assert time.time() < floor, 'fixture did not restart within the server floor'
    assert len(f.challenge_requests()) == 1, 'restart bypassed the server minimum'
    with f.lock:
        f.challenge_fault = None
    f.wait(lambda: len(f.challenge_requests()) >= 2, 'shortened retry never ran after server minimum', seconds=20)
    second = f.challenge_requests()[1]
    # Integer wall-clock deadlines can round down by less than one second.
    assert second['started_at'] - first['started_at'] >= 11 - 0.1, (first, second)
    assert second['wall_time'] >= floor - 0.1, (before, second)
    assert second['started_at'] - first['started_at'] < 23, 'generic 30s delay still controlled challenge retry'
    f.wait(lambda: f.read_record('answer', 'discovery', 'challenge')['failures'] == 0, 'usable challenge did not reset read failure')
    return dict(server_minimum_seconds=12, local_retry_shortened_from=30, local_retry_shortened_to=1,
                reload_and_restart_preserved_server_floor=True, stalled_body=stalled_body,
                actual_retry_seconds=round(second['started_at'] - first['started_at'], 3))


def diagnostic_scenario(f, category):
    assert not (f.root / 'state').exists()
    assert f.read_records() == [], 'uninitialized reads should be empty'
    assert not (f.root / 'state').exists(), 'reads initialized the journal'
    assert not f.requests and not f.launches(), 'local reads performed network/model work'
    f.lanes['answer']['mode'] = 'read_only'
    f.lanes['answer']['timeouts']['read_http_seconds'] = 1
    f.lanes['answer']['schedule']['retry_seconds'] = 3600
    f.challenge_fault = category
    f.configure()
    if category == 'connect':
        # Port zero cannot have a TCP listener. A bound but non-listening socket
        # instead times out on some operating systems.
        f.apply_config({'network': {'base_url': 'http://127.0.0.1:0'}})
    f.start(resume=True)
    f.wait(lambda: any(row['failures'] >= 1 for row in f.read_records()),
           'read failure was not recorded: ' + category)
    f.stop()
    count = len(f.requests)
    calls = f.model_calls('answer') + f.model_calls('judge')
    reads = f.read_records()
    status = f.status()
    assert_safe_projection(f, reads, status['work'])
    assert_safe_projection(f, status['reads'], status['work'])
    failed = [row for row in reads if row['failures'] >= 1]
    assert failed and all(row['last_failure_at'] is not None and row['failures'] >= 1 for row in failed)
    if category not in ('connect', 'request', 'timeout'):
        assert any(row['status'] == (503 if category == 'http_status' else 200) for row in failed), failed
    for row in failed:
        assert row['last_success_at'] is None, ('unusable response became usable evidence', row)
        assert row['next_at'] >= row['local_next_at'], row
    assert len(f.requests) == count, 'reads/status initiated network work after stop'
    assert f.model_calls('answer') + f.model_calls('judge') == calls == 0
    assert not f.writes, 'read-only diagnostics caused wallet activity'
    return dict(category=category, keys=[(row['owner'], row['purpose'], row['resource']) for row in failed],
                safe_read_only_projection=True, uninitialized_reads_nonmutating=True)


def recovery_active_policy_scenario(f):
    f.lanes['answer']['timeouts']['read_http_seconds'] = 15
    f.answer_response, f.stall_scope = 'bound', 'job'
    f.lanes['answer']['participation'].update(mode='participation_first', uncertainty_grace_seconds=0)
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
    f.lanes['answer']['mode'] = 'off'
    f.lanes['judge']['mode'] = mode
    f.lanes['mine']['mode'] = 'off'
    f.inventory_fault = fault
    f.lanes['judge']['preparation']['while_blocked'] = True
    f.lanes['judge']['timeouts']['read_http_seconds'] = 1 if fault == 'stalled_body' else 3
    f.configure()
    f.start(resume=True)
    f.wait(lambda: (f.read_record('judge', 'discovery', 'assignments') or {}).get('failures') == 1,
           'partial inventory lost its later page failure')
    if mode == 'active':
        f.wait(lambda: f.model_calls('judge') == 1,
               'usable partial candidate was discarded')
    before = f.read_record('judge', 'discovery', 'assignments')
    restriction = next(row for row in f.restrictions()
                       if row['scope'] == 'account_authenticated' and row['basis'] == 'server_retry_after')
    floor = restriction['not_before']
    assert floor > time.time(), restriction
    assert before['server_not_before'] == 0, before
    assert before['last_success_at'] is None, 'earlier page erased later failure'
    f.stop()
    f.start()
    f.wait(lambda: not f.status()['controller_stopped'], 'controller did not restart')
    after = f.read_record('judge', 'discovery', 'assignments')
    assert restriction in f.restrictions(), 'restart erased the actual shared restriction'
    assert after['server_not_before'] == 0, after
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
    f.wait(lambda: f.read_record('judge', 'discovery', 'assignments')['failures'] == 0,
           'fresh usable inventory did not recover')
    return dict(mode=mode, fault=fault, server_floor_preserved_across_restart=True,
                partial_candidate_prepared=mode == 'active')


def lane_pause_isolation_scenario(f):
    f.answer_response, f.receipt_state, f.mine_response = 'bound', 'final', 'completed'
    f.assignments, f.queued_grades = True, True
    for lane in f.lanes.values():
        lane['mode'] = 'active'
        lane['participation'].update(mode='participation_first', uncertainty_grace_seconds=0)
    f.lanes['judge']['participation']['max_unresolved_operations'] = 1
    f.lanes['mine']['schedule']['each_epoch'] = True
    f.configure()
    f.start(resume=True)
    f.wait(lambda: all(f.dispatched(lane) for lane in ('answer', 'judge', 'mine')),
           'all three active lanes did not dispatch')
    generation = f.status()['generation']
    controls = {lane: f.invoke('lane', 'show', lane)['desired'] for lane in f.lanes}
    ack = f.invoke('lane', 'pause', 'judge', '--expected-control', controls['judge']['control_token'])
    assert ack['fence_ack']['acknowledged'] and ack['desired']['paused'], ack
    judge_calls, judge_dispatches = f.model_calls('judge'), len(f.dispatched('judge'))
    assert judge_calls == judge_dispatches == 1
    # Remove the old quota blocker: the pause must now be the actual fence.
    f.apply_config({'capabilities': {'judge': {'participation': {'max_unresolved_operations': 3}}}})
    f.rollover(11)
    f.wait(lambda: len(f.dispatched('answer')) >= 2 and len(f.dispatched('mine')) >= 2,
           'paused judge blocked answer or mine progress')
    f.cycles(2)
    status = f.status()
    assert status['generation'] == generation
    assert status['work']['judge']['admission']['reason'] == 'lane_paused'
    assert f.model_calls('judge') == judge_calls
    assert len(f.dispatched('judge')) == judge_dispatches
    for lane in ('answer', 'mine'):
        current = f.invoke('lane', 'show', lane)['desired']
        for field in ('control_token', 'control_revision', 'paused'):
            assert current[field] == controls[lane][field]
    f.invoke('lane', 'resume', 'judge', '--expected-control', ack['desired']['control_token'])
    f.wait(lambda: len(f.dispatched('judge')) >= 2, 'resumed judge did not admit fresh work')
    assert f.status()['generation'] == generation
    assert f.model_calls('mine') == 0
    return dict(judge_pause_acknowledged=True, answer_and_mine_progressed=True,
                sibling_controls_unchanged=True, account_generation_unchanged=True,
                judge_resumed_with_fresh_work=True)


def read_only_assessment_scenario(f, missing_words=False):
    f.lanes['answer']['mode'] = 'read_only'
    f.lanes['judge']['mode'] = 'read_only'
    f.lanes['mine']['mode'] = 'off'
    f.assessment_hydration = True
    f.assessment_missing_words = missing_words
    f.configure()
    f.start()  # Fresh account remains globally paused; ordinary bounded reads continue.
    def assessed(lane):
        return f.status().get('lane_participation', {}).get(lane, {}).get('assessment') or {}
    f.wait(lambda: assessed('judge').get('locally_judgeable') is (not missing_words),
           'read-only judge did not hydrate and assess the candidate')
    f.wait(lambda: assessed('answer').get('observed_opportunities') == 1,
           'read-only answer did not expose comparable observation evidence')
    answer, judge = assessed('answer'), assessed('judge')
    if missing_words:
        assert judge['assessment_reason'] == 'required_words_absent', judge
    for evidence in (answer, judge):
        assert evidence['assessment_creates_model_work'] is False, evidence
        assert evidence['observed_at'] <= evidence['valid_until'], evidence
        assert evidence['outcome'] == 'unobserved', evidence
    assert judge['source'] == 'validated_assignment_inventory', judge
    assert judge['completeness'] == 'complete', judge
    assert any('/api/explorer/tx/' in row['route'] for row in f.requests)
    desired = f.invoke('lane', 'show', 'judge')['desired']
    ack = f.invoke('lane', 'pause', 'judge', '--expected-control', desired['control_token'])
    assert ack['fence_ack']['acknowledged'] and ack['desired']['paused'], ack
    def refreshed_under_pause():
        lane = f.status().get('lane_participation', {}).get('judge', {})
        return (lane.get('stamp', {}).get('lane_control_revision') == ack['desired']['control_revision']
                and (lane.get('assessment') or {}).get('locally_judgeable') is (not missing_words))
    f.wait(refreshed_under_pause, 'lane pause incorrectly stopped read-only assessment')
    f.stop()
    assert f.rows('SELECT COUNT(*) AS n FROM operations')[0]['n'] == 0
    assert f.rows('SELECT COUNT(*) AS n FROM manual_grants')[0]['n'] == 0
    assert not f.writes and not f.launches(), 'assessment created model/grant/effect participation'
    stopped = f.invoke('lane', 'show', 'judge')
    assert stopped['observed_admission']['state'] == 'unknown', stopped
    return dict(read_only_hydration=True, comparable_sourced_assessments=True,
                globally_paused=True, lane_paused=True, model_calls=0, operations=0, grants=0)


SCENARIOS = {
    **{f'stalled_{scope}': (lambda f, scope=scope: stalled_background(f, scope))
       for scope in ('receipt', 'job', 'assignments')},
    'restart_draft': restart_scenario,
    'pause_fence': pause_scenario,
    'independent_caps': independent_caps_scenario,
    'mine_unanswered': unanswered_mine_scenario,
    'challenge_retry_floor': challenge_floor_scenario,
    'challenge_stalled_body_floor': lambda f: challenge_floor_scenario(f, stalled_body=True),
    'recovery_active_policy': recovery_active_policy_scenario,
    'lane_pause_isolation': lane_pause_isolation_scenario,
    'read_only_assessment': read_only_assessment_scenario,
    'read_only_abstention': lambda f: read_only_assessment_scenario(f, missing_words=True),
    'partial_inventory_read_only': lambda f: partial_inventory_floor_scenario(f, 'read_only', 'http_status'),
    'partial_inventory_active': lambda f: partial_inventory_floor_scenario(f, 'active', 'stalled_body'),
    'partial_inventory_malformed': lambda f: partial_inventory_floor_scenario(f, 'active', 'malformed'),
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
