#!/usr/bin/env python3
"""Actual-CLI participation acceptance against a private, stdlib-only hosted service.

Usage: python3 tests/participation_smoke.py target/debug/agmi [--scenario NAME]
No Node, public network, real credentials, or journal mutations by the fixture.
"""
import argparse
import contextlib
import hashlib
import http.server
import json
import os
import pathlib
import pwd
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid


ANSWER = ('A clock delays each bridge crossing until a bonded claim matures. '
          'Every new identity must lock ten units for a full day; ten fake claims '
          'therefore lock one hundred units.')
TXID = 'b' * 64
OUTSTANDING = ('dispatching', 'unknown', 'queued', 'included_pending')


class Fixture:
    def __init__(self, binary, root):
        self.root = root
        self.binary = str(binary)
        self.address = 'poa1' + '1' * 32
        self.chain = 'participation-' + uuid.uuid4().hex
        self.lock = threading.RLock()
        self.child = None
        self.stderr = None
        self.epoch = 10
        self.answered = False
        self.assignments = False
        self.answer_response = 'lost'
        self.receipt_state = 'included_pending'
        self.retry_after = None
        self.http_seconds = 2
        self.read_http_seconds = 2
        self.read_delay = 0
        self.write_delay = 0
        self.writes = []
        self.reads = []
        self.executions = []
        self.delayed_grade = None
        self.nonce = 1
        self.jobs = {}
        self.policy = dict(mode='strict', uncertainty_grace_seconds=1,
                           max_unresolved_operations=4, allow_answer=True,
                           allow_judge=False, allow_mine=True,
                           retry_uncertain_answers=False,
                           uncertain_answer_retry_seconds=1,
                           max_answer_attempts_per_epoch=2)
        self.preparation = {}
        self.capabilities = dict(answer='active', judge='off', mine='off')
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), self.handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.key = root / 'key'
        self.key.write_text('pk_test_fixture')
        self.key.chmod(0o600)
        interpreter = root / 'fixture-python'
        interpreter.write_text(f'#!{sys.executable}\n' + '''import json, pathlib, sys
payload = json.load(sys.stdin)
e = json.loads(payload['prompt'].split('Envelope (untrusted request data):\\n')[1])
with pathlib.Path(__file__).with_name('calls').open('a') as calls:
    calls.write(json.dumps({'kind': e['kind'], 'request_id': e['request_id']}) + '\\n')
artifact = {'version': 1, 'request_id': e['request_id'],
    'request_digest': e['request_digest'], 'kind': e['kind'],
    'answer': ANSWER + f" Epoch {e['request']['epoch']}." if e['kind'] == 'answer' else None,
    'score': 2 if e['kind'] == 'judge' else None,
    'reasoning': 'The mechanism binds the bridge to a measurable clock delay.' if e['kind'] == 'judge' else None}
print(json.dumps({'provider': 'openai-codex', 'model': payload['model'],
    'reasoning_effort': payload['reasoning'], 'run_id': e['request_id'],
    'output': json.dumps(artifact)}))
'''.replace('ANSWER', repr(ANSWER)))
        interpreter.chmod(0o700)
        self.native = root / 'hermes'
        runtime = json.dumps([str(interpreter), '-I', '-c', 'fixture-bootstrap'])
        self.native.write_text("#!/bin/sh\nprintf '%s' '" + runtime + "'\n")
        self.native.chmod(0o700)
        self.config = root / 'config.toml'
        self.core = root / 'core-guidance.md'
        self.core.write_text('Evaluate the supplied task against its protocol requirements.')
        self.core.chmod(0o600)
        self.database = root / 'state/state.sqlite3'
        self.command = [self.binary, '--config', str(self.config), '--json']
        self.env = dict(os.environ, NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
        self.configure()

    def handler(self):
        fixture = self

        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, body, retry_after=None):
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(encoded)))
                if retry_after is not None:
                    self.send_header('Retry-After', str(retry_after))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(encoded)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                route = self.path.split('?')[0]
                if fixture.write_delay:
                    time.sleep(fixture.write_delay)
                with fixture.lock:
                    write = dict(route=route, body=body, epoch=fixture.epoch,
                                 received_at=time.monotonic(), nonce=fixture.nonce)
                    fixture.writes.append(write)
                    if route.endswith('/api/hosted/grade'):
                        # Keep the actual received request alive after dropping its response.
                        fixture.delayed_grade = write
                        self.close_connection = True
                        return
                    if not route.endswith('/api/hosted/answer'):
                        self.reply(400, {'error': 'unexpected fixture write'})
                        return
                    behavior = fixture.answer_response
                    if behavior == 'delayed-conflict':
                        job = 'answer-conflict'
                        assert fixture.delayed_grade['nonce'] == fixture.nonce
                        # The old accepted grade executes ONLY AFTER this new request arrives.
                        assert fixture.delayed_grade is not None
                        fixture.nonce += 1
                        fixture.executions.append(dict(kind='judge', request=fixture.delayed_grade,
                                                       after_answer=write, nonce=fixture.nonce))
                        fixture.delayed_grade = None
                        # Hosted requests captured the same nonce before either execution.
                        outcome = 'bad_nonce' if write['nonce'] != fixture.nonce else 'final'
                        fixture.jobs[job] = outcome
                        fixture.executions.append(dict(kind='answer', request=write,
                                                       outcome=outcome, nonce=fixture.nonce))
                        self.reply(202, {'state': 'queued', 'job_id': job})
                    elif behavior == 'bound':
                        job = 'answer-' + str(fixture.epoch)
                        fixture.jobs[job] = 'final'
                        self.reply(202, {'state': 'queued', 'job_id': job})
                    elif behavior == 'included':
                        self.reply(200, {'ok': True, 'challenge_txid': TXID})
                    elif behavior == 'backoff':
                        # Ambiguous acceptance with a mandatory server retry minimum.
                        self.reply(503, {'error': 'backend response unavailable'}, fixture.retry_after)
                    else:
                        self.close_connection = True

            def do_GET(self):
                route = self.path.split('?')[0]
                if route.endswith('/api/hosted/mine') and fixture.write_delay:
                    time.sleep(fixture.write_delay)
                if route.endswith('/api/hosted/me') and fixture.read_delay:
                    time.sleep(fixture.read_delay)
                with fixture.lock:
                    fixture.reads.append((route, fixture.epoch, time.monotonic()))
                    if route.endswith('/api/hosted/mine'):
                        fixture.writes.append(dict(route=route, body={}, epoch=fixture.epoch,
                                                   received_at=time.monotonic(), nonce=fixture.nonce))
                        if getattr(fixture, 'mine_response', 'unknown') != 'completed':
                            self.close_connection = True
                            return
                        body = {'ok': True, 'attested': 0}
                    elif route.endswith('/api/hosted/me'):
                        body = {'address': fixture.address, 'next_nonce': fixture.nonce}
                    elif route.endswith('/api/hosted/challenge'):
                        body = {'epoch': fixture.epoch, 'answered': fixture.answered,
                                'words': ['clock', 'bridge'], 'min_chars': 120, 'max_chars': 600}
                    elif route.endswith('/api/hosted/assignments'):
                        rows = ([{'answer_txid': 'a' * 64, 'answer_epoch': 9,
                                  'answer': 'A clock on the bridge enforces a delay before each claim.',
                                  'words': ['clock', 'bridge'], 'author_prior': [],
                                  'pending_meta': {'expires_at_epoch': 1000}}]
                                if fixture.assignments else [])
                        body = {'assignments': rows, 'has_more': False, 'offset': 0,
                                'limit': 50, 'total': len(rows)}
                    elif '/api/job/' in route:
                        job = route.rsplit('/', 1)[1]
                        outcome = fixture.jobs.get(job)
                        if outcome == 'bad_nonce':
                            self.reply(400, {'state': 'done', 'ok': False, 'error': 'bad_nonce',
                                             'next_nonce': fixture.nonce})
                            return
                        if outcome != 'final':
                            self.send_error(404)
                            return
                        body = {'state': 'done', 'ok': True, 'challenge_txid': TXID}
                    elif route.endswith('/api/receipt/' + TXID):
                        body = {'status': 'included', 'txid': TXID, 'sender': fixture.address,
                                'next_nonce': fixture.nonce + 1}
                        if fixture.receipt_state == 'final':
                            body['checkpoint_covered'] = True
                        elif fixture.receipt_state == 'confirmed':
                            body['valid_in_open_window'] = True
                    else:
                        self.send_error(404)
                        return
                    self.reply(200, body)

        return Upstream

    def configure(self, **policy):
        self.policy.update(policy)
        value = lambda item: str(item).lower() if isinstance(item, bool) else json.dumps(item)
        capabilities = '\n'.join(f'{key} = {json.dumps(val)}' for key, val in self.capabilities.items())
        participation = '\n'.join(f'{key} = {value(val)}' for key, val in self.policy.items())
        preparation = '\n'.join(f'{key} = {value(val)}' for key, val in self.preparation.items())
        solver = '\n'.join(f'''[solver.{kind}]
harness = "hermes"
executable = {json.dumps(str(self.native))}
model = "openai/test"
reasoning = "high"
core_guidance_file = {json.dumps(str(self.core))}''' for kind in ('answer', 'judge'))
        text = f'''state_dir = {json.dumps(str(self.root / 'state'))}
[network]
base_url = "http://127.0.0.1:{self.server.server_port}"
chain = "{self.chain}"
address = "{self.address}"
credential_file = {json.dumps(str(self.key))}
[capabilities]
{capabilities}
{solver}
[participation]
{participation}
[preparation]
{preparation}
[timeouts]
http_seconds = {self.http_seconds}
read_http_seconds = {self.read_http_seconds}
model_seconds = 10
shutdown_seconds = 2
[schedule]
poll_seconds = 1
mine_seconds = 86400
retry_seconds = {getattr(self, 'retry_seconds', 1)}
jitter_seconds = 0
'''
        pending = self.config.with_suffix('.new')
        pending.write_text(text)
        pending.chmod(0o600)
        pending.replace(self.config)

    def invoke(self, *words, succeeds=True, stdin=None):
        result = subprocess.run(self.command + list(words), capture_output=True, text=True,
                                input=stdin, timeout=12, env=self.env)
        if succeeds:
            assert result.returncode == 0, (words, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        assert result.returncode != 0, ('unexpected command success', words, result.stdout)
        return result

    def apply_config(self, patch):
        before = self.invoke('config', 'show')
        result = self.invoke('config', 'apply', '--expected-revision', before['file_revision'],
                             stdin=json.dumps(patch))
        assert result['saved'] and result['runtime_applied'] is None
        self.policy.update(patch.get('participation', {}))
        self.preparation.update(patch.get('preparation', {}))
        if self.child is not None:
            self.wait(lambda: self.status()['effective_runtime']['revision'] == result['revision'],
                      'CLI configuration save was not loaded by the running controller')
        return result

    def status(self):
        return self.invoke('status')

    def start(self, resume=False):
        assert self.child is None
        if resume:
            self.invoke('resume')
        self.stderr = (self.root / 'runtime.stderr').open('a+')
        self.child = subprocess.Popen(self.command + ['run'], stdout=subprocess.DEVNULL,
                                      stderr=self.stderr, env=self.env)

    def stop(self, crash=False):
        if self.child is not None:
            if self.child.poll() is None:
                self.child.kill() if crash else self.child.terminate()
                try:
                    self.child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=5)
            self.child = None
        if self.stderr is not None:
            self.stderr.close()
            self.stderr = None

    def rows(self, sql, parameters=()):
        if not self.database.exists():
            return []
        with sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=2) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(sql, parameters)]

    def operations(self, kind=None):
        return self.rows('SELECT * FROM operations' + (' WHERE kind=?' if kind else '') + ' ORDER BY id',
                         (kind,) if kind else ())

    def dispatched(self, kind=None):
        return self.rows('SELECT o.*, e.dispatch_sequence FROM operations o JOIN operation_evidence e '
                         'ON e.operation_id=o.id WHERE e.dispatch_sequence IS NOT NULL'
                         + (' AND o.kind=?' if kind else '') + ' ORDER BY o.id',
                         (kind,) if kind else ())

    def model_calls(self, kind):
        calls = self.root / 'calls'
        return sum(json.loads(line)['kind'] == kind for line in calls.read_text().splitlines()) if calls.exists() else 0

    def wait(self, predicate, description, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.child is not None and self.child.poll() is not None:
                raise AssertionError('runtime exited: ' + (self.root / 'runtime.stderr').read_text())
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError(json.dumps(dict(failure=description, writes=self.writes,
                                             operations=self.operations(), status=self.status(),
                                             stderr=(self.root / 'runtime.stderr').read_text())))

    def loaded(self):
        expected_revision = self.invoke('config', 'check')['revision']
        def matches():
            status = self.status()
            runtime = status.get('effective_runtime') or {}
            return (runtime.get('revision') == expected_revision
                    and not runtime.get('reload_blocked'))
        self.wait(matches, 'effective participation policy did not reload')

    def cycles(self, count=3):
        # A negative assertion spans actual observer cycles, never a blind long sleep.
        if self.capabilities['answer'] == 'off' and self.capabilities['mine'] == 'off':
            baseline = self.status()['effective_runtime']['observed_at']
            self.wait(lambda: self.status()['effective_runtime']['observed_at'] >= baseline + count,
                      'disabled controller did not advance its heartbeat')
            return
        with self.lock:
            baseline = sum(route.endswith('/api/hosted/challenge') for route, _, _ in self.reads)
        self.wait(lambda: sum(route.endswith('/api/hosted/challenge') for route, _, _ in self.reads)
                  >= baseline + count, 'observer did not complete challenge turns')

    def no_more_writes(self, count):
        self.cycles()
        assert len(self.writes) == count, ('unexpected wallet dispatch', self.writes)
        assert len(self.dispatched()) == count, 'network and durable dispatch counts disagree'

    def rollover(self, epoch, answered=False):
        with self.lock:
            self.epoch, self.answered = epoch, answered
        self.wait(lambda: (self.status().get('observation') or {}).get('epoch') == epoch,
                  'new epoch was not observed')

    def unknown(self, kind, count=1):
        self.wait(lambda: sum(row['state'] == 'unknown' for row in self.operations(kind)) == count,
                  f'{kind} unknown count did not reach {count}')

    def risks(self):
        return self.rows('SELECT * FROM risk_admissions ORDER BY operation_id')

    def preserved(self, original):
        current = next(row for row in self.operations() if row['id'] == original['id'])
        for field in ('kind', 'work_key', 'request', 'payload', 'created_at', 'state'):
            assert current[field] == original[field], ('uncertain history changed', field, current)
        assert current['state'] == 'unknown'

    def close(self):
        self.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        lock_key = hashlib.sha256(f'{self.chain}\n{self.address}'.encode()).hexdigest()
        lock_root = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.agmi-account-locks'
        for entry in lock_root.glob(lock_key + '.*'):
            entry.unlink()


def old_judgment(fixture):
    fixture.answered = True
    fixture.assignments = True
    fixture.capabilities['judge'] = 'active'
    fixture.configure()
    fixture.start(resume=True)
    fixture.unknown('judge')
    assert len(fixture.writes) == 1 and fixture.writes[0]['route'].endswith('/grade')
    original = fixture.dispatched('judge')[0]
    assert original['job_id'] is None and original['txid'] is None
    return original


def rollover_scenario(f):
    old = old_judgment(f)
    f.rollover(11)
    f.no_more_writes(1)
    assert f.model_calls('answer') == 1, 'strict must still capture current work without dispatch'
    f.answer_response = 'delayed-conflict'
    f.apply_config({'participation': {'mode': 'participation_first', 'max_unresolved_operations': 2}})
    f.loaded()
    f.unknown('answer')
    assert len(f.writes) == 2
    assert f.executions[0]['kind'] == 'judge'
    assert f.executions[0]['request'] == f.writes[0]
    assert f.executions[0]['after_answer'] == f.writes[1]
    assert f.executions[1]['outcome'] == 'bad_nonce'
    assert f.writes[1]['received_at'] > f.writes[0]['received_at']
    f.preserved(old)
    conflict = f.dispatched('answer')[0]
    assert conflict['job_id'] == 'answer-conflict' and conflict['state'] == 'unknown'
    risks = f.risks()
    assert len(risks) == 1 and risks[0]['operation_id'] == conflict['id']
    assert old['id'] in json.loads(risks[0]['blocker_ids'])
    assert json.loads(risks[0]['policy'])['mode'] == 'participation_first'
    assert risks[0]['revision'] and risks[0]['dispatch_sequence']
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.rollover(12)
    f.no_more_writes(2)
    assert f.status()['participation']['unresolved_count'] == 2
    f.stop(crash=True)
    f.start()
    f.loaded()
    f.no_more_writes(2)
    f.preserved(old)
    assert len(f.risks()) == 1, 'restart erased or duplicated risk admission'
    f.configure(max_unresolved_operations=3)
    f.loaded()
    f.wait(lambda: any(row['state'] == 'final' and row['job_id'] == 'answer-12'
                       for row in f.operations('answer')), 'newer bound job starved behind unknown')
    assert len(f.writes) == 3
    assert any(route.endswith('/api/job/answer-12') for route, _, _ in f.reads)
    assert len(f.risks()) == 2
    assert f.status()['participation']['unresolved_count'] == 2
    f.preserved(old)
    f.configure(mode='strict')
    f.loaded()
    f.rollover(13)
    f.no_more_writes(3)
    assert f.status()['participation']['risk_admissions'] == 2
    return dict(wallet_mutations=3, delayed_old_execution=True, nonce_conflict='unknown',
                newer_bound_job='final', cap_survived_restart=True, unknown_preserved=True)


def retry_scenario(f):
    f.configure(mode='participation_first')
    f.start(resume=True)
    f.unknown('answer')
    original = f.dispatched('answer')[0]
    f.no_more_writes(1)  # Default-off means opt-in is a real behavioral switch.
    f.configure(retry_uncertain_answers=True, uncertainty_grace_seconds=3600,
                uncertain_answer_retry_seconds=3600)
    f.loaded()
    f.no_more_writes(1)
    f.configure(uncertainty_grace_seconds=1, uncertain_answer_retry_seconds=1)
    f.loaded()
    f.unknown('answer', 2)
    f.no_more_writes(2)
    attempts = f.dispatched('answer')
    assert len(attempts) == 2 and attempts[0]['id'] != attempts[1]['id']
    assert attempts[0]['payload'] == attempts[1]['payload'], 'retry changed captured payload'
    assert f.writes[0]['body'] == f.writes[1]['body'], 'retry changed wire payload'
    assert f.model_calls('answer') == 1, 'identical challenge retry invoked inference again'
    link = f.rows('SELECT * FROM operation_links WHERE operation_id=?', (attempts[1]['id'],))[0]
    assert link['retry_of'] == original['id'] and link['payload_reused'] == 1
    risk = f.risks()[0]
    assert risk['retry_of'] == original['id'] and original['id'] in json.loads(risk['blocker_ids'])
    f.preserved(original)
    f.stop(crash=True)
    f.start()
    f.loaded()
    f.no_more_writes(2)
    assert f.model_calls('answer') == 1
    assert len(f.risks()) == 1
    f.preserved(original)
    return dict(wallet_mutations=2, answer_inferences=1, retry_linked=True,
                attempt_budget_survived_restart=True, unknown_preserved=True)


def changed_epoch_scenario(f):
    f.start(resume=True)
    f.unknown('answer')
    original = f.dispatched('answer')[0]
    f.rollover(11)
    f.wait(lambda: f.model_calls('answer') == 2, 'new epoch did not prepare its own answer')
    f.no_more_writes(1)
    f.configure(mode='participation_first', retry_uncertain_answers=True,
                max_unresolved_operations=2)
    f.loaded()
    f.unknown('answer', 2)
    f.no_more_writes(2)
    current = f.dispatched('answer')[1]
    assert json.loads(original['request'])['solver']['epoch'] == 10
    assert json.loads(current['request'])['solver']['epoch'] == 11
    assert f.model_calls('answer') == 2, 'new epoch reused old inference'
    assert not f.rows('SELECT * FROM operation_links WHERE operation_id=?', (current['id'],))
    assert f.risks()[0]['retry_of'] is None, 'old epoch was relabeled as current retry'
    f.preserved(original)
    return dict(wallet_mutations=2, changed_epoch_prepared_fresh=True, old_unknown_preserved=True)


def fences_scenario(f):
    f.start(resume=True)
    f.unknown('answer')
    original = f.dispatched('answer')[0]
    f.configure(retry_uncertain_answers=True)  # Strict overrides opt-in.
    f.loaded()
    f.no_more_writes(1)
    f.configure(mode='participation_first', allow_answer=False)
    f.loaded()
    f.no_more_writes(1)
    for capability in ('read_only', 'off'):
        f.capabilities['answer'] = capability
        f.configure(mode='participation_first', allow_answer=True)
        f.loaded()
        f.no_more_writes(1)
    with f.lock:
        f.answered = True
    f.capabilities['answer'] = 'active'
    f.configure()
    f.loaded()
    f.no_more_writes(1)
    assert f.status()['epoch_evidence']['answered'] is True
    f.invoke('pause')
    with f.lock:
        f.answered = False
    f.no_more_writes(1)
    assert f.status()['paused'] is True
    f.preserved(original)
    return dict(wallet_mutations=1,
                fences=['strict', 'allow_answer', 'read_only', 'off', 'answered', 'pause'])


def inclusion_scenario(f):
    f.answer_response = 'included'
    f.configure(mode='participation_first', retry_uncertain_answers=True,
                uncertainty_grace_seconds=0, uncertain_answer_retry_seconds=0)
    f.start(resume=True)
    for state in ('included_pending', 'confirmed'):
        f.receipt_state = state
        f.wait(lambda: any(row['state'] == state for row in f.operations('answer')),
               'answer inclusion state not observed: ' + state)
        f.no_more_writes(1)
        assert f.status()['participation']['uncertainty_blocks']['answer'] is False, \
            'accepted current answer was misreported as an uncertainty blocker'
    # Confirmed operations are terminal and need not poll for finality.
    f.stop()
    f.start()
    f.no_more_writes(1)
    assert f.model_calls('answer') == 1 and not f.risks()
    return dict(wallet_mutations=1, included_and_confirmed_exclude_retry=True,
                exclusion_survived_restart=True)


def final_scenario(f):
    f.answer_response, f.receipt_state = 'included', 'final'
    f.configure(mode='participation_first', retry_uncertain_answers=True,
                uncertainty_grace_seconds=0, uncertain_answer_retry_seconds=0)
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'final' for row in f.operations('answer')),
           'final answer not observed')
    f.no_more_writes(1)
    assert not f.risks()
    return dict(wallet_mutations=1, final_excludes_retry=True)


def retry_after_scenario(f):
    f.answer_response, f.retry_after = 'backoff', 8
    f.configure(mode='participation_first', retry_uncertain_answers=True,
                uncertainty_grace_seconds=0, uncertain_answer_retry_seconds=0)
    f.start(resume=True)
    f.unknown('answer')
    original = f.dispatched('answer')[0]
    assert original['next_at'] > int(time.time()), 'server retry minimum not retained'
    f.no_more_writes(1)
    f.stop(crash=True)
    f.start()
    f.loaded()
    f.wait(lambda: len(f.writes) == 2, 'retry minimum never became eligible', seconds=20)
    assert f.writes[1]['received_at'] - f.writes[0]['received_at'] >= 7, 'server Retry-After bypassed'
    f.unknown('answer', 2)
    f.no_more_writes(2)
    assert f.model_calls('answer') == 1
    return dict(wallet_mutations=2, retry_after_seconds=8, retry_minimum_survived_restart=True)


def manual_scenario(f):
    f.preparation['max_attempts_per_work'] = 1
    old = old_judgment(f)
    f.configure(mode='manual', uncertainty_grace_seconds=3600,
                uncertain_answer_retry_seconds=3600, retry_uncertain_answers=True)
    f.loaded()
    f.rollover(11)
    f.no_more_writes(1)
    f.invoke('recover', 'authorize', '--epoch', '11', '--kind', 'answer', succeeds=False)
    f.stop()
    heartbeat = f.status()['effective_runtime']['observed_at']
    reads = len(f.reads)
    f.invoke('recover', 'authorize', '--epoch', '11', '--kind', 'judge', succeeds=False)
    revoked = f.invoke('recover', 'authorize', '--epoch', '11', '--kind', 'answer')
    f.invoke('recover', 'revoke', '--grant', str(revoked['grant_id']))
    listed = f.invoke('recover', 'grants', '--limit', '1')
    assert listed['grants'][0]['state'] == 'revoked'
    f.start()
    f.no_more_writes(1)
    f.stop()
    heartbeat = f.status()['effective_runtime']['observed_at']
    reads = len(f.reads)
    f.invoke('recover', 'authorize', '--epoch', '11', '--kind', 'answer')
    first_page = f.invoke('recover', 'grants', '--limit', '1')
    older_page = f.invoke('recover', 'grants', '--limit', '1', '--before', str(first_page['next_before']))
    assert older_page['grants'][0]['grant_id'] == revoked['grant_id']
    inspected = f.invoke('operations', 'list', '--state', 'unknown', '--limit', '1')['operations'][0]
    assert inspected['operation_id'] == old['id']
    assert not {'payload', 'request', 'result', 'job_id', 'txid'}.intersection(inspected)
    assert len(f.reads) == reads, 'risk authorization performed network I/O'
    assert f.status()['effective_runtime']['observed_at'] == heartbeat, 'grant fabricated heartbeat'
    f.start()
    f.unknown('answer')
    f.no_more_writes(2)
    assert len(f.risks()) == 1 and f.risks()[0]['manual_grant_id'] is not None
    f.preserved(old)
    f.rollover(12)
    f.no_more_writes(2)
    f.stop()
    f.invoke('recover', 'authorize', '--epoch', '12', '--kind', 'answer')
    f.invoke('pause')
    f.invoke('resume')
    f.start()
    f.loaded()
    f.no_more_writes(2)
    f.stop()
    f.invoke('recover', 'authorize', '--epoch', '12', '--kind', 'answer')
    f.start()
    f.no_more_writes(2)
    # Pause invalidated an unsent draft; a manual network grant does not also
    # authorize exceeding the independent model-generation budget.
    f.apply_config({'preparation': {'max_attempts_per_work': 2}})
    f.wait(lambda: len(f.writes) == 3, 'fresh generation manual grant did not admit answer')
    f.unknown('answer', 2)
    f.no_more_writes(3)
    assert len(f.risks()) == 2
    assert len({row['manual_grant_id'] for row in f.risks()}) == 2
    f.preserved(old)
    return dict(wallet_mutations=3, manual_grants_consumed=2, grants_one_shot=True,
                stale_generation_rejected=True, metadata_only_authorization=True)


def slow_read_scenario(f):
    f.http_seconds, f.read_http_seconds = 1, 3
    f.read_delay, f.write_delay = 1.5, 2
    f.answer_response = 'included'
    f.configure()
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'unknown' for row in f.operations('answer')),
           'slow GET did not permit dispatch with independent short POST timeout', seconds=40)
    f.wait(lambda: len(f.writes) == 1, 'timed-out POST never reached local server')
    operation = f.dispatched('answer')[0]
    assert operation['txid'] is None, 'POST improperly inherited the longer read timeout'
    assert f.status()['hosted_identity_verified'] is True
    assert f.model_calls('answer') == 1
    f.no_more_writes(1)
    return dict(wallet_mutations=1, read_http_seconds=3, http_seconds=1,
                slow_read_succeeded=True, slow_write='unknown')


def mine_epoch_scenario(f):
    f.answered = True
    f.capabilities['mine'] = 'active'
    f.configure(mode='participation_first')
    f.apply_config({'schedule': {'mine_each_epoch': True}})
    f.start(resume=True)
    f.unknown('mine')
    original = f.dispatched('mine')[0]
    f.no_more_writes(1)
    f.stop(crash=True)
    f.start()
    f.no_more_writes(1)
    f.mine_response, f.write_delay = 'completed', 1.5
    f.apply_config({'timeouts': {'http_seconds': 3, 'read_http_seconds': 1}})
    with f.lock:
        f.epoch, f.answered = 11, True
    f.wait(lambda: any(row['state'] == 'completed' for row in f.operations('mine')),
           'new epoch mine did not use its independent write deadline')
    f.no_more_writes(2)
    f.preserved(original)
    f.apply_config({'schedule': {'mine_each_epoch': False}})
    with f.lock:
        f.epoch, f.answered = 12, True
    f.wait(lambda: len(f.dispatched('mine')) == 3, 'interval mining did not start its cadence')
    f.no_more_writes(3)
    with f.lock:
        f.epoch, f.answered = 13, True
    f.no_more_writes(3)
    f.apply_config({'schedule': {'mine_each_epoch': True}})
    f.wait(lambda: len(f.dispatched('mine')) == 4, 'per-epoch mining did not reload')
    f.no_more_writes(4)
    assert [write['epoch'] for write in f.writes] == [10, 11, 12, 13]
    assert f.model_calls('answer') == 0 and f.model_calls('judge') == 0
    assert len(f.risks()) == 3
    f.preserved(original)
    return dict(wallet_mutations=4, one_mine_per_epoch=True, cadence_hot_reloaded=True,
                effectful_get_uses_write_timeout=True, old_unknown_preserved=True)


def local_retry_scenario(f):
    f.retry_seconds = 3600
    f.policy.update(mode='participation_first', uncertainty_grace_seconds=0)
    original = old_judgment(f)
    minimum = f.rows('SELECT retry_not_before FROM operation_timing WHERE operation_id=?', (original['id'],))[0]
    assert minimum['retry_not_before'] <= time.time(), 'local cadence became a server-minimum fence'
    f.stop(crash=True)
    f.start()
    f.rollover(11)
    f.unknown('answer')
    f.no_more_writes(2)
    f.apply_config({'participation': {'mode': 'manual'}})
    f.rollover(12)
    f.no_more_writes(2)
    f.stop()
    f.invoke('recover', 'authorize', '--epoch', '12', '--kind', 'answer')
    f.start()
    f.wait(lambda: len(f.dispatched('answer')) == 2, 'manual grant inherited local retry cadence')
    f.no_more_writes(3)
    f.preserved(original)
    return dict(wallet_mutations=3, local_retry_seconds=3600,
                zero_grace_and_manual_unblocked=True, restart_preserved_server_minimum_separation=True)


SCENARIOS = dict(rollover=rollover_scenario, retry=retry_scenario, fences=fences_scenario,
                 inclusion=inclusion_scenario, final=final_scenario,
                 retry_after=retry_after_scenario, manual=manual_scenario,
                 slow_read=slow_read_scenario, changed_epoch=changed_epoch_scenario,
                 mine_epoch=mine_epoch_scenario, local_retry=local_retry_scenario)


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
        with tempfile.TemporaryDirectory(prefix='agmi-participation-') as directory:
            fixture = Fixture(binary, pathlib.Path(directory))
            try:
                result = scenario(fixture)
                print(json.dumps(dict(scenario=name, **result)), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
