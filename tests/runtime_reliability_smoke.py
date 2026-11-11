#!/usr/bin/env python3
"""Runtime reliability regressions against a real CLI and local synthetic transport.

Usage: python3 tests/runtime_reliability_smoke.py target/debug/agmi --scenario NAME
The fake native interpreter exercises runtime supervision, not the Hermes bridge.
No real credentials, public network, or fixture journal writes are used.
"""
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

from participation_smoke import Fixture


BAD = 'a' * 64
GOOD = 'c' * 64


def assignment(identifier, expiry):
    return dict(answer_txid=identifier, answer_epoch=9,
                answer='A clock on the bridge delays each claim.',
                words=['clock', 'bridge'], author_prior=[],
                pending_meta=dict(expires_at_epoch=expiry))


class RuntimeFixture(Fixture):
    def __init__(self, binary, root):
        self.inventory = None
        self.partial = False
        self.page_failure = False
        self.write_behavior = None
        self.write_started = threading.Event()
        self.urgent_started = threading.Event()
        self.write_release = threading.Event()
        self.read_release = threading.Event()
        self.headers_sent = threading.Event()
        self.hold_inventory = False
        self.inventory_started = threading.Event()
        self.inventory_release = threading.Event()
        self.hold_evidence = False
        self.evidence_started = threading.Event()
        self.evidence_release = threading.Event()
        self.hydrated_words = None
        self.errors = []
        super().__init__(binary, root)

    def handler(self):
        base = super().handler()
        fixture = self

        class Upstream(base):
            def do_GET(self):
                route = urlsplit(self.path).path
                if route.endswith('/api/hosted/assignments') and fixture.inventory is not None:
                    with fixture.lock:
                        fixture.reads.append((route, fixture.epoch, time.monotonic()))
                    offset = int(parse_qs(urlsplit(self.path).query).get('offset', ['0'])[0])
                    if fixture.hold_inventory:
                        fixture.inventory_started.set()
                        if not fixture.inventory_release.wait(15):
                            fixture.errors.append('inventory gate expired')
                    if offset and fixture.page_failure:
                        self.reply(503, {'error': 'fixture page unavailable'}, 60)
                    else:
                        self.reply(200, dict(assignments=fixture.inventory,
                                            has_more=fixture.partial, offset=offset))
                    return
                if route.endswith('/api/explorer/tx/' + BAD):
                    if fixture.hold_evidence:
                        fixture.evidence_started.set()
                        if not fixture.evidence_release.wait(15):
                            fixture.errors.append('evidence gate expired')
                    body = {'type': 'challenge', 'epoch': 9,
                            'answer': 'A clock on the bridge delays each claim.'}
                    if fixture.hydrated_words is not None:
                        body['words'] = fixture.hydrated_words
                    self.reply(200, {'id': BAD, 'body': body})
                    return
                if route.endswith('/api/hosted/challenge') and fixture.write_started.is_set() and fixture.write_behavior == 'capture':
                    fixture.urgent_started.set()
                    if not fixture.read_release.wait(20):
                        fixture.errors.append('urgent read gate expired')
                    # The runtime may already have cancelled this socket.
                    self.reply(503, {'error': 'fixture delayed read'}, 60)
                    return
                if '/api/job/ready-job' in route:
                    self.reply(200, {'state': 'queued', 'job_id': 'ready-job'})
                    return
                super().do_GET()

            def do_POST(self):
                if fixture.write_behavior is None:
                    super().do_POST()
                    return
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                with fixture.lock:
                    fixture.writes.append(dict(route=self.path, body=body, epoch=fixture.epoch,
                                               received_at=time.monotonic(), nonce=fixture.nonce))
                fixture.write_started.set()
                if fixture.write_behavior == 'floor':
                    self.send_response(503)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', '100')
                    self.send_header('Retry-After', '60')
                    self.end_headers()
                    self.wfile.flush()
                    fixture.headers_sent.set()
                    fixture.write_release.wait(20)
                    self.close_connection = True
                elif fixture.write_behavior == 'capture':
                    if not fixture.write_release.wait(12):
                        fixture.errors.append('write gate expired')
                    self.reply(202, {'state': 'queued', 'job_id': 'ready-job'})

        return Upstream

    def close(self):
        self.write_release.set()
        self.read_release.set()
        self.inventory_release.set()
        self.evidence_release.set()
        super().close()


def missing_words(f, hydrated=False, empty=False):
    bad = assignment(BAD, 20)
    if empty:
        bad['words'] = []
    else:
        del bad['words']
    if hydrated:
        del bad['answer_epoch']
    f.inventory = [bad, assignment(GOOD, 1000)]
    f.lanes['answer']['mode'] = 'off'
    f.lanes['judge']['mode'] = 'active'
    f.lanes['mine']['mode'] = 'off'
    f.configure()
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'abstained' and row['work_key'] == BAD
                       for row in f.operations('judge')),
           'missing original words were not durably abstained', seconds=8)
    f.wait(lambda: any(row['work_key'] == GOOD for row in f.dispatched('judge')),
           'unjudgeable first assignment starved the usable second assignment', seconds=8)
    bad_rows = [row for row in f.operations('judge') if row['work_key'] == BAD]
    assert len(bad_rows) == 1 and bad_rows[0]['state'] == 'abstained', bad_rows
    assert len(f.dispatched('judge')) == 1 and f.model_calls('judge') == 1
    assert all(write['body']['assignment'] == GOOD for write in f.writes)
    assert not any(row['owner'] == 'judge' and row['purpose'] in ('discovery', 'assignment') and row['failures']
                   for row in f.rows('SELECT * FROM read_state WHERE retired=0'))
    return dict(abstained=BAD, submitted=GOOD, model_calls=1, hydrated=hydrated)


def write_floor(f):
    f.write_behavior = 'floor'
    f.lanes['answer']['timeouts']['http_seconds'] = 1
    f.configure('answer', mode='participation_first', uncertainty_grace_seconds=0)
    f.start(resume=True)
    f.wait(f.headers_sent.is_set, 'server headers were not sent')
    assert not f.restrictions(), 'unassembled headers provisionally published shared authority'
    f.unknown('answer')
    original = f.dispatched('answer')[0]
    restriction = next(row for row in f.restrictions()
                       if row['scope'] == 'account_authenticated' and row['basis'] == 'server_retry_after')
    timing = restriction['not_before']
    assert timing >= original['created_at'] + 60, ('received Retry-After floor was lost', restriction)
    f.epoch = 11
    f.no_more_writes(1)
    admission = f.status()['work']['answer']['admission']
    assert admission['reason'] == 'shared_server_restriction' and admission['not_before'] == timing, admission
    assert f.status()['observations']['answer']['epoch'] == 10
    assert len(f.operations('answer')) == 1, 'shared floor permitted fresh authenticated discovery'
    f.preserved(original)
    return dict(retained_retry_not_before=timing, writes=len(f.writes), old_unknown_preserved=True)


def write_capture(f, stop=False):
    f.write_behavior = 'capture'
    f.lanes['answer']['timeouts']['http_seconds'] = 8
    f.lanes['answer']['timeouts']['read_http_seconds'] = 15
    f.configure()
    f.start(resume=True)
    f.wait(f.urgent_started.is_set, 'urgent challenge did not overlap the write', seconds=6)
    started = time.monotonic()
    f.write_release.set()
    f.wait(lambda: any(row['job_id'] == 'ready-job' for row in f.operations()),
           'completed write waited for the unrelated urgent read', seconds=2)
    assert not f.read_release.is_set()
    if stop:
        f.stop()
    else:
        result = subprocess.run(f.command + ['pause'], capture_output=True, text=True,
                                timeout=2, env=f.env)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert f.status()['paused']
        f.stop()
    assert time.monotonic() - started < 5
    assert len(f.writes) == len(f.dispatched()) == 1
    assert not any(row['in_flight'] for row in f.rows('SELECT * FROM read_state WHERE retired=0'))
    assert not f.errors, f.errors
    return dict(job_id='ready-job', capture_before_read_release=True,
                admission_released=True, stop=stop, writes=1)


def stop_pending_write(f):
    f.write_behavior = 'capture'
    f.lanes['answer']['timeouts']['http_seconds'] = 8
    f.lanes['answer']['timeouts']['read_http_seconds'] = 15
    f.configure()
    f.apply_config({'runtime': {'shutdown_seconds': 5}})
    f.start(resume=True)
    f.wait(f.urgent_started.is_set, 'urgent challenge did not overlap pending write', seconds=6)
    original = f.dispatched('answer')[0]
    assert original['state'] == 'dispatching' and not f.write_release.is_set()
    f.child.terminate()
    f.wait(lambda: not any(row['in_flight'] for row in
                          f.rows("SELECT * FROM read_state WHERE owner='answer' AND purpose='discovery' AND resource='challenge' AND retired=0")),
           'stop did not finish the urgent read while the write remained pending', seconds=2)
    assert f.child.poll() is None, 'stop abandoned the pending write before its drain deadline'
    pending = next(row for row in f.operations('answer') if row['id'] == original['id'])
    assert pending['state'] == 'dispatching' and pending['job_id'] is None, pending
    assert not f.read_release.is_set() and not f.write_release.is_set()
    f.write_release.set()
    f.child.wait(timeout=5)
    assert f.child.returncode == 0
    assert any(row['id'] == original['id'] and row['job_id'] == 'ready-job'
               for row in f.operations('answer'))
    assert not any(row['in_flight'] for row in f.rows('SELECT * FROM read_state WHERE retired=0'))
    assert len(f.dispatched()) == len(f.writes) == 1
    assert not f.errors, f.errors
    f.stop()
    return dict(job_id='ready-job', stopped_with_write_pending=True, writes=1)


def model_timeout(f, inference=False):
    f.lanes['answer']['timeouts']['model_seconds'] = 1
    if inference:
        interpreter = f.root / 'fixture-python'
        text = interpreter.read_text().replace("artifact =", "import time\ntime.sleep(5)\nartifact =", 1)
        interpreter.write_text(text)
    else:
        f.native.write_text(f'#!{sys.executable}\nimport time\ntime.sleep(5)\n')
    f.configure()
    f.start(resume=True)
    expected = 'model_unknown' if inference else 'prelaunch_failed'
    f.wait(lambda: any(row['state'] != 'generating' for row in f.operations('answer')),
           'model deadline was not bounded', seconds=6)
    row = f.operations('answer')[0]
    assert row['state'] == expected, ('runtime erased solver timeout classification', row)
    assert f.model_calls('answer') == int(inference)
    assert not f.writes
    return dict(state=expected, inference_started=inference)


def inventory_selection(f, partial=False, page_failure=False):
    f.lanes['answer']['mode'] = 'off'
    f.lanes['judge']['mode'] = 'active'
    f.lanes['mine']['mode'] = 'off'
    f.inventory = [assignment(BAD, 20)] if partial else []
    f.lanes['judge']['excluded_assignments'] = [BAD]
    f.partial, f.page_failure = partial, page_failure
    f.configure()
    f.start(resume=True)
    f.wait(lambda: (f.status()['work']['judge'].get('assessment') or {}).get('locally_judgeable') is False,
           'judge did not publish bounded observed-inventory evidence', seconds=8)
    assessment = f.status()['work']['judge']['assessment']
    assert assessment['locally_judgeable'] is False
    assert assessment['completeness'] == ('bounded_partial' if partial else 'complete')
    assert assessment['observed_opportunities'] == int(partial)
    if page_failure:
        read = next(row for row in f.status()['reads'] if row['owner'] == 'judge' and row['purpose'] == 'discovery' and row['resource'] == 'assignments')
        restriction = next(row for row in f.restrictions()
                           if row['scope'] == 'account_authenticated' and row['basis'] == 'server_retry_after')
        floor = restriction['not_before']
        assert floor >= int(time.time()) + 50
        assert f.status()['work']['judge']['admission']['not_before'] >= floor
        assert read['server_not_before'] == 0
    f.stop()
    assert f.status()['work']['judge']['assessment'] == assessment
    assert f.status()['lane_participation']['judge']['freshness'] == 'stopped'
    assert not f.writes and not f.operations('judge') and not f.model_calls('judge')
    return dict(shared_retry_floor=page_failure, assessment=assessment, persisted_after_stop=True)


def inventory_generation(f):
    f.lanes['answer']['mode'] = 'off'
    f.lanes['judge']['mode'] = 'active'
    f.lanes['mine']['mode'] = 'off'
    f.inventory = []
    f.hold_inventory = True
    f.lanes['judge']['timeouts']['read_http_seconds'] = 15
    f.configure()
    f.apply_config({'capabilities': {'judge': {'schedule': {'poll_seconds': 30}}}})
    f.start(resume=True)
    f.wait(f.inventory_started.is_set, 'inventory request did not start')
    old_generation = f.status()['generation']
    f.invoke('pause')
    f.invoke('resume')
    assert f.status()['generation'] > old_generation
    f.inventory_release.set()
    f.wait(lambda: not any(row['in_flight'] for row in
                          f.rows("SELECT * FROM read_state WHERE owner='judge' AND purpose='discovery' AND resource='assignments' AND retired=0")),
           'inventory response did not finish')
    f.stop()
    assert f.status()['work']['judge']['assessment'] is None
    assert not f.writes and not f.model_calls('judge')
    return dict(pre_pause_inventory_discarded=True, writes=0)


def unjudgeable_selection(f):
    f.lanes['answer']['mode'] = 'off'
    f.lanes['judge']['mode'] = 'active'
    f.lanes['mine']['mode'] = 'off'
    bad = assignment(BAD, 20)
    bad['words'] = []
    f.inventory = [bad]
    f.configure()
    f.apply_config({'capabilities': {'judge': {'schedule': {'poll_seconds': 30}}}})
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'abstained' for row in f.operations('judge')),
           'unjudgeable seat was not abstained')
    work = f.status()['work']['judge']
    f.stop()
    assert work['assessment']['locally_judgeable'] is False, work
    assert not f.writes and not f.model_calls('judge')
    return dict(unjudgeable_not_eligible=True, model_calls=0)


def hydration_policy(f, pause=False, usable=False):
    f.lanes['answer']['mode'] = 'off'
    f.lanes['judge']['mode'] = 'active'
    f.lanes['mine']['mode'] = 'off'
    bad = assignment(BAD, 20)
    del bad['words']
    del bad['answer_epoch']
    f.inventory = [bad]
    f.hold_evidence = True
    if usable:
        f.hydrated_words = ['clock', 'bridge']
    f.lanes['judge']['timeouts']['read_http_seconds'] = 15
    f.configure()
    f.start(resume=True)
    f.wait(f.evidence_started.is_set, 'hydration did not start')
    if pause:
        f.invoke('pause')
        f.invoke('resume')
    else:
        f.apply_config({'capabilities': {'judge': {'excluded_assignments': [BAD]}}})
        f.loaded()
    f.evidence_release.set()
    if pause:
        f.wait(lambda: not any(row['in_flight'] for row in
                              f.rows("SELECT * FROM read_state WHERE owner='judge' AND purpose='assignment' AND retired=0")),
               'hydration did not finish')
    else:
        f.wait(lambda: (f.status()['work']['judge'].get('assessment') or {}).get('locally_judgeable') is False,
               'post-hydration assessment did not finish')
    f.stop()
    assert not f.operations('judge') and not f.model_calls('judge')
    f.hydrated_words = ['clock', 'bridge']
    f.apply_config({'capabilities': {'judge': {'excluded_assignments': []}}})
    f.start()
    f.wait(lambda: len(f.dispatched('judge')) == 1,
           'fresh eligible evidence remained poisoned by an old abstention')
    assert f.dispatched('judge')[0]['work_key'] == BAD
    assert f.model_calls('judge') == 1
    return dict(pause=pause, usable=usable, stale_attempts=0, fresh_judgment_submitted=True)


def oldest_diagnostic(f):
    f.answered = True
    f.assignments = True
    f.lanes['judge']['mode'] = 'active'
    f.lanes['judge']['participation'].update(mode='participation_first', uncertainty_grace_seconds=0)
    f.configure('answer', mode='participation_first', uncertainty_grace_seconds=0)
    f.start(resume=True)
    f.unknown('judge')
    old = f.dispatched('judge')[0]
    f.wait(lambda: int(time.time()) >= old['created_at'] + 9, 'old uncertainty did not age')
    f.configure('answer', uncertainty_grace_seconds=8)
    f.loaded()
    f.rollover(11)
    f.unknown('answer')
    recent = f.dispatched('answer')[0]
    f.rollover(12)
    f.wait(lambda: f.status()['work']['answer']['reason'] == 'account_uncertainty_grace',
           'recent uncertainty did not fence prepared current work', seconds=6)
    status = f.status()
    assert status['oldest_unresolved_operation'] == old['id']
    assert status['oldest_unresolved_since'] < recent['created_at']
    assert status['work']['answer']['next_at'] >= recent['created_at'] + 8
    assert status['admission_blocked']
    health = subprocess.run(f.command + ['health', '--min-free-mib', '0'],
                            capture_output=True, text=True, timeout=3, env=f.env)
    health = json.loads(health.stdout)['data']
    assert health['oldest_unresolved_operation'] == old['id']
    assert health['oldest_unresolved_since'] == status['oldest_unresolved_since']
    for value in (status, health):
        assert not any(key in value for key in ('blocking_operation', 'blocked_since', 'blocked_age_seconds'))
    return dict(oldest_operation=old['id'], recent_operation=recent['id'],
                reason=status['work']['answer']['reason'])


SCENARIOS = {
    'missing-words': lambda f: missing_words(f),
    'empty-words': lambda f: missing_words(f, empty=True),
    'hydrated-missing-words': lambda f: missing_words(f, hydrated=True),
    'write-floor': write_floor,
    'write-capture': write_capture,
    'write-capture-stop': lambda f: write_capture(f, stop=True),
    'stop-pending-write': stop_pending_write,
    'discovery-timeout': lambda f: model_timeout(f),
    'inference-timeout': lambda f: model_timeout(f, inference=True),
    'empty-inventory': inventory_selection,
    'partial-inventory': lambda f: inventory_selection(f, partial=True),
    'page-floor': lambda f: inventory_selection(f, partial=True, page_failure=True),
    'inventory-generation': inventory_generation,
    'unjudgeable-selection': unjudgeable_selection,
    'hydration-exclusion': hydration_policy,
    'hydration-generation': lambda f: hydration_policy(f, pause=True),
    'hydration-excluded-usable': lambda f: hydration_policy(f, usable=True),
    'oldest-diagnostic': oldest_diagnostic,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--scenario', choices=SCENARIOS)
    args = parser.parse_args()
    binary = args.binary.resolve()
    scenarios = [args.scenario] if args.scenario else SCENARIOS
    for name in scenarios:
        with tempfile.TemporaryDirectory(prefix='agmi-runtime-') as directory:
            fixture = RuntimeFixture(binary, pathlib.Path(directory))
            try:
                evidence = SCENARIOS[name](fixture)
                print(json.dumps(dict(scenario=name, **evidence)), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
