#!/usr/bin/env python3
"""Real-CLI queued polling and health acceptance; localhost and dummy credentials only."""
import argparse
import json
import pathlib
import sqlite3
import tempfile
import threading
import time

from participation_smoke import Fixture


class QueuedFixture(Fixture):
    def __init__(self, binary, root):
        self.job_polls = []
        self.pending_polls = 2
        self.job_minimum = None
        self.expire_jobs = False
        self.job_requests = []
        self.slow_job = None
        self.bad_job = None
        self.slow_started = threading.Event()
        self.slow_release = threading.Event()
        super().__init__(binary, root)
        self.answer_response = 'bound'
        self.receipt_state = 'confirmed'
        self.lanes['answer']['schedule']['retry_seconds'] = 30
        self.configure()

    def handler(self):
        parent = super().handler()
        fixture = self

        class Upstream(parent):
            def do_GET(self):
                if '/api/job/' in self.path:
                    job = self.path.split('?')[0].rsplit('/', 1)[1]
                    with fixture.lock:
                        fixture.job_requests.append((job, time.monotonic()))
                    if job == fixture.slow_job:
                        fixture.slow_started.set()
                        fixture.slow_release.wait(15)
                    if job == fixture.bad_job:
                        self.reply(404, {'error': 'unknown job'})
                        return
                    with fixture.lock:
                        fixture.job_polls.append(time.monotonic())
                        pending = len(fixture.job_polls) <= fixture.pending_polls
                    if fixture.expire_jobs:
                        self.reply(408, {'state': 'expired', 'error': 'job_expired'})
                        return
                    if pending:
                        self.reply(202, {'state': 'queued'}, fixture.job_minimum)
                        return
                super().do_GET()

        return Upstream

    def close(self):
        self.slow_release.set()
        super().close()


def fast_polling(f):
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}}}})
    f.start(resume=True)
    f.wait(lambda: len(f.job_polls) >= 3, 'bounded queued polls did not progress', seconds=20)
    first = f.job_polls[0] - f.writes[0]['received_at']
    intervals = [b - a for a, b in zip(f.job_polls, f.job_polls[1:])]
    assert first < 4, ('accepted job skipped the initial polling window', first)
    assert all(1 <= gap < 8 for gap in intervals), intervals
    f.wait(lambda: any(o['state'] == 'confirmed' for o in f.operations('answer')),
           'bound result did not reach receipt confirmation')
    assert len(f.writes) == 1 and f.model_calls('answer') == 1
    return {'first_poll_seconds': round(first, 3),
            'poll_intervals_seconds': [round(v, 3) for v in intervals],
            'confirmed': True, 'writes': 1, 'model_calls': 1}


def retained_floor(f):
    f.pending_polls = 1
    f.job_minimum = 7
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}}}})
    f.start(resume=True)
    f.wait(lambda: len(f.job_polls) == 1, 'first bound job poll missing')
    f.wait(lambda: any(row['owner'] == 'answer' and row['purpose'] == 'job'
                       and row['server_not_before'] >= int(time.time()) + 5
                       for row in f.invoke('reads')['reads']), 'server retry floor was not recorded')
    before = f.invoke('operations', 'list', '--limit', '1')['operations'][0]['wait']
    assert before['queued_since'] is not None and before['queued_age_seconds'] >= 1
    f.stop()
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 2}}}}})
    f.start()
    after = f.invoke('operations', 'list', '--limit', '1')['operations'][0]['wait']
    assert after['queued_since'] == before['queued_since'], 'restart reset the queued phase age'
    assert after['queued_age_seconds'] >= before['queued_age_seconds']
    f.wait(lambda: len(f.job_polls) >= 2, 'retained floor never reopened', seconds=20)
    gap = f.job_polls[1] - f.job_polls[0]
    assert gap >= 7, ('restart or smaller cap shortened Retry-After', gap)
    f.wait(lambda: any(o['state'] == 'confirmed' for o in f.operations('answer')),
           'restarted queued operation did not confirm')
    assert len(f.writes) == 1 and f.model_calls('answer') == 1
    return {'server_minimum_seconds': 7, 'actual_poll_gap_seconds': round(gap, 3),
            'restart_and_policy_change_preserved_floor': True,
            'cli_queued_age_preserved': True, 'writes': 1}


def risk_health(f):
    # Match the pilots: an old lost judgment, not permission to retry an answer.
    f.lanes['answer']['mode'] = 'read_only'
    f.lanes['judge']['mode'] = 'active'
    f.lanes['mine']['mode'] = 'off'
    f.assignments = True
    f.answered = True
    f.configure()
    f.start(resume=True)
    f.wait(lambda: any(o['state'] == 'unknown' for o in f.operations('judge')),
           'lost judgment response did not preserve unknown')
    health = json.loads(f.invoke('health', succeeds=False).stdout)['data']
    assert health['operational']['status'] == 'blocked', health
    assert health['risk']['attention_required'] and not health['healthy']
    f.apply_config({'capabilities': {'judge': {'participation': {'mode': 'participation_first',
                                      'uncertainty_grace_seconds': 0, 'max_unresolved_operations': 2}}}})
    f.wait(lambda: f.status()['work']['judge']['admission']['allowed'],
           'configured judge admission did not reopen')
    def judge_inventory_assessed():
        assessment = f.status()['work']['judge']['assessment'] or {}
        return (assessment.get('completeness') == 'complete'
                and assessment.get('locally_judgeable') is False)
    f.wait(judge_inventory_assessed,
           'judge did not assess retained inventory under the reloaded policy')
    health = f.invoke('health')
    assert health['operational']['status'] == 'clear', health
    assert health['risk']['attention_required'] and health['attention_required']
    assert health['healthy'] and not health['issues']
    assert 'pending_outcome_uncertain' in health['warnings']
    disk = json.loads(f.invoke('health', '--min-free-mib', '999999999', succeeds=False).stdout)['data']
    assert disk['operational']['status'] == 'degraded', disk
    assert 'state_disk_space_low' in disk['operational']['issues']
    assert len(f.writes) == 1 and f.operations('judge')[0]['state'] == 'unknown'
    # Create later work through the real dispatch boundary, retaining its binding
    # and intent witness. Only its clock is aged while the controller is stopped.
    f.queued_grades = True
    f.wait(lambda: any(o['state'] == 'queued' for o in f.operations('judge')),
           'later genuine queued judgment was not captured')
    f.assignments = False
    f.stop()
    later = next(o['id'] for o in f.operations('judge') if o['state'] == 'queued')
    for state in ('queued', 'included_pending'):
        if state == 'included_pending':
            for job in f.jobs:
                f.jobs[job] = 'final'
            f.receipt_state = 'included_pending'
            f.start()
            f.wait(lambda: any(o['id'] == later and o['state'] == state for o in f.operations('judge')),
                   'later queued judgment never reached genuine receipt evidence')
            f.stop()
        with sqlite3.connect(f.database) as db:
            db.execute('UPDATE operations SET created_at=1,updated_at=1 WHERE id=?', (later,))
            db.execute('UPDATE operation_evidence SET blocked_since=1 WHERE operation_id=?', (later,))
            db.execute('UPDATE events SET at=1 WHERE operation_id=?', (later,))
        overdue = json.loads(f.invoke('health', succeeds=False).stdout)['data']
        assert 'pending_work_overdue' in overdue['issues'], overdue
        assert 'pending_outcome_uncertain' in overdue['warnings']
    assert len(f.writes) == 2 and f.operations('judge')[0]['state'] == 'unknown'
    return {'strict_block_visible': True, 'risk_retained_after_admission_opens': True,
            'healthy_with_warnings_exits_zero': True, 'later_overdue_work_detected': True,
            'disk_failure_still_operational': True, 'writes': 2}


def policy_administration(f):
    before = f.config.read_bytes()
    for policy in ({'initial_seconds': 1}, {'initial_seconds': 1, 'max_seconds': 4, 'unknown': 1}):
        revision = f.invoke('config', 'show')['file_revision']
        result = f.invoke('config', 'apply', '--expected-revision', revision, succeeds=False,
                          stdin=json.dumps({'capabilities': {'answer': {'schedule': {'queued_job_polling': policy}}}}))
        assert json.loads(result.stderr)['error']['code'] == 'admin_validation'
        assert f.config.read_bytes() == before, 'invalid policy patch changed the configuration'
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}}}})
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': {'max_seconds': 8}}}}})
    enabled = f.invoke('config', 'show')['config']['capabilities']['answer']['schedule']['queued_job_polling']
    assert enabled == {'initial_seconds': 1, 'max_seconds': 8}
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': None}}}})
    assert f.invoke('config', 'show')['config']['capabilities']['answer']['schedule'].get('queued_job_polling') is None
    assert not f.writes and not f.database.exists()
    return {'enable_partial_update_disable': True, 'invalid_patch_nonmutating': True,
            'no_state_initialization_or_network_writes': True}


def due_backlog(f):
    f.pending_polls = 100
    f.configure('answer', mode='participation_first', uncertainty_grace_seconds=0,
                retry_uncertain_answers=True, uncertain_answer_retry_seconds=0,
                max_answer_attempts_per_epoch=1, max_unresolved_operations=8)
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': {'initial_seconds': 60, 'max_seconds': 60}}}}})
    f.start(resume=True)
    for count in range(1, 4):
        f.wait(lambda: len(f.writes) == count and
               sum(o['state'] == 'queued' for o in f.operations('answer')) == count,
               'could not prepare three independent queued epochs')
        if count < 3:
            with f.lock:
                f.epoch += 1
    f.stop()
    f.apply_config({'capabilities': {'answer': {'mode': 'off', 'schedule': {'poll_seconds': 30}}}})
    # Isolated fixture only: model three deadlines becoming due together,
    # without changing payloads, bindings, server minima or transition evidence.
    with sqlite3.connect(f.database) as db:
        db.execute("UPDATE operations SET next_at=0 WHERE state='queued'")
        db.execute("UPDATE read_state SET local_next_at=0 WHERE owner='answer' AND purpose='job' AND retired=0")
    before = len(f.job_polls)
    f.start()
    f.wait(lambda: len(f.job_polls) >= before + 3,
           'third actionable queued job slept behind the ordinary poll interval', seconds=5)
    assert len(f.writes) == 3 and f.model_calls('answer') == 3
    return {'three_due_jobs_drained': True, 'ordinary_poll_seconds': 30,
            'writes_unchanged': 3}


def independent_scope(f):
    f.pending_polls = 100
    f.job_minimum = 60
    f.lanes['answer']['schedule']['retry_seconds'] = 1
    f.configure('answer', mode='participation_first', uncertainty_grace_seconds=0,
                max_unresolved_operations=8)
    f.apply_config({'capabilities': {'answer': {'schedule': {
        'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 1}}}}})
    f.start(resume=True)
    for epoch in (10, 11):
        if epoch != 10:
            f.rollover(epoch)
        def current_epoch_job_restricted():
            current_ids = {op['id'] for op in f.dispatched('answer')
                           if json.loads(op['request'])['solver']['epoch'] == epoch}
            return any(row['owner'] == 'answer' and row['purpose'] == 'job'
                       and row['server_not_before'] > time.time() + 50
                       and row['operation_id'] in current_ids
                       for row in f.invoke('reads')['reads'])
        f.wait(current_epoch_job_restricted,
               'valid queued202 did not retain its own job minimum')
    f.answer_response = 'included'
    f.receipt_state = 'included_pending'
    f.rollover(12)
    f.wait(lambda: any(o['state'] == 'included_pending' for o in f.operations('answer')),
           'job resource floors blocked fresh answer dispatch')
    before = len(f.job_polls)
    f.receipt_state = 'final'
    f.wait(lambda: any(o['state'] == 'final' for o in f.operations('answer')),
           'two job resource floors starved an eligible receipt', seconds=5)
    assert len(f.job_polls) == before
    assert sum(o['state'] == 'queued' for o in f.operations('answer')) == 2
    assert len(f.writes) == 3
    return dict(receipt_finalized_behind_two_blocked_jobs=True, blocked_jobs_not_polled=True,
                genuine_resource_minima=True, writes_unchanged=3)


def slow_bad_jobs(f):
    f.pending_polls = 0
    f.slow_job, f.bad_job = 'answer-10', 'grade-10'
    f.queued_grades, f.assignments = True, True
    f.mine_response, f.receipt_state = 'completed', 'final'
    f.lanes['answer']['timeouts']['read_http_seconds'] = 15
    f.lanes['answer']['schedule']['retry_seconds'] = 1
    for lane in ('answer', 'judge', 'mine'):
        f.lanes[lane]['mode'] = 'active'
        f.lanes[lane]['participation'].update(mode='participation_first',
            uncertainty_grace_seconds=0, max_unresolved_operations=1 if lane == 'judge' else 4)
        f.lanes[lane]['schedule']['queued_job_polling'] = dict(initial_seconds=1, max_seconds=1)
    f.lanes['mine']['schedule']['each_epoch'] = True
    f.configure()
    f.start(resume=True)
    f.wait(f.slow_started.is_set, 'slow answer job was not reached')
    f.unknown('judge')
    bad = f.dispatched('judge')[0]
    assert bad['job_id'] == 'grade-10' and bad['state'] == 'unknown'
    f.rollover(11)
    f.wait(lambda: any(o['job_id'] == 'answer-11' and o['state'] == 'final'
                       for o in f.operations('answer')),
           'slow and bad jobs starved another resource on the same endpoint', seconds=5)
    f.wait(lambda: sum(o['state'] == 'completed' for o in f.operations('mine')) == 2,
           'slow and bad jobs starved independent mining', seconds=5)
    assert not f.slow_release.is_set()
    assert next(o for o in f.operations('answer') if o['job_id'] == 'answer-10')['state'] == 'queued'
    f.preserved(bad)
    f.slow_release.set()
    f.wait(lambda: any(o['job_id'] == 'answer-10' and o['state'] == 'final'
                       for o in f.operations('answer')), 'slow job completion was discarded')
    assert len(f.dispatched('answer')) == 2 and len(f.dispatched('judge')) == 1
    f.preserved(bad)
    return dict(slow_resource_retained=True, other_resource_finalized=True,
                bad_job_404_still_unknown=True, mine_progressed=True)


def retry_age(f):
    f.expire_jobs = True
    f.apply_config({'capabilities': {'answer': {'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}}}})
    f.start(resume=True)
    f.wait(lambda: any(o['state'] == 'retry' for o in f.operations('answer')),
           'authoritative job expiry did not retain retryable work')
    operation = f.invoke('operations', 'list', '--limit', '1')['operations'][0]
    assert operation['wait']['unsent_since_capture_seconds'] is None, (
        'sent/queued time was mislabeled as unsent', operation['wait'])
    assert len(f.writes) == 1 and f.model_calls('answer') == 1
    return {'expired_sent_work_not_labeled_unsent': True, 'writes': 1}


SCENARIOS = {'fast_polling': fast_polling, 'retained_floor': retained_floor,
             'risk_health': risk_health, 'policy_administration': policy_administration,
             'due_backlog': due_backlog, 'independent_scope': independent_scope,
             'slow_bad_jobs': slow_bad_jobs, 'retry_age': retry_age}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--scenario', choices=['all', *SCENARIOS], default='all')
    args = parser.parse_args()
    scenarios = SCENARIOS if args.scenario == 'all' else {args.scenario: SCENARIOS[args.scenario]}
    for name, scenario in scenarios.items():
        with tempfile.TemporaryDirectory(prefix='agmi-queued-polling-') as directory:
            fixture = QueuedFixture(args.binary.resolve(), pathlib.Path(directory))
            try:
                print(json.dumps({'scenario': name, **scenario(fixture)}), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
