#!/usr/bin/env python3
"""Real-CLI queued polling and health acceptance; localhost and dummy credentials only."""
import argparse
import json
import pathlib
import sqlite3
import tempfile
import time

from participation_smoke import Fixture


class QueuedFixture(Fixture):
    def __init__(self, binary, root):
        self.job_polls = []
        self.pending_polls = 2
        self.job_minimum = None
        self.expire_jobs = False
        super().__init__(binary, root)
        self.answer_response = 'bound'
        self.receipt_state = 'confirmed'
        self.retry_seconds = 30
        self.configure()

    def handler(self):
        parent = super().handler()
        fixture = self

        class Upstream(parent):
            def do_GET(self):
                if '/api/job/' in self.path:
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


def fast_polling(f):
    f.apply_config({'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}})
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
    f.apply_config({'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}})
    f.start(resume=True)
    f.wait(lambda: len(f.job_polls) == 1, 'first bound job poll missing')
    f.wait(lambda: f.operations('answer')[0]['next_at'] >= int(time.time()) + 5,
           'server retry floor was not recorded')
    before = f.invoke('operations', 'list', '--limit', '1')['operations'][0]['wait']
    assert before['queued_since'] is not None and before['queued_age_seconds'] >= 1
    f.stop()
    f.apply_config({'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 2}}})
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
    f.capabilities = dict(answer='read_only', judge='active', mine='off')
    f.assignments = True
    f.answered = True
    f.configure()
    f.start(resume=True)
    f.wait(lambda: any(o['state'] == 'unknown' for o in f.operations('judge')),
           'lost judgment response did not preserve unknown')
    health = json.loads(f.invoke('health', succeeds=False).stdout)['data']
    assert health['operational']['status'] == 'blocked', health
    assert health['risk']['attention_required'] and not health['healthy']
    f.apply_config({'participation': {'mode': 'participation_first',
                                      'allow_judge': True, 'uncertainty_grace_seconds': 0}})
    f.wait(lambda: not f.status()['admission_blocked'], 'configured admission did not reopen')
    health = f.invoke('health')
    assert health['operational']['status'] == 'clear', health
    assert health['risk']['attention_required'] and health['attention_required']
    assert health['healthy'] and not health['issues']
    assert 'pending_outcome_uncertain' in health['warnings']
    disk = json.loads(f.invoke('health', '--min-free-mib', '999999999', succeeds=False).stdout)['data']
    assert disk['operational']['status'] == 'degraded', disk
    assert 'state_disk_space_low' in disk['operational']['issues']
    assert len(f.writes) == 1 and f.operations('judge')[0]['state'] == 'unknown'
    f.stop()
    # Isolated journal fixture: a later overdue effect must not disappear behind
    # the original unknown. The stopped controller cannot race these timestamps.
    old = f.operations('judge')[0]['id']
    with sqlite3.connect(f.database) as db:
        later = db.execute(
            "INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at) "
            "SELECT kind,work_key||'-later','queued',request,generation,revision,1,1 "
            "FROM operations WHERE id=?", (old,)).lastrowid
    for state, issue in [('queued', 'pending_work_overdue'),
                         ('included_pending', 'pending_work_overdue'),
                         ('dispatching', 'dispatch_outcome_uncertain')]:
        with sqlite3.connect(f.database) as db:
            db.execute("UPDATE operations SET state=? WHERE id=?", (state, later))
        overdue = json.loads(f.invoke('health', succeeds=False).stdout)['data']
        assert issue in overdue['issues'], overdue
        assert 'pending_outcome_uncertain' in overdue['warnings']
    assert len(f.writes) == 1
    return {'strict_block_visible': True, 'risk_retained_after_admission_opens': True,
            'healthy_with_warnings_exits_zero': True,
            'later_overdue_work_detected': True,
            'disk_failure_still_operational': True, 'writes': 1}


def policy_administration(f):
    before = f.config.read_bytes()
    for policy in ({'initial_seconds': 1}, {'initial_seconds': 1, 'max_seconds': 4, 'unknown': 1}):
        revision = f.invoke('config', 'show')['file_revision']
        result = f.invoke('config', 'apply', '--expected-revision', revision, succeeds=False,
                          stdin=json.dumps({'schedule': {'queued_job_polling': policy}}))
        assert json.loads(result.stderr)['error']['code'] == 'admin_validation'
        assert f.config.read_bytes() == before, 'invalid policy patch changed the configuration'
    f.apply_config({'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}})
    f.apply_config({'schedule': {'queued_job_polling': {'max_seconds': 8}}})
    enabled = f.invoke('config', 'show')['config']['schedule']['queued_job_polling']
    assert enabled == {'initial_seconds': 1, 'max_seconds': 8}
    f.apply_config({'schedule': {'queued_job_polling': None}})
    assert f.invoke('config', 'show')['config']['schedule'].get('queued_job_polling') is None
    assert not f.writes and not f.database.exists()
    return {'enable_partial_update_disable': True, 'invalid_patch_nonmutating': True,
            'no_state_initialization_or_network_writes': True}


def due_backlog(f):
    f.pending_polls = 100
    f.configure(mode='participation_first', uncertainty_grace_seconds=0,
                retry_uncertain_answers=True, uncertain_answer_retry_seconds=0,
                max_answer_attempts_per_epoch=1, max_unresolved_operations=8)
    f.apply_config({'schedule': {'queued_job_polling': {'initial_seconds': 60, 'max_seconds': 60}}})
    f.start(resume=True)
    for count in range(1, 4):
        f.wait(lambda: len(f.writes) == count and
               sum(o['state'] == 'queued' for o in f.operations('answer')) == count,
               'could not prepare three independent queued epochs')
        if count < 3:
            with f.lock:
                f.epoch += 1
    f.stop()
    f.apply_config({'schedule': {'poll_seconds': 30}, 'capabilities': {'answer': 'off'}})
    # Isolated fixture only: model three deadlines becoming due together,
    # without changing payloads, bindings, server minima or transition evidence.
    with sqlite3.connect(f.database) as db:
        db.execute("UPDATE operations SET next_at=0 WHERE state='queued'")
    before = len(f.job_polls)
    f.start()
    f.wait(lambda: len(f.job_polls) >= before + 3,
           'third actionable queued job slept behind the ordinary poll interval', seconds=5)
    assert len(f.writes) == 3 and f.model_calls('answer') == 3
    return {'three_due_jobs_drained': True, 'ordinary_poll_seconds': 30,
            'writes_unchanged': 3}


def independent_scope(f):
    f.pending_polls = 100
    f.retry_seconds = 1
    f.configure(mode='participation_first', uncertainty_grace_seconds=0,
                max_unresolved_operations=8)
    f.apply_config({'schedule': {'queued_job_polling': {'initial_seconds': 60, 'max_seconds': 60}}})
    f.start(resume=True)
    for count in range(1, 4):
        expected = 'included_pending' if count == 3 else 'queued'
        f.wait(lambda: len(f.writes) == count and
               any(o['state'] == expected and o['work_key'].startswith(str(f.epoch) + ':')
                   for o in f.operations('answer')), 'bound fixture work did not settle locally')
        if count < 3:
            with f.lock:
                if count == 2:
                    f.answer_response = 'included'
                    f.receipt_state = 'included_pending'
                f.epoch += 1
    f.stop()
    f.apply_config({'capabilities': {'answer': 'off'}})
    receipt_deadline = f.rows("SELECT next_at FROM read_backoff WHERE scope='receipt'")
    if receipt_deadline:
        f.wait(lambda: int(time.time()) >= receipt_deadline[0]['next_at'],
               'fixture receipt scope is not yet eligible', seconds=3)
    floor = int(time.time()) + 60
    # Isolated deadline setup only: preserve actual queued/included payloads
    # and evidence, but make two Job rows due behind their endpoint floor.
    with sqlite3.connect(f.database) as db:
        db.execute("UPDATE operations SET next_at=0 WHERE state IN ('queued','included_pending')")
        db.execute("INSERT OR REPLACE INTO read_backoff(scope,failures,next_at) VALUES ('job',1,?)", (floor,))
        db.execute("INSERT INTO read_observations(scope,server_not_before) VALUES ('job',?) "
                   "ON CONFLICT(scope) DO UPDATE SET server_not_before=excluded.server_not_before", (floor,))
    f.receipt_state = 'final'
    before = len(f.job_polls)
    f.start()
    f.wait(lambda: any(o['state'] == 'final' for o in f.operations('answer')),
           'Job endpoint floor starved an eligible Receipt poll', seconds=5)
    assert len(f.job_polls) == before
    assert sum(o['state'] == 'queued' for o in f.operations('answer')) == 2
    assert len(f.writes) == 3
    return dict(receipt_finalized_behind_two_blocked_jobs=True, blocked_jobs_not_polled=True,
                writes_unchanged=3)


def retry_age(f):
    f.expire_jobs = True
    f.apply_config({'schedule': {'queued_job_polling': {'initial_seconds': 1, 'max_seconds': 4}}})
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
             'due_backlog': due_backlog, 'independent_scope': independent_scope, 'retry_age': retry_age}


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
