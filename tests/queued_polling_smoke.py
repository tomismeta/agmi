#!/usr/bin/env python3
"""Real-CLI queued polling and health acceptance; localhost and dummy credentials only."""
import argparse
import hashlib
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


class TransientJudgingFixture(QueuedFixture):
    def __init__(self, binary, root):
        self.lost_job = 'grade-10'
        self.lost_job_reads = []
        self.remaining_404s = 2
        self.queued_floor_sent = False
        self.recovery_release = threading.Event()
        super().__init__(binary, root)

    def handler(self):
        parent = super().handler()
        fixture = self

        class Upstream(parent):
            def do_POST(self):
                if self.path.endswith('/api/hosted/grade'):
                    # Publish one assignment at a time, with no discovery race.
                    with fixture.lock:
                        fixture.assignments = False
                        super().do_POST()
                    return
                super().do_POST()

            def do_GET(self):
                if self.path.endswith('/api/job/' + fixture.lost_job):
                    with fixture.lock:
                        fixture.lost_job_reads.append(time.time())
                        if fixture.remaining_404s:
                            fixture.remaining_404s -= 1
                            self.reply(404, {'error': 'unknown job'})
                            return
                        queued_floor = not fixture.queued_floor_sent
                        fixture.queued_floor_sent = True
                    if queued_floor:
                        fixture.recovery_release.wait(20)
                        # Only a valid queued response establishes a resource
                        # minimum; Retry-After on a 404 is account-scoped.
                        self.reply(202, {'state': 'queued'}, 12)
                        return
                super().do_GET()

        return Upstream

    def close(self):
        self.recovery_release.set()
        super().close()


def transient_job_loss(f):
    f.pending_polls = 0
    f.queued_grades, f.assignments = True, True
    f.receipt_state = 'final'
    f.lanes['answer']['mode'] = 'off'
    f.lanes['judge']['mode'] = 'active'
    f.lanes['judge']['timeouts']['read_http_seconds'] = 15
    f.lanes['judge']['schedule'].update(
        retry_seconds=1, backoff_max_seconds=4,
        queued_job_polling=dict(initial_seconds=1, max_seconds=1))
    f.configure('judge', mode='participation_first',
                max_unresolved_operations='unbounded', uncertainty_grace_seconds=3600)
    f.start(resume=True)

    def lost_read():
        rows = f.rows("SELECT * FROM read_state WHERE owner='judge' AND purpose='job' "
                      "AND operation_id=? AND retired=0", (original['id'],))
        return rows[0] if rows else None

    f.wait(lambda: len(f.dispatched('judge')) == 1, 'judgment A was not dispatched')
    original = f.dispatched('judge')[0]
    f.wait(lambda: lost_read() is not None and lost_read()['failures'] == 2,
           'two transient 404s were not retained')
    before = lost_read()
    assert before['status'] == 404 and before['local_next_at'] > time.time(), before
    original = f.dispatched('judge')[0]
    assert original['state'] == 'unknown' and original['job_id'] == f.lost_job
    assert original['txid'] is None and len(f.lost_job_reads) == 2

    with f.lock:
        f.assignments = True
    f.wait(lambda: len(f.dispatched('judge')) == 2 and f.dispatched('judge')[1]['job_id'],
           'retained uncertainty or grace blocked distinct judgment B')
    second = f.dispatched('judge')[1]
    assert second['work_key'] != original['work_key']
    assert f.dispatched('judge')[0]['state'] == 'unknown'
    assert len(f.writes) == 2 and f.model_calls('judge') == 2
    f.recovery_release.set()
    f.wait(lambda: lost_read()['status'] == 202
           and lost_read()['server_not_before'] > time.time(),
           'valid queued response did not retain its resource minimum')
    before = lost_read()
    assert len(f.lost_job_reads) == 3
    f.stop()
    # Match a current-format journal created by the previous binary. The new
    # writer must provision its access paths, not require fresh initialization.
    with sqlite3.connect(f.database) as db:
        db.executescript("""
            DROP INDEX operations_reconciliation;
            DROP INDEX operations_model_key;
            DROP INDEX operations_model_retry_recent;
            DROP INDEX operations_model_retry_fair;
        """)

    # Observe real binary clocks and persisted floors, without rewriting time,
    # deadlines, binding evidence, or runtime state in the isolated journal.
    stopped = lost_read()
    floors = ('local_next_at', 'server_not_before', 'retained_conservative_floor')
    assert {key: stopped[key] for key in floors} == {key: before[key] for key in floors}
    services = f.rows("SELECT kind,next_at FROM schedule WHERE kind IN "
                      "('reconciliation:judge','reconciliation:fair:judge',"
                      "'reconciliation:missing:judge')")
    eligible_at = max(*(stopped[key] for key in floors),
                      *(row['next_at'] for row in services))
    assert time.time() < stopped['server_not_before'], 'fixture missed the restart fence window'
    for job in (original['job_id'], second['job_id']):
        f.jobs[job] = 'final'
    started_at = time.monotonic()
    f.start()

    # Two bound jobs: allow a complete recent/fair/missing service rotation,
    # followed by their receipts, after the retained effective floor.
    service_rotation = 4 * (f.lanes['judge']['schedule']['backoff_max_seconds'] + 1)
    window = max(0, eligible_at - time.time()) + service_rotation + 4
    f.wait(lambda: all(op['state'] == 'final' for op in f.dispatched('judge'))
           and len(f.dispatched('judge')) == 2,
           'matching evidence did not reconcile both original bindings', seconds=window)
    f.stop()
    final = f.dispatched('judge')
    assert len(f.writes) == 2 and f.model_calls('judge') == 2
    assert len(f.lost_job_reads) == 4
    assert f.lost_job_reads[3] >= eligible_at, 'restart refunded a retained polling floor'
    for old, current in zip((original, second), final):
        for field in ('id', 'work_key', 'payload', 'request', 'result', 'dispatch_sequence'):
            assert current[field] == old[field], (field, old, current)
        assert current['txid'] == hashlib.sha256(old['job_id'].encode()).hexdigest()
        assert f.rows("SELECT retired FROM read_state WHERE owner='judge' AND purpose='job' "
                      "AND operation_id=? AND binding_revision=?",
                      (old['id'], old['binding_revision'])) == [{'retired': 1}]
    return dict(fresh_judgment_during_uncertainty=True, cold_restart=True,
                server_floor_preserved=True, matching_jobs_reconciled=True,
                original_submissions=2, model_calls=2,
                recovery_seconds=round(time.monotonic() - started_at, 3))


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
    f.lanes['judge']['timeouts']['model_seconds'] = 30
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
    same_work = json.loads(f.invoke('health', succeeds=False).stdout)['data']
    assert same_work['operational']['status'] == 'blocked', same_work
    assert 'current_work_outcome_unresolved' in same_work['issues']
    assert same_work['risk']['attention_required'] and not same_work['healthy']
    original = f.operations('judge')[0]
    assert len(f.writes) == 1 and original['state'] == 'unknown'

    # Publish a genuinely different assignment, holding its actual native
    # execution so diagnostics observe a stable, viable path before dispatch.
    interpreter = f.root / 'fixture-python'
    source = interpreter.read_text()
    marker = 'artifact = {'
    assert source.count(marker) == 1
    interpreter.write_text(source.replace(marker,
        "import time\n"
        "while pathlib.Path(__file__).with_name('hold-judge-model').exists():\n"
        "    time.sleep(0.05)\n" + marker, 1))
    hold = f.root / 'hold-judge-model'
    hold.touch()
    try:
        f.queued_grades = True
        f.wait(lambda: f.model_calls('judge') == 2
               and len(f.rows("SELECT o.id FROM operations o JOIN operation_evidence e "
                              "ON e.operation_id=o.id WHERE o.kind='judge' "
                              "AND o.state='generating' AND e.model_deadline IS NOT NULL")) == 1,
               'distinct judgment did not begin genuine native execution')
        later = f.operations('judge')[-1]
        assert later['work_key'] != original['work_key']
        health = f.invoke('health')
        assert health['operational']['status'] == 'clear', health
        assert health['risk']['attention_required'] and health['attention_required']
        assert health['healthy'] and not health['issues']
        assert 'pending_outcome_uncertain' in health['warnings']
        assert health['work']['judge']['progress'] == 'working'
        disk = json.loads(f.invoke('health', '--min-free-mib', '999999999', succeeds=False).stdout)['data']
        assert disk['operational']['status'] == 'degraded', disk
        assert 'state_disk_space_low' in disk['operational']['issues']
        assert len(f.writes) == 1 and f.operations('judge')[0]['state'] == 'unknown'

        # Crash with the genuine attempt in flight, then age only its deadline.
        # Queued/accepted remote history is risk, not an overdue local execution.
        f.stop(crash=True)
        with sqlite3.connect(f.database) as db:
            db.execute('UPDATE operation_evidence SET model_deadline=1 WHERE operation_id=?',
                       (later['id'],))
        overdue = json.loads(f.invoke('health', succeeds=False).stdout)['data']
        assert 'model_work_overdue' in overdue['issues'], overdue
        assert 'pending_outcome_uncertain' in overdue['warnings']
        assert overdue['work']['judge']['intervention']['status'] == 'undetermined'
        assert len(f.writes) == 1 and f.operations('judge')[0]['state'] == 'unknown'
    finally:
        hold.unlink(missing_ok=True)
    return {'strict_block_visible': True, 'same_work_stays_blocked': True,
            'risk_retained_with_distinct_work': True, 'healthy_with_warnings_exits_zero': True,
            'later_overdue_model_detected': True, 'disk_failure_still_operational': True, 'writes': 1}


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
    # Recovery now has an aggregate two-slot cadence, independent of discovery.
    # Request a short service interval rather than expecting a 60-second budget
    # to drain an arbitrary batch immediately.
    f.apply_config({'capabilities': {'answer': {'mode': 'off', 'schedule': {
        'poll_seconds': 30, 'queued_job_polling': {'initial_seconds': 2, 'max_seconds': 60}}}}})
    # Isolated fixture only: model three deadlines becoming due together,
    # without changing payloads, bindings, server minima or transition evidence.
    with sqlite3.connect(f.database) as db:
        db.execute("UPDATE operations SET next_at=0 WHERE state='queued'")
        db.execute("UPDATE read_state SET local_next_at=0 WHERE owner='answer' AND purpose='job' AND retired=0")
    before = len(f.job_polls)
    requests_before = len(f.job_requests)
    f.start()
    f.wait(lambda: {job for job, _ in f.job_requests[requests_before:]} ==
           {'answer-10', 'answer-11', 'answer-12'},
           'paced recovery failed to serve all three due jobs ahead of discovery', seconds=8)
    assert len(f.job_polls) >= before + 3
    assert len(f.writes) == 3 and f.model_calls('answer') == 3
    return {'three_due_jobs_served': True, 'ordinary_poll_seconds': 30,
            'recovery_service_seconds': 2, 'writes_unchanged': 3}


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
             'slow_bad_jobs': slow_bad_jobs, 'retry_age': retry_age,
             'transient_job_loss': transient_job_loss}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--scenario', choices=['all', *SCENARIOS], default='all')
    args = parser.parse_args()
    scenarios = SCENARIOS if args.scenario == 'all' else {args.scenario: SCENARIOS[args.scenario]}
    for name, scenario in scenarios.items():
        with tempfile.TemporaryDirectory(prefix='agmi-queued-polling-') as directory:
            fixture_type = TransientJudgingFixture if name == 'transient_job_loss' else QueuedFixture
            fixture = fixture_type(args.binary.resolve(), pathlib.Path(directory))
            try:
                print(json.dumps({'scenario': name, **scenario(fixture)}), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
