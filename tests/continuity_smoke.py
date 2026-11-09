#!/usr/bin/env python3
"""Actual-CLI continuity and targeted-read scenarios; loopback/synthetic identity only."""
import argparse
import json
import pathlib
import tempfile
import time
import urllib.parse

from work_first_smoke import WorkFixture, STALL_SECONDS


class ContinuityFixture(WorkFixture):
    def __init__(self, *args):
        self.unneeded_pages = 0
        self.judge_dispatches = []
        self.targeted_inventory = False
        super().__init__(*args)

    def handler(self):
        base = super().handler()
        f = self

        class Upstream(base):
            def do_POST(self):
                if self.path.split('?')[0].endswith('/hosted/grade'):
                    f.judge_dispatches.append((time.monotonic(), f.unneeded_pages))
                super().do_POST()

            def do_GET(self):
                route = self.path.split('?')[0]
                if f.targeted_inventory and route.endswith('/hosted/assignments'):
                    offset = int(urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                                 .get('offset', ['0'])[0])
                    if offset:
                        f.unneeded_pages += 1
                        f.closing.wait(STALL_SECONDS)
                        self.reply(503, {'error': 'unrelated page unavailable'}, 30)
                        return
                    self.reply(200, {'assignments': [{
                        'answer_txid': 'a' * 64, 'answer_epoch': 9,
                        'answer': 'A clock on the bridge enforces a delay before each claim.',
                        'words': ['clock', 'bridge'], 'author_prior': [],
                        'pending_meta': {'expires_at_epoch': 1000},
                    }], 'has_more': f.model_calls('judge') > 0})
                    return
                super().do_GET()
        return Upstream


def targeted_judgment(f):
    f.capabilities.update(answer='off', judge='active', mine='off')
    f.targeted_inventory = True
    f.configure(mode='participation_first', allow_judge=True)
    f.start(resume=True)
    f.wait(lambda: f.model_calls('judge') == 1, 'judge model did not start')
    captured = next(json.loads(line)['started_at'] for line in
                    (f.root / 'calls').read_text().splitlines()
                    if json.loads(line)['kind'] == 'judge')
    f.wait(lambda: bool(f.judge_dispatches), 'prepared grade stalled on unrelated inventory',
           seconds=STALL_SECONDS - 1)
    assert f.judge_dispatches[0][1] == 0, 'targeted freshness fetched unrelated pages before dispatch'
    assert f.model_calls('judge') == 1
    return dict(model_start_to_dispatch_seconds=round(f.judge_dispatches[0][0] - captured, 3),
                unrelated_pages=0, single_inference=True)


def identity_rollover(f):
    f.read_http_seconds = 15
    f.stall_scope = 'identity'
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.configure(mode='participation_first')
    f.start(resume=True)
    assert f.stall_entered.wait(5), 'identity request did not start'
    started = time.monotonic()
    f.rollover(11)
    f.wait(lambda: (f.status().get('observation') or {}).get('epoch') == 11,
           'identity read blocked epoch observation', seconds=3)
    elapsed = time.monotonic() - started
    assert not f.dispatched(), 'write occurred before identity verification'
    with f.lock:
        f.stall_scope = None
    f.wait(lambda: any(row['state'] == 'final' for row in f.operations('answer')),
           'answer did not progress after identity recovery', seconds=25)
    assert all(json.loads(row['request'])['solver']['epoch'] == 11 for row in f.dispatched('answer'))
    return dict(epoch_observation_seconds=round(elapsed, 3), identity_required=True,
                current_epoch_answer_final=True)


def historical_continuity(f):
    f.configure(mode='participation_first')
    f.start(resume=True)
    f.unknown('answer')
    original = f.dispatched('answer')[0]
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.apply_config({'participation': {'retry_uncertain_answers': True}})
    f.wait(lambda: any(row['state'] == 'final' for row in f.operations('answer')),
           'linked retry never reached inclusion')
    f.apply_config({'participation': {
        'max_unresolved_operations': 1, 'max_historical_unknown_answers': 1}})
    f.stop(crash=True)
    f.challenge_fault = 'timeout'
    with f.lock:
        f.epoch, f.answered = 11, False
    f.start()
    f.wait(lambda: (f.read_record('challenge') or {}).get('failures', 0) > 0,
           'outage was not observed')
    assert len(f.dispatched('answer')) == 2, 'stale observations admitted a new answer'
    f.preserved(original)
    f.challenge_fault = None
    f.wait(lambda: any(row['state'] == 'final' and
                       json.loads(row['request'])['solver']['epoch'] == 11
                       for row in f.operations('answer')),
           'next epoch blocked by qualifying historical uncertainty', seconds=30)
    next_answer = f.dispatched('answer')[-1]
    # Inspect the immutable journal through the fixture's read-only connection.
    historical = f.rows('SELECT operation_id,accepted_answer_id FROM risk_historical_answers '
                        'WHERE dispatch_sequence=?', (next_answer['dispatch_sequence'],))
    assert historical[0]['operation_id'] == original['id'], historical
    assert f.status()['participation']['historical_unknown_answer_count'] == 1
    f.preserved(original)
    return dict(lost_reply=True, linked_retry_included=True, cold_restart=True,
                outage_recovered=True, next_epoch_included=True,
                original_still_unknown=True, risk_witness_retained=bool(historical))


def accepted_linked_continuity(f):
    """Eight real lost replies plus accepted direct retries, not synthetic journal rows."""
    policy = dict(mode='participation_first', max_unresolved_operations=2,
                  max_historical_unknown_answers=2)
    baseline = getattr(f, 'bounded_baseline', False)
    if not baseline:
        policy['historical_unknown_answer_capacity'] = 'accepted_linked'
    f.configure(**policy)
    f.receipt_state = 'final'
    f.start(resume=True)
    originals = []
    for index in range(8):
        epoch = 10 + index
        if index:
            f.answer_response = 'lost'
            f.rollover(epoch)
        f.unknown('answer', index + 1)
        original = f.dispatched('answer')[-1]
        originals.append(original)
        f.answer_response = 'bound'
        f.apply_config({'participation': {'retry_uncertain_answers': True}})
        f.wait(lambda: any(row['state'] == 'final' and
                           json.loads(row['request'])['solver']['epoch'] == epoch
                           for row in f.operations('answer')),
               f'accepted retry failed at epoch {epoch}')
        f.apply_config({'participation': {'retry_uncertain_answers': False}})
        risk = f.status()['participation']
        assert risk['unresolved_count'] == index + 1, risk
        assert risk['active_unresolved_count'] == 0, ('historical capacity ratchet', epoch, risk)
        assert risk['historical_unknown_answer_count'] == index + 1, risk
        if not baseline:
            assert risk['historical_eligible_count'] == index + 1, risk
            assert risk['capacity_exempt_count'] == index + 1, risk
        for original in originals:
            f.preserved(original)
        if index == 2:
            f.stop(crash=True)
            f.start()
            f.loaded()

    # Tightening is immediate; accumulated uncertainty is never evicted to fit.
    f.apply_config({'participation': {'historical_unknown_answer_capacity': 'bounded',
                                      'max_unresolved_operations': 1}})
    risk = f.status()['participation']
    assert (risk['historical_eligible_count'], risk['capacity_exempt_count'],
            risk['active_unresolved_count']) == (8, 2, 6), risk
    f.answer_response = 'lost'
    f.rollover(18)
    f.no_more_writes(16)
    f.apply_config({'participation': {'historical_unknown_answer_capacity': 'accepted_linked'}})
    f.unknown('answer', 9)
    originals.append(f.dispatched('answer')[-1])
    f.answer_response = 'bound'
    f.apply_config({'participation': {'retry_uncertain_answers': True}})
    f.no_more_writes(17)  # One active original plus prospective retry exceeds cap one.
    f.apply_config({'participation': {'max_unresolved_operations': 2}})
    f.wait(lambda: any(row['state'] == 'final' and
                       json.loads(row['request'])['solver']['epoch'] == 18
                       for row in f.operations('answer')), 'capacity restoration did not admit retry')
    f.apply_config({'participation': {'retry_uncertain_answers': False}})
    # A final fresh dispatch captures the ninth witness without copying its predecessors.
    f.rollover(19)
    f.wait(lambda: any(row['state'] == 'final' and
                       json.loads(row['request'])['solver']['epoch'] == 19
                       for row in f.operations('answer')), 'fresh epoch did not continue')
    for original in originals:
        f.preserved(original)
    events = f.rows('SELECT * FROM historical_answer_accounting_events ORDER BY revision')
    snapshots = f.rows('SELECT * FROM risk_accounting_snapshots ORDER BY dispatch_sequence')
    assert len(events) == 9 and len(snapshots) == 18, (events, snapshots)
    assert not f.rows('SELECT * FROM risk_historical_answers'), 'historical evidence copied per admission'
    admissions = f.risks()
    assert sum(len(json.loads(row['blocker_ids'])) for row in admissions) == 9, admissions
    assert snapshots[-1]['exempt_count'] == 9 and snapshots[-1]['unresolved_count'] == 9
    inspected = f.invoke('recover', 'inspect', '--operation', str(f.dispatched('answer')[-1]['id']))
    # The public CLI inspection must reconstruct the captured revision, not current eligibility.
    captured = inspected['risk_admissions'][0]
    assert captured['accounting']['witness_revision'] == events[-1]['revision'], captured
    assert captured['historical_unknown_answer_count'] == 9, captured
    assert len(captured['historical_unknown_answers']) == 9, captured
    return dict(retried_epochs=9, third_and_later_epochs_continue=True, cold_restart=True,
                hot_reload=True, capacity_reduction_enforced=True, original_unknowns=9,
                active_capacity=0, witness_rows=9, admission_snapshots=18,
                copied_historical_rows=0, captured_active_blocker_ids=9)


def accepted_linked_unlinked_and_floor(f):
    f.answer_response, f.retry_after = 'backoff', 3600
    f.configure(mode='participation_first', historical_unknown_answer_capacity='accepted_linked',
                max_unresolved_operations=2, retry_uncertain_answers=True,
                uncertainty_grace_seconds=0, uncertain_answer_retry_seconds=0)
    f.start(resume=True)
    f.unknown('answer')
    original = f.dispatched('answer')[0]
    floor = f.rows('SELECT retry_not_before FROM operation_timing WHERE operation_id=?',
                   (original['id'],))[0]['retry_not_before']
    assert floor >= int(time.time()) + 3590, floor
    f.stop(crash=True)
    f.start()
    f.loaded()
    f.apply_config({'participation': {'max_historical_unknown_answers': 100,
                                      'max_unresolved_operations': 8}})
    f.answer_response = 'bound'
    f.no_more_writes(1)
    f.rollover(11)
    f.no_more_writes(1)
    risk = f.status()['participation']
    assert (risk['unresolved_count'], risk['historical_eligible_count'],
            risk['capacity_exempt_count'], risk['active_unresolved_count']) == (1, 0, 0, 1), risk
    f.preserved(original)
    assert f.rows('SELECT retry_not_before FROM operation_timing WHERE operation_id=?',
                  (original['id'],))[0]['retry_not_before'] == floor
    return dict(unlinked_unknown_charged=True, server_floor_seconds=3600,
                floor_preserved_across_restart_reload_rollover=True, wallet_mutations=1)


SCENARIOS = {'targeted_judgment': targeted_judgment, 'identity_rollover': identity_rollover,
             'historical_continuity': historical_continuity,
             'accepted_linked_continuity': accepted_linked_continuity,
             'accepted_linked_unlinked_and_floor': accepted_linked_unlinked_and_floor}



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--scenario', choices=['all', *SCENARIOS], default='all')
    parser.add_argument('--bounded-baseline', action='store_true',
                        help='Exercise the same continuity expectation with the old bounded policy.')
    args = parser.parse_args()
    scenarios = SCENARIOS if args.scenario == 'all' else {args.scenario: SCENARIOS[args.scenario]}
    for name, scenario in scenarios.items():
        with tempfile.TemporaryDirectory(prefix='agmi-continuity-') as directory:
            fixture = ContinuityFixture(args.binary.resolve(), pathlib.Path(directory))
            fixture.bounded_baseline = args.bounded_baseline
            try:
                print(json.dumps(dict(scenario=name, status='passed', **scenario(fixture))), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
