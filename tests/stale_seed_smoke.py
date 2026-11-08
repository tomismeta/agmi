#!/usr/bin/env python3
"""Exercise bound stale-seed rejection and bounded regeneration with the real CLI."""
import argparse
import json
import pathlib
import tempfile
import sqlite3
import time

from participation_smoke import Fixture


class StaleFixture(Fixture):
    def __init__(self, binary, root):
        self.with_nonce = True
        self.always_stale = False
        self.hold_job = False
        super().__init__(binary, root)
        self.answer_response = 'bound'
        self.receipt_state = 'confirmed'

    def handler(self):
        parent = super().handler()
        fixture = self

        class Upstream(parent):
            def do_GET(self):
                if '/api/job/' in self.path and (len(fixture.writes) == 1 or fixture.always_stale):
                    if fixture.hold_job:
                        self.reply(200, {'state': 'queued'})
                        return
                    body = {'state': 'done', 'error': 'stale_seed'}
                    if fixture.with_nonce:
                        body['next_nonce'] = fixture.nonce + 1
                    self.reply(400, body)
                    return
                if self.path.split('?')[0].endswith('/api/hosted/challenge') and fixture.writes:
                    with fixture.lock:
                        fixture.reads.append((self.path.split('?')[0], fixture.epoch, time.monotonic()))
                    self.reply(200, {'epoch': fixture.epoch, 'answered': False,
                                    'words': ['clock', 'bridge', 'units'],
                                    'min_chars': 120, 'max_chars': 600})
                    return
                super().do_GET()

        return Upstream


def exercise(f, scenario):
    f.with_nonce = scenario != 'missing_nonce'
    f.always_stale = scenario == 'budget'
    if scenario == 'legacy_budget':
        f.hold_job = True
        f.policy['max_answer_attempts_per_epoch'] = 1
        f.configure()
    f.start(resume=True)
    if scenario == 'legacy_budget':
        f.wait(lambda: any(o['state'] == 'queued' for o in f.operations('answer')),
               'bound legacy fixture did not queue')
        f.stop()
        with sqlite3.connect(f.database) as db:
            db.execute('UPDATE operation_evidence SET dispatch_sequence=NULL')
            db.execute('DELETE FROM events')
        f.hold_job = False
        f.start()
        f.wait(lambda: any(o['state'] == 'stale' for o in f.operations('answer')),
               'bound legacy rejection did not reconcile')
        f.cycles()
        assert len(f.writes) == 1, 'legacy terminal answer escaped the epoch dispatch budget'
        assert len(f.dispatched()) == 0, 'fixture unexpectedly acquired a legacy dispatch witness'
    elif scenario == 'missing_nonce':
        f.wait(lambda: any(o['state'] == 'unknown' for o in f.operations('answer')),
               'missing nonce incorrectly resolved uncertainty')
        f.no_more_writes(1)
    elif scenario == 'budget':
        f.wait(lambda: len(f.writes) == 2, 'terminal stale rejection stranded the epoch')
        f.wait(lambda: sum(o['state'] == 'stale' for o in f.operations('answer')) == 2,
               'second stale rejection missing')
        f.stop()
        f.start()
        f.no_more_writes(2)
    else:
        f.wait(lambda: any(o['state'] == 'confirmed' for o in f.operations('answer')),
               'terminal stale rejection prevented a fresh answer', seconds=15)
        assert len(f.writes) == 2 and f.model_calls('answer') == 2
        assert any(o['state'] == 'stale' for o in f.operations('answer'))
    return {'scenario': scenario, 'writes': len(f.writes), 'model_calls': f.model_calls('answer')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    scenarios = ['fresh_answer', 'missing_nonce', 'budget', 'legacy_budget']
    parser.add_argument('--scenario', choices=['all', *scenarios], default='all')
    args = parser.parse_args()
    for scenario in (scenarios if args.scenario == 'all' else [args.scenario]):
        with tempfile.TemporaryDirectory(prefix='agmi-stale-seed-') as directory:
            fixture = StaleFixture(args.binary.resolve(), pathlib.Path(directory))
            try:
                print(json.dumps(exercise(fixture, scenario)), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
