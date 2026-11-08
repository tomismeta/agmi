#!/usr/bin/env python3
"""Actual-CLI endpoint acceptance using private stdlib-only hosted fixtures.

Usage: python3 tests/endpoints_smoke.py target/debug/agmi [--scenario NAME]
No public service, registration, real credentials, or journal mutations.
"""
import argparse
import json
import pathlib
import tempfile
import time
import urllib.parse

from participation_smoke import OUTSTANDING, TXID, old_judgment
from work_first_smoke import WorkFixture


# Deliberately invert path-based authentication heuristics: hosted operations use
# public-looking paths; unauthenticated evidence uses hosted-looking paths.
ROUTES = {
    'identity': '/public/who',
    'challenge': '/public/question',
    'answer': '/public/submit',
    'mine': '/public/readiness',
    'assignments': '/public/tasks',
    'grade': '/public/evaluate',
    'job': '/api/hosted/results/{id}',
    'receipt': '/api/hosted/proofs/{id}',
}
CANONICAL = {
    'identity': '/api/hosted/me',
    'challenge': '/api/hosted/challenge',
    'answer': '/api/hosted/answer',
    'mine': '/api/hosted/mine',
    'assignments': '/api/hosted/assignments',
    'grade': '/api/hosted/grade',
    'job': '/api/job/{id}',
    'receipt': '/api/receipt/{id}',
}
AUTHENTICATED = {'identity', 'challenge', 'answer', 'mine', 'assignments', 'grade'}


class EndpointFixture(WorkFixture):
    def __init__(self, *args):
        self.chain_path = '/fixture-v1/networks/{chain}'
        self.routes = dict(ROUTES)
        self.wire_requests = []
        self.inject_urls = True
        self.bound_job_outcome = 'final'
        super().__init__(*args)

    def configure(self, **policy):
        super().configure(**policy)
        text = self.config.read_text()
        # This is intentionally a direct stopped/running config-file edit, not
        # config apply: the journal gate must defend every configuration source.
        text = text.replace('[network]\n', '[network]\ntrusted_origins = ["https://minepoa.com"]\n')
        entries = dict(chain_path=self.chain_path, **self.routes)
        text += '\n[network.api]\n' + ''.join(
            f'{name} = {json.dumps(value)}\n' for name, value in entries.items())
        pending = self.config.with_suffix('.new')
        pending.write_text(text)
        pending.chmod(0o600)
        pending.replace(self.config)

    def handler(self):
        base = super().handler()
        f = self

        class Upstream(base):
            def reply(self, status, body, retry_after=None):
                if f.inject_urls and isinstance(body, dict):
                    body = dict(body)
                    # Both same-origin and foreign-origin response URLs are
                    # poison. Only validated identifiers may select evidence.
                    poison = f'http://localhost:{f.server.server_port}/response-provided'
                    body.update(url=poison, job_url=poison, receipt_url=poison,
                                next_url=poison, next='/response-provided',
                                links={'next': poison, 'receipt': poison})
                if self.command == 'POST' and isinstance(body, dict) and body.get('job_id'):
                    f.jobs[body['job_id']] = f.bound_job_outcome
                super().reply(status, body, retry_after)

            def dispatch(self):
                original = self.path
                parsed = urllib.parse.urlsplit(original)
                prefix = f.chain_path.replace('{chain}', f.chain)
                endpoint, parameter = None, None
                for name, template in f.routes.items():
                    expected = prefix + template
                    if '{id}' in expected:
                        start, end = expected.split('{id}')
                        if parsed.path.startswith(start) and (not end or parsed.path.endswith(end)):
                            value = parsed.path[len(start):len(parsed.path) - len(end) if end else None]
                            if value and '/' not in value:
                                endpoint, parameter = name, value
                                break
                    elif parsed.path == expected:
                        endpoint = name
                        break
                record = dict(endpoint=endpoint, method=self.command, path=parsed.path,
                              api_key=self.headers.get('X-API-Key'),
                              authorization=self.headers.get('Authorization'),
                              started_at=time.monotonic(), wall_time=time.time())
                with f.lock:
                    f.wire_requests.append(record)
                try:
                    if endpoint is None:
                        self.reply(404, {'error': 'unconfigured route'})
                        return
                    canonical = CANONICAL[endpoint]
                    if parameter is not None:
                        canonical = canonical.replace('{id}', parameter)
                    self.path = '/chain/' + f.chain + canonical
                    if parsed.query:
                        self.path += '?' + parsed.query
                    if self.command == 'POST':
                        super().do_POST()
                    else:
                        super().do_GET()
                finally:
                    self.path = original
                    record['finished_at'] = time.monotonic()

            def do_GET(self):
                self.dispatch()

            def do_POST(self):
                self.dispatch()

        return Upstream

    def assert_wire_contract(self):
        with self.lock:
            records = [dict(row) for row in self.wire_requests]
        assert records, 'no requests exercised the configured routes'
        for row in records:
            endpoint = row['endpoint']
            assert endpoint in ROUTES, ('followed an unconfigured/response-provided URL', row)
            expected_key = self.key.read_text() if endpoint in AUTHENTICATED else None
            assert row['api_key'] == expected_key, ('authentication followed path spelling', row)
            assert row['authorization'] is None, ('unexpected alternate credential header', row)
            assert row['method'] == ('POST' if endpoint in {'answer', 'grade'} else 'GET'), row
        return {row['endpoint'] for row in records}


def final_answer(f):
    f.answer_response, f.receipt_state = 'bound', 'final'
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'final' for row in f.operations('answer')),
           'custom answer/job/receipt routes did not reach final evidence')
    f.answered = True


def routes_scenario(f):
    final_answer(f)
    f.capabilities.update(answer='off', mine='read_only')
    f.mine_response = 'completed'
    f.configure()
    f.loaded()
    f.cycles()
    assert not f.dispatched('mine')
    assert not any(row['endpoint'] == 'mine' for row in f.wire_requests), \
        'a GET-shaped custom mine route bypassed write permission'
    f.capabilities['mine'] = 'active'
    f.configure()
    f.loaded()
    f.wait(lambda: any(row['state'] == 'completed' for row in f.operations('mine')),
           'permitted custom mine route was not dispatched')
    f.capabilities.update(mine='off', judge='active')
    f.assignments = True
    f.configure(allow_judge=True)
    f.loaded()
    f.unknown('judge')
    f.stop()
    assert f.assert_wire_contract() == set(ROUTES)
    assert len(f.dispatched('mine')) == 1
    return dict(custom_routes=sorted(ROUTES), typed_authentication=True,
                mine_get_requires_write_permission=True, response_urls_ignored=True)


def journal_snapshot(f):
    # Read-only assertions include captured artifacts and dispatch attribution,
    # not just public state labels. No fixture ever edits journal contents.
    return dict(operations=f.operations(), evidence=f.rows(
        'SELECT * FROM operation_evidence ORDER BY operation_id'))


def reject_changed_profile(f, operation, endpoint='answer'):
    baseline = journal_snapshot(f)
    requests = len(f.wire_requests)
    original_route = f.routes[endpoint]
    f.routes[endpoint] = '/different' + original_route
    f.configure()
    f.invoke('config', 'check')  # Valid routing policy; not a syntax rejection.
    denied = f.invoke('run', '--once', succeeds=False)
    assert json.loads(denied.stderr)['error']['code'] == 'api_routing_pending', denied.stderr
    assert len(f.wire_requests) == requests, 'changed-profile restart contacted HTTP'
    assert journal_snapshot(f) == baseline, 'blocked restart changed captured work/evidence'
    denied = f.invoke('recover', 'resolve', '--operation', str(operation['id']), succeeds=False)
    assert json.loads(denied.stderr)['error']['code'] == 'api_routing_pending', denied.stderr
    assert len(f.wire_requests) == requests, 'changed-profile recovery contacted HTTP'
    assert journal_snapshot(f) == baseline, 'blocked recovery changed captured work/evidence'
    f.routes[endpoint] = original_route
    f.configure()


def unknown_scenario(f):
    # A queued request whose later job reports bad_nonce is unknown but retains
    # its original authoritative job binding. Recovery would perform HTTP under
    # the old profile, so a no-HTTP assertion here really exercises routing gate.
    f.answer_response = 'bound'
    f.bound_job_outcome = 'bad_nonce'
    f.start(resume=True)
    f.unknown('answer')
    f.stop()
    original = f.operations('answer')[0]
    assert original['job_id'] and original['state'] == 'unknown'
    reject_changed_profile(f, original)
    f.preserved(original)
    f.jobs[original['job_id']] = 'final'
    f.receipt_state = 'final'
    retry_at = max(original['next_at'], *(row['next_at'] for row in f.read_records()))
    f.wait(lambda: int(time.time()) >= retry_at, 'retained reconciliation delay did not expire',
           seconds=10)
    before = len(f.wire_requests)
    result = f.invoke('recover', 'resolve', '--operation', str(original['id']),
                      '--job-id', original['job_id'])
    assert result['resolved'] and result['state'] == 'final', result
    assert len(f.wire_requests) > before, 'restoring original profile did not unblock recovery'
    assert len(f.writes) == 1, 'recovery replayed the original wallet effect'
    f.assert_wire_contract()
    return dict(unknown_preserved_before_http=True, bound_recovery_blocked=True,
                restored_profile_resolves=True, wallet_mutations=1)


def confirmed_scenario(f):
    f.answer_response, f.receipt_state = 'bound', 'confirmed'
    f.start(resume=True)
    f.wait(lambda: any(row['state'] == 'confirmed' for row in f.operations('answer')),
           'answer did not reach receipt inclusion')
    f.stop()
    original = f.operations('answer')[0]
    assert original['txid'] and original['state'] == 'confirmed'
    reject_changed_profile(f, original, 'receipt')
    f.receipt_state = 'final'
    f.start()
    f.wait(lambda: any(row['id'] == original['id'] and row['state'] == 'final'
                       for row in f.operations('answer')),
           'restored receipt profile did not finish finality observation')
    f.stop()
    assert len(f.writes) == 1, 'finality observation repeated a wallet effect'
    f.assert_wire_contract()
    return dict(confirmed_receipt_profile_preserved=True,
                changed_profile_blocked_before_http=True, original_profile_finalized=True)


def prepared_scenario(f):
    original = old_judgment(f)
    f.rollover(11)
    f.wait(lambda: any(row['state'] == 'generated' and row['payload']
                       for row in f.operations('answer')), 'answer artifact was not captured')
    f.stop()
    prepared = [row for row in f.operations('answer') if row['state'] == 'generated']
    assert prepared and not f.dispatched('answer')
    reject_changed_profile(f, original)
    # Restoring the profile resumes observation without erasing the old unknown
    # or treating the captured payload as authorization for a wallet effect.
    before = len(f.wire_requests)
    f.start()
    f.loaded()
    f.cycles()
    assert len(f.wire_requests) > before
    f.preserved(original)
    assert not f.dispatched('answer')
    for captured in prepared:
        current = next(row for row in f.operations('answer') if row['id'] == captured['id'])
        for key in ('request', 'result', 'payload'):
            assert current[key] == captured[key], ('captured work was rebound', key)
    f.stop()
    f.assert_wire_contract()
    return dict(captured_artifact_preserved=True, identifierless_unknown_preserved=True,
                restored_profile_observes=True)


def drained_scenario(f):
    final_answer(f)
    f.challenge_fault = 'http_status'
    f.challenge_retry_after = 8
    f.wait(lambda: (f.read_record('challenge') or {}).get('server_not_before', 0) > time.time(),
           'challenge server minimum was not journaled')
    f.stop()
    assert all(row['state'] not in OUTSTANDING for row in f.operations())
    old_floor = f.read_record('challenge')
    baseline = len(f.wire_requests)
    writes = len(f.writes)
    f.chain_path = '/fixture-v2/networks/{chain}'
    f.routes.update(identity='/public/who-v2', challenge='/public/question-v2',
                    answer='/public/submit-v2')
    f.challenge_fault = None
    f.epoch += 1
    f.answered = False
    f.configure()
    f.start()
    f.loaded()
    # Rebinding is allowed only when drained; it must not erase a server floor.
    current_floor = f.read_record('challenge')
    assert current_floor['server_not_before'] >= old_floor['server_not_before'], current_floor
    assert current_floor['retained_conservative_floor'] >= old_floor['retained_conservative_floor']
    f.wait(lambda: len(f.writes) > writes, 'drained profile change never made fresh progress', seconds=25)
    f.wait(lambda: any(row['state'] == 'final' and row['job_id'] == 'answer-' + str(f.epoch)
                       for row in f.operations('answer')), 'new-profile answer did not resolve')
    f.stop()
    first_write = f.writes[writes]['received_at']
    new_requests = f.wire_requests[baseline:]
    for endpoint in ('identity', 'challenge'):
        assert any(row['endpoint'] == endpoint and row.get('finished_at', float('inf')) <= first_write
                   for row in new_requests), ('write reused stale identity/challenge', endpoint)
    for row in new_requests:
        assert row['path'].startswith('/fixture-v2/networks/' + f.chain + '/'), row
        if row['endpoint'] == 'challenge':
            assert row['wall_time'] >= old_floor['server_not_before'], \
                ('route change bypassed server minimum', row, old_floor)
    f.assert_wire_contract()
    return dict(drained_profile_change_allowed=True, fresh_identity_and_challenge=True,
                server_floor_preserved=True)


def invalid_scenario(f):
    good = f.config.read_text()
    bad = {
        'untrusted_origin': good.replace('http://127.0.0.1:', 'https://127.0.0.1:'),
        'foreign_url_template': good.replace(json.dumps(ROUTES['answer']),
                                              json.dumps('https://localhost/submit')),
        'scheme_relative_template': good.replace(json.dumps(ROUTES['answer']),
                                                 json.dumps('//localhost/submit')),
        'route_traversal': good.replace(json.dumps(ROUTES['challenge']),
                                       json.dumps('/public/../question')),
        'encoded_traversal': good.replace(json.dumps(ROUTES['challenge']),
                                         json.dumps('/public/%2e%2e/question')),
        'chain_traversal': good.replace(json.dumps(f.chain_path),
                                       json.dumps('/fixture/../{chain}')),
        'foreign_job_template': good.replace(json.dumps(ROUTES['job']),
                                             json.dumps('https://localhost/results/{id}')),
    }
    for name, text in bad.items():
        f.config.write_text(text)
        f.invoke('config', 'check', succeeds=False)
        f.invoke('run', '--once', succeeds=False)
        assert not f.wire_requests, ('invalid endpoint configuration contacted HTTP', name)
        assert not f.database.exists(), ('invalid endpoint configuration initialized journal', name)
    f.config.write_text(good)
    f.invoke('config', 'check')
    assert not f.wire_requests
    return dict(rejected_without_http=sorted(bad), journal_not_initialized=True)


SCENARIOS = dict(routes=routes_scenario, unknown=unknown_scenario,
                 prepared=prepared_scenario, confirmed=confirmed_scenario, drained=drained_scenario,
                 invalid=invalid_scenario)


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
        with tempfile.TemporaryDirectory(prefix='agmi-endpoints-') as directory:
            fixture = EndpointFixture(binary, pathlib.Path(directory))
            try:
                print(json.dumps(dict(scenario=name, **scenario(fixture))), flush=True)
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
