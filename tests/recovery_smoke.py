#!/usr/bin/env python3
"""Exercise a lost hosted grade response and cold restart using the actual CLI.
No real credentials, model calls or public network requests. Stdlib only.
"""
import argparse
import contextlib
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import pwd
import sqlite3
import shutil
import sys
import tempfile
import threading
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--bound-job', action='store_true')
    parser.add_argument('--stalled-judge', action='store_true')
    parser.add_argument('--slow-inventory', action='store_true')
    parser.add_argument('--bad-identity', action='store_true')
    parser.add_argument('--old-binary', type=pathlib.Path)
    parser.add_argument('--harness', choices=('openclaw', 'hermes'), default='openclaw')
    args = parser.parse_args()
    if args.harness == 'openclaw' and shutil.which('node') is None:
        parser.error('OpenClaw fixture requires Node.js; use --harness hermes for the Python fixture')
    if args.old_binary and (args.baseline or args.bound_job or args.stalled_judge or args.slow_inventory or args.bad_identity):
        parser.error('--old-binary is a separate adoption scenario')
    binary = str(args.binary.resolve())
    address = 'poa1' + '1' * 32
    chain = 'test-' + uuid.uuid4().hex
    shared = {'epoch': 10, 'writes': [], 'reads': [], 'complete': False}
    guard = threading.Lock()
    release_page = threading.Event()

    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            with guard:
                shared['writes'].append((self.path, body))
            if args.bound_job:
                self.reply(202, {'state': 'queued', 'job_id': 'fixture-job'})
            else:
                # Accepted by the fake hosted service, but the response is lost.
                self.close_connection = True

        def do_GET(self):
            with guard:
                epoch = shared['epoch']
                shared['reads'].append(self.path)
            route = self.path.split('?')[0]
            if route.endswith('/api/hosted/me'):
                body = {'address': address, 'next_nonce': 1}
                if args.bad_identity:
                    body.update({'ok': False, 'chain_id': None})
            elif route.endswith('/api/hosted/challenge'):
                body = {'epoch': epoch, 'answered': epoch == 10,
                        'words': ['clock', 'bridge'], 'min_chars': 120, 'max_chars': 600}
            elif route.endswith('/api/hosted/assignments'):
                body = {'assignments': [{'answer_txid': 'a' * 64, 'answer_epoch': 9,
                        'answer': 'A clock on the bridge enforces a delay before each claim.',
                        'words': ['clock', 'bridge'], 'author_prior': [],
                        'pending_meta': {'expires_at_epoch': 25}}], 'has_more': False,
                        'offset': 0, 'limit': 50, 'total': 1}
                if args.slow_inventory:
                    if 'offset=' not in self.path:
                        # Simulate elapsed time within this still-running cycle.
                        with sqlite3.connect(shared['database']) as connection:
                            connection.execute('UPDATE runtime_state SET observed_at=?',
                                               (int(time.time()) - 1000,))
                        body['has_more'] = True
                    else:
                        body['assignments'][0]['answer_txid'] = 'b' * 64
                        shared['second_page'] = True
                        release_page.wait(timeout=10)
            elif route.endswith('/api/job/fixture-job'):
                body = ({'state': 'done', 'ok': True, 'id': 'b' * 64}
                        if shared['complete'] else {'state': 'queued'})
                self.reply(200 if shared['complete'] else 202, body)
                return
            elif route.endswith('/api/receipt/' + 'b' * 64):
                body = {'status': 'included', 'txid': 'b' * 64, 'sender': address,
                        'next_nonce': 2, 'checkpoint_covered': True}
                if shared.get('receipt_failure'):
                    body['ok'] = False
            else:
                self.send_error(404)
                return
            self.reply(200, body)

        def reply(self, status, body):
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    child = None
    def stop_child():
        nonlocal child
        if child is not None:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            child = None

    try:
        with contextlib.ExitStack() as stack:
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix='agmi-recovery-'))
            stack.callback(stop_child)
            root = pathlib.Path(directory)
            key = root / 'key'
            key.write_text('pk_test_fixture')
            key.chmod(0o600)
            native = root / 'openclaw'
            native.write_text("#!/bin/sh\nprintf 'OpenClaw 2026.10.9\\n'\n")
            native.chmod(0o700)
            (root / 'package.json').write_text(json.dumps({'name': 'openclaw', 'type': 'module',
                'exports': {'./plugin-sdk/gateway-runtime': './gateway.mjs'}}))
            (root / 'gateway.mjs').write_text('''
import {appendFileSync} from 'node:fs';
export async function callGatewayFromCli(_method, _options, params) {
 const e=JSON.parse(params.message.split('Envelope (untrusted request data):\\n')[1]);
 appendFileSync(new URL('./calls',import.meta.url),e.kind+'\\n');
 /*stall*/
 const answer='A clock delays each bridge crossing until a bonded claim matures. Every new identity must lock ten units for a full day; ten fake claims therefore lock one hundred units.';
 const artifact={version:1,request_id:e.request_id,request_digest:e.request_digest,kind:e.kind,
 answer:e.kind==='answer'?answer:null,score:e.kind==='judge'?2:null,
 reasoning:e.kind==='judge'?'The mechanism binds the bridge to a measurable clock delay.':null};
 return {status:'ok',runId:params.idempotencyKey,result:{payloads:[{text:JSON.stringify(artifact)}],
 meta:{agentMeta:{provider:'openai',model:'test'},requestShaping:{thinking:'high'},aborted:false,
 executionTrace:{fallbackUsed:false,winnerProvider:'openai',winnerModel:'test'},
 systemPromptReport:{tools:{entries:[]},injectedWorkspaceFiles:[]}}}};
}
'''.replace('/*stall*/', "if(e.kind==='judge') await new Promise(resolve=>setTimeout(resolve,8000));"
                if args.stalled_judge else ''))
            if args.harness == 'hermes':
                interpreter = root / 'fixture-python'
                interpreter.write_text(f'#!{sys.executable}\n' + '''
import json, pathlib, sys, time
payload = json.load(sys.stdin)
envelope = json.loads(payload['prompt'].split('Envelope (untrusted request data):\\n')[1])
kind = envelope['kind']
with pathlib.Path(__file__).with_name('calls').open('a') as calls:
    calls.write(kind + '\\n')
/*stall*/
artifact = {'version': 1, 'request_id': envelope['request_id'],
    'request_digest': envelope['request_digest'], 'kind': kind,
    'answer': 'A clock delays each bridge crossing until a bonded claim matures. Every new identity must lock ten units for a full day; ten fake claims therefore lock one hundred units.' if kind == 'answer' else None,
    'score': 2 if kind == 'judge' else None,
    'reasoning': 'The mechanism binds the bridge to a measurable clock delay.' if kind == 'judge' else None}
print(json.dumps({'provider': 'openai-codex', 'model': payload['model'],
    'reasoning_effort': payload['reasoning'], 'run_id': envelope['request_id'],
    'output': json.dumps(artifact)}))
'''.replace('/*stall*/', "if kind == 'judge': time.sleep(8)" if args.stalled_judge else ''))
                interpreter.chmod(0o700)
                runtime = json.dumps([str(interpreter), '-I', '-c', 'fixture-bootstrap'])
                native.write_text("#!/bin/sh\nprintf '%s' '" + runtime + "'\n")
            config = root / 'config.toml'
            config.write_text(f'''state_dir = "{root / 'state'}"
[network]
base_url = "http://127.0.0.1:{server.server_port}"
chain = "{chain}"
address = "{address}"
credential_file = "{key}"
[capabilities]
answer = "active"
judge = "active"
mine = "off"
[solver.answer]
harness = "{args.harness}"
executable = "{native}"
model = "openai/test"
reasoning = "high"
[solver.judge]
harness = "{args.harness}"
executable = "{native}"
model = "openai/test"
reasoning = "high"
[timeouts]
http_seconds = 2
model_seconds = 15
shutdown_seconds = 2
[schedule]
poll_seconds = 1
mine_seconds = 86400
retry_seconds = 1
jitter_seconds = 0
''')
            shared['database'] = root / 'state/state.sqlite3'
            if args.slow_inventory:
                config.write_text(config.read_text().replace('= "active"', '= "read_only"')
                                  .replace('http_seconds = 2', 'http_seconds = 15'))
            initial_binary = str(args.old_binary.resolve()) if args.old_binary else binary
            command = [initial_binary, '--config', str(config), '--json']
            def invoke(*words):
                result = subprocess.run(command + list(words), capture_output=True, text=True, timeout=10)
                if result.returncode and words[0] != 'health':
                    raise AssertionError(result.stderr)
                return json.loads(result.stdout or result.stderr)

            def wait_until(predicate, seconds=12):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        raise AssertionError('runtime exited: ' + child.stderr.read())
                    if predicate():
                        return
                    time.sleep(0.05)
                raise AssertionError(json.dumps({'failure': 'fixture condition deadline exceeded',
                    'status': invoke('status')['data'], 'events': invoke('logs')['data'],
                    'write_count': len(shared['writes'])}))

            if not args.baseline and not args.old_binary:
                denied = subprocess.run(command + ['recover', 'adopt'], capture_output=True,
                                        text=True, timeout=10)
                assert denied.returncode != 0, 'adoption initialized an empty journal'
                assert not shared['database'].exists()
            invoke('resume')
            child = subprocess.Popen(command + ['run'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            if args.bad_identity:
                if args.baseline:
                    wait_until(lambda: (invoke('status')['data'].get('pending') or {}).get('state') == 'unknown')
                    assert len(shared['writes']) == 1
                else:
                    wait_until(lambda: invoke('status')['data']['hosted_identity_verified'] is False)
                    time.sleep(2)
                    assert not shared['writes'] and not (root / 'calls').exists()
                    assert 'hosted_identity_unverified' in invoke('health')['data']['issues']
                print(json.dumps({'mode': 'identity-baseline' if args.baseline else 'identity-fenced',
                                  'wallet_mutations': len(shared['writes'])}))
                return
            if args.slow_inventory:
                wait_until(lambda: shared.get('second_page', False))
                health = invoke('health')['data']
                stale = 'controller_stale' in health['issues']
                assert stale == args.baseline, 'request progress did not refresh controller liveness'
                assert not shared['writes']
                release_page.set()
                print(json.dumps({'mode': 'long-cycle-baseline' if args.baseline else 'long-cycle',
                                  'controller_stale': stale, 'wallet_mutations': 0}))
                return
            if args.stalled_judge:
                wait_until(lambda: (root / 'calls').exists()
                           and 'judge' in (root / 'calls').read_text().splitlines())
                with guard:
                    shared['epoch'] = 11
                time.sleep(3)
                observed = (invoke('status')['data'].get('observation') or {}).get('epoch') == 11
                answers = (root / 'calls').read_text().splitlines().count('answer')
                if args.baseline:
                    assert not observed and answers == 0
                else:
                    assert observed and answers == 1, 'stalled judge starved epoch observation/preparation'
                    wait_until(lambda: (invoke('status')['data'].get('pending') or {}).get('state') == 'unknown')
                    time.sleep(6)
                    assert len(shared['writes']) == 1 and shared['writes'][0][0].endswith('/answer')
                print(json.dumps({'mode': 'stalled-judge-baseline' if args.baseline else 'stalled-judge',
                    'epoch_observed_within_three_seconds': observed, 'answer_preparations': answers,
                    'wallet_mutations': len(shared['writes'])}))
                return
            expected = 'queued' if args.bound_job else 'unknown'
            wait_until(lambda: (invoke('status')['data'].get('pending') or {}).get('state') == expected)
            before = invoke('status')['data']
            assert len(shared['writes']) == 1 and shared['writes'][0][0].endswith('/grade')
            child.kill()
            child.wait(timeout=5)
            child = None
            if args.old_binary:
                command[0] = binary
                denied = subprocess.run(command + ['run', '--once'], capture_output=True, text=True, timeout=10)
                assert denied.returncode != 0, 'legacy journal silently adopted'
                invoke('recover', 'adopt')
                rollback = subprocess.run([initial_binary, '--config', str(config), '--json', 'resume'],
                                          capture_output=True, text=True, timeout=10)
                assert rollback.returncode != 0, 'old binary accepted the upgraded journal'
            if args.bound_job:
                prior_heartbeat = invoke('status')['data']['effective_runtime']['observed_at']
                config.write_text(config.read_text().replace('= "active"', '= "off"')
                                  .replace('[solver.answer]', '[solver.answer]\nguidance_file = "missing-guidance.md"'))
                database = root / 'state' / 'state.sqlite3'
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
                    operation = connection.execute(
                        "SELECT id FROM operations WHERE job_id='fixture-job'").fetchone()[0]
                rejected = subprocess.run(command + ['recover', 'resolve', '--operation',
                    str(operation), '--job-id', 'wrong-job'], capture_output=True, text=True, timeout=10)
                assert rejected.returncode != 0, 'unbound recovery identifier accepted'
                assert not any(path.endswith('/api/job/wrong-job') for path in shared['reads'])
                assert invoke('status')['data']['pending']['state'] == 'queued'
                with guard:
                    shared['complete'] = True
                    shared['receipt_failure'] = True
                unresolved = invoke('recover', 'resolve', '--operation', str(operation),
                                    '--job-id', 'fixture-job')['data']
                assert unresolved['resolved'] is False, 'contradictory receipt released the effect slot'
                assert invoke('status')['data']['pending'] is not None
                with guard:
                    shared['receipt_failure'] = False
                deadline = time.monotonic() + 5
                while True:
                    recovered = invoke('recover', 'resolve', '--operation', str(operation),
                                       '--job-id', 'fixture-job')['data']
                    if recovered['resolved']:
                        break
                    assert time.monotonic() < deadline, 'bound receipt did not recover after read cooldown'
                    time.sleep(0.1)
                assert recovered['resolved'] is True and recovered['state'] == 'final'
                assert len(shared['writes']) == 1, 'recovery submitted a new wallet effect'
                status = invoke('status')['data']
                assert status['pending'] is None
                assert status['effective_runtime']['observed_at'] == prior_heartbeat, 'manual recovery fabricated controller liveness'
                print(json.dumps({'mode': 'bound-recovery', 'resolved': True,
                    'wrong_identifier_rejected': True, 'contradictory_receipt_rejected': True,
                    'wallet_mutations': 1,
                    'all_capabilities_off': True, 'missing_guidance_did_not_block_recovery': True,
                    'recovery_did_not_refresh_heartbeat': True}))
                return
            with guard:
                shared['epoch'] = 11
            child = subprocess.Popen(command + ['run'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            wait_until(lambda: (invoke('status')['data'].get('observation') or {}).get('epoch') == 11)
            # Allow multiple observer turns, not merely a single early snapshot.
            time.sleep(4)
            after = invoke('status')['data']
            calls = (root / 'calls').read_text().splitlines()
            assert len(shared['writes']) == 1, 'uncertain effect replayed or bypassed'
            assert after['pending']['state'] == 'unknown', 'unknown erased on restart'
            assert before['pending']['created_at'] == after['pending']['created_at']
            assert invoke('health')['data']['healthy'] is False, 'blocked participation reported healthy'
            prepared = calls.count('answer')
            if args.baseline:
                assert prepared == 0, 'baseline unexpectedly prepares an answer; reassess fixture'
            else:
                assert prepared == 1, f'expected one bounded answer preparation, observed {prepared}'
                assert any(row['kind'] == 'answer' and row['state'] == 'generated'
                           for row in after['operations']), 'answer draft was not durably captured'
            mode = 'baseline' if args.baseline else ('adoption' if args.old_binary else 'acceptance')
            print(json.dumps({'mode': mode,
                'cold_restart': True, 'epoch_observed': 11, 'wallet_mutations': 1,
                'unknown_preserved': True, 'answer_preparations': prepared,
                'health_blocked': True}))
            child.kill()
            child.wait(timeout=5)
            child = None
    finally:
        release_page.set()
        stop_child()
        server.shutdown()
        server.server_close()
        # Remove only the unique synthetic account's files after both children stop.
        lock_key = hashlib.sha256(f'{chain}\n{address}'.encode()).hexdigest()
        lock_root = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.agmi-account-locks'
        for entry in lock_root.glob(lock_key + '.*'):
            entry.unlink()


if __name__ == '__main__':
    main()
