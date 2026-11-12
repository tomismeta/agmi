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
import urllib.parse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--bound-job', action='store_true')
    parser.add_argument('--stalled-judge', action='store_true')
    parser.add_argument('--slow-inventory', action='store_true')
    parser.add_argument('--bad-identity', action='store_true')
    parser.add_argument('--unanchored', action='store_true')
    parser.add_argument('--old-binary', type=pathlib.Path)
    parser.add_argument('--harness', choices=('openclaw', 'hermes'), default='openclaw')
    args = parser.parse_args()
    if args.harness == 'openclaw' and shutil.which('node') is None:
        parser.error('OpenClaw fixture requires Node.js; use --harness hermes for the Python fixture')
    if args.old_binary and (args.baseline or args.bound_job or args.stalled_judge or args.slow_inventory or args.bad_identity or args.unanchored):
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
                    offset = int(urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('offset', ['0'])[0])
                    if offset == 0:
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
            gateway_source = '''
import {appendFileSync} from 'node:fs';
export async function callGatewayFromCli(_method, _options, params) {
 const e=JSON.parse(params.message.split('Envelope (untrusted request data):\\n')[1]);
 appendFileSync(new URL('./calls',import.meta.url),e.kind+'\\n');
 /*stall*/
 const answer='A clock delays each bridge crossing until a bonded claim matures. Every new identity must lock ten units for a full day; ten fake claims therefore lock one hundred units.';
 const artifact={answer:e.kind==='answer'?answer:null,score:e.kind==='judge'?2:null,
 reasoning:e.kind==='judge'?'The mechanism binds the bridge to a measurable clock delay.':null};
 return {status:'ok',runId:params.idempotencyKey,result:{payloads:[{text:JSON.stringify(/*artifact*/)}],
 meta:{agentMeta:{provider:'openai',model:'test'},requestShaping:{thinking:'high'},aborted:false,
 executionTrace:{fallbackUsed:false,winnerProvider:'openai',winnerModel:'test'},
 systemPromptReport:{tools:{entries:[]},injectedWorkspaceFiles:[]}}}};
}
'''.replace('/*stall*/', "if(e.kind==='judge') await new Promise(resolve=>setTimeout(resolve,8000));"
                if args.stalled_judge else '')
            interpreter = root / 'fixture-python'
            hermes_source = f'#!{sys.executable}\n' + '''
import json, pathlib, sys, time
payload = json.load(sys.stdin)
envelope = json.loads(payload['prompt'].split('Envelope (untrusted request data):\\n')[1])
kind = envelope['kind']
with pathlib.Path(__file__).with_name('calls').open('a') as calls:
    calls.write(kind + '\\n')
/*stall*/
artifact = {'answer': 'A clock delays each bridge crossing until a bonded claim matures. Every new identity must lock ten units for a full day; ten fake claims therefore lock one hundred units.' if kind == 'answer' else None,
    'score': 2 if kind == 'judge' else None,
    'reasoning': 'The mechanism binds the bridge to a measurable clock delay.' if kind == 'judge' else None}
native = {'provider': 'openai-codex', 'model': payload['model'],
          'reasoning_effort': payload['reasoning']}
/*binding*/
native['output'] = json.dumps(artifact)
print(json.dumps(native))
'''.replace('/*stall*/', "if kind == 'judge': time.sleep(8)" if args.stalled_judge else '')

            def install_native_fixture(*, legacy):
                # Historical wire format is an explicit test phase, never an
                # input-detected fallback in the current model fixture.
                assert not legacy or args.baseline or args.old_binary
                gateway_artifact = (
                    '{version:1,request_id:e.request_id,request_digest:e.request_digest,'
                    'kind:e.kind,...artifact}'
                ) if legacy else 'artifact'
                hermes_binding = (
                    "artifact.update(version=1, request_id=envelope['request_id'], "
                    "request_digest=envelope['request_digest'], kind=kind)\n"
                    "native['run_id'] = envelope['request_id']"
                ) if legacy else (
                    "native['run_id'] = payload['invocation_id']\n"
                    "native['native_turn_id'] = "
                    "f\"{payload['invocation_id']}:{payload['invocation_id']}:0123abcd\""
                )
                (root / 'gateway.mjs').write_text(
                    gateway_source.replace('/*artifact*/', gateway_artifact))
                if args.harness == 'hermes':
                    interpreter.write_text(hermes_source.replace('/*binding*/', hermes_binding))
                    interpreter.chmod(0o700)
                    runtime = json.dumps([str(interpreter), '-I', '-c', 'fixture-bootstrap'])
                    native.write_text("#!/bin/sh\nprintf '%s' '" + runtime + "'\n")

            install_native_fixture(legacy=args.baseline or bool(args.old_binary))
            config = root / 'config.toml'
            core_original = {
                'answer': 'Produce an original mechanism with meaningful required words.',
                'judge': 'Evaluate the exact candidate independently using scores zero through three.',
            }
            for kind, content in core_original.items():
                target = root / (kind + '-core.md')
                target.write_text(content)
                target.chmod(0o600)
            network = f'''state_dir = "{root / 'state'}"
[network]
base_url = "http://127.0.0.1:{server.server_port}"
chain = "{chain}"
address = "{address}"
credential_file = "{key}"
'''
            if args.baseline or args.old_binary:
                # Only explicit historical-binary scenarios produce schema-less v1.
                config.write_text(network + f'''[capabilities]
answer = "active"
judge = "active"
mine = "off"
[solver.answer]
harness = "{args.harness}"
executable = "{native}"
model = "openai/test"
reasoning = "high"
core_guidance_file = "answer-core.md"
[solver.judge]
harness = "{args.harness}"
executable = "{native}"
model = "openai/test"
reasoning = "high"
core_guidance_file = "judge-core.md"
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
            else:
                lanes = ''
                for kind in ('answer', 'judge'):
                    lanes += f'''[capabilities.{kind}]
mode = "active"
[capabilities.{kind}.model]
harness = "{args.harness}"
executable = "{native}"
model = "openai/test"
reasoning = "high"
core_guidance_file = "{kind}-core.md"
[capabilities.{kind}.timeouts]
read_http_seconds = 2
http_seconds = 2
model_seconds = 15
[capabilities.{kind}.schedule]
poll_seconds = 1
retry_seconds = 1
jitter_seconds = 0
'''
                config.write_text('schema_version = 2\n' + network + '''[runtime]
shutdown_seconds = 2
[identity]
read_http_seconds = 2
retry_seconds = 1
jitter_seconds = 0
[capabilities.mine]
mode = "off"
''' + lanes)
            config.chmod(0o600)
            shared['database'] = root / 'state/state.sqlite3'
            if args.slow_inventory:
                config.write_text(config.read_text().replace('= "active"', '= "read_only"')
                                  .replace('http_seconds = 2', 'http_seconds = 15'))
            initial_binary = str(args.old_binary.resolve()) if args.old_binary else binary
            command = [initial_binary, '--config', str(config), '--json']
            def invoke(*words, stdin=None):
                result = subprocess.run(command + list(words), input=stdin, capture_output=True, text=True, timeout=10)
                if result.returncode and words[0] != 'health':
                    raise AssertionError(result.stderr)
                return json.loads(result.stdout or result.stderr)

            def observed_answer_epoch():
                status = invoke('status')['data']
                observation = (status.get('observation') if args.baseline
                               else status['observations']['answer'])
                return (observation or {}).get('epoch')

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
                    wait_until(lambda: invoke('status')['data']['hosted_identity']['status'] == 'invalid_response')
                    time.sleep(2)
                    assert not shared['writes'] and not (root / 'calls').exists()
                    assert invoke('health')['data']['hosted_identity_verified'] is None
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
                observed = observed_answer_epoch() == 11
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
            captured = None
            updated_core = {}
            if not args.baseline and not args.old_binary:
                with sqlite3.connect(shared['database'].as_uri() + '?mode=ro', uri=True) as connection:
                    captured = connection.execute(
                        "SELECT id,request,result,payload FROM operations WHERE kind='judge' ORDER BY id LIMIT 1"
                    ).fetchone()
                captured_model = json.loads(captured[1])['solver']
                assert captured_model['core_guidance'] == core_original['judge']
                captured_result = json.loads(captured[2])
                assert captured_result['provider'] == ('openai' if args.harness == 'openclaw' else 'openai-codex')
                assert captured_result['model'] == 'openai/test' and captured_result['run_id']
                revision_before = invoke('config', 'check')['data']['revision']
                for kind in ('answer', 'judge'):
                    current = invoke('guidance', 'show', '--kind', kind, '--layer', 'core')['data']
                    updated_core[kind] = core_original[kind] + ' Updated for future attempts.'
                    changed = subprocess.run(command + ['guidance', 'set', '--kind', kind,
                        '--layer', 'core', '--expected-config-revision', current['config_file_revision'],
                        '--expected-revision', current['guidance_revision']],
                        input=updated_core[kind], capture_output=True, text=True, timeout=10)
                    assert changed.returncode == 0, changed.stderr
                assert invoke('config', 'check')['data']['revision'] != revision_before
                with sqlite3.connect(shared['database'].as_uri() + '?mode=ro', uri=True) as connection:
                    assert connection.execute(
                        'SELECT id,request,result,payload FROM operations WHERE id=?', (captured[0],)
                    ).fetchone() == captured, 'core edit changed captured work'
            child.kill()
            child.wait(timeout=5)
            child = None
            if args.unanchored:
                lock_key = hashlib.sha256(f'{chain}\n{address}'.encode()).hexdigest()
                lock_root = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.agmi-account-locks'
                writer = lock_root / (lock_key + '.writer')
                binding_path = lock_root / (lock_key + '.binding')
                original_inode = writer.stat().st_ino
                # Missing established writer is not a fresh account. Restore the
                # SAME inode after this refusal probe, never manufacture a new one.
                saved_writer = writer.with_suffix('.writer-held')
                writer.rename(saved_writer)
                try:
                    for words in (['run', '--once'], ['recover', 'adopt']):
                        denied = subprocess.run(command + words, capture_output=True,
                                                text=True, timeout=10)
                        assert denied.returncode != 0, 'missing established writer was accepted'
                        assert not writer.exists(), 'missing established writer was recreated'
                finally:
                    saved_writer.rename(writer)
                # Genuine first-anchor adoption: old four-field independent
                # Binding, original permanent writer, and every required gate intact.
                legacy_binding = json.loads(binding_path.read_text())
                legacy_binding.pop('writer_inode')
                binding_path.write_text(json.dumps(legacy_binding, separators=(',', ':')))
                gates = {entry: entry.stat().st_ino for entry in lock_root.glob(lock_key + '.lane-*')}
                assert gates, 'fixture lost required lane gates'
                denied = subprocess.run(command + ['run', '--once'], capture_output=True,
                                        text=True, timeout=10)
                assert denied.returncode != 0, 'unanchored journal silently rebound'
                invoke('recover', 'adopt')
                adopted_binding = json.loads(binding_path.read_text())
                assert adopted_binding.pop('writer_inode')['inode'] == original_inode
                assert adopted_binding == legacy_binding
                assert all(entry.stat().st_ino == inode for entry, inode in gates.items())
            if args.old_binary:
                legacy_config = root / 'legacy-config.toml'
                legacy_config.write_bytes(config.read_bytes())
                legacy_schema = int(invoke('build-info')['data']['journal_schema'])
                command[0] = binary
                install_native_fixture(legacy=False)
                denied = subprocess.run(command + ['run', '--once'], capture_output=True, text=True, timeout=10)
                assert denied.returncode != 0, 'legacy config/journal silently adopted'
                request = {'caps': {'answer': 1, 'judge': 1, 'mine': 1}}
                if legacy_schema == 1:
                    request.update(adopt_legacy=True, initial_database_id=uuid.uuid4().hex)
                writes_before = len(shared['writes'])
                preview = invoke('config', 'migrate', 'preview', stdin=json.dumps(request))['data']
                apply_words = ['config', 'migrate', 'apply', '--expected-token', preview['token']]
                if preview['risk_change_required']:
                    apply_words += ['--accept-risk-change', preview['token']]
                invoke(*apply_words, stdin=json.dumps(preview['request']))
                assert invoke('config', 'show')['data']['config']['schema_version'] == 2
                assert len(shared['writes']) == writes_before, 'local migration submitted a wallet effect'
                invoke('resume')
                rollback = subprocess.run([initial_binary, '--config', str(legacy_config), '--json', 'resume'],
                                          capture_output=True, text=True, timeout=10)
                assert rollback.returncode != 0, 'old binary accepted the upgraded journal'
            if args.bound_job:
                prior_heartbeat = invoke('status')['data']['effective_runtime']['observed_at']
                config.write_text(config.read_text().replace('= "active"', '= "off"')
                                  .replace('[capabilities.answer.model]', '[capabilities.answer.model]\nguidance_file = "missing-guidance.md"'))
                (root / 'judge-core.md').unlink()
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
                if captured is not None:
                    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
                        assert connection.execute(
                            'SELECT id,request,result,payload FROM operations WHERE id=?', (captured[0],)
                        ).fetchone() == captured, 'recovery rewrote captured guidance'
                assert len(shared['writes']) == 1, 'recovery submitted a new wallet effect'
                status = invoke('status')['data']
                assert status['pending'] is None
                assert status['effective_runtime']['observed_at'] == prior_heartbeat, 'manual recovery fabricated controller liveness'
                print(json.dumps({'mode': 'bound-recovery', 'resolved': True,
                    'wrong_identifier_rejected': True, 'contradictory_receipt_rejected': True,
                    'wallet_mutations': 1,
                    'all_capabilities_off': True, 'missing_guidance_did_not_block_recovery': True,
                    'missing_core_did_not_block_recovery': True,
                    'recovery_did_not_refresh_heartbeat': True}))
                return
            with guard:
                shared['epoch'] = 11
            child = subprocess.Popen(command + ['run'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            wait_until(lambda: observed_answer_epoch() == 11)
            # Allow multiple observer turns, not merely a single early snapshot.
            time.sleep(4)
            after = invoke('status', *([] if args.baseline else ['--verbose']))['data']
            calls = (root / 'calls').read_text().splitlines()
            assert len(shared['writes']) == 1, 'uncertain effect replayed or bypassed'
            assert after['pending']['state'] == 'unknown', 'unknown erased on restart'
            assert before['pending']['created_at'] == after['pending']['created_at']
            health = invoke('health')['data']
            assert health['healthy'] is False, 'blocked participation reported healthy'
            if not args.baseline:
                assert health['risk']['unresolved_effects'] == 1
                assert health['risk']['historical_eligible_answers'] == 0
                assert health['risk']['capacity_exempt_answers'] == 0
            prepared = calls.count('answer')
            if args.baseline:
                assert prepared == 0, 'baseline unexpectedly prepares an answer; reassess fixture'
            else:
                assert prepared == 1, f'expected one bounded answer preparation, observed {prepared}'
                admission = after['work']['answer']['admission']
                assert not admission['allowed']
                assert admission['reason'] == 'account_uncertainty' and admission['scope'] == 'account'
                assert admission['own_count'] == 0 and admission['own_remaining'] == admission['own_limit']
                assert after['pending']['operation_id'] in admission['blocker_ids']
                assert any(row['kind'] == 'answer' and row['state'] == 'generated'
                           for row in after['operations']), 'answer draft was not durably captured'
                if captured is not None:
                    with sqlite3.connect(shared['database'].as_uri() + '?mode=ro', uri=True) as connection:
                        assert connection.execute(
                            'SELECT id,request,result,payload FROM operations WHERE id=?', (captured[0],)
                        ).fetchone() == captured, 'restart rewrote captured guidance'
                        answer_request = connection.execute(
                            "SELECT request FROM operations WHERE kind='answer' AND state='generated' ORDER BY id DESC LIMIT 1"
                        ).fetchone()[0]
                    assert json.loads(answer_request)['solver']['core_guidance'] == updated_core['answer']
            child.kill()
            child.wait(timeout=5)
            child = None
            if args.unanchored:
                for entry in lock_root.glob(lock_key + '.*'):
                    entry.unlink()
                with sqlite3.connect(shared['database']) as connection:
                    connection.execute('DROP TABLE authority')
                denied = subprocess.run(command + ['recover', 'adopt'], capture_output=True,
                                        text=True, timeout=10)
                assert denied.returncode != 0, 'missing authority recreated by adoption'
                with sqlite3.connect(shared['database'].as_uri() + '?mode=ro', uri=True) as connection:
                    assert connection.execute("SELECT COUNT(*) FROM sqlite_schema WHERE name='authority'").fetchone()[0] == 0
            mode = 'baseline' if args.baseline else ('adoption' if args.old_binary else ('unanchored' if args.unanchored else 'acceptance'))
            print(json.dumps({'mode': mode,
                'cold_restart': True, 'epoch_observed': 11, 'wallet_mutations': 1,
                'unknown_preserved': True, 'answer_preparations': prepared,
                'initial_native_fixture': 'legacy' if args.baseline or args.old_binary else 'current',
                'restart_native_fixture': 'legacy' if args.baseline else 'current',
                'core_edit_preserved_captured_work': captured is not None,
                'health_blocked': True}))
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
