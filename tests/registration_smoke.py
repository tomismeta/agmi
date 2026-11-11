#!/usr/bin/env python3
"""Isolated actual-CLI registration fixtures. No build or public registration.

Run: python3 tests/registration_smoke.py target/debug/agmi [--scenario NAME]
"""
import argparse
import contextlib
import hashlib
import http.server
import json
import os
import pathlib
import pwd
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

KEY = 'pk_registration_private_fixture'
ROTATED_KEY = 'pk_registration_rotated_fixture'
ADDRESS = 'poa1' + '1' * 32
ALGO = 'fixture-sha256-leading-zero-bits'
CHAIN = 'registration-fixture-' + uuid.uuid4().hex


def snapshot(root):
    return {str(path.relative_to(root)): (stat.S_IMODE(path.stat().st_mode), path.read_bytes())
            for path in root.rglob('*') if path.is_file() and not path.is_symlink()}


class Fixture:
    def __init__(self, binary, root):
        self.binary = str(pathlib.Path(binary).resolve())
        self.root = pathlib.Path(root)
        self.directory = self.root / 'identity'
        self.config = self.directory / 'config.toml'
        self.mode = 'success'
        self.identity_key = KEY
        self.bits = 0
        self.expires = None
        self.algorithm = ALGO
        self.challenge_path = f'/chain/{CHAIN}/api/join-pow'
        self.register_path = f'/chain/{CHAIN}/api/hosted/register'
        self.identity_path = f'/chain/{CHAIN}/api/hosted/me'
        self.network_profile = None
        self.requests = []
        self.posts = []
        self.seen_post = threading.Event()
        self.release = threading.Event()
        self.env = {**os.environ, 'HOME': str(self.root / 'home'),
                    'XDG_CONFIG_HOME': str(self.root / 'home/config'),
                    'XDG_DATA_HOME': str(self.root / 'home/data'),
                    'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1',
                    'ALL_PROXY': 'http://127.0.0.1:1', 'NO_PROXY': ''}
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def record(self):
                assert not self.headers.get('X-Api-Key') and not self.headers.get('Authorization')
                assert '?' not in self.path
                fixture.requests.append((self.command, self.path))

            def reply(self, code, body, headers=None):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Content-Type', 'application/json')
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(data)

            def do_GET(self):
                if self.path == fixture.identity_path:
                    assert self.headers.get('X-Api-Key') == fixture.identity_key
                    fixture.requests.append((self.command, self.path))
                    if fixture.mode == 'identity-unavailable':
                        self.reply(503, {'error': KEY})
                    else:
                        self.reply(200, {'address': ADDRESS, 'chain_id': CHAIN})
                    return
                self.record()
                assert self.path == fixture.challenge_path, self.path
                if fixture.mode == 'challenge-unavailable':
                    self.reply(503, {'error': 'not available'})
                else:
                    self.reply(200, {'challenge': 'fixture', 'bits': fixture.bits,
                                     'expires_ts': fixture.expires or int(time.time()) + 60,
                                     'algo': fixture.algorithm, 'required': True})

            def do_POST(self):
                self.record()
                assert self.path == fixture.register_path, self.path
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                fixture.posts.append(payload)
                fixture.seen_post.set()
                nonce = payload['pow']['nonce']
                assert isinstance(nonce, str) and nonce.isdecimal()
                proof = hashlib.sha256(('fixture:' + nonce).encode()).digest()
                assert int.from_bytes(proof, 'big') < (1 << (256 - fixture.bits))
                assert payload['label'] == 'registration fixture'
                if fixture.mode == 'hold':
                    fixture.release.wait(10)
                if fixture.mode == 'loss':
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                elif fixture.mode == 'truncated':
                    self.send_response(200)
                    self.send_header('Content-Length', '1000')
                    self.end_headers()
                    self.wfile.write(b'{"ok":true,"api_key":"' + KEY.encode())
                    self.wfile.flush()
                    self.close_connection = True
                elif fixture.mode == 'malformed':
                    self.reply(200, b'{"api_key":"' + KEY.encode())
                elif fixture.mode == 'oversized':
                    self.reply(200, b'x' * (1024 * 1024 + 1))
                elif fixture.mode == 'server-error':
                    self.reply(500, {'ok': False, 'error': KEY})
                elif fixture.mode == 'redirect':
                    self.reply(307, {'error': KEY}, {'Location': fixture.origin + '/leak'})
                elif fixture.mode == 'rate-limit':
                    self.reply(429, {'ok': False, 'retry_after_seconds': 3}, {'Retry-After': '1'})
                elif fixture.mode == 'header-floor':
                    self.reply(429, {'ok': False, 'retry_after_seconds': 1}, {'Retry-After': '3'})
                elif fixture.mode == 'proof-rejected':
                    self.reply(403, {'ok': False, 'required_bits': 0, 'get_challenge': '/api/join-pow'})
                else:
                    self.reply(200, {'ok': True, 'address': ADDRESS, 'api_key': KEY,
                                     'chain_id': CHAIN, 'join_txid': 'a' * 64})

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.origin = f'http://127.0.0.1:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if (self.directory / 'state/state.sqlite3').exists():
            lock_key = hashlib.sha256(f'{CHAIN}\n{ADDRESS}'.encode()).hexdigest()
            lock_root = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.agmi-account-locks'
            for entry in lock_root.glob(lock_key + '.*'):
                entry.unlink()

    def args(self, confirm=True, extra=()):
        return ['identity', 'create', '--label', 'registration fixture', '--chain', CHAIN,
                '--base-url', self.origin, '--expected-pow-algo', ALGO,
                '--pow-seconds', '1', '--http-seconds', '1',
                *(['--network-config', str(self.network_profile)] if self.network_profile else []),
                *(['--confirm'] if confirm else []), *extra]

    def command(self, args, json_output=True):
        return [self.binary, *(['--json'] if json_output else []), '--config', str(self.config), *args]

    def run(self, args=None, success=True, json_output=True, cwd=None, stdin=None):
        process = subprocess.run(self.command(self.args() if args is None else args, json_output),
                                 env=self.env, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=15)
        combined = process.stdout + process.stderr
        assert all(key not in combined for key in (KEY, ROTATED_KEY)), 'credential escaped to CLI output'
        assert (process.returncode == 0) == success, combined
        if not json_output:
            return combined
        envelope = json.loads(process.stdout if success else process.stderr)
        assert envelope['schema'] == 'agmi.cli.v1'
        return envelope['data'] if success else envelope['error']

    def status(self, success=True):
        return self.run(['identity', 'status'], success=success)

    def private(self):
        for path in [self.directory, *self.directory.rglob('*')]:
            assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, str(path)


def success(f):
    before = snapshot(f.root)
    assert f.status()['stage'] == 'clean'
    plan = f.run(f.args(confirm=False))
    assert not plan['confirmed'] and plan['risk']
    resume_plan = f.run(['identity', 'resume'])
    assert resume_plan['stage'] == 'plan' and not resume_plan['confirmed']
    assert resume_plan['local_only'] and resume_plan['status']['stage'] == 'clean'
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_resume_unavailable'
    assert snapshot(f.root) == before and not f.requests and not f.directory.exists()
    data = f.run()
    assert data['stage'] == 'created' and data['credential_saved'] and data['account'] == ADDRESS
    assert not data['identity_verified'] and not data['ready_for_participation']
    assert len(f.posts) == 1 and len(f.requests) == 2
    assert (f.directory / 'credential').read_text() == KEY
    intent = json.loads((f.directory / 'registration-000001.intent.json').read_text())
    capture = json.loads((f.directory / 'registration-000001.capture.json').read_text())
    raw = bytes(capture['body'])
    assert json.loads(raw)['api_key'] == KEY
    assert capture['complete'] and capture['body_len'] == len(raw)
    assert capture['body_sha256'] == hashlib.sha256(raw).hexdigest()
    assert capture['intent_sha256'] == hashlib.sha256((f.directory / 'registration-000001.intent.json').read_bytes()).hexdigest()
    assert intent['binding']['chain'] == CHAIN and intent['binding']['base_url'] == f.origin
    action = data['next_actions'][0]
    argv = action['argv']
    assert action['authorization_required'] and argv[:4] == ['agmi', '--config', str(f.config), 'init']
    for flag, value in [('--account', ADDRESS), ('--chain', CHAIN), ('--base-url', f.origin),
                        ('--api-key-file', str(f.directory / 'credential')),
                        ('--state-dir', str(f.directory / 'state')),
                        ('--network-config', str(f.directory / 'network.toml'))]:
        assert argv[argv.index(flag) + 1] == value
    before = snapshot(f.root)
    assert f.status()['stage'] == 'created'
    assert f.run()['stage'] == 'created'
    f.run(json_output=False)
    assert len(f.posts) == 1 and len(f.requests) == 2 and snapshot(f.root) == before
    f.private()


def capture_resume(f):
    configure_custom_routes(f)
    f.run()
    f.network_profile.unlink()
    credential = f.directory / 'credential'
    original_key = credential.read_bytes()
    original_inode = credential.stat().st_ino
    original_network = (f.directory / 'network.toml').read_bytes()
    retained = {name: (f.directory / name).read_bytes() for name in [
        'registration-000001.intent.json', 'registration-000001.capture.json']}
    elsewhere = f.root / 'different-cwd'
    elsewhere.mkdir()
    for name in ['registration.json', 'network.toml']:
        (f.directory / name).unlink()
    before = snapshot(f.root)
    data = f.status()
    assert data['stage'] == 'response_captured' and data['account'] == ADDRESS
    assert data['credential_saved'] and not data['metadata_saved'] and not data['network_config_saved']
    action = data['next_actions'][0]
    assert action['kind'] == 'command' and action['authorization_required'] is True
    assert action['argv'] == ['agmi', '--config', str(f.config), 'identity', 'resume', '--confirm']
    assert pathlib.Path(action['argv'][2]).is_absolute()
    plan = f.run(['identity', 'resume'], cwd=elsewhere)
    assert plan['stage'] == 'plan' and not plan['confirmed'] and plan['local_only']
    assert plan['status']['next_actions'] == data['next_actions']
    assert snapshot(f.root) == before and len(f.requests) == 2
    process = subprocess.run([f.binary, '--json', *action['argv'][1:]], env=f.env, cwd=elsewhere,
                             capture_output=True, text=True, timeout=15)
    assert KEY not in process.stdout + process.stderr
    assert process.returncode == 0, process.stderr
    envelope = json.loads(process.stdout)
    assert envelope['schema'] == 'agmi.cli.v1'
    resumed = envelope['data']
    assert resumed['stage'] == 'created' and resumed['account'] == ADDRESS
    assert resumed['credential_saved'] and resumed['metadata_saved'] and resumed['network_config_saved']
    assert credential.read_bytes() == original_key and credential.stat().st_ino == original_inode
    assert not f.config.exists() and not (f.directory / 'state').exists()
    for name, contents in retained.items():
        assert (f.directory / name).read_bytes() == contents
    assert (f.directory / 'network.toml').read_bytes() == original_network
    before = snapshot(f.root)
    assert f.run(['identity', 'resume', '--confirm'], cwd=elsewhere)['stage'] == 'created'
    assert f.status()['stage'] == 'created' and snapshot(f.root) == before
    assert len(f.requests) == 2 and len(f.posts) == 1
    for name in ['credential', 'registration.json', 'network.toml']:
        (f.directory / name).unlink()
    before = snapshot(f.root)
    assert f.run(['identity', 'resume'], cwd=elsewhere)['status']['stage'] == 'response_captured'
    assert snapshot(f.root) == before
    assert f.run(['identity', 'resume', '--confirm'], cwd=elsewhere)['account'] == ADDRESS
    assert credential.read_bytes() == original_key
    credential.write_text('pk_other_fixture')
    before = snapshot(f.root)
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_conflict'
    assert f.run(['identity', 'resume'], success=False)['code'] == 'registration_conflict'
    assert snapshot(f.root) == before and len(f.posts) == 1 and len(f.requests) == 2
    f.private()


def publication_interruption(f):
    f.run()
    name = {'publish-credential': 'credential', 'publish-metadata': 'registration.json',
            'publish-network': 'network.toml'}[f.scenario]
    target = f.directory / name
    original = target.read_bytes()
    target.unlink()
    retained = snapshot(f.directory)
    inodes = {path.name: path.stat().st_ino for path in f.directory.iterdir() if path.is_file()}
    # Kill the actual resume process during a derived-file write. The capture is
    # already complete; RLIMIT_FSIZE applies only to new writes, not reads/fsyncs.
    worker = (
        'import os, resource, signal, sys; '
        'resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); '
        'signal.signal(signal.SIGXFSZ, signal.SIG_DFL); '
        'limit = int(sys.argv[1]); '
        'resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit)); '
        'os.execv(sys.argv[2], sys.argv[2:])'
    )
    process = subprocess.run(
        [sys.executable, '-c', worker, str(max(1, len(original) // 2)),
         *f.command(['identity', 'resume', '--confirm'])],
        env=f.env, capture_output=True, text=True, timeout=15)
    assert KEY not in process.stdout + process.stderr
    assert process.returncode == -signal.SIGXFSZ, 'fixture did not interrupt a write'
    assert not target.exists(), 'interrupted publication exposed a partial final file'
    interrupted = snapshot(f.directory)
    assert all(interrupted[path] == contents for path, contents in retained.items())
    assert f.status()['stage'] == 'response_captured'
    assert f.run(['identity', 'resume'])['status']['stage'] == 'response_captured'
    assert snapshot(f.directory) == interrupted, 'inspection changed retained evidence'
    assert f.run(['identity', 'resume', '--confirm'])['stage'] == 'created'
    assert target.read_bytes() == original and target.stat().st_nlink == 1
    after = snapshot(f.directory)
    assert all(after[path] == contents for path, contents in interrupted.items())
    assert all((f.directory / path).stat().st_ino == inode for path, inode in inodes.items())
    assert len(f.requests) == 2 and len(f.posts) == 1
    f.private()
    # A partial final left by an older version is conflicting evidence, not a
    # recoverable temporary: never repair it by overwriting an existing identity.
    target.write_bytes(original[:max(1, len(original) // 2)])
    before = snapshot(f.directory)
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_conflict'
    assert snapshot(f.directory) == before and len(f.requests) == 2


def loss_boundaries(f):
    f.run()
    for name in ['credential', 'registration.json', 'network.toml', 'registration-000001.capture.json']:
        (f.directory / name).unlink()
    assert f.status()['stage'] == 'outcome_unknown'
    before = snapshot(f.root)
    assert f.run(success=False)['code'] == 'registration_outcome_unknown'
    assert f.run(f.args(extra=['--retry-rejected']), success=False)['code'] == 'registration_outcome_unknown'
    assert f.run(['identity', 'resume'])['status']['stage'] == 'outcome_unknown'
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_outcome_unknown'
    assert snapshot(f.root) == before and len(f.posts) == 1


def partial_capture(f):
    f.run()
    capture = f.directory / 'registration-000001.capture.json'
    if f.scenario == 'incomplete-capture':
        value = json.loads(capture.read_text())
        value['complete'] = False
        capture.write_text(json.dumps(value))
    else:
        capture.write_bytes(capture.read_bytes()[:30])
    before = snapshot(f.root)
    assert f.status(success=False)['code'] == 'registration_outcome_unknown'
    assert f.run(success=False)['code'] == 'registration_outcome_unknown'
    assert f.run(['identity', 'resume'], success=False)['code'] == 'registration_outcome_unknown'
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_outcome_unknown'
    assert snapshot(f.root) == before and len(f.posts) == 1 and len(f.requests) == 2


def mismatched_capture(f):
    f.run()
    capture = f.directory / 'registration-000001.capture.json'
    value = json.loads(capture.read_text())
    value['intent_sha256'] = '0' * 64
    capture.write_text(json.dumps(value))
    before = snapshot(f.root)
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_outcome_unknown'
    assert snapshot(f.root) == before and len(f.requests) == 2
    assert f.run(success=False)['code'] == 'registration_outcome_unknown'
    assert len(f.posts) == 1


def ambiguous(f):
    f.mode = f.scenario
    error = f.run(success=False)
    assert error['code'] == 'registration_outcome_unknown'
    assert error['details']['retry_allowed'] is False
    assert len(f.posts) == 1
    before = snapshot(f.root)
    assert f.status()['stage'] == 'outcome_unknown'
    assert f.run(success=False)['code'] == 'registration_outcome_unknown'
    assert f.run(['identity', 'resume'])['status']['stage'] == 'outcome_unknown'
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_outcome_unknown'
    assert len(f.posts) == 1 and snapshot(f.root) == before
    assert not (f.directory / 'credential').exists()
    assert len(f.requests) == 2, 'redirect, retry or credential followup occurred'


def rejection(f):
    f.mode = f.scenario
    data = f.run()
    assert data['stage'] == 'rejected' and len(f.posts) == 1
    before = snapshot(f.root)
    assert f.run()['stage'] == 'rejected'
    assert f.run(['identity', 'resume'])['status']['stage'] == 'rejected'
    assert f.run(['identity', 'resume', '--confirm'])['stage'] == 'rejected'
    assert len(f.requests) == 2
    assert snapshot(f.root) == before and len(f.posts) == 1
    if f.mode != 'proof-rejected':
        assert data['retry_after_seconds'] >= 2
        assert f.run(f.args(extra=['--retry-rejected']), success=False)['code'] == 'registration_retry_floor'
        assert len(f.posts) == 1
        time.sleep(max(0, data['retry_not_before'] - time.time()) + 0.1)
    f.mode = 'success'
    result = f.run(f.args(extra=['--retry-rejected']))
    assert result['stage'] == 'created' and result['attempt'] == 2
    assert len(f.posts) == 2 and len(list(f.directory.glob('registration-*.intent.json'))) == 2
    assert (f.directory / 'registration-000001.intent.json').read_bytes() == before['identity/registration-000001.intent.json'][1]
    assert (f.directory / 'registration-000001.capture.json').read_bytes() == before['identity/registration-000001.capture.json'][1]


def preflight(f):
    f.directory.mkdir(mode=0o700)
    path = f.directory / ('state' if f.scenario == 'existing-state' else 'credential')
    if f.scenario == 'existing-config':
        path = f.config
        path.write_text('existing config')
    elif f.scenario == 'existing-state':
        path.mkdir(mode=0o700)
    elif f.scenario == 'symlink':
        target = f.root / 'target'
        target.write_text('pk_other_fixture')
        path.symlink_to(target)
    else:
        path.write_text('pk_other_fixture')
    before = snapshot(f.root)
    f.run(success=False)
    assert not f.requests and snapshot(f.root) == before


def unsafe_evidence(f):
    f.run()
    capture = f.directory / 'registration-000001.capture.json'
    if f.scenario == 'hardlink':
        os.link(capture, f.root / 'linked-capture')
    elif f.scenario == 'public-file':
        capture.chmod(0o644)
    else:
        f.directory.chmod(0o755)
    assert f.status(success=False)['code'] == 'registration_unsafe_file'
    assert f.run(success=False)['code'] == 'registration_unsafe_file'
    assert f.run(['identity', 'resume'], success=False)['code'] == 'registration_unsafe_file'
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_unsafe_file'
    assert len(f.posts) == 1


def proof_limits(f):
    extra = []
    if f.scenario == 'expired':
        f.expires = int(time.time()) - 1
    elif f.scenario in ('algorithm', 'secret-algorithm', 'invalid-algorithm'):
        f.algorithm = {'algorithm': 'unrecognized', 'secret-algorithm': KEY,
                       'invalid-algorithm': 'private algorithm / untrusted'}[f.scenario]
    elif f.scenario == 'unbound-algorithm':
        pass
    elif f.scenario == 'difficulty':
        f.bits = 25
    elif f.scenario == 'hash-budget':
        f.bits = 3
        extra = ['--max-pow-hashes', '1']
    elif f.scenario == 'time-budget':
        f.bits = 256
        extra = ['--max-pow-bits', '256', '--max-pow-hashes', '1099511627776']
    else:
        f.mode = 'challenge-unavailable'
    words = f.args(extra=extra)
    if f.scenario == 'unbound-algorithm':
        index = words.index('--expected-pow-algo')
        del words[index:index + 2]
    error = f.run(words, success=False)
    if f.scenario in ('algorithm', 'unbound-algorithm', 'secret-algorithm', 'invalid-algorithm'):
        assert error['code'] == 'registration_pow_algorithm_unbound'
        assert error['details']['expected_tag_matches'] is False
        safe_tag = f.algorithm if f.scenario in ('algorithm', 'unbound-algorithm') else None
        assert error['details']['negotiated_pow_algo'] == safe_tag
        if safe_tag is None:
            assert f.algorithm not in json.dumps(error)
        help_actions = [action for action in error['next_actions']
                        if action.get('argv', [])[3:] == ['identity', 'create', '--help']]
        assert len(help_actions) == 1 and not help_actions[0]['authorization_required']
        help_process = subprocess.run(
            [f.binary, *help_actions[0]['argv'][1:]], env=f.env,
            capture_output=True, text=True, timeout=15)
        assert help_process.returncode == 0 and '--expected-pow-algo' in help_process.stdout
        assert KEY not in help_process.stdout + help_process.stderr
        human = f.run(words, success=False, json_output=False)
        assert KEY not in human and ROTATED_KEY not in human
        assert len(f.requests) == 2
    else:
        assert len(f.requests) == 1
    assert not f.posts
    assert not list(f.directory.glob('registration-*.intent.json'))


def concurrent(f):
    f.mode = 'hold'
    first = subprocess.Popen(f.command(f.args()), env=f.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert f.seen_post.wait(5)
    second = subprocess.Popen(f.command(f.args()), env=f.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    f.release.set()
    for process in [first, second]:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0 and KEY not in stdout + stderr
        assert json.loads(stdout)['data']['stage'] == 'created'
    assert len(f.posts) == 1 and len(f.requests) == 2


def concurrent_init(f):
    f.mode = 'hold'
    words = f.args()
    words[words.index('--http-seconds') + 1] = '10'
    first = subprocess.Popen(f.command(words), env=f.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert f.seen_post.wait(5)
    init = ['init', '--account', ADDRESS, '--chain', CHAIN, '--base-url', f.origin,
            '--state-dir', str(f.directory / 'state'), '--key-stdin']
    second = subprocess.Popen(f.command(init), env=f.env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    second.stdin.write(KEY)
    second.stdin.close()
    second.stdin = None
    deadline = time.monotonic() + 5
    while not any(path == f.identity_path for _, path in f.requests) and time.monotonic() < deadline:
        time.sleep(0.01)
    f.release.set()
    stdout, stderr = first.communicate(timeout=10)
    assert first.returncode == 0 and KEY not in stdout + stderr
    stdout, stderr = second.communicate(timeout=10)
    assert KEY not in stdout + stderr
    if second.returncode == 0:
        assert json.loads(stdout)['data']['identity_verified']
    else:
        assert json.loads(stderr)['error']['code']
        assert not f.config.exists()
    assert len(f.posts) == 1
    assert (f.directory / 'credential').read_text() == KEY
    assert f.status()['stage'] in ('created', 'configured')


def cancellation(f):
    f.mode = 'hold'
    words = f.args()
    words[words.index('--http-seconds') + 1] = '10'
    process = subprocess.Popen(f.command(words), env=f.env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert f.seen_post.wait(5)
    process.send_signal(signal.SIGINT)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode != 0 and KEY not in stdout + stderr
    f.release.set()
    assert f.status()['stage'] == 'outcome_unknown'
    assert f.run(success=False)['code'] == 'registration_outcome_unknown'
    assert len(f.posts) == 1


def separate_init(f):
    data = f.run()
    words = data['next_actions'][0]['argv'][3:]
    f.mode = 'identity-unavailable'
    f.run(words, success=False)
    assert (f.directory / 'credential').read_text() == KEY
    assert not f.config.exists() and len(f.posts) == 1
    f.mode = 'success'
    initialized = f.run(words)
    assert initialized['identity_verified'] and initialized['paused']
    assert not initialized['journal_initialized'] and len(f.posts) == 1
    configured = f.run(['config', 'show'])['config']
    assert configured['schema_version'] == 2
    assert configured['network']['address'] == ADDRESS
    assert configured['network']['base_url'] == f.origin
    assert configured['network']['chain'] == CHAIN
    assert configured['network']['api']['identity'] == ('/me' if f.network_profile else '/api/hosted/me')
    assert set(configured['capabilities']) == {'answer', 'judge', 'mine'}
    for lane in configured['capabilities'].values():
        assert lane['mode'] == 'read_only'
        assert lane['timeouts']['read_http_seconds'] > 0
        assert lane['timeouts']['http_seconds'] > 0
        assert lane['participation']['mode'] == 'strict'
    assert not any(name in configured for name in ('solver', 'timeouts', 'schedule', 'participation'))
    before = snapshot(f.root)
    assert f.status()['stage'] == 'configured'
    assert f.run()['stage'] == 'configured'
    assert snapshot(f.root) == before and len(f.posts) == 1


def rotated_status(f):
    separate_init(f)
    f.run(['pause'])  # Initialize paused local authority without any hosted observations.
    f.identity_key = ROTATED_KEY
    rotated = f.run(['credentials', 'rotate', '--key-stdin'], stdin=ROTATED_KEY)
    assert rotated['identity_verified'] and rotated['state_preserved']
    before = snapshot(f.root)
    requests = list(f.requests)
    status = f.status()
    assert status['stage'] == 'configured' and status['created']
    assert status['current_credential_matches_registration'] is False
    assert status['current_credential_verified'] is False
    assert status['identity_verified'] is False and not status['next_actions']
    assert snapshot(f.root) == before and f.requests == requests
    assert (f.directory / 'credential').read_text() == ROTATED_KEY
    assert f.run(['identity', 'resume', '--confirm'], success=False)['code'] == 'registration_conflict'
    assert f.run(success=False)['code'] == 'registration_conflict'
    assert snapshot(f.root) == before and f.requests == requests and len(f.posts) == 1


def mining_cancellation(f):
    f.bits = 256
    words = f.args(extra=['--max-pow-bits', '256', '--max-pow-hashes', '1099511627776'])
    words[words.index('--pow-seconds') + 1] = '30'
    process = subprocess.Popen(f.command(words), env=f.env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 5
    while not f.requests and time.monotonic() < deadline:
        time.sleep(0.01)
    assert f.requests
    process.send_signal(signal.SIGINT)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode != 0 and KEY not in stdout + stderr
    assert not f.posts and not list(f.directory.glob('registration-*.intent.json'))
    assert f.status()['stage'] == 'clean'


def configure_custom_routes(f):
    f.challenge_path = f'/v2/{CHAIN}/join'
    f.register_path = f'/v2/{CHAIN}/signup'
    f.identity_path = f'/v2/{CHAIN}/me'
    f.network_profile = f.root / 'input-network.toml'
    f.network_profile.write_text(
        f'base_url = {json.dumps(f.origin)}\nchain = {json.dumps(CHAIN)}\n'
        f'trusted_origins = [{json.dumps(f.origin)}]\n'
        '[api]\nchain_path = "/v2/{chain}"\njoin_pow = "/join"\n'
        'register = "/signup"\nidentity = "/me"\n')
    f.network_profile.chmod(0o600)


def custom_routes(f):
    configure_custom_routes(f)
    success(f)
    separate_init(f)


SCENARIOS = {'success': success, 'capture-resume': capture_resume, 'loss-boundaries': loss_boundaries,
             'partial-capture': partial_capture, 'mismatched-capture': mismatched_capture,
             'incomplete-capture': partial_capture,
             'concurrent': concurrent, 'concurrent-init': concurrent_init, 'cancellation': cancellation,
             'separate-init': separate_init, 'mining-cancellation': mining_cancellation,
             'custom-routes': custom_routes, 'rotated-status': rotated_status}
SCENARIOS.update({name: publication_interruption for name in ['publish-credential', 'publish-metadata', 'publish-network']})
SCENARIOS.update({name: ambiguous for name in ['loss', 'truncated', 'malformed', 'oversized', 'server-error', 'redirect', 'hold']})
SCENARIOS.update({name: rejection for name in ['rate-limit', 'header-floor', 'proof-rejected']})
SCENARIOS.update({name: preflight for name in ['existing-config', 'existing-key', 'existing-state', 'symlink']})
SCENARIOS.update({name: unsafe_evidence for name in ['hardlink', 'public-file', 'public-directory']})
SCENARIOS.update({name: proof_limits for name in ['expired', 'algorithm', 'unbound-algorithm', 'secret-algorithm', 'invalid-algorithm', 'difficulty', 'hash-budget', 'time-budget', 'challenge-unavailable']})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('--scenario', choices=sorted(SCENARIOS))
    args = parser.parse_args()
    for name in [args.scenario] if args.scenario else SCENARIOS:
        with tempfile.TemporaryDirectory(prefix='agmi-registration-') as root:
            fixture = Fixture(args.binary, root)
            fixture.scenario = name
            try:
                SCENARIOS[name](fixture)
                print(name + ': ok')
            finally:
                fixture.close()


if __name__ == '__main__':
    main()
