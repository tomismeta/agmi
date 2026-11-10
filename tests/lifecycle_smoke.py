#!/usr/bin/env python3
"""Isolated stdlib actual-CLI lifecycle acceptance (no build or public network).

Run: python3 tests/lifecycle_smoke.py target/debug/agmi [--scenario NAME]
Fixtures only; temporary state and fixture account locks are removed on exit.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import pty
import select
import signal
import stat
import subprocess
import tempfile
import termios
import time
import traceback

from participation_smoke import Fixture

import sys
import types
OLD = 'pk_test_fixture'
NEW = 'pk_lifecycle_replacement_fixture'
WRONG = 'pk_lifecycle_wrong_identity_fixture'
ECHO = 'pk_lifecycle_echo_fixture'
SECRETS = (OLD, NEW, WRONG, ECHO)


def safe(text):
    for secret in SECRETS:
        text = text.replace(secret, '[fixture credential redacted]')
    return text


class LifecycleFixture(Fixture):
    def __init__(self, binary, root):
        self.identity_reads = []
        super().__init__(binary, root)

    def handler(self):
        base = super().handler()
        fixture = self

        class Hosted(base):
            def do_GET(self):
                if self.path.endswith('/api/hosted/me'):
                    key = self.headers.get('X-Api-Key')
                    with fixture.lock:
                        fixture.identity_reads.append(key)
                    if key not in SECRETS:
                        self.reply(401, {'ok': False})
                        return
                    body = {'address': fixture.address, 'chain_id': fixture.chain,
                            'next_nonce': fixture.nonce}
                    if key == WRONG:
                        body['address'] = 'poa1' + '2' * 32
                    if key == ECHO:
                        body['untrusted'] = {'nested': [key]}
                    self.reply(200, body)
                else:
                    super().do_GET()
        return Hosted

    def cli(self, config, words, key=None, succeeds=True):
        command = [self.binary, '--json']
        if config is not None:
            command += ['--config', str(config)]
        result = subprocess.run(command + words,
                                input=key, text=True, capture_output=True, timeout=15,
                                env=self.env)
        output = result.stdout + result.stderr
        assert not any(secret in output for secret in SECRETS), 'credential leaked to CLI output'
        assert (result.returncode == 0) == succeeds, safe(output)
        if not succeeds:
            envelope = json.loads(result.stderr)
            assert envelope['schema'] == 'agmi.cli.v1' and not envelope['ok']
            error = envelope['error']
            assert error['code'] and isinstance(error['details'], dict)
            for action in error['next_actions']:
                if action['kind'] == 'instruction':
                    continue
                assert action['kind'] == 'command'
                if config is not None:
                    assert action['argv'][:3] == ['agmi', '--config', str(config)]
                words = action['argv'][3:] if action['argv'][1:2] == ['--config'] else action['argv'][1:]
                requires_authorization = words in (['pause'], ['service', 'stop'])
                assert action['authorization_required'] is requires_authorization
        return json.loads(result.stdout)['data'] if succeeds else output

    def init_args(self, target):
        return ['init', '--account', self.address, '--chain', self.chain,
                '--base-url', f'http://127.0.0.1:{self.server.server_port}',
                '--state-dir', str(target / 'state')]


def snapshot(root):
    # SQLite readers update shared-memory lock coordination, not journal data.
    # Keep the actual database and WAL byte-for-byte in this comparison.
    return {str(p.relative_to(root)): (stat.S_IMODE(p.stat().st_mode), p.read_bytes())
            for p in root.rglob('*') if p.is_file() and p.name != 'state.sqlite3-shm'}


def private_tree(root):
    for path in [root, *root.rglob('*')]:
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, str(path)


def init(f):
    for mode in ('file', 'stdin'):
        target = f.root / mode
        config = target / 'config.toml'
        args = f.init_args(target)
        key_args = ['--api-key-file', str(f.key)] if mode == 'file' else ['--key-stdin']
        before = snapshot(f.root)
        count = len(f.identity_reads)
        result = f.cli(config, args + key_args + ['--dry-run'], OLD if mode == 'stdin' else None)
        assert result['dry_run'] and result['identity_verified']
        assert result['ready_for_participation'] is False
        assert result['next_actions'][0]['kind'] == 'instruction'
        assert result['next_actions'][0]['authorization_required']
        assert snapshot(f.root) == before and not target.exists(), 'dry-run wrote files'
        assert len(f.identity_reads) == count + 1
        result = f.cli(config, args + key_args, OLD if mode == 'stdin' else None)
        assert result['identity_verified'] and result['paused'] and not result['journal_initialized']
        assert result['ready_for_participation'] is False and result['service_state'] == 'not_inspected'
        actions = result['next_actions']
        commands = [action for action in actions if action['kind'] == 'command']
        assert all(action['argv'][:3] == ['agmi', '--config', str(config)] for action in commands)
        tails = [action['argv'][3:] for action in commands]
        assert tails.index(['config', 'check']) < tails.index(['run', '--once']) < tails.index(['resume']) < tails.index(['health'])
        assert all(action['authorization_required'] for action in commands if action['argv'][3:] in (['run', '--once'], ['resume']))
        assert all(not action['authorization_required'] for action in commands if action['argv'][3:] in (['config', 'check'], ['health']))
        assert not (target / 'state/state.sqlite3').exists()
        text = config.read_text()
        assert 'read_only' in text and not any(secret in text for secret in SECRETS)
        private_tree(target)
        assert (f.key if mode == 'file' else target / 'credential').read_text() == OLD
        before = snapshot(f.root)
        f.cli(config, args + ['--key-stdin'], NEW, succeeds=False)
        assert snapshot(f.root) == before, 'existing config overwritten'
    for matching in (False, True):
        target = f.root / ('interrupted-match' if matching else 'interrupted-different')
        config = target / 'config.toml'
        args = f.init_args(target) + ['--key-stdin']
        f.cli(config, args, OLD)
        config.unlink()  # The durable state just before init publishes configuration.
        key = target / 'credential'
        identity = (key.stat().st_ino, key.stat().st_mtime_ns)
        before = snapshot(target)
        f.cli(config, args, OLD if matching else NEW, succeeds=matching)
        assert key.read_text() == OLD and (key.stat().st_ino, key.stat().st_mtime_ns) == identity
        if matching:
            assert config.is_file()
            after = snapshot(target)
            after.pop('config.toml')
            assert after == before, 'resumed init changed existing private files'
        else:
            assert snapshot(target) == before, 'different credential overwrote interrupted init'
    for token, name in ((WRONG, 'wrong'), (ECHO, 'echo')):
        target = f.root / name
        before = snapshot(f.root)
        f.cli(target / 'config.toml', f.init_args(target) + ['--key-stdin'], token, succeeds=False)
        assert snapshot(f.root) == before and not target.exists()
    f.key.chmod(0o644)
    try:
        target = f.root / 'public-key'
        f.cli(target / 'config.toml', f.init_args(target) + ['--api-key-file', str(f.key)], succeeds=False)
        assert not target.exists()
    finally:
        f.key.chmod(0o600)
    assert not f.writes and not f.reads, 'onboarding did more than identity GETs'


def invalid_init(f):
    for flag, value, field in [('--account', ECHO, 'network.address'),
                               ('--chain', ECHO + '/invalid', 'network.chain')]:
        target = f.root / field
        config = target / 'config.toml'
        words = f.init_args(target) + ['--key-stdin']
        words[words.index(flag) + 1] = value
        for dry_run in (False, True):
            before = snapshot(f.root)
            output = f.cli(config, words + (['--dry-run'] if dry_run else []),
                           OLD, succeeds=False)
            error = json.loads(output)['error']
            assert error['code'] == 'initialization_invalid'
            assert error['details']['reason'] == 'field_invalid'
            assert error['details']['field'] == field
            assert error['message'] == ('Invalid account address.' if flag == '--account'
                                        else 'Invalid network chain.')
            actions = error['next_actions']
            assert actions[0]['argv'] == ['agmi', '--config', str(config), 'init', '--help']
            assert not actions[0]['authorization_required']
            assert not any(action.get('argv', [])[3:] in (['config', 'show'], ['config', 'check'])
                           for action in actions)
            assert any('No identity verification was requested' in action.get('message', '')
                       for action in actions)
            help_process = subprocess.run([f.binary, *actions[0]['argv'][1:]], env=f.env,
                                          capture_output=True, text=True, timeout=15)
            assert help_process.returncode == 0 and '--account' in help_process.stdout
            assert not any(secret in help_process.stdout + help_process.stderr for secret in SECRETS)
            assert snapshot(f.root) == before and not target.exists()
            assert not f.identity_reads and not f.reads and not f.writes
        process = subprocess.run([f.binary, '--config', str(config), *words], input=OLD,
                                 text=True, capture_output=True, timeout=15, env=f.env)
        assert process.returncode != 0 and error['message'] in process.stderr
        assert 'initialization_failed' not in process.stderr and 'init' in process.stderr
        assert not any(secret in process.stdout + process.stderr for secret in SECRETS)
        assert snapshot(f.root) == before and not target.exists()
        assert not f.identity_reads and not f.reads and not f.writes


def terminal(f, target, interrupt=None):
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    output = bytearray()
    child = None

    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    try:
        controlling_terminal()
        child = subprocess.Popen([f.binary, '--json', '--config', str(target / 'config.toml'),
                                  *f.init_args(target), '--key-prompt'],
                                 stdin=slave, stdout=slave, stderr=slave, env=f.env)
        deadline = time.monotonic() + 10
        while b'(hidden): ' not in output:
            assert time.monotonic() < deadline and child.poll() is None, safe(output.decode())
            if select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))
        prompt_flags = termios.tcgetattr(slave)[3]
        hidden = not (prompt_flags & termios.ECHO)
        os.write(master, OLD.encode() + (b'\n' if interrupt is None else b''))
        if interrupt is not None:
            child.send_signal(interrupt)
        while child.poll() is None:
            assert time.monotonic() < deadline, 'hidden prompt did not finish'
            if select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))
        while select.select([master], [], [], 0)[0]:
            chunk = os.read(master, 65536)
            if not chunk:
                break
            output.extend(chunk)
        assert termios.tcgetattr(slave) == original, 'terminal attributes not restored'
        text = output.decode()
        assert not any(secret in text for secret in SECRETS), (
            f'hidden input leaked; echo_disabled={hidden}; terminal_restored=True; '
            f'original_lflag={original[3]}; prompt_lflag={prompt_flags}; '
            f'exit={child.returncode}; transcript={safe(text)!r}')
        assert (child.returncode == 0) == (interrupt is None), safe(text)
        assert hidden, 'prompt left echo enabled'
        if interrupt is None:
            assert (target / 'credential').read_text() == OLD
            assert '"identity_verified":true' in text.replace(' ', '')
            private_tree(target)
        else:
            assert not target.exists(), 'interrupted input created onboarding files'
    finally:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        os.close(master)
        os.close(slave)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def isolated_terminal(f, target, interrupt=None):
    # Controlling-terminal fork must not run in the threaded HTTP process.
    payload = dict(binary=f.binary, target=str(target), args=f.init_args(target),
                   interrupt=interrupt)
    result = subprocess.run([sys.executable, __file__, '--terminal-worker'],
                            input=json.dumps(payload), text=True, capture_output=True,
                            timeout=20, env=f.env)
    assert result.returncode == 0, safe(result.stdout + result.stderr)


def prompt(f):
    isolated_terminal(f, f.root / 'prompt')


def signals(f):
    failures = []
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGTSTP):
        before = snapshot(f.root)
        count = len(f.identity_reads)
        try:
            isolated_terminal(f, f.root / f'interrupt-{sig}', sig)
            assert snapshot(f.root) == before and len(f.identity_reads) == count
            print(f'PASS signal {sig.name}', flush=True)
        except Exception as error:
            failures.append(f'{sig.name}: {error}')
    assert not f.writes and not f.reads
    assert not failures, '\n'.join(failures)


def rotate(f):
    f.start(resume=True)
    f.unknown('answer')
    f.invoke('pause')
    old = f.key.read_bytes()
    count = len(f.identity_reads)
    f.cli(f.config, ['credentials', 'rotate', '--key-stdin'], NEW, succeeds=False)
    assert f.key.read_bytes() == old and len(f.identity_reads) == count
    f.stop()
    f.invoke('resume')
    count = len(f.identity_reads)
    f.cli(f.config, ['credentials', 'rotate', '--key-stdin'], NEW, succeeds=False)
    assert f.key.read_bytes() == old and len(f.identity_reads) == count
    f.invoke('pause')
    operations = f.operations()
    assert any(op['state'] == 'unknown' for op in operations)
    before = snapshot(f.root)
    writes = len(f.writes)
    failures = []
    for token in (WRONG, ECHO):
        f.cli(f.config, ['credentials', 'rotate', '--key-stdin'], token, succeeds=False)
        current = snapshot(f.root)
        changed = [name for name in before.keys() | current.keys()
                   if before.get(name) != current.get(name)]
        if changed:
            failures.append(f'rejected rotation changed files: {changed}')
    result = f.cli(f.config, ['credentials', 'rotate', '--key-stdin', '--dry-run'], NEW)
    assert result['dry_run'] and result['identity_verified']
    current = snapshot(f.root)
    changed = [name for name in before.keys() | current.keys()
               if before.get(name) != current.get(name)]
    if changed:
        failures.append(f'dry-run changed files: {changed}')
    result = f.cli(f.config, ['credentials', 'rotate', '--key-stdin'], NEW)
    assert result['state_preserved'] and result['paused']
    after = snapshot(f.root)
    assert after.pop('key')[1] == NEW.encode()
    before.pop('key')
    changed = [name for name in before.keys() | after.keys()
               if before.get(name) != after.get(name)]
    if changed:
        failures.append(f'rotation changed files: {changed}')
    assert stat.S_IMODE(f.key.stat().st_mode) == 0o600
    assert f.operations() == operations and len(f.writes) == writes
    assert f.identity_reads[-1] == NEW
    assert not failures, '; '.join(failures)


def installer(f):
    home = f.root / 'home'
    home.mkdir(mode=0o700)
    f.env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                 XDG_DATA_HOME=str(home / '.local/share'))

    def failed_update(words):
        result = subprocess.run([f.binary, '--json', 'update', *words],
                                capture_output=True, text=True, timeout=15, env=f.env)
        assert result.returncode != 0
        assert not any(secret in result.stdout + result.stderr for secret in SECRETS)
        envelope = json.loads(result.stdout)
        assert envelope['type'] == 'update' and not envelope['ok']
        assert envelope['data']['success'] is False
        return envelope['data']['installation']

    before = snapshot(f.root)
    for words in (['install', '--binary', '/nonexistent/fixture-binary', '--sha256', '0' * 64],
                  ['install', '--stage-only', '--binary', '/nonexistent/fixture-binary', '--sha256', '0' * 64],
                  ['update', '--binary', '/nonexistent/fixture-binary', '--sha256', '0' * 64],
                  ['update', '--release', 'r-' + '0' * 64, '--stopped'],
                  ['service', 'start']):
        f.cli(None, words + ['--dry-run'])
        assert snapshot(f.root) == before
    error = json.loads(f.cli(None, ['install', '--binary', '/nonexistent/fixture-binary',
                                    '--sha256', '0' * 64], succeeds=False))['error']
    assert error['code'] == 'installer_failed'
    assert error['details']['stage'] == 'preflight'
    assert error['details']['activation'] == 'not_started'
    assert error['details']['service'] == 'unknown'
    assert error['details']['failure_code'] == (
        'candidate_unavailable' if sys.platform.startswith('linux') else 'unsupported_platform')
    assert snapshot(f.root) == before
    if sys.platform.startswith('linux'):
        error = failed_update(['--binary', f.binary, '--sha256', '0' * 64])
        assert error['failure_code'] == 'digest_mismatch'
        assert error['activation'] == 'not_started'
        candidate = f.root / 'unreporting-incoming-release'
        candidate.write_text(f"#!/bin/sh\nprintf '%s\\n' '{ECHO}' >&2\nexit 7\n")
        candidate.chmod(0o700)
        try:
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            candidate.chmod(0o600)
            error = failed_update(['--binary', str(candidate), '--sha256', digest])
            assert error['failure_code'] == 'candidate_execution_unavailable'
            assert error['activation'] == 'not_started'
            error = json.loads(f.cli(None, ['install', '--stage-only', '--binary', str(candidate),
                                            '--sha256', digest], succeeds=False))['error']
            assert error['details']['failure_code'] == 'candidate_execution_unavailable'
            assert error['details']['activation'] == 'not_started'
            candidate.chmod(0o700)
            error = failed_update(['--binary', str(candidate), '--sha256', digest])
            assert error['stage'] == 'unknown'
            assert error['activation'] == 'unknown'
            assert error['service'] == 'unknown'
            assert error['failure_code'] == 'unknown'
            candidate.write_text(
                "#!/bin/sh\nprintf '%s\\n' '" + json.dumps({
                    'schema': 'agmi.cli.v1', 'error': {'code': 'installer_failed',
                    'details': {'failure_code': ECHO, 'stage': ECHO,
                                'service': ECHO, 'activation': ECHO}}})
                + "' >&2\nexit 7\n")
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            error = failed_update(['--binary', str(candidate), '--sha256', digest])
            assert error['failure_code'] == 'unknown'
            assert error['stage'] == 'unknown'
        finally:
            candidate.unlink()
        assert snapshot(f.root) == before
    assert not f.identity_reads and not f.reads and not f.writes


SCENARIOS = {'init': init, 'invalid-init': invalid_init, 'prompt': prompt, 'signals': signals,
             'rotate': rotate, 'installer': installer}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--scenario', choices=SCENARIOS)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    failures = 0
    for name in ([args.scenario] if args.scenario else SCENARIOS):
        with tempfile.TemporaryDirectory(prefix='agmi-lifecycle-') as directory:
            fixture = LifecycleFixture(binary, pathlib.Path(directory))
            try:
                SCENARIOS[name](fixture)
                print(f'PASS {name}', flush=True)
            except Exception:
                failures += 1
                print(f'FAIL {name}\n{safe(traceback.format_exc())}', flush=True)
            finally:
                fixture.close()
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    if sys.argv[1:] == ['--terminal-worker']:
        payload = json.load(sys.stdin)
        worker = types.SimpleNamespace(binary=payload['binary'], env=os.environ,
                                       init_args=lambda _: payload['args'])
        terminal(worker, pathlib.Path(payload['target']), payload['interrupt'])
    else:
        main()
