#!/usr/bin/env python3
"""Isolated stdlib actual-CLI lifecycle acceptance (no build or public network).

Run: python3 tests/lifecycle_smoke.py target/debug/agmi [--scenario NAME]
Fixtures only; temporary state and fixture account locks are removed on exit.
"""
import argparse
import contextlib
import fcntl
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
        assert snapshot(f.root) == before and not target.exists(), 'dry-run wrote files'
        assert len(f.identity_reads) == count + 1
        result = f.cli(config, args + key_args, OLD if mode == 'stdin' else None)
        assert result['identity_verified'] and result['paused'] and not result['journal_initialized']
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
            assert 'interrupted' in text and not target.exists(), safe(text)
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
    error = f.cli(f.config, ['credentials', 'rotate', '--key-stdin'], NEW, succeeds=False)
    assert 'running' in error or 'writer' in error or 'stop' in error, error
    assert f.key.read_bytes() == old and len(f.identity_reads) == count
    f.stop()
    f.invoke('resume')
    count = len(f.identity_reads)
    error = f.cli(f.config, ['credentials', 'rotate', '--key-stdin'], NEW, succeeds=False)
    assert 'pause' in error, error
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
    before = snapshot(f.root)
    for words in (['install', '--binary', '/nonexistent/fixture-binary', '--sha256', '0' * 64],
                  ['update', '--binary', '/nonexistent/fixture-binary', '--sha256', '0' * 64],
                  ['update', '--release', 'r-' + '0' * 64, '--stopped']):
        result = f.cli(None, words + ['--dry-run'])
        assert result['dry_run'] and not result['network_downloads']
        assert result['pause_state'] == 'unchanged' and 'plan only' in result['preview']
        assert snapshot(f.root) == before
    assert not f.identity_reads and not f.reads and not f.writes


SCENARIOS = {'init': init, 'prompt': prompt, 'signals': signals,
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
