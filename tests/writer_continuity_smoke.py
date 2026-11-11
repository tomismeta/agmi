#!/usr/bin/env python3
"""Real runtime/native-child writer continuity refusal, with no public network.

Usage: python3 tests/writer_continuity_smoke.py target/debug/agmi
The native transport is a held local fixture; no remote cancellation is claimed.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import signal
import sqlite3
import subprocess
import tempfile
import time
import threading

from participation_smoke import Fixture


def journal_snapshot(fixture):
    with contextlib.closing(sqlite3.connect(fixture.database.as_uri() + '?mode=ro', uri=True)) as db:
        return tuple(db.iterdump())


def suspend_outside_admission(fixture, paths):
    """Stop only A, while the fixture demonstrably owns both released gates."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with contextlib.ExitStack() as stack:
            try:
                for path in paths:
                    gate = stack.enter_context(path.open('rb'))
                    fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.kill(fixture.child.pid, signal.SIGSTOP)
                pid, status = os.waitpid(fixture.child.pid, os.WUNTRACED)
                assert pid == fixture.child.pid and os.WIFSTOPPED(status)
                return
            except BlockingIOError:
                pass
        time.sleep(0.01)
    raise AssertionError('native child never released account/lane admission gates')


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def scenario(binary, mode):
    with tempfile.TemporaryDirectory(prefix='agmi-writer-continuity-') as directory:
        root = pathlib.Path(directory)
        fixture = Fixture(binary, root)
        stopped = False
        native_pid = None
        try:
            native = root / 'fixture-python'
            script = native.read_text()
            script = script.replace('import json, pathlib, sys', 'import json, pathlib, sys, os, time')
            script = script.replace('artifact = ', '''root = pathlib.Path(__file__).parent
(root / 'native-started').write_text(str(os.getpid()))
while not (root / 'release-native').exists():
    time.sleep(0.02)
artifact = ''')
            native.write_text(script)
            native.chmod(0o700)
            fixture.lanes['answer']['timeouts']['model_seconds'] = 90
            fixture.configure()
            fixture.start(resume=True)
            fixture.wait(lambda: (root / 'native-started').exists(), 'held inference was not spawned')
            native_pid = int((root / 'native-started').read_text())
            assert alive(native_pid), 'fixture did not hold a real inference child'
            fixture.wait(lambda: any(row['state'] == 'generating' for row in fixture.operations('answer')),
                         'held native child has no generating journal operation')
            key = hashlib.sha256(f'{fixture.chain}\n{fixture.address}'.encode()).hexdigest()
            lock_root = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.agmi-account-locks'
            writer = lock_root / (key + '.writer')
            binding_path = lock_root / (key + '.binding')
            binding_bytes = binding_path.read_bytes()
            binding = json.loads(binding_bytes)
            original = writer.stat()
            assert binding['writer_inode'] == dict(device=original.st_dev, inode=original.st_ino)
            with writer.open('rb') as probe:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('runtime A did not retain the lifetime writer lock')
            suspend_outside_admission(fixture, [
                lock_root / (key + '.admission'),
                lock_root / (key + '.lane-' + binding['database_id'] + '-answer'),
            ])
            stopped = True
            before = journal_snapshot(fixture)
            calls = (root / 'calls').read_bytes()
            with fixture.lock:
                read_count, write_count = len(fixture.reads), len(fixture.writes)
            assert write_count == 0, 'held inference fixture already crossed HTTP effect boundary'
            if mode == 'missing':
                writer.unlink()
            else:
                replacement = writer.with_suffix('.replacement')
                replacement.write_bytes(writer.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, writer)
                assert writer.stat().st_ino != original.st_ino
                with writer.open('rb') as probe:
                    # The reproduced defect: this new inode can be locked while A lives.
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            second = subprocess.run(fixture.command + ['run', '--once'], capture_output=True,
                                    text=True, timeout=12, env=fixture.env)
            assert second.returncode != 0, ('replacement authorized runtime B', second.stdout, second.stderr)
            assert fixture.child.poll() is None and alive(native_pid), 'A or its held child ended before B refusal'
            assert journal_snapshot(fixture) == before, 'B mutated recovery, routing, witness or runtime state'
            assert binding_path.read_bytes() == binding_bytes, 'B changed the independent witness/anchor'
            assert (root / 'calls').read_bytes() == calls, 'B spawned new native work'
            with fixture.lock:
                assert (len(fixture.reads), len(fixture.writes)) == (read_count, write_count), 'B reached the network'
            assert writer.exists() == (mode != 'missing'), 'missing established writer was recreated'
            if mode != 'missing':
                assert writer.read_bytes() == b'agmi-authority-v2\n'
            os.kill(fixture.child.pid, signal.SIGCONT)
            stopped = False
            # A's next existing authority boundary must close the runtime, not
            # collect/launch more work under a newly learned writer identity.
            fixture.child.wait(timeout=10)
            assert fixture.child.returncode != 0, 'A did not report authority discontinuity'
            assert len(fixture.writes) == 0, 'A dispatched after losing writer continuity'
            assert (root / 'calls').read_bytes() == calls, 'A launched additional inference'
            assert all(row['state'] == 'generating' for row in fixture.operations('answer')), (
                'authority loss was misreported as successful model recovery')
            print(json.dumps(dict(scenario=mode, second_writer_refused=True,
                                  original_runtime_failed_closed=True, held_native_child=True,
                                  admission_gates_released=True, journal_unchanged_by_second=True)))
        finally:
            # Explicitly release the local fixture and let its actual owner reap;
            # no assertion here implies a hosted model or remote effect was stopped.
            (root / 'release-native').touch()
            if stopped and fixture.child is not None and fixture.child.poll() is None:
                os.kill(fixture.child.pid, signal.SIGCONT)
            fixture.close()
            if native_pid is not None:
                deadline = time.monotonic() + 5
                while alive(native_pid) and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert not alive(native_pid), 'runtime did not reap its local inference child'


def wait_for_gate_descriptor(process, path, original):
    """Observe the real pause process opening the old, still-held inode."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, 'pause returned while the original effect gate was held'
        descriptors = pathlib.Path('/proc') / str(process.pid) / 'fd'
        if descriptors.exists():
            for descriptor in descriptors.iterdir():
                try:
                    metadata = descriptor.stat()
                except FileNotFoundError:
                    continue
                if (metadata.st_dev, metadata.st_ino) == (original.st_dev, original.st_ino):
                    return
        else:
            opened = subprocess.run(
                ['lsof', '-a', '-p', str(process.pid), '-F', 'n', str(path)],
                capture_output=True, text=True, timeout=2,
            )
            if 'n' + str(path) in opened.stdout.splitlines():
                return
        time.sleep(0.01)
    raise AssertionError('pause never opened the original admission gate')


def account_gate_effect_scenario(binary, mode, during_wait):
    with tempfile.TemporaryDirectory(prefix='agmi-account-gate-') as directory:
        fixture = Fixture(binary, pathlib.Path(directory))
        entered, release = threading.Event(), threading.Event()
        original_handler = fixture.server.RequestHandlerClass

        class HeldEffect(original_handler):
            def do_POST(self):
                entered.set()
                if not release.wait(20):
                    self.close_connection = True
                    return
                super().do_POST()

        fixture.server.RequestHandlerClass = HeldEffect
        fixture.lanes['answer']['timeouts']['http_seconds'] = 30
        fixture.configure()
        stopped, pause = False, None
        try:
            fixture.start(resume=True)
            fixture.wait(entered.is_set, 'runtime did not begin the held real HTTP effect')
            assert any(row['state'] == 'dispatching' for row in fixture.operations('answer'))
            key = hashlib.sha256(f'{fixture.chain}\n{fixture.address}'.encode()).hexdigest()
            lock_root = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.agmi-account-locks'
            admission = lock_root / (key + '.admission')
            binding_path = lock_root / (key + '.binding')
            binding_bytes = binding_path.read_bytes()
            original = admission.stat()
            assert json.loads(binding_bytes)['admission_inode'] == dict(
                device=original.st_dev, inode=original.st_ino)
            with admission.open('rb') as probe:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('the actual HTTP effect did not retain account admission')
            os.kill(fixture.child.pid, signal.SIGSTOP)
            pid, status = os.waitpid(fixture.child.pid, os.WUNTRACED)
            assert pid == fixture.child.pid and os.WIFSTOPPED(status)
            stopped = True
            before = journal_snapshot(fixture)
            if during_wait or mode == 'intact':
                pause = subprocess.Popen(fixture.command + ['pause'], stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True, env=fixture.env)
                wait_for_gate_descriptor(pause, admission, original)
            if mode == 'missing':
                admission.unlink()
            elif mode == 'replacement':
                replacement = admission.with_suffix('.replacement')
                replacement.write_bytes(admission.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, admission)
                assert admission.stat().st_ino != original.st_ino
                with admission.open('rb') as probe:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if pause is None:
                result = subprocess.run(fixture.command + ['pause'], capture_output=True,
                                        text=True, timeout=8, env=fixture.env)
                assert result.returncode != 0, ('pause acknowledged a detached gate', result.stdout)
                assert journal_snapshot(fixture) == before, 'refused ordinary pause mutated the journal'
                assert binding_path.read_bytes() == binding_bytes
            else:
                time.sleep(0.1)
                assert pause.poll() is None, 'pause bypassed the old effect gate'
                assert journal_snapshot(fixture) == before, 'waiting pause mutated the journal'
            release.set()
            os.kill(fixture.child.pid, signal.SIGCONT)
            stopped = False
            if pause is not None:
                stdout, stderr = pause.communicate(timeout=12)
                if mode == 'intact':
                    assert pause.returncode == 0, (stdout, stderr)
                    assert fixture.invoke('status')['paused'] is True
                else:
                    assert pause.returncode != 0, ('pause accepted replacement after waiting', stdout, stderr)
            if mode != 'intact':
                fixture.child.wait(timeout=12)
                assert fixture.child.returncode != 0, 'effect owner accepted changed admission authority'
                assert admission.exists() == (mode != 'missing')
                assert binding_path.read_bytes() == binding_bytes
            print(json.dumps(dict(scenario='account-gate-' + mode,
                                  during_lock_wait=during_wait, held_real_http_effect=True,
                                  pause_acknowledged=mode == 'intact')))
        finally:
            release.set()
            if stopped and fixture.child is not None and fixture.child.poll() is None:
                os.kill(fixture.child.pid, signal.SIGCONT)
            if pause is not None and pause.poll() is None:
                pause.kill()
                pause.communicate(timeout=5)
            fixture.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    for mode in ('missing', 'same-marker-replacement'):
        scenario(binary, mode)
    account_gate_effect_scenario(binary, 'intact', False)
    for mode in ('missing', 'replacement'):
        for during_wait in (False, True):
            account_gate_effect_scenario(binary, mode, during_wait)


if __name__ == '__main__':
    main()
