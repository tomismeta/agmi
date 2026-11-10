#!/usr/bin/env python3
"""Linux public-CLI installer boundaries with fixture systemd tools.

Default execution stages only and proves alternate-HOME refusal. Activation and
cancellation require --isolated-home in the verified disposable systemd container;
its guard reads that manager, but installer commands use only fixture tools.
"""
import contextlib
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
if sys.platform != 'linux':
    raise SystemExit('Run this public-CLI installer regression on Linux; native filesystem unit tests also run on Darwin.')
if sys.argv[2:] not in ([], ['--isolated-home']):
    raise SystemExit('Expected an optional --isolated-home for the disposable systemd container.')
isolated_home = None
if sys.argv[2:] == ['--isolated-home']:
    from systemd_smoke import isolation
    isolated_home = isolation()


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def wait_until(predicate, process, description):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError((description, process.returncode, stdout, stderr))
        time.sleep(0.001)
    process.kill()
    stdout, stderr = process.communicate()
    raise AssertionError(('timeout', description, stdout, stderr))


with tempfile.TemporaryDirectory(prefix='agmi-installer-boundaries-') as directory, contextlib.ExitStack() as cleanup:
    root = pathlib.Path(directory)
    home = isolated_home or root / 'home'
    if isolated_home is None:
        home.mkdir(mode=0o700)
    else:
        # isolation() proved this account/container has no agmi installation.
        for path in (home / '.config/agmi', home / '.local/share/agmi'):
            assert not path.exists()
            cleanup.callback(shutil.rmtree, path, ignore_errors=True)
        for path in (home / '.local/bin/agmi', *(home / '.config/systemd/user' / unit for unit in
                     ('agmi.service', 'agmi-health.service', 'agmi-health.timer'))):
            assert not path.exists() and not path.is_symlink()
            cleanup.callback(path.unlink, missing_ok=True)
    tools = root / 'tools'
    tools.mkdir(mode=0o700)
    temporary = root / 'tmp'
    temporary.mkdir(mode=0o700)
    events = root / 'events'
    releases = home / '.local/share/agmi/releases'
    marker = root / 'untrusted-executed'
    env = dict(os.environ, HOME=str(home), PATH=str(tools), TMPDIR=str(temporary),
               AGMI_FIXTURE_ROOT=str(root), AGMI_ATTACK_MARKER=str(marker))
    for variable in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'SYSTEMD_UNIT_PATH', 'SYSTEMD_BUS_ADDRESS',
                     'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR'):
        env.pop(variable, None)

    fixture_tool = '''import json, os, pathlib, signal, sys, time
root = pathlib.Path(os.environ['AGMI_FIXTURE_ROOT'])
home = pathlib.Path(os.environ['HOME'])
name = pathlib.Path(sys.argv[0]).name
with (root / 'events').open('a') as stream:
    stream.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
if name == 'systemd-analyze':
    assert sys.argv[1:3] == ['--user', 'verify']
    for artifact in sys.argv[3:]:
        assert pathlib.Path(artifact).is_file()
    raise SystemExit(1 if (root / 'reject-units').exists() else 0)
assert name == 'systemctl' and sys.argv[1] == '--user'
args = sys.argv[2:]
if args[0] == 'show':
    prop = next((arg.removeprefix('--property=') for arg in args if arg.startswith('--property=')), '')
    if '--value' not in args:
        print('LoadState=loaded\\nActiveState=inactive\\nMainPID=0')
    elif prop == 'UnitPath':
        print('/another/home/.config/systemd/user' if (root / 'wrong-manager').exists()
              else home / '.config/systemd/user')
    elif prop == 'LoadState':
        print('loaded' if (home / '.config/systemd/user' / args[1]).exists() else 'not-found')
    elif prop == 'ActiveState':
        if (root / 'state-query-failed').exists(): raise SystemExit(1)
        print('inactive')
    elif prop == 'FragmentPath': print(home / '.config/systemd/user' / args[1])
    elif prop == 'MainPID': print('0')
    elif prop == 'DropInPaths': print('')
    elif prop == 'TimeoutStopUSec': print('infinity')
    elif prop == 'Description':
        print('fixture [release=' + os.readlink(home / '.local/share/agmi/releases/current') + ']')
    else: raise AssertionError(args)
elif args[0] == 'is-active': raise SystemExit(3)
elif args[0] == 'daemon-reload':
    (root / 'reload-entered').touch()
    while (root / 'block-reload').exists(): time.sleep(0.01)
elif args[0] not in ('stop', 'enable', 'disable'):
    raise AssertionError(args)
'''
    for name in ('systemctl', 'systemd-analyze'):
        path = tools / name
        path.write_text('#!' + sys.executable + '\n' + fixture_tool)
        path.chmod(0o700)

    def cli(*arguments, success=True, environment=None):
        result = subprocess.run([str(binary), '--json', *arguments], env=environment or env,
                                capture_output=True, text=True, timeout=180)
        assert (result.returncode == 0) == success, (arguments, result.stdout, result.stderr)
        envelope = json.loads(result.stdout if success or arguments[0] == 'update' else result.stderr)
        assert envelope['schema'] == 'agmi.cli.v1'
        if arguments[0] == 'update':
            assert envelope['type'] == 'update' and envelope['ok'] is success
            return envelope['data']
        return envelope['data'] if success else envelope['error']

    def calls():
        return [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []

    config = home / '.config/agmi/config.toml'
    cli('config', 'init')
    state = home / 'untouched-state'
    text = config.read_text()
    config.write_text('\n'.join('state_dir = ' + json.dumps(str(state)) if line.startswith('state_dir =') else line
                                for line in text.splitlines()) + '\n')
    original_config = config.read_bytes()
    credential = home / '.config/agmi/private-sentinel'
    credential.write_bytes(b'private-input-must-not-change')
    credential.chmod(0o600)

    # Replace the actual input pathname after Rust has opened it and begun its
    # private copy. A large inert ELF suffix makes this observable without a
    # command interception, implementation patch, test hook or unsafe execution.
    candidate = root / 'candidate'
    shutil.copy2(binary, candidate)
    with candidate.open('ab') as stream:
        stream.truncate(candidate.stat().st_size + 128 * 1024 * 1024)
    trusted = digest(candidate)
    first_id = 'r-' + trusted
    process = subprocess.Popen([str(binary), '--json', 'install', '--stage-only', '--binary', str(candidate), '--sha256', trusted],
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wait_until(lambda: any(path.stat().st_size > 0 for path in temporary.glob('agmi-installer.*/incoming-agmi')),
               process, 'private candidate copy opened')
    replacement = root / 'replacement'
    replacement.write_text('#!/bin/sh\nprintf executed > "$AGMI_ATTACK_MARKER"\nexit 1\n')
    replacement.chmod(0o700)
    replacement.replace(candidate)
    stdout, stderr = process.communicate(timeout=180)
    assert process.returncode == 0, (stdout, stderr)
    evidence = json.loads(stdout)['data']['installation']
    assert evidence['staging'] == 'complete' and evidence['activation'] == 'not_started'
    assert digest(releases / first_id / 'agmi') == trusted
    assert not marker.exists(), 'Replacement pathname was executed instead of the verified private copy'
    assert not (releases / 'current').is_symlink()
    assert not (home / '.local/bin/agmi').is_symlink()
    assert not state.exists()
    assert all(call[0] == 'systemd-analyze' for call in calls()), 'Stage contacted a user manager'
    assert not list(temporary.iterdir()), 'Incoming delegation left private executables behind'
    error = cli('install', '--stage-only', '--binary', str(candidate), '--sha256', trusted, success=False)
    assert error['details']['failure_code'] == 'digest_mismatch'
    assert not marker.exists()
    print(json.dumps({'scenario': 'candidate_path_replaced_during_private_copy', 'trusted_release_staged': True,
                      'unverified_candidate_executed': False, 'activation': 'not_started'}))

    second = root / 'second'
    shutil.copy2(binary, second)
    with second.open('ab') as stream:
        stream.write(b'\ninstaller fixture incoming release B\n')
    second_hash = digest(second)
    second_id = 'r-' + second_hash
    (root / 'reject-units').touch()
    error = cli('install', '--stage-only', '--binary', str(second), '--sha256', second_hash, success=False)
    assert error['details']['failure_code'] == 'unit_invalid'
    assert error['details']['staging'] == 'published' and error['details']['activation'] == 'not_started'
    assert (releases / second_id / 'SHA256SUMS').is_file()
    assert not (releases / 'current').is_symlink()
    assert not list(releases.glob('.stage.*'))
    (root / 'reject-units').unlink()
    cli('install', '--stage-only', '--binary', str(second), '--sha256', second_hash)
    assert all(call[0] == 'systemd-analyze' for call in calls())

    if isolated_home is None:
        before = len(calls())
        error = cli('service', 'stop', success=False)
        assert error['details']['failure_code'] == 'manager_context_mismatch'
        assert len(calls()) == before, 'Alternate HOME reached a user manager'
        print('PASS alternate HOME refused before any manager contact; activation cases require --isolated-home')
        raise SystemExit(0)

    # A manager belonging to a different installation must never be stopped.
    (root / 'wrong-manager').touch()
    before = len(calls())
    error = cli('update', '--release', first_id, '--stopped', success=False)
    assert error['installation']['failure_code'] == 'manager_context_mismatch'
    assert not any(call[2] == 'stop' for call in calls()[before:])
    assert not (releases / 'current').is_symlink()
    (root / 'wrong-manager').unlink()

    lock = releases / '.install-lock'
    lock.mkdir()
    error = cli('service', 'stop', success=False)
    assert error['details']['failure_code'] == 'installer_busy' and lock.is_dir()
    error = cli('service', 'stop', success=False, environment=dict(env, PATH=str(root / 'missing-tools')))
    assert error['details']['failure_code'] == 'missing_prerequisite' and lock.is_dir()
    error = cli('service', 'status', success=False, environment=dict(env, PATH=str(root / 'missing-tools')))
    assert error['details']['failure_code'] == 'missing_prerequisite', error
    lock.rmdir()
    cli('update', '--release', first_id, '--stopped')
    status_tools = root / 'status-tools'
    status_tools.mkdir(mode=0o700)
    (status_tools / 'systemctl').symlink_to(tools / 'systemctl')
    before = len(calls())
    cli('service', 'status', environment=dict(env, PATH=str(status_tools)))
    assert calls()[before:] and all(call[0] == 'systemctl' for call in calls()[before:])
    print(json.dumps({'scenario': 'status_without_systemd_analyze', 'status_succeeded': True}))
    (root / 'state-query-failed').touch()
    before = len(calls())
    error = cli('update', '--release', second_id, '--stopped', success=False)
    assert error['installation']['failure_code'] == 'service_state_unavailable'
    assert not any(call[2] == 'stop' for call in calls()[before:])
    assert os.readlink(releases / 'current') == first_id
    (root / 'state-query-failed').unlink()

    # Interrupt an actual public update after selection, while its systemd child
    # is blocked. Every catchable old trap signal must retain current and stop
    # all units before releasing its lock. These are fixture tools, never systemd.
    for interruption, selected, delegated in (
            (signal.SIGTERM, second_id, False), (signal.SIGINT, first_id, False),
            (signal.SIGHUP, second_id, False), (signal.SIGTERM, second_id, True)):
        (root / 'reload-entered').unlink(missing_ok=True)
        (root / 'block-reload').touch()
        before = len(calls())
        selection = ['--binary', str(second), '--sha256', second_hash] if delegated else ['--release', selected]
        process = subprocess.Popen([str(binary), '--json', 'update', *selection, '--stopped'],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_until(lambda: (root / 'reload-entered').exists(), process, 'selected release reload boundary')
        assert os.readlink(releases / 'current') == selected
        process.send_signal(interruption)
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode != 0, stdout
        evidence = json.loads(stdout)['data']['installation']
        assert evidence['failure_code'] == 'reload_failed'
        assert evidence['activation'] == 'selected' and evidence['service'] == 'stopped'
        assert os.readlink(releases / 'current') == selected, 'Cancellation silently reverted current'
        stopped = [call[-1] for call in calls()[before:] if call[:3] == ['systemctl', '--user', 'stop']]
        assert stopped == ['agmi-health.timer', 'agmi-health.service', 'agmi.service'] * 2, stopped
        assert not lock.exists()
        assert not list(releases.glob('.agmi-link.*'))
        (root / 'block-reload').unlink()
        print(json.dumps({'scenario': 'post_selection_cancellation', 'signal': interruption.name,
                          'delegated': delegated, 'pointer_retained': True, 'cleanup_stopped_units': True}))

    # Freeze the delegating parent while the verified incoming installer finishes.
    # A pending termination must not turn into success when the parent observes
    # the already-exited child before it gets a chance to forward the signal.
    (root / 'reload-entered').unlink(missing_ok=True)
    (root / 'block-reload').touch()
    process = subprocess.Popen(
        [str(binary), '--json', 'update', '--binary', str(second),
         '--sha256', second_hash, '--stopped'],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_until(lambda: (root / 'reload-entered').exists(), process, 'delegated reload boundary')
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(('delegated process exited before stop', process.returncode, stdout, stderr))
        children = []
        for entry in pathlib.Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / 'status').read_text()
            except (FileNotFoundError, PermissionError):
                continue
            if any(line.split() == ['PPid:', str(process.pid)] for line in status.splitlines()):
                children.append(entry.name)
        assert len(children) == 1, children
        child_stat = pathlib.Path(f'/proc/{children[0]}/stat')
        process.send_signal(signal.SIGSTOP)
        (root / 'block-reload').unlink()
        wait_until(lambda: child_stat.read_text().rsplit(')', 1)[1].split()[0] == 'Z',
                   process, 'incoming installer completed while parent stopped')
        process.send_signal(signal.SIGTERM)
        process.send_signal(signal.SIGCONT)
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode != 0, 'delegated installer reported success after cancellation'
        evidence = json.loads(stdout)['data']['installation']
        assert evidence['failure_code'] == 'interrupted', evidence
        assert evidence['stage'] == 'complete' and evidence['activation'] == 'loaded_verified'
        assert evidence['service'] != 'unknown'
        assert os.readlink(releases / 'current') == second_id
        print(json.dumps({'scenario': 'cancelled_parent_after_child_success',
                          'completed_cutover_evidence_preserved': True}))
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGCONT)
            process.terminate()
            process.wait(timeout=30)
        (root / 'block-reload').unlink(missing_ok=True)

    assert config.read_bytes() == original_config
    assert credential.read_bytes() == b'private-input-must-not-change'
    assert not state.exists()
    assert (releases / first_id).is_dir() and (releases / second_id).is_dir()
    print(json.dumps({'scenario': 'safe_failure_categories', 'private_inputs_unchanged': True,
                      'failure_codes': ['digest_mismatch', 'unit_invalid', 'installer_busy', 'missing_prerequisite', 'reload_failed']}))
