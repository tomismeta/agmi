#!/usr/bin/env python3
"""Real installer/user-systemd acceptance, ONLY in systemd_fixture.Dockerfile.

The driver starts a disposable container with a private cgroup namespace, /run
and executable /tmp (`--tmpfs /tmp:exec,mode=1777`), no network and only read-only
repository/binary mounts. The installer executes privately staged candidates;
Docker's default noexec tmpfs is unsuitable for its TMPDIR. Inside the container:
  systemctl start user@17321.service
  runuser -u agmi-systemd-fixture -- env HOME=/home/agmi-systemd-fixture \
    XDG_RUNTIME_DIR=/run/user/17321 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/17321/bus \
    python3 /src/tests/systemd_smoke.py /input/agmi
No host user manager is contacted. A HOME override alone is NOT isolation.
The default current suite's second ELF has an inert appended label and exercises
release selection only. Compatibility instead REQUIRES an authentic pre-change
Linux format3 ELF and its externally recorded SHA256. A build from a hash-verified
preserved source checkpoint is valid; record that provenance separately and do
not call it a previously published release executable:
  ... systemd_smoke.py /input/agmi --suite compatibility \
      --old-binary /input/agmi-format3 --old-sha256 <preserved-sha256>
It uses strace syscall delay to kill conversion after its durable seal and before
configuration publication; the container must permit same-user ptrace (for example
CAP_SYS_PTRACE with a suitable seccomp policy). No binary is relabelled as old.
After compatibility exits, an external authorized driver must reboot the same
disposable container with its home/state intact, restart user@17321.service, and run:
  ... systemd_smoke.py /input/agmi --suite after-reboot
The second phase requires a changed kernel boot_id; restarting a user manager or
container under the same kernel is not reboot proof. Use a dedicated Linux VM for
that phase if the container runtime cannot provide a distinct kernel boot.
"""
import argparse
import hashlib
import json
import os
import pathlib
import signal
import sqlite3
from contextlib import closing
import pwd
import shutil
import subprocess
import sys
import time

from participation_smoke import Fixture

UNITS = ('agmi.service', 'agmi-health.service', 'agmi-health.timer')


def run(words, success=True):
    result = subprocess.run(words, capture_output=True, text=True, timeout=60)
    assert (result.returncode == 0) == success, (words, result.stdout, result.stderr)
    return result


def systemctl(*words):
    return run(['systemctl', '--user', *words]).stdout.strip()


def property_value(unit, name):
    return systemctl('show', unit, '--property=' + name, '--value')


def active(unit):
    return property_value(unit, 'ActiveState') == 'active'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def isolation(existing=False):
    assert sys.platform == 'linux' and pathlib.Path('/.dockerenv').is_file()
    assert pathlib.Path('/etc/agmi-systemd-fixture').read_text().strip() == 'agmi-isolated-systemd-acceptance'
    assert pathlib.Path('/proc/1/comm').read_text().strip() == 'systemd'
    account = pwd.getpwuid(os.getuid())
    assert account.pw_name == 'agmi-systemd-fixture' and account.pw_uid == 17321
    home = pathlib.Path('/home/agmi-systemd-fixture')
    assert account.pw_dir == str(home) and pathlib.Path.home() == home
    assert os.environ.get('HOME') == str(home)
    assert os.environ.get('XDG_RUNTIME_DIR') == '/run/user/17321'
    assert os.environ.get('DBUS_SESSION_BUS_ADDRESS') == 'unix:path=/run/user/17321/bus'
    assert pathlib.Path('/run/user/17321').stat().st_uid == os.getuid()
    for variable in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'SYSTEMD_UNIT_PATH', 'SYSTEMD_BUS_ADDRESS'):
        assert not os.environ.get(variable), variable
    if not existing:
        for unit in UNITS:
            assert property_value(unit, 'LoadState') == 'not-found', ('existing unit', unit)
        assert not (home / '.local/share/agmi').exists()
        assert not (home / '.config/agmi').exists()
        assert not (home / '.local/bin/agmi').exists()
    assert not (os.statvfs(os.environ.get('TMPDIR') or '/tmp').f_flag & os.ST_NOEXEC), (
        'Installer TMPDIR must allow execution; use --tmpfs /tmp:exec,mode=1777')
    return home


def embedded_manifest(binary):
    with binary.open('rb') as stream:
        assert stream.read(4) == b'\x7fELF', 'authentic Linux ELF required'
    return dict(line.split('=', 1) for line in
                run([str(binary), 'build-info', '--manifest']).stdout.splitlines())


def journal_rows(path, columns=None):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        names = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        result, captured = {}, {}
        for name in names if columns is None else columns:
            quoted = '"' + name.replace('"', '""') + '"'
            fields = [row[1] for row in db.execute('PRAGMA table_info(' + quoted + ')')] if columns is None else columns[name]
            # The format fence alone changes; all old source3 authority/data stays.
            fields = [field for field in fields if not (name == 'control' and field == 'version')]
            captured[name] = fields
            selected = ','.join('"' + field.replace('"', '""') + '"' for field in fields)
            result[name] = [list(row) for row in db.execute('SELECT ' + selected + ' FROM ' + quoted + ' ORDER BY rowid')]
        return result, captured


def assert_conversion_preserved(path, before, columns):
    expected = dict(before)
    # Format 3 allowed sparse cadence rows. Conversion provisions only missing
    # registered lanes; existing cadence/cursors and every other old row stay exact.
    fields = columns['schedule']
    kinds = {row[fields.index('kind')] for row in before['schedule']}
    expected['schedule'] = list(before['schedule'])
    for lane in ('answer', 'judge', 'mine'):
        if lane not in kinds:
            defaults = dict(kind=lane, next_at=0, cursor=None)
            expected['schedule'].append([defaults[field] for field in fields])
    actual = journal_rows(path, columns)[0]
    changed = [name for name in expected if actual[name] != expected[name]]
    assert not changed, ('conversion changed retained rows', changed)


def file_inventory(*roots):
    result = {}
    for root in roots:
        for path in sorted(root.rglob('*')):
            assert not path.is_symlink(), ('unexpected fixture authority symlink', path)
            if path.is_file():
                stat = path.stat()
                # A refused read-only SQLite open can touch SHM's mtime without
                # changing bytes. Keep all durable-file times and every hash/inode.
                mtime = None if path.name == 'state.sqlite3-shm' else stat.st_mtime_ns
                result[str(path)] = [digest(path), stat.st_dev, stat.st_ino, stat.st_mode, mtime]
    return result


def compatibility(binary, old, expected_old_hash, home):
    assert old is not None and expected_old_hash, 'preserved old ELF and external SHA256 are mandatory'
    assert digest(old) == expected_old_hash and digest(old) != digest(binary)
    old_manifest, current_manifest = embedded_manifest(old), embedded_manifest(binary)
    assert old_manifest['journal_schema'] == '3'
    current = int(current_manifest['journal_schema'])
    assert current > 3 and old_manifest != current_manifest
    config_root = home / '.config/agmi'
    config_root.mkdir(parents=True, mode=0o700)
    fixture = Fixture(str(old), config_root)
    releases = home / '.local/share/agmi/releases'
    current_id, old_id = 'r-' + digest(binary), 'r-' + digest(old)
    lock_root = home / '.agmi-account-locks'
    receipt_written = False

    def cli(executable, *words, success=True, data=None):
        command = [str(executable), '--json']
        if words[0] not in ('install', 'update', 'service'):
            command += ['--config', str(fixture.config)]
        completed = subprocess.run(command + list(words),
                                   input=None if data is None else json.dumps(data),
                                   capture_output=True, text=True, timeout=60)
        assert (completed.returncode == 0) == success, (words, completed.stdout, completed.stderr)
        if success:
            return json.loads(completed.stdout)['data']
        return completed

    try:
        # Obtain real retained uncertain work from the old executable against the
        # loopback protocol/native fixtures. This is not installed-native proof.
        fixture.start(resume=True)
        fixture.wait(lambda: bool(fixture.writes), 'old executable produced no retained effect')
        fixture.stop(crash=True)
        fixture.invoke('pause')
        for lane in fixture.lanes.values():
            lane['mode'] = 'off'
        fixture.configure()
        # Finish the old binary's own conservative crash recovery before taking
        # the immutable conversion baseline; migration does not rewrite it.
        fixture.start()
        fixture.wait(lambda: not fixture.rows(
            "SELECT id FROM operations WHERE state IN ('dispatching','generating')"),
            'old executable did not conservatively recover interrupted work')
        fixture.stop()
        assert fixture.rows('SELECT id FROM operations')
        assert fixture.rows('SELECT version FROM control')[0]['version'] == 3
        baseline, columns = journal_rows(fixture.database)
        private = {str(path): digest(path) for path in (fixture.config, fixture.key, fixture.core)}
        writes = len(fixture.writes)

        # No release pointer is not evidence of a fresh account.
        cli(binary, 'install', '--binary', str(binary), '--sha256', digest(binary), success=False)
        assert not (releases / 'current').exists()
        assert journal_rows(fixture.database, columns)[0] == baseline
        cli(old, 'install', '--binary', str(old), '--sha256', expected_old_hash)
        assert os.readlink(releases / 'current') == old_id
        cli(binary, 'update', '--binary', str(binary), '--sha256', digest(binary), '--stopped', success=False)
        assert os.readlink(releases / 'current') == old_id
        cli(binary, 'update', '--binary', str(binary), '--sha256', digest(binary), '--stopped', '--migration-only')
        assert os.readlink(releases / 'current') == current_id
        assert all(not active(unit) for unit in UNITS)
        assert all(property_value(unit, 'UnitFileState') in ('disabled', 'linked')
                   for unit in ('agmi.service', 'agmi-health.timer'))
        assert journal_rows(fixture.database, columns)[0] == baseline

        proposal = cli(binary, 'config', 'migrate', 'preview', data={})
        assert proposal['target_journal_format'] == current
        token = proposal['token']
        command = ['strace', '-f', '-o', str(home / 'conversion.strace'),
                   '-e', 'trace=rename,renameat,renameat2',
                   '-e', 'inject=rename:delay_enter=30s',
                   '-e', 'inject=renameat:delay_enter=30s',
                   '-e', 'inject=renameat2:delay_enter=30s',
                   str(binary), '--config', str(fixture.config), '--json', 'config', 'migrate', 'apply',
                   '--expected-token', token]
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
        child.stdin.write(json.dumps(proposal['request']))
        child.stdin.close()
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise AssertionError(('conversion exited before interruption', child.returncode, child.stderr.read()))
                with closing(sqlite3.connect(fixture.database.as_uri() + '?mode=ro', uri=True)) as db:
                    exists = db.execute("SELECT count(*) FROM sqlite_schema WHERE name='capability_migration'").fetchone()[0]
                    if exists and db.execute('SELECT phase FROM capability_migration').fetchone() == ('journal_ready',):
                        break
                time.sleep(0.01)
            else:
                raise AssertionError('did not observe durable conversion seal before rename')
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
            child.stdout.close()
            child.stderr.close()
        pending = cli(binary, 'config', 'migrate', 'status', '--state-dir', str(fixture.database.parent))
        assert pending['phase'] == 'journal_ready' and pending['token'] == token
        cli(binary, 'run', success=False)
        cli(binary, 'config', 'migrate', 'resume', '--state-dir', str(fixture.database.parent), '--expected-token', token)
        assert_conversion_preserved(fixture.database, baseline, columns)
        assert all(digest(pathlib.Path(path)) == value for path, value in private.items())
        assert fixture.rows('SELECT version FROM control')[0]['version'] == current

        # Genuine old refusal must precede WAL/DDL/binding/network changes.
        before = file_inventory(fixture.database.parent, lock_root)
        observations = (len(fixture.reads), len(fixture.writes))
        for command in ('status', 'pause', 'run'):
            cli(old, command, success=False)
            assert file_inventory(fixture.database.parent, lock_root) == before
            assert (len(fixture.reads), len(fixture.writes)) == observations
        for extra in ([], ['--migration-only']):
            cli(binary, 'update', '--release', old_id, '--stopped', *extra, success=False)
            assert os.readlink(releases / 'current') == current_id

        fixture.command = [str(binary), '--config', str(fixture.config), '--json']
        desired = fixture.invoke('lane', 'show', 'answer')['desired']
        fixture.invoke('lane', 'pause', 'answer', '--expected-control', desired['control_token'])
        protected = ['control', 'authority', 'operations', 'operation_evidence', 'operation_links',
                     'manual_grants', 'manual_grant_revocations', 'lane_control', 'capability_migration',
                     'capability_migration_evidence']
        before_restart, protected_columns = journal_rows(fixture.database)
        protected_columns = {name: protected_columns[name] for name in protected}
        def observed_runtime():
            rows = fixture.rows('SELECT runtime_instance,controller_stopped FROM runtime_state WHERE singleton=1')
            return rows[0]['runtime_instance'] if rows and not rows[0]['controller_stopped'] else None

        # Actual systemd process loss and restart, with no auto-resume.
        systemctl('start', 'agmi.service')
        assert active('agmi.service')
        fixture.wait(lambda: observed_runtime() is not None, 'systemd process did not initialize its runtime')
        first_runtime = observed_runtime()
        first_pid = property_value('agmi.service', 'MainPID')
        restarts = int(property_value('agmi.service', 'NRestarts'))
        systemctl('kill', '--kill-whom=main', '--signal=SIGKILL', 'agmi.service')
        fixture.wait(lambda: observed_runtime() not in (None, first_runtime),
                     'systemd did not automatically restart a new runtime incarnation')
        assert active('agmi.service')
        assert property_value('agmi.service', 'MainPID') != first_pid
        assert int(property_value('agmi.service', 'NRestarts')) > restarts
        systemctl('stop', *UNITS)
        assert journal_rows(fixture.database, protected_columns)[0] == {
            name: before_restart[name] for name in protected}
        assert len(fixture.writes) == writes
        assert fixture.status()['paused'] is True
        # Starting/restarting must preserve the migration-only disabled boot intent.
        # Another disable would remove the installed out-of-tree definition links.
        assert all(property_value(unit, 'UnitFileState') in ('disabled', 'linked')
                   for unit in ('agmi.service', 'agmi-health.timer'))
        rows, fields = journal_rows(fixture.database)
        receipt = {'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   'binary_sha256': digest(binary), 'old_sha256': expected_old_hash,
                   'database': str(fixture.database), 'release_id': current_id,
                   'private': private, 'authority_files': file_inventory(lock_root),
                   'rows': rows, 'columns': fields}
        path = home / 'atomic-reboot-receipt.json'
        with path.open('w') as stream:
            path.chmod(0o600)
            json.dump(receipt, stream)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        receipt_written = True
        print('PASS authentic old/new crossing, sealed interruption/recovery, refusal, restart and preservation; real kernel reboot phase still required', flush=True)
    finally:
        primary_failure = sys.exc_info()[0] is not None
        try:
            try:
                loaded = [unit for unit in UNITS if property_value(unit, 'LoadState') != 'not-found']
                if loaded:
                    systemctl('stop', *loaded)
            finally:
                if receipt_written:
                    # Preserve the exact authority inodes for the separate reboot phase.
                    fixture.stop()
                    fixture.server.shutdown()
                    fixture.server.server_close()
                    fixture.thread.join(timeout=5)
                else:
                    fixture.close()
        except Exception as error:
            if not primary_failure:
                raise
            print(f'Additional fixture cleanup failure: {error}', file=sys.stderr)


def after_reboot(binary, home):
    receipt = json.loads((home / 'atomic-reboot-receipt.json').read_text())
    assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() != receipt['boot_id'], (
        'a real kernel reboot is required; manager/container restart is insufficient')
    assert digest(binary) == receipt['binary_sha256']
    assert os.readlink(home / '.local/share/agmi/releases/current') == receipt['release_id']
    assert all(not active(unit) for unit in UNITS), 'migration boot intent unexpectedly started a unit'
    assert all(property_value(unit, 'UnitFileState') in ('disabled', 'linked')
               for unit in ('agmi.service', 'agmi-health.timer'))
    assert journal_rows(pathlib.Path(receipt['database']), receipt['columns'])[0] == receipt['rows']
    assert file_inventory(home / '.agmi-account-locks') == receipt['authority_files']
    assert all(digest(pathlib.Path(path)) == value for path, value in receipt['private'].items())
    print('PASS real kernel reboot preserves disabled boot intent, journal/evidence, authority inodes, configuration, guidance and credential', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--suite', choices=('current', 'compatibility', 'after-reboot'), default='current')
    parser.add_argument('--old-binary', type=pathlib.Path)
    parser.add_argument('--old-sha256')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    home = isolation(existing=args.suite == 'after-reboot')
    if args.suite == 'compatibility':
        compatibility(binary, args.old_binary.resolve(strict=True) if args.old_binary else None,
                      args.old_sha256, home)
        return
    if args.suite == 'after-reboot':
        after_reboot(binary, home)
        return
    config_root = home / '.config/agmi'
    config_root.mkdir(parents=True, mode=0o700)
    fixture = Fixture(str(binary), config_root)
    fixture.lanes['answer']['mode'] = 'off'
    fixture.lanes['judge']['mode'] = 'off'
    fixture.lanes['mine']['mode'] = 'off'
    fixture.configure()
    releases = home / '.local/share/agmi/releases'
    unit_dir = home / '.config/systemd/user'
    runtime_override = pathlib.Path('/run/user/17321/systemd/user/agmi.service.d')
    candidates = home / 'fixture-releases'
    candidates.mkdir(mode=0o700)
    first = candidates / 'agmi-a'
    second = candidates / 'agmi-b'
    shutil.copy2(binary, first)
    shutil.copy2(binary, second)
    with second.open('ab') as stream:
        stream.write(b'\nagmi isolated systemd fixture release B\n')
    first.chmod(0o700)
    second.chmod(0o700)
    hashes = {candidate: digest(candidate) for candidate in (first, second)}
    ids = {candidate: 'r-' + value for candidate, value in hashes.items()}
    assert ids[first] != ids[second]

    def cli(*words, success=True):
        result = run([str(binary), '--json', *words], success=success)
        envelope = json.loads(result.stdout if success or words[0] == 'update' else result.stderr)
        assert envelope['schema'] == 'agmi.cli.v1'
        if words[0] == 'update':
            assert envelope['type'] == 'update' and envelope['ok'] is success
            return envelope['data']
        return envelope['data'] if success else envelope['error']

    def selected(candidate, runtime=False, timer=False):
        release_id = ids[candidate]
        assert os.readlink(releases / 'current') == release_id
        assert digest(releases / release_id / 'agmi') == hashes[candidate]
        assert (home / '.local/bin/agmi').resolve() == releases / release_id / 'agmi'
        for unit in UNITS:
            assert (unit_dir / unit).resolve() == releases / release_id / unit
            assert property_value(unit, 'Description').endswith('[release=' + release_id + ']')
            assert not property_value(unit, 'DropInPaths')
        assert property_value('agmi.service', 'TimeoutStopUSec') == 'infinity'
        assert active('agmi.service') == runtime
        assert active('agmi-health.timer') == timer
        if runtime:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = fixture.status()
                if status.get('effective_runtime'):
                    break
                time.sleep(0.05)
            else:
                raise AssertionError('systemd runtime did not publish loaded configuration')
            pid = int(property_value('agmi.service', 'MainPID'))
            assert pid > 0 and digest(pathlib.Path(f'/proc/{pid}/exe')) == hashes[candidate]
        else:
            assert property_value('agmi.service', 'MainPID') == '0'
        assert fixture.status()['paused'] is True
        assert fixture.key.read_text() == 'pk_test_fixture'
        assert not fixture.writes and not fixture.model_calls('answer')

    def install(action, candidate, **kwargs):
        data = cli(action, '--binary', str(candidate), '--sha256', hashes[candidate], **kwargs)
        if kwargs.get('success', True):
            evidence = data['installation']
            assert evidence['failure_code'] == 'none'
            assert evidence['stage'] == 'complete' and evidence['activation'] == 'loaded_verified'
        return data

    def activate(candidate, *extra):
        data = cli('update', '--release', ids[candidate], *extra)
        assert data['installation']['activation'] == 'loaded_verified'
        return data

    try:
        # Public staging replaces direct installer entrypoints. Both the current
        # binary and a distinct incoming image must stage without selecting a
        # release, creating state, installing bindings or contacting live units.
        private_inputs = {path: path.read_bytes() for path in (fixture.config, fixture.key)}
        assert not fixture.database.exists()
        for candidate in (first, second):
            data = cli('install', '--stage-only', '--binary', str(candidate), '--sha256', hashes[candidate])
            evidence = data['installation']
            assert evidence['failure_code'] == 'none' and evidence['staging'] == 'complete'
            assert evidence['activation'] == 'not_started'
            assert (releases / ids[candidate] / 'SHA256SUMS').is_file()
            assert not (releases / 'current').is_symlink()
            assert not (home / '.local/bin/agmi').is_symlink()
            assert not fixture.database.exists()
            assert all(property_value(unit, 'LoadState') == 'not-found' for unit in UNITS)
            assert all(path.read_bytes() == value for path, value in private_inputs.items())
        print('PASS public stage-only with incoming-owned staging and no state or activation', flush=True)

        fixture.invoke('pause')  # A real initialized, paused journal, no participation.
        journal = digest(fixture.database)
        install('install', first)
        selected(first)
        assert systemctl('is-enabled', 'agmi.service', 'agmi-health.timer').splitlines() == ['enabled', 'enabled']
        assert digest(fixture.database) == journal
        install('update', second)
        selected(second)
        activate(first)
        selected(first)
        assert digest(fixture.database) == journal
        print('PASS fresh install, stopped forward update and retained activation', flush=True)

        definitions = {unit: os.readlink(unit_dir / unit) for unit in UNITS}
        cli('service', 'disable')
        selected(first)
        assert {unit: os.readlink(unit_dir / unit) for unit in UNITS} == definitions
        assert all(property_value(unit, 'UnitFileState') in ('disabled', 'linked')
                   for unit in ('agmi.service', 'agmi-health.timer'))
        cli('service', 'enable')
        selected(first)
        assert systemctl('is-enabled', 'agmi.service', 'agmi-health.timer').splitlines() == ['enabled', 'enabled']
        assert digest(fixture.database) == journal
        print('PASS service disable preserves definitions and permits re-enable without starting work', flush=True)

        cli('service', 'start')
        selected(first, runtime=True, timer=True)
        install('update', second)
        selected(second, runtime=True, timer=True)
        activate(first)
        selected(first, runtime=True, timer=True)
        print('PASS running forward update and retained activation with real process identity', flush=True)

        systemctl('stop', 'agmi.service')
        install('update', second)
        selected(second, timer=True)
        systemctl('stop', 'agmi-health.timer', 'agmi-health.service')
        systemctl('start', 'agmi.service')
        activate(first)
        selected(first, runtime=True)
        activate(second, '--stopped')
        selected(second)
        print('PASS independent runtime/timer intent and explicit stopped activation', flush=True)

        # A real runtime-directory override is accepted syntactically at preflight
        # but rejected by loaded-unit verification AFTER current is selected. No
        # fake systemctl, installer patch, journal mutation or failure hook.
        journal = digest(fixture.database)
        runtime_override.mkdir(parents=True, mode=0o700)
        (runtime_override / 'fixture.conf').write_text('[Unit]\nDescription=isolated fixture post-switch rejection\n')
        error = cli('update', '--release', ids[first], success=False)
        assert error['update']['reason'] == 'installer_failed'
        evidence = error['installation']
        assert evidence['failure_code'] == 'reload_failed'
        assert evidence['stage'] == 'reloading' and evidence['activation'] == 'selected'
        assert evidence['service'] == 'stopped'
        assert os.readlink(releases / 'current') == ids[first], 'failed activation silently reverted pointer'
        assert all(not active(unit) for unit in UNITS)
        assert property_value('agmi.service', 'MainPID') == '0'
        assert digest(fixture.database) == journal, 'failed activation changed or rewound journal'
        assert all((releases / ids[candidate]).is_dir() for candidate in (first, second))
        assert fixture.key.read_text() == 'pk_test_fixture' and not fixture.writes
        print('PASS post-switch failure stops units, retains selected release and preserves journal', flush=True)
    finally:
        # This manager was proven disposable before the first mutation. Missing
        # units are normal after a preflight failure; cleanup must not hide it.
        primary_failure = sys.exc_info()[0] is not None
        try:
            try:
                loaded = [unit for unit in reversed(UNITS)
                          if property_value(unit, 'LoadState') != 'not-found']
                if loaded:
                    systemctl('stop', *loaded)
            finally:
                fixture.close()
        except Exception as error:
            if not primary_failure:
                raise
            print(f'Additional fixture cleanup failure: {error}', file=sys.stderr)


if __name__ == '__main__':
    main()
