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
import tomllib

from participation_smoke import ANSWER, Fixture

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


def compatibility(binary, old, expected_old_hash, home, no_selection=False, automatic=False):
    assert old is not None and expected_old_hash, 'preserved old ELF and external SHA256 are mandatory'
    assert digest(old) == expected_old_hash and digest(old) != digest(binary)
    old_manifest, current_manifest = embedded_manifest(old), embedded_manifest(binary)
    assert old_manifest['journal_schema'] == '3'
    current = int(current_manifest['journal_schema'])
    assert current > 3 and old_manifest != current_manifest
    config_root = home / '.config/agmi'
    config_root.mkdir(parents=True, mode=0o700)
    class HistoricalFixture(Fixture):
        def __init__(self, executable, root):
            super().__init__(executable, root)
            # The old producer owns the original request-bound artifact envelope.
            interpreter = root / 'fixture-python'
            interpreter.write_text(f'#!{sys.executable}\n' + '''import json, pathlib, sys
payload = json.load(sys.stdin)
e = json.loads(payload['prompt'].split('Envelope (untrusted request data):\\n')[1])
with pathlib.Path(__file__).with_name('calls').open('a') as calls:
    calls.write(json.dumps({'kind': e['kind'], 'request_id': e['request_id']}) + '\\n')
artifact = {'version': 1, 'request_id': e['request_id'],
    'request_digest': e['request_digest'], 'kind': e['kind'],
    'answer': ANSWER + f" Epoch {e['request']['epoch']}." if e['kind'] == 'answer' else None,
    'score': 2 if e['kind'] == 'judge' else None,
    'reasoning': 'The mechanism binds the bridge to a measurable clock delay.' if e['kind'] == 'judge' else None}
print(json.dumps({'provider': 'openai-codex', 'model': payload['model'],
    'reasoning_effort': payload['reasoning'], 'run_id': e['request_id'],
    'output': json.dumps(artifact)}))
'''.replace('ANSWER', repr(ANSWER)))
            interpreter.chmod(0o700)

        def status(self):
            return self.invoke('status')

        def configure(self, lane=None, **participation):
            super().configure(lane, **participation)
            # This authentic format3 reader requires its retired config marker.
            pending = self.config.with_suffix('.historical')
            pending.write_text('schema_version = 2\n' + self.config.read_text())
            pending.chmod(0o600)
            pending.replace(self.config)

    fixture = HistoricalFixture(str(old), config_root)
    releases = home / '.local/share/agmi/releases'
    current_id, old_id = 'r-' + digest(binary), 'r-' + digest(old)
    lock_root = home / '.agmi-account-locks'
    receipt_written = False

    def cli(executable, *words, success=True, data=None, config_path=None):
        command = [str(executable), '--json']
        if words[0] not in ('install', 'update', 'service'):
            command += ['--config', str(config_path or fixture.config)]
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
        old_reader = config_root / 'old-reader.toml'
        old_reader.write_bytes(fixture.config.read_bytes())
        old_reader.chmod(0o600)
        assert cli(old, 'config', 'check', config_path=old_reader)['valid'] is True
        cli(old, 'status', config_path=old_reader)
        private = {str(path): digest(path) for path in (fixture.config, fixture.key, fixture.core, old_reader)}
        writes = len(fixture.writes)

        # The new permanent lease cannot be consumed by the frozen installer's
        # old mkdir lock. Exercise missing selection in a separate fresh case.
        if no_selection:
            cli(binary, 'install', '--binary', str(binary), '--sha256', digest(binary), success=False)
            assert not (releases / 'current').exists()
            assert journal_rows(fixture.database, columns)[0] == baseline
            assert all(digest(pathlib.Path(path)) == value for path, value in private.items())
            print('PASS missing selection never makes an authentic historical journal fresh', flush=True)
            return
        cli(old, 'install', '--binary', str(old), '--sha256', expected_old_hash)
        assert os.readlink(releases / 'current') == old_id
        if automatic:
            result = cli(binary, 'update', '--binary', str(binary), '--sha256', digest(binary))
            assert result['update']['status'] == 'updated'
            assert result['migration']['phase'] == 'complete'
            assert result['restoration']['verified'] is True
            assert_conversion_preserved(fixture.database, baseline, columns)
            expected = tomllib.loads(old_reader.read_text())
            expected.pop('schema_version')
            assert tomllib.loads(fixture.config.read_text()) == expected
            assert all(digest(pathlib.Path(path)) == value for path, value in private.items()
                       if pathlib.Path(path) != fixture.config)
            assert all(not active(unit) for unit in UNITS)
            assert len(fixture.writes) == writes
            assert not (releases / '.update-state.json').exists()
            print('PASS plain authentic source3 upgrade preserves uncertain history, policy and stopped/paused intent', flush=True)
            return
        cli(binary, 'update', '--binary', str(binary), '--sha256', digest(binary),
            '--stopped', '--dry-run')
        assert os.readlink(releases / 'current') == old_id
        original_policy = tomllib.loads(fixture.config.read_text())
        assert original_policy.pop('schema_version') == 2
        command = ['strace', '-f', '-o', str(home / 'conversion.strace'),
                   '-e', 'trace=rename,renameat,renameat2',
                   '-e', 'inject=rename:delay_enter=2s',
                   '-e', 'inject=renameat:delay_enter=2s',
                   '-e', 'inject=renameat2:delay_enter=2s',
                   str(binary), '--json', 'update', '--binary', str(binary),
                   '--sha256', digest(binary), '--migrate']
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
        try:
            deadline = time.monotonic() + 60
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
        assert pending['phase'] == 'journal_ready'
        token = pending['token']
        sealed = cli(binary, 'config', 'migrate', 'export',
                     '--state-dir', str(fixture.database.parent), '--expected-token', token)
        assert tomllib.loads(sealed['candidate_toml']) == original_policy
        cli(binary, 'run', success=False)
        recovered = cli(binary, 'update')
        assert recovered['migration']['phase'] == 'complete'
        assert recovered['migration']['token'] == token
        assert recovered['migration']['participation_resumed'] is False
        expected_config = hashlib.sha256(sealed['candidate_toml'].encode()).hexdigest()
        assert digest(fixture.config) == expected_config, 'configuration differs from approved candidate'
        private[str(fixture.config)] = expected_config
        assert_conversion_preserved(fixture.database, baseline, columns)
        assert all(digest(pathlib.Path(path)) == value for path, value in private.items())
        assert fixture.rows('SELECT version FROM control')[0]['version'] == current

        # Genuine old refusal must precede WAL/DDL/binding/network changes.
        before = file_inventory(fixture.database.parent, lock_root)
        observations = (len(fixture.reads), len(fixture.writes))
        for command in ('status', 'pause', 'run'):
            if command == 'status':
                trace = home / 'old-status.strace'
                trace.touch(mode=0o600)
                refused = run(['strace', '-f', '-qq', '-s', '4096', '-e', 'trace=openat',
                               '-o', str(trace), str(old), '--config', str(old_reader),
                               '--json', command], success=False)
                opened = [line for line in trace.read_text().splitlines()
                          if f'"{fixture.database}"' in line]
                assert opened, 'old reader never opened the converted journal'
                assert any(line.rsplit(' = ', 1)[-1].strip().isdigit() for line in opened), (
                    'old reader never successfully opened the converted journal')
                assert all('O_RDONLY' in line and 'O_RDWR' not in line and 'O_WRONLY' not in line
                           for line in opened), 'old reader opened the journal for writing'
            else:
                refused = cli(old, command, success=False, config_path=old_reader)
            # The authentic CLI redacts the underlying unsupported-schema cause.
            # Valid old config and a read-only DB open rule out a parse-only pass.
            assert json.loads(refused.stderr)['error']['code'] == 'operation_failed'
            assert file_inventory(fixture.database.parent, lock_root) == before
            assert (len(fixture.reads), len(fixture.writes)) == observations
            assert all(digest(pathlib.Path(path)) == value for path, value in private.items())
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
        assert all(digest(pathlib.Path(path)) == value for path, value in private.items())
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


def seamless(binary, old, expected_old_hash, home, maintenance=False, config_only=False):
    assert old is not None and expected_old_hash, 'authentic pre-feature format4 source required'
    assert digest(old) == expected_old_hash and digest(old) != digest(binary)
    assert embedded_manifest(old)['journal_schema'] == '4'
    config_root = home / '.config/agmi'
    config_root.mkdir(parents=True, mode=0o700)
    fixture = Fixture(str(binary), config_root)
    for lane in fixture.lanes.values():
        lane['mode'] = 'off'
    fixture.configure()
    if not config_only:
        fixture.invoke('pause')
    fixture.config.write_text('schema_version = 2\n' + fixture.config.read_text())
    fixture.config.chmod(0o600)
    original = tomllib.loads(fixture.config.read_text())
    expected = dict(original)
    expected.pop('schema_version')
    private_files = {path: path.read_bytes()
                     for path in (fixture.key, fixture.core)}
    releases = home / '.local/share/agmi/releases'
    record = releases / '.update-state.json'
    candidates = home / 'seamless-candidates'
    candidates.mkdir(mode=0o700)
    alternate = candidates / 'agmi-alternate'
    shutil.copy2(binary, alternate)
    alternate.chmod(0o700)
    with alternate.open('ab') as stream:
        stream.write(b'\nagmi seamless fixture alternate image\n')
    hashes = {path: digest(path) for path in (binary, alternate)}

    def cli(executable, *words):
        result = run([str(executable), '--json', *words])
        envelope = json.loads(result.stdout)
        assert envelope['ok'] is True, envelope
        return envelope['data']

    def control():
        with closing(sqlite3.connect(fixture.database.as_uri() + '?mode=ro', uri=True)) as db:
            return db.execute('SELECT paused,generation,version FROM control WHERE singleton=1').fetchone()

    def authority():
        with closing(sqlite3.connect(fixture.database.as_uri() + '?mode=ro', uri=True)) as db:
            return db.execute('SELECT database_id,dispatch_sequence FROM authority WHERE singleton=1').fetchone()

    def assert_intent(candidate, paused, runtime, timer, service_boot, timer_boot):
        assert (releases / 'current').resolve().name == 'r-' + hashes[candidate]
        assert active('agmi.service') is runtime
        assert active('agmi-health.timer') is timer
        assert property_value('agmi.service', 'UnitFileState') == service_boot
        assert property_value('agmi-health.timer', 'UnitFileState') == timer_boot
        assert bool(control()[0]) is paused
        assert tomllib.loads(fixture.config.read_text()) == expected
        assert all(path.read_bytes() == value for path, value in private_files.items())
        assert authority() == initial_authority
        assert not fixture.writes and not fixture.model_calls('answer')
        if runtime:
            pid = int(property_value('agmi.service', 'MainPID'))
            assert digest(pathlib.Path(f'/proc/{pid}/exe')) == hashes[candidate]
            policy = fixture.status()['effective_runtime']['policy']
            assert policy['process']['pid'] == pid
            assert policy['process']['invocation_id'] == property_value('agmi.service', 'InvocationID')
        else:
            assert property_value('agmi.service', 'MainPID') == '0'

    def prior_boot_input():
        captured = json.loads(record.read_text())
        simulated_prior_boot = '11111111-1111-4111-8111-111111111111'
        assert captured['payload']['boot'] != simulated_prior_boot
        captured['payload']['boot'] = simulated_prior_boot
        temporary = record.with_suffix('.fixture-input')
        temporary.write_text(json.dumps(captured))
        temporary.chmod(0o600)
        temporary.replace(record)

    def interrupt(candidate, boundary='prepared'):
        assert not record.exists()
        trace = home / f'seamless-interrupted-{boundary}.trace'
        command = [str(binary), '--json', 'update', '--binary', str(candidate),
                   '--sha256', hashes[candidate]]
        env = dict(os.environ)
        gate = home / 'seamless-disable-returned'
        if boundary == 'disabled':
            if maintenance:
                command.append('--migrate')
            wrapper_dir = home / 'systemctl-reply-gate'
            wrapper_dir.mkdir(mode=0o700)
            wrapper = wrapper_dir / 'systemctl'
            # The real manager removes its actual definition links. Hold only
            # the client's return so the updater can be killed before repair.
            wrapper.write_text('#!/bin/sh\n/usr/bin/systemctl "$@"\nstatus=$?\n'
                               'for arg do\nif [ "$arg" = disable ]; then\n'
                               f': > {gate}\nsleep 45\nfi\ndone\nexit "$status"\n')
            wrapper.chmod(0o700)
            env['PATH'] = str(wrapper_dir) + os.pathsep + env['PATH']
        else:
            command = ['strace', '-f', '-o', str(trace),
                       '-e', 'trace=rename,renameat,renameat2',
                       '-e', 'inject=rename:delay_exit=2s', *command]
        with (home / f'seamless-interrupted-{boundary}.stdout').open('w') as output, \
                (home / f'seamless-interrupted-{boundary}.stderr').open('w') as errors:
            child = subprocess.Popen(command, stdout=output, stderr=errors,
                                     start_new_session=True, env=env)
            try:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    assert child.poll() is None, 'updater exited before interruption boundary'
                    if record.exists():
                        phase = json.loads(record.read_text())['payload']['phase']
                        reached = (
                            boundary == 'prepared'
                            or (boundary == 'ready' and phase in ('runtime_ready', 'restoring', 'complete'))
                            or (boundary == 'complete' and phase == 'complete')
                            or (boundary == 'config_only' and phase == 'converting'
                                and tomllib.loads(fixture.config.read_text()) == expected)
                            or (boundary == 'disabled' and gate.exists() and any(
                                not (home / '.config/systemd/user' / unit).is_symlink()
                                for unit in UNITS)))
                        if reached:
                            break
                    time.sleep(0.01)
                else:
                    raise AssertionError('did not observe durable update interruption boundary')
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
        assert record.exists(), 'hard kill lost pinned original intent'


    try:
        cli(old, 'install', '--binary', str(old), '--sha256', expected_old_hash)
        if config_only:
            interrupt(binary, 'config_only')
            assert not fixture.database.exists()
            cli(binary, 'service', 'stop')
            result = cli(binary, 'update')
            assert result['migration']['phase'] == 'complete'
            assert result['restoration']['status'] == 'cancelled'
            assert result['restoration']['verified'] is False
            assert not fixture.database.exists() and not record.exists()
            assert tomllib.loads(fixture.config.read_text()) == expected
            assert all(path.read_bytes() == value for path, value in private_files.items())
            assert all(not active(unit) for unit in UNITS)
            print('PASS cancelled config-only commit finishes without inventing a journal or replaying intent', flush=True)
            return
        cli(old, 'resume')
        cli(old, 'service', 'enable')
        cli(old, 'service', 'start')
        initial_authority = authority()
        before = control()
        old_pid = property_value('agmi.service', 'MainPID')
        interrupt(binary, 'disabled')
        assert control() == before
        result = cli(binary, 'update')
        if maintenance:
            assert result['update']['status'] == 'migration_complete_stopped'
            assert result['installation']['operation_mode'] == 'maintenance'
            assert result['restoration']['status'] == 'not_needed'
            assert result['restoration']['verified'] is False
            assert control() == (1, before[1] + 1, before[2])
            assert_intent(binary, True, False, False, 'linked', 'linked')
            assert not record.exists()
            print('PASS plain pinned rerun preserves explicit stopped maintenance and reports its persisted mode', flush=True)
            return
        assert result['update']['status'] == 'updated'
        assert result['restoration']['verified'] is True
        assert control() == (0, before[1] + 2, before[2])
        assert property_value('agmi.service', 'MainPID') != old_pid
        assert_intent(binary, False, True, True, 'enabled', 'enabled')
        print('PASS one-command authentic marker4 conversion restores running/unpaused intent and identity', flush=True)
        print('PASS hard kill after real boot-disable link removal recovers original definitions and intent', flush=True)

        pid = property_value('agmi.service', 'MainPID')
        before = control()
        for flags in ((), ('--migrate',)):
            result = cli(binary, 'update', '--release', 'r-' + hashes[binary], *flags)
            assert result['update']['status'] == 'current'
            assert property_value('agmi.service', 'MainPID') == pid and control() == before
        print('PASS already-current update does not interrupt the controller or advance generation', flush=True)

        cli(binary, 'pause')
        cli(binary, 'service', 'disable')
        systemctl('stop', 'agmi-health.timer', 'agmi-health.service')
        before = control()
        result = cli(binary, 'update', '--binary', str(alternate), '--sha256', hashes[alternate])
        assert result['restoration']['verified'] is True and control() == before
        assert_intent(alternate, True, True, False, 'linked', 'linked')
        print('PASS paused active runtime and inactive timer retain independent disabled boot intent', flush=True)

        cli(alternate, 'resume')
        cli(alternate, 'service', 'stop')
        systemctl('enable', '--runtime', 'agmi-health.timer')
        systemctl('start', 'agmi-health.timer')
        before = control()
        result = cli(binary, 'update', '--binary', str(binary), '--sha256', hashes[binary])
        assert result['restoration']['verified'] is True and control() == before
        assert_intent(binary, False, False, True, 'linked', 'enabled-runtime')
        print('PASS stopped unpaused runtime and runtime-only timer enablement remain independent', flush=True)

        # Delay real rename returns; SIGKILL updater children after publication.
        interrupt(alternate)
        before = control()
        for flag in ('--stopped', '--migrate'):
            refused = run([str(binary), '--json', 'update', flag], success=False)
            assert json.loads(refused.stdout)['data']['update']['status'] == 'recovery_required'
            assert control() == before and record.exists()
            assert_intent(binary, False, False, True, 'linked', 'enabled-runtime')
        result = cli(binary, 'update')
        assert result['update']['status'] in ('updated', 'current')
        assert result['restoration']['verified'] is True
        assert_intent(alternate, False, False, True, 'linked', 'enabled-runtime')
        assert not record.exists()
        print('PASS killed updater releases lease and plain offline rerun finishes exact pinned target', flush=True)

        # A later canonical command, even with the same pause value, cancels
        # historical restoration after cutover instead of resurrecting a timer.
        interrupt(binary, 'ready')
        before = control()
        cli(binary, 'resume')
        assert control() == (0, before[1] + 1, before[2])
        cli(binary, 'service', 'stop')
        operator_control = control()
        result = cli(binary, 'update')
        assert result['restoration']['status'] == 'cancelled'
        assert result['restoration']['verified'] is False
        assert control() == operator_control
        assert_intent(binary, False, False, False, 'linked', 'enabled-runtime')
        assert not record.exists()
        print('PASS same-valued newer operator control cancels stale timer and pause restoration', flush=True)

        before = control()
        interrupt(alternate, 'complete')
        result = cli(binary, 'update')
        assert result['restoration']['verified'] is True and control() == before
        assert result['migration']['phase'] == 'not_required'
        assert_intent(alternate, False, False, False, 'linked', 'enabled-runtime')
        assert not record.exists()
        print('PASS complete-before-unlink recovery revalidates intent without a false incomplete report', flush=True)

        # Simulate only the saved prior-boot input, not a kernel reboot. Real
        # systemd activity is restored independently of expired runtime links.
        for runtime_only_unit, candidate in (
                ('agmi.service', binary), ('agmi-health.timer', alternate)):
            cli(binary, 'service', 'disable')
            cli(binary, 'service', 'start')
            systemctl('enable', '--runtime', runtime_only_unit)
            before = control()
            interrupt(candidate)
            prior_boot_input()
            systemctl('stop', *UNITS)
            systemctl('disable', '--runtime', runtime_only_unit)
            systemctl('daemon-reload')
            result = cli(binary, 'update')
            assert result['restoration']['verified'] is True and control() == before
            assert_intent(candidate, False, True, True, 'linked', 'linked')
            assert not record.exists()
            print(f'PASS simulated changed-boot preserves both active roles while {runtime_only_unit} runtime-only enablement expires', flush=True)

        # A complete record is cleanup, not permission to replay prior-boot
        # activity. Model both boot-disabled stop and persistent autostart.
        cli(binary, 'service', 'disable')
        before = control()
        interrupt(binary, 'complete')
        prior_boot_input()
        systemctl('stop', *UNITS)
        result = cli(binary, 'update')
        assert result['restoration']['status'] == 'not_needed'
        assert result['restoration']['verified'] is False
        assert result['installation']['service'] == 'unchanged'
        assert control() == before and not record.exists()
        assert_intent(binary, False, False, False, 'linked', 'linked')
        print('PASS simulated post-completion reboot clears record without replaying active/boot-disabled roles', flush=True)

        cli(binary, 'service', 'enable')
        before = control()
        interrupt(alternate, 'complete')
        prior_boot_input()
        systemctl('start', 'agmi.service', 'agmi-health.timer')
        result = cli(binary, 'update')
        assert result['restoration']['status'] == 'not_needed'
        assert result['installation']['service'] == 'unchanged'
        assert control() == before and not record.exists()
        assert_intent(alternate, False, True, True, 'enabled', 'enabled')
        print('PASS simulated post-completion reboot accepts persistent autostart without replaying formerly stopped roles', flush=True)
    finally:
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


def future_handoff(binary, future, expected_hash, home, recovery=False):
    assert future is not None and expected_hash and digest(future) == expected_hash
    assert int(embedded_manifest(future)['journal_schema']) > int(embedded_manifest(binary)['journal_schema'])
    config_root = home / '.config/agmi'
    config_root.mkdir(parents=True, mode=0o700)
    fixture = Fixture(str(future if recovery else binary), config_root)
    for lane in fixture.lanes.values():
        lane['mode'] = 'off'
    fixture.configure()
    fixture.invoke('pause')
    releases = home / '.local/share/agmi/releases'
    record = releases / '.update-state.json'
    source = future if recovery else binary
    private = {path: path.read_bytes() for path in (fixture.config, fixture.key, fixture.core)}
    protected = ('control', 'authority', 'operations', 'operation_evidence', 'manual_grants',
                 'manual_grant_revocations', 'lane_control')
    baseline = {table: fixture.rows(f'SELECT * FROM {table} ORDER BY rowid') for table in protected}
    assert baseline['control'][0]['version'] == int(embedded_manifest(source)['journal_schema'])
    try:
        run([str(source), '--json', 'install', '--binary', str(source), '--sha256', digest(source)])
        if recovery:
            run([str(binary), '--config', str(fixture.config), '--json', 'status'], success=False)
            alternate = home / 'agmi-future-alternate'
            shutil.copy2(future, alternate)
            alternate.chmod(0o700)
            with alternate.open('ab') as stream:
                stream.write(b'\nagmi future recovery fixture alternate image\n')
            target = 'r-' + digest(alternate)
            with (home / 'future-interrupted.stdout').open('w') as output, \
                    (home / 'future-interrupted.stderr').open('w') as errors:
                child = subprocess.Popen([
                    'strace', '-f', '-o', str(home / 'future-interrupted.trace'),
                    '-e', 'trace=rename,renameat,renameat2', '-e', 'inject=rename:delay_exit=2s',
                    str(future), '--json', 'update', '--binary', str(alternate),
                    '--sha256', digest(alternate),
                ], stdout=output, stderr=errors, start_new_session=True)
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline and not record.exists():
                        assert child.poll() is None, 'future updater exited before durable record'
                        time.sleep(0.01)
                    assert record.exists()
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
            # This older caller cannot open the actual newer journal. Recovery
            # must route the pinned target before latest discovery or data reads.
            completed = run([str(binary), '--json', 'update'])
            report = json.loads(completed.stdout)['data']
            assert report['restoration']['verified'] is True
            assert (releases / 'current').resolve().name == target and not record.exists()
            print('PASS older caller completes pinned newer-journal transaction offline through its real target', flush=True)
        else:
            trace = home / 'future-refusal.trace'
            refused = run(['strace', '-f', '-s', '4096', '-e', 'trace=execve', '-o', str(trace),
                           str(binary), '--json', 'update', '--binary', str(future),
                           '--sha256', expected_hash], success=False)
            assert json.loads(refused.stdout)['ok'] is False
            delegated = False
            for line in trace.read_text().splitlines():
                if 'execve(' not in line or ' = 0' not in line or expected_hash not in line:
                    continue
                executable, arguments = line.split('execve(', 1)[1].split(', [', 1)
                executable = json.loads(executable)
                arguments = json.loads('[' + arguments.split('],', 1)[0] + ']')
                if 'update' in arguments and '--binary' in arguments:
                    delegated |= (executable != str(binary)
                                  and arguments[arguments.index('--binary') + 1] == executable)
            assert delegated, 'verified incoming target never received its own public update handoff'
            assert (releases / 'current').resolve().name == 'r-' + digest(binary)
            assert not record.exists()
            print('PASS future-format acquisition delegates source compatibility refusal to the real incoming target', flush=True)
        assert all(path.read_bytes() == value for path, value in private.items())
        assert {table: fixture.rows(f'SELECT * FROM {table} ORDER BY rowid')
                for table in protected} == baseline
        assert all(not active(unit) for unit in UNITS)
        assert not fixture.writes and not fixture.model_calls('answer')
    finally:
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


def published_upgrade(binary, old, expected_hash, home):
    assert old is not None and expected_hash and digest(old) == expected_hash
    assert embedded_manifest(old)['journal_schema'] == '2'
    config_root = home / '.config/agmi'
    config_root.mkdir(parents=True, mode=0o700)
    fixture = Fixture(str(binary), config_root)
    def table(name, values):
        value = lambda item: str(item).lower() if isinstance(item, bool) else json.dumps(item)
        return '[' + name + ']\n' + '\n'.join(
            f'{key} = {value(item)}' for key, item in values.items()) + '\n'
    source = 'state_dir = ' + json.dumps(str(fixture.database.parent)) + '\n'
    source += table('network', dict(base_url=f'http://127.0.0.1:{fixture.server.server_port}',
                                   chain=fixture.chain, address=fixture.address,
                                   credential_file=str(fixture.key)))
    source += table('capabilities', dict(answer='off', judge='off', mine='off'))
    for lane in ('answer', 'judge'):
        source += table('solver.' + lane, dict(harness='hermes', executable=str(fixture.native),
                        model='openai/test', reasoning='high', guidance_file=str(fixture.core)))
    source += table('timeouts', dict(http_seconds=2, read_http_seconds=2,
                                    model_seconds=10, shutdown_seconds=2))
    source += table('schedule', dict(poll_seconds=1, mine_seconds=86400,
                                    retry_seconds=1, backoff_max_seconds=900, jitter_seconds=0))
    source += table('participation', dict(mode='participation_first', uncertainty_grace_seconds=1,
                                        max_unresolved_operations=4, allow_answer=True,
                                        allow_judge=False, allow_mine=True))
    fixture.config.write_text(source)
    fixture.config.chmod(0o600)
    releases = home / '.local/share/agmi/releases'
    candidate = home / 'agmi-approved-incoming'
    shutil.copy2(binary, candidate)
    candidate.chmod(0o700)
    with candidate.open('ab') as stream:
        stream.write(b'\nagmi published-client approval handoff fixture\n')
    candidate_hash = digest(candidate)
    def cli(executable, *words, success=True):
        result = run([str(executable), '--json', *words], success=success)
        return json.loads(result.stdout)['data']
    try:
        cli(old, 'pause')
        assert fixture.rows('SELECT version FROM control')[0]['version'] == 2
        identity = fixture.rows('SELECT * FROM authority')
        control = fixture.rows('SELECT * FROM control')
        private = {path: path.read_bytes() for path in (fixture.key, fixture.core)}
        cli(old, 'install', '--binary', str(old), '--sha256', expected_hash)
        missing = cli(binary, 'update', '--binary', str(candidate), '--sha256', candidate_hash, success=False)
        assert missing['update']['status'] == 'decision_required'
        assert missing['migration']['decision_reason'] == 'lane_limits_required'
        help_action = next(action for action in missing['next_actions']
                           if action.get('argv', [])[-4:] == ['config', 'migrate', 'preview', '--help'])
        run([str(binary), *help_action['argv'][1:]])
        human = run([str(binary), 'update', '--binary', str(candidate),
                     '--sha256', candidate_hash], success=False)
        print(human.stdout, end='', flush=True)
        assert (releases / 'current').resolve().name == 'r-' + expected_hash
        assert fixture.config.read_text() == source and fixture.rows('SELECT * FROM control') == control
        request_file = config_root / 'explicit-upgrade.json'
        request_file.write_text(json.dumps({'caps': dict(answer=1, judge=1, mine=1)}))
        request_file.chmod(0o600)
        prepared = cli(binary, 'update', '--binary', str(candidate), '--sha256', candidate_hash,
                       '--proposal', str(request_file), success=False)
        assert prepared['update']['status'] == 'decision_required' and prepared['private'] is True
        preview = prepared['preview']
        token = prepared['migration']['token']
        release = prepared['migration']['release_id']
        request_file.write_text(json.dumps(preview['request']))
        arguments = ['update', '--release', release, '--proposal', str(request_file),
                     '--expected-token', token]
        if preview['risk_change_required']:
            arguments += ['--accept-risk-change', token]
        completed = cli(binary, *arguments)
        assert completed['migration']['phase'] == 'complete'
        assert completed['restoration']['verified'] is True
        assert fixture.rows('SELECT version,paused FROM control') == [dict(version=4, paused=1)]
        assert fixture.rows('SELECT * FROM authority') == identity
        assert digest(fixture.config) == hashlib.sha256(preview['candidate_toml'].encode()).hexdigest()
        assert all(path.read_bytes() == value for path, value in private.items())
        assert all(not active(unit) for unit in UNITS)
        assert not fixture.writes and not fixture.model_calls('answer')
        assert not (releases / '.update-state.json').exists()
        print('PASS authentic published journal2 client requires explicit quotas, then exact approved upgrade preserves identity and intent', flush=True)
    finally:
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




def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--suite', choices=('current', 'seamless', 'seamless-maintenance', 'seamless-config-only', 'future-refusal', 'future-recovery', 'compatibility', 'compatibility-no-selection', 'compatibility-auto', 'published010', 'published011', 'after-reboot'), default='current')
    parser.add_argument('--old-binary', type=pathlib.Path)
    parser.add_argument('--old-sha256')
    parser.add_argument('--future-binary', type=pathlib.Path)
    parser.add_argument('--future-sha256')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    home = isolation(existing=args.suite == 'after-reboot')
    if args.suite in ('published010', 'published011'):
        published_upgrade(binary, args.old_binary.resolve(strict=True) if args.old_binary else None,
                          args.old_sha256, home)
        return
    if args.suite in ('future-refusal', 'future-recovery'):
        future_handoff(binary, args.future_binary.resolve(strict=True) if args.future_binary else None,
                       args.future_sha256, home, recovery=args.suite == 'future-recovery')
        return
    if args.suite in ('seamless', 'seamless-maintenance', 'seamless-config-only'):
        seamless(binary, args.old_binary.resolve(strict=True) if args.old_binary else None,
                 args.old_sha256, home, maintenance=args.suite == 'seamless-maintenance',
                 config_only=args.suite == 'seamless-config-only')
        return
    if args.suite in ('compatibility', 'compatibility-no-selection', 'compatibility-auto'):
        compatibility(binary, args.old_binary.resolve(strict=True) if args.old_binary else None,
                      args.old_sha256, home, no_selection=args.suite == 'compatibility-no-selection',
                      automatic=args.suite == 'compatibility-auto')
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
