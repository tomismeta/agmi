#!/usr/bin/env python3
"""Destructive ONLY inside a fresh systemd_fixture.Dockerfile container.

Root invocation (no host home/bus/cgroup mounts; --network none, private cgroup
namespace, --tmpfs /run, --tmpfs /tmp:exec,mode=1777):
  python3 /src/tests/storage_runtime_smoke.py /input/agmi
Root establishes inherited private /tmp for user@17321 before its first start,
then invokes the normal unprivileged helper. Do NOT invoke the helper directly.
All model/API work is deterministic fixture work; no provider SDK, credentials
or external network is used. No host namespace policy or AGMI privileges change.
ENOSPC is exercised with a one-inode tmpfs in the service's inherited/private
mount namespace. EDQUOT/EROFS mapping has typed errno coverage.
"""
import argparse
import fcntl
import json
import os
import pathlib
import pwd
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time

from participation_smoke import ANSWER, Fixture
from systemd_smoke import UNITS, digest, isolation, property_value, run, systemctl

UID = 17321
HOME = pathlib.Path('/home/agmi-systemd-fixture')
RUNTIME = pathlib.Path('/run/user/17321')
SCRATCH = RUNTIME / 'agmi'
CONTROL = RUNTIME / 'storage-runtime-acceptance'


def require(condition, description):
    if not condition:
        raise AssertionError(description)


def identity(path):
    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino


def container_guard():
    require(sys.platform == 'linux' and pathlib.Path('/.dockerenv').is_file(), 'Docker required')
    marker = pathlib.Path('/etc/agmi-systemd-fixture')
    metadata = marker.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1,
            'unsafe fixture marker')
    require(marker.read_text().strip() == 'agmi-isolated-systemd-acceptance', 'wrong fixture')
    require(pathlib.Path('/proc/1/comm').read_text().strip() == 'systemd', 'PID1 must be systemd')
    require(pwd.getpwuid(UID).pw_dir == str(HOME)
            and pwd.getpwuid(UID).pw_name == 'agmi-systemd-fixture', 'wrong fixture account')
    require(HOME.lstat().st_uid == UID and not HOME.is_symlink(), 'unsafe account home')
    # Docker's isolated namespace can contain dormant kernel tunnel devices.
    # Require loopback-only connectivity, not a kernel-specific interface list.
    interfaces = socket.if_nameindex()
    require(any(name == 'lo' for _, name in interfaces), 'loopback interface required')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for _, name in interfaces:
            flags = fcntl.ioctl(control, 0x8913, struct.pack('256s', name.encode()))  # SIOCGIFFLAGS
            require(name == 'lo' or not (struct.unpack_from('H', flags, 16)[0] & 1),
                    'container must use --network none; non-loopback link is up')
    mounts = [line.split() for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines()]
    for target in ('/tmp', '/run'):
        entries = [fields for fields in mounts if fields[4] == target]
        require(len(entries) == 1 and entries[0][entries[0].index('-') + 1] == 'tmpfs',
                'dedicated private tmpfs required: ' + target)
    require(not any(fields[4] == '/home' or fields[4].startswith(str(HOME)) for fields in mounts),
            'home must not be a host/bind mount')


def account_environment():
    return dict(PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                HOME=str(HOME), USER='agmi-systemd-fixture', LOGNAME='agmi-systemd-fixture',
                XDG_RUNTIME_DIR=str(RUNTIME),
                DBUS_SESSION_BUS_ADDRESS='unix:path=' + str(RUNTIME / 'bus'),
                AGMI_UPDATE_CHECKS='0', NO_PROXY='127.0.0.1,localhost',
                no_proxy='127.0.0.1,localhost', LANG='C.UTF-8')


def process_identity(pid):
    process = pathlib.Path(f'/proc/{pid}')
    fields = (process / 'stat').read_text().rsplit(')', 1)[1].split()
    return (process.stat().st_uid, fields[19], identity(process / 'exe'),
            os.readlink(process / 'ns/mnt'))


def root_orchestrator(binary):
    require(os.geteuid() == 0, 'invoke this acceptance as container root')
    container_guard()
    wait(lambda: subprocess.run(['systemctl', 'show', '--property=Version', '--value'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0,
         'system manager did not become ready', seconds=60)
    manager_unit = f'user@{UID}.service'
    require(run(['systemctl', 'show', manager_unit, '--property=MainPID', '--value']).stdout.strip() == '0',
            'fixture manager must not start before namespace setup')
    dropin = pathlib.Path(f'/etc/systemd/system/{manager_unit}.d/agmi-storage-fixture.conf')
    require(not dropin.exists() and not dropin.is_symlink(), 'fresh fixture manager definition required')
    dropin.parent.mkdir(mode=0o755, parents=True)
    dropin.write_text('[Service]\nPrivateTmp=yes\n')
    dropin.chmod(0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'start', manager_unit])
    manager_pid = int(run(['systemctl', 'show', manager_unit, '--property=MainPID', '--value']).stdout)
    manager_identity = process_identity(manager_pid)
    manager_tmp = pathlib.Path(f'/proc/{manager_pid}/root/tmp')
    require(manager_identity[0] == UID and identity(manager_tmp) != identity(pathlib.Path('/tmp')),
            'root-managed inherited private tmp was not established')
    require(RUNTIME.stat().st_uid == UID, 'wrong runtime owner')
    require(not CONTROL.exists() and not CONTROL.is_symlink(), 'fresh fixture control required')
    CONTROL.mkdir(mode=0o700)
    os.chown(CONTROL, UID, pwd.getpwuid(UID).pw_gid)
    env_words = [key + '=' + value for key, value in account_environment().items()]
    command = ['runuser', '-u', 'agmi-systemd-fixture', '--', 'env', '-i', *env_words,
               sys.executable, str(pathlib.Path(__file__).resolve()), str(binary), '--user-helper']
    child = subprocess.Popen(command)
    deleted = False
    capacity_pid = None
    capacity_mounted = False
    deadline = time.monotonic() + 360
    try:
        while child.poll() is None:
            require(time.monotonic() < deadline, 'bounded acceptance deadline exceeded')
            request = CONTROL / 'delete-private-tmp.json'
            if request.exists() and not deleted:
                container_guard()
                metadata = request.lstat()
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == UID
                        and metadata.st_nlink == 1, 'unsafe deletion request')
                pid = json.loads(request.read_text())['pid']
                require(type(pid) is int and pid > 1, 'invalid service pid')
                observed = subprocess.run(['runuser', '-u', 'agmi-systemd-fixture', '--',
                    'env', '-i', *env_words, 'systemctl', '--user', 'show', 'agmi.service',
                    '--property=MainPID', '--value'], capture_output=True, text=True, timeout=10)
                require(observed.returncode == 0 and observed.stdout.strip() == str(pid),
                        'requested PID is not actual managed service')
                require(pathlib.Path(f'/proc/{pid}').stat().st_uid == UID, 'wrong service uid')
                service_identity = process_identity(pid)
                capabilities = dict(line.split(':', 1) for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
                require(all(int(capabilities[name].strip(), 16) == 0
                            for name in ('CapEff', 'CapPrm', 'CapAmb')), 'AGMI gained capabilities')
                require(os.readlink(f'/proc/{pid}/ns/mnt') != os.readlink('/proc/self/ns/mnt'),
                        'service has no private mount namespace')
                private_tmp = pathlib.Path(f'/proc/{pid}/root/tmp')
                require(identity(private_tmp) != identity(pathlib.Path('/tmp')), 'tmp is not private')
                scratch_identity = identity(SCRATCH)
                require(scratch_identity == identity(pathlib.Path(f'/proc/{pid}/root') / str(SCRATCH)[1:]),
                        'runtime scratch not shared with service')
                boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
                matches = {}
                # Root supplies an inherited namespace when user namespaces are
                # unavailable. Nested AGMI isolation, when supported, stays intact.
                roots = [(pathlib.Path('/tmp'), (manager_unit, 'agmi.service')),
                         (manager_tmp, ('agmi.service',))]
                for parent, names in roots:
                    for tree in parent.iterdir():
                        if not any(tree.name.startswith('systemd-private-' + boot + '-' + name + '-')
                                   for name in names):
                            continue
                        outer = tree.lstat()
                        require(stat.S_ISDIR(outer.st_mode) and outer.st_uid in (0, UID)
                                and stat.S_IMODE(outer.st_mode) & 0o077 == 0, 'unsafe private tree')
                        backing = tree / 'tmp'
                        require(not backing.is_symlink(), 'symlink private backing refused')
                        if backing.is_dir() and identity(backing) == identity(private_tmp):
                            matches.setdefault(identity(backing), (backing, identity(tree)))
                require(len(matches) == 1, 'cannot uniquely attest live inherited/private tmp backing')
                backing, parent_identity = next(iter(matches.values()))
                require(process_identity(pid) == service_identity
                        and process_identity(manager_pid) == manager_identity,
                        'service or manager changed before deletion')
                outer = backing.parent.lstat()
                require(stat.S_ISDIR(outer.st_mode) and outer.st_uid in (0, UID)
                        and stat.S_IMODE(outer.st_mode) & 0o077 == 0
                        and identity(backing.parent) == parent_identity
                        and not backing.is_symlink() and identity(backing) == identity(private_tmp),
                        'backing ownership or identity changed')
                shutil.rmtree(backing)
                require(private_tmp.stat().st_nlink == 0, 'private tmp backing was not deleted')
                require(identity(SCRATCH) == scratch_identity, 'managed runtime root was disturbed')
                (CONTROL / 'deleted.json').write_text(json.dumps(dict(pid=pid, deleted=True)))
                deleted = True
            capacity_request = CONTROL / 'capacity.json'
            if capacity_request.exists():
                container_guard()
                metadata = capacity_request.lstat()
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == UID
                        and metadata.st_nlink == 1, 'unsafe capacity request')
                message = json.loads(capacity_request.read_text())
                require(type(message['mounted']) is bool, 'invalid mount intent')
                if message['mounted'] != capacity_mounted:
                    target_pid = message['pid']
                    require(type(target_pid) is int and target_pid > 1, 'invalid capacity PID')
                    observed = subprocess.run(['runuser', '-u', 'agmi-systemd-fixture', '--',
                        'env', '-i', *env_words, 'systemctl', '--user', 'show', 'agmi.service',
                        '--property=MainPID', '--value'], capture_output=True, text=True, timeout=10)
                    require(observed.returncode == 0 and observed.stdout.strip() == str(target_pid),
                            'capacity target is not managed service')
                    require(pathlib.Path(f'/proc/{target_pid}').stat().st_uid == UID
                            and os.readlink(f'/proc/{target_pid}/ns/mnt')
                            != os.readlink('/proc/self/ns/mnt'), 'unsafe capacity namespace')
                    target = pathlib.Path(f'/proc/{target_pid}/root') / str(SCRATCH)[1:]
                    require(stat.S_ISDIR(target.lstat().st_mode) and target.stat().st_uid == UID,
                            'unsafe capacity mountpoint')
                    if message['mounted']:
                        require(capacity_pid is None, 'capacity mount may run only once')
                        run(['nsenter', '--target', str(target_pid), '--mount', '--',
                             'mount', '-t', 'tmpfs', '-o',
                             f'size=4096,nr_inodes=1,uid={UID},gid={pwd.getpwuid(UID).pw_gid},mode=0700',
                             'agmi-fixture-capacity', str(SCRATCH)])
                        capacity_pid = target_pid
                    else:
                        require(target_pid == capacity_pid, 'capacity process changed')
                        run(['nsenter', '--target', str(target_pid), '--mount', '--',
                             'umount', '--', str(SCRATCH)])
                    capacity_mounted = message['mounted']
                    applied = CONTROL / 'capacity-applied.pending'
                    applied.write_text(json.dumps(message))
                    applied.replace(CONTROL / 'capacity-applied.json')
            time.sleep(0.05)
        require(child.returncode == 0, 'unprivileged acceptance failed')
        require(deleted, 'private tmp destruction proof never ran')
    finally:
        if capacity_mounted and capacity_pid and pathlib.Path(f'/proc/{capacity_pid}').exists():
            subprocess.run(['nsenter', '--target', str(capacity_pid), '--mount', '--',
                            'umount', '--', str(SCRATCH)], timeout=10, check=False)
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def wait(predicate, description, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(description)


def standalone_advisory_refusals(binary):
    """Actual OS account isolation, not a spoofed HOME or test trust bypass."""
    durable = HOME / '.local/share/agmi/update-advisory'
    durable.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    require(not durable.exists() and not durable.is_symlink(), 'fresh advisory owner required')
    config = HOME / 'not-created/config.toml'
    untouched = HOME / 'advisory-fixture-untouched'
    untouched.mkdir(mode=0o700)
    try:
        for kind in ('file', 'symlink'):
            if kind == 'file':
                durable.write_text('not a directory')
            else:
                durable.symlink_to(untouched, target_is_directory=True)
            try:
                command = [str(binary), '--config', str(config), 'update', '--check']
                result = subprocess.run([command[0], '--json', *command[1:]],
                                        env=account_environment(), capture_output=True, text=True, timeout=25)
                require(result.returncode != 0, 'unsafe advisory owner accepted')
                report = json.loads(result.stdout)
                require(report['type'] == 'update' and not report['data']['success'],
                        'standalone refusal lost CLI contract')
                data = report['data']
                require(data['update']['check'] and data['release_advisory']['availability'] == 'unknown',
                        'refusal fabricated availability')
                require(data['next_actions'][0]['kind'] == 'instruction'
                        and data['next_actions'][0].get('argv') is None,
                        'unmanaged refusal proposed mutation')
                require('installation' not in data and 'readiness' not in data,
                        'check fabricated installation or readiness')
                require(not config.parent.exists() and not (durable.parent / 'state.sqlite3').exists(),
                        'standalone check created account state')
                require(not list(untouched.iterdir()), 'advisory wrote through directory symlink')
                if kind == 'file':
                    require(durable.read_text() == 'not a directory', 'advisory replaced foreign file')
                    human = subprocess.run(command, env=account_environment(), capture_output=True,
                                           text=True, timeout=25)
                    require(human.returncode == result.returncode,
                            'human and JSON advisory refusals disagree')
                    print(human.stdout.strip(), flush=True)
            finally:
                durable.unlink()
    finally:
        untouched.rmdir()
    print('PASS standalone advisory CLI without account; unsafe owner refused, no symlink writes, non-executable recovery actions', flush=True)


def helper(binary):
    container_guard()
    home = isolation()
    require(os.getuid() == UID and CONTROL.stat().st_uid == UID, 'root orchestrator required')
    systemctl('set-environment', 'AGMI_UPDATE_CHECKS=0')
    standalone_advisory_refusals(binary)
    root = home / '.config/agmi'
    root.mkdir(parents=True, mode=0o700)
    fixture = Fixture(str(binary), root)
    # Fixture's HOME override is not isolation or native installation authority.
    fixture.env = account_environment()
    fixture.lanes['answer']['timeouts']['model_seconds'] = 45
    fixture.lanes['judge']['timeouts']['model_seconds'] = 45
    fixture.lanes['judge']['mode'] = 'active'
    fixture.answer_response = 'bound'
    fixture.receipt_state = 'confirmed'
    fixture.queued_grades = True
    fixture.configure()
    # Replace only the supported deterministic native fixture, not production
    # code. Every actual child records its inherited temp root and workspace.
    interpreter = root / 'fixture-python'
    interpreter.write_text('#!' + sys.executable + '\n' + '''import json, os, pathlib, stat, sys, time
payload = json.load(sys.stdin)
e = json.loads(payload['prompt'].split('Envelope (untrusted request data):\\n')[1])
root = pathlib.Path(__file__).parent
workspace = pathlib.Path.cwd()
record = dict(kind=e['kind'], request_id=e['request']['id'], pid=os.getpid(),
              uid=os.getuid(), cwd=str(workspace), tmpdir=os.environ.get('TMPDIR'),
              mode=stat.S_IMODE(workspace.stat().st_mode), invocation_id=payload['invocation_id'])
with (root / 'calls').open('a') as stream:
    stream.write(json.dumps(record) + '\\n')
stop = time.monotonic() + 35
while (root / ('hold-' + e['kind'])).exists():
    if time.monotonic() > stop:
        raise RuntimeError('bounded fixture model hold expired')
    time.sleep(0.025)
artifact = dict(answer=ANSWER + f" Epoch {e['request']['epoch']}." if e['kind'] == 'answer' else None,
                score=2 if e['kind'] == 'judge' else None,
                reasoning='The bridge enforces a measurable clock delay.' if e['kind'] == 'judge' else None)
print(json.dumps(dict(provider='openai-codex', model=payload['model'],
    reasoning_effort=payload['reasoning'], run_id=payload['invocation_id'],
    native_turn_id=f"{payload['invocation_id']}:{payload['invocation_id']}:0123abcd",
    output=json.dumps(artifact))))
'''.replace('ANSWER', repr(ANSWER)))
    interpreter.chmod(0o700)
    bootstrap = fixture.native.read_text()
    fixture.native.write_text(bootstrap.replace('#!/bin/sh\n', '#!/bin/sh\nprintf "launch\\n" >> '
        + str(root / 'bootstrap-calls') + '\n', 1))
    fixture.native.chmod(0o700)
    candidates = home / 'storage-fixture-releases'
    candidates.mkdir(mode=0o700)
    second = candidates / 'agmi-b'
    shutil.copy2(binary, second)
    with second.open('ab') as stream:
        stream.write(b'\nagmi storage fixture distinct update image\n')
    second.chmod(0o700)

    def cli(*words):
        result = run([str(binary), '--json', *words])
        envelope = json.loads(result.stdout)
        require(envelope['ok'], 'CLI failed')
        return envelope['data']

    def pid():
        return int(property_value('agmi.service', 'MainPID'))

    def calls():
        path = root / 'calls'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def launches():
        path = root / 'bootstrap-calls'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def model_records():
        return [json.loads(row['model_attempt']) for row in fixture.rows(
            'SELECT model_attempt FROM operation_evidence WHERE model_attempt IS NOT NULL ORDER BY operation_id')]

    def judge_record(key):
        rows = fixture.rows(
            'SELECT o.id,o.revision,o.state,e.model_attempt FROM operations o '
            'LEFT JOIN operation_evidence e ON e.operation_id=o.id '
            'WHERE o.kind=? AND o.work_key=? ORDER BY o.id LIMIT 1', ('judge', key))
        if not rows or rows[0]['model_attempt'] is None:
            return None
        row = rows[0]
        row['native'] = json.loads(row.pop('model_attempt'))
        return row

    def workspace_diagnosis(key, pinned, category, revision, deadline):
        last = {}

        def diagnostic(command):
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'diagnostic publication deadline: ' + json.dumps(last)[:16000])
            result = subprocess.run([str(binary), '--json', command, '--verbose'],
                                    capture_output=True, text=True, timeout=min(5, remaining),
                                    env=fixture.env)
            require(result.returncode in ((0,) if command == 'status' else (0, 1)),
                    'diagnostic command failed')
            return json.loads(result.stdout)['data']

        def witness(status):
            runtime = status['effective_runtime']
            lane = status['work']['judge']
            model, assessment = lane.get('model', {}), lane.get('assessment', {})
            at = int(time.time())
            exclusions = assessment.get('exclusions', {})
            relevant = lambda reason: reason == 'already_attempted' or reason.startswith('model_')
            positive = any(row.get('work_key', '').lower() == key
                           and relevant(row.get('reason', ''))
                           for row in assessment.get('excluded_work', []))
            ready = (runtime.get('revision') == revision and not runtime.get('reload_blocked')
                     and runtime.get('authority_epoch') ==
                         pinned['native']['producer']['preflight_admission']['authority_epoch']
                     and status.get('controller_stopped') is False
                     and model.get('operation_id') == pinned['id']
                     and model.get('current_route') is True and model.get('current_runtime') is True
                     and model.get('state') == 'prelaunch_failed'
                     and model.get('failure_category') == category
                     and assessment.get('completeness') == 'complete'
                     and assessment.get('locally_judgeable') is False
                     and 0 <= assessment.get('observed_at', -1) <= at
                     and assessment.get('valid_until', -1) > at
                     and sum(count for reason, count in exclusions.items() if relevant(reason)) > 0
                     and positive)
            stamp = (runtime.get('revision'), runtime.get('runtime_instance'),
                     runtime.get('authority_epoch'), assessment.get('observed_at'),
                     assessment.get('valid_until'), model.get('operation_id'))
            return ready, stamp

        while time.monotonic() < deadline:
            row = judge_record(key)
            require(row is not None and row['id'] == pinned['id']
                    and row['revision'] == pinned['revision']
                    and row['native']['producer'] == pinned['native']['producer'],
                    'a later attempt substituted for the selected failure')
            before = diagnostic('status')
            last = dict(key=key, operation_id=pinned['id'], model=before['work']['judge'].get('model'),
                        assessment=before['work']['judge'].get('assessment'))
            ready, stamp = witness(before)
            if ready:
                require(before['work']['judge']['model'].get('scope') == 'current_work',
                        'positive current-work evidence has wrong scope: ' + json.dumps(last)[:16000])
                doctor = diagnostic('doctor')
                after = diagnostic('status')
                current = judge_record(key)
                require(current is not None and current['id'] == pinned['id']
                        and current['revision'] == pinned['revision']
                        and current['native']['producer'] == pinned['native']['producer'],
                        'attempt identity changed during diagnosis')
                after_ready, after_stamp = witness(after)
                if after_ready:
                    require(after['work']['judge']['model'].get('scope') == 'current_work',
                            'post-diagnosis current-work evidence has wrong scope: ' + json.dumps(last)[:16000])
                stale = doctor['thresholds']['stale_seconds']
                at = int(time.time())
                live = all(0 <= at - status['effective_runtime']['observed_at'] <= stale
                           for status in (before, after))
                if after_ready and after_stamp == stamp and live:
                    lane = doctor['work']['judge']
                    model = lane['model']
                    last['doctor'] = lane
                    require(model['operation_id'] == pinned['id']
                            and model['failure_category'] == category
                            and model['current_route'] is True and model['current_runtime'] is True
                            and model['state'] == 'prelaunch_failed'
                            and lane['intervention']['status'] == 'operator_required'
                            and lane['intervention']['next_action'] == 'inspect_model_workspace',
                            'current judge failure lacks safe recovery guidance: ' + json.dumps(last)[:16000])
                    return json.dumps(doctor)
            time.sleep(0.05)
        raise AssertionError('exact diagnostic evidence did not converge: ' + json.dumps(last)[:16000])

    def assert_process(expected):
        wait(lambda: cli('status', '--verbose')['process_observation']['state'] == 'observed_match',
             'actual canonical process never reached observed_match')
        require(pid() == expected, 'controller restarted during storage fault')

    def captured_answer(epoch):
        return any(row['job_id'] == 'answer-' + str(epoch) and row['state'] in ('confirmed', 'final')
                   for row in fixture.operations('answer'))

    def capacity(mounted, service_pid):
        message = dict(pid=service_pid, mounted=mounted)
        pending = CONTROL / 'capacity.pending'
        pending.write_text(json.dumps(message))
        pending.replace(CONTROL / 'capacity.json')
        def applied():
            path = CONTROL / 'capacity-applied.json'
            return path.exists() and json.loads(path.read_text()) == message
        wait(applied, 'root did not apply private capacity fault')

    displaced = RUNTIME / 'storage-fixture-displaced'
    hold = root / 'hold-answer'
    try:
        fixture.invoke('pause')
        preserved = {path: path.read_bytes() for path in (fixture.config, fixture.key, fixture.core)}
        database_identity = identity(fixture.database)
        journal = digest(fixture.database)
        for action, candidate in (('install', binary), ('update', second)):
            data = cli(action, '--binary', str(candidate), '--sha256', digest(candidate))
            require(data['installation']['activation'] == 'loaded_verified', 'native activation failed')
            require(identity(fixture.database) == database_identity and digest(fixture.database) == journal,
                    'stopped native activation changed journal')
            require(all(path.read_bytes() == contents for path, contents in preserved.items()),
                    'native activation changed private account data')

        legacy = HOME / '.cache/agmi/update.json'
        legacy.parent.mkdir(parents=True, mode=0o700)
        old_lock = legacy.with_name('update.lock')
        old_lock.touch(mode=0o600)
        lock_identity = identity(old_lock)
        started = int(time.time()) - 100
        retained = dict(format=1, source='https://api.github.com/repos/tomismeta/agmi',
                        context='retained-before-native-update', started_at=started,
                        finished_at=None, attempt_id='retained-incomplete',
                        outcome='in_progress', reason='check_in_progress',
                        next_due_at=started + 21600, retry_not_before=started + 3600, good=None)
        legacy.write_text(json.dumps(retained))
        legacy.chmod(0o600)
        durable = HOME / '.local/share/agmi/update-advisory/update.json'
        before = (legacy.read_bytes(), legacy.stat().st_mtime_ns, old_lock.stat().st_mtime_ns,
                  legacy.parent.stat().st_mtime_ns)
        notice = cli('status', '--verbose')['release_advisory']
        require(notice['storage'] == 'legacy' and notice['adoption_required']
                and notice['retry_not_before'] == retained['retry_not_before'],
                'readonly CLI hid legacy retry evidence')
        require(notice['next_action']['kind'] == 'unavailable',
                'incomplete legacy evidence recommended an ineffective check')
        require(not durable.parent.exists(), 'readonly status initialized durable advisory')
        require(before == (legacy.read_bytes(), legacy.stat().st_mtime_ns, old_lock.stat().st_mtime_ns,
                           legacy.parent.stat().st_mtime_ns), 'readonly status mutated advisory source')
        check = subprocess.run([str(home / '.local/bin/agmi'), '--json', 'update', '--check'],
                               env=fixture.env, capture_output=True, text=True, timeout=25)
        require(check.returncode != 0, 'retained source floor was bypassed')
        report = json.loads(check.stdout)['data']
        require(report['update']['reason'] == 'source_retry_not_before',
                'ordinary installed check did not adopt and enforce retained floor: ' + check.stdout)
        require(report['release_advisory']['next_action']['kind'] == 'unavailable',
                'throttled incomplete check recommended another retry')
        adopted = json.loads(durable.read_text())
        require(adopted['format'] == 2 and adopted['adoption']['phase'] == 'ready'
                and all(adopted[key] == value for key, value in retained.items() if key != 'format'),
                'native-owner adoption changed historical evidence')
        require(not legacy.exists() and identity(old_lock) == lock_identity,
                'adoption left duplicate source or replaced permanent old lease')
        require(all(path.read_bytes() == contents for path, contents in preserved.items())
                and identity(fixture.database) == database_identity and digest(fixture.database) == journal,
                'advisory adoption changed account or journal')
        print('PASS actual installed update --check adopts legacy evidence; retained floor/incomplete attempt; readonly status; no account changes', flush=True)
        original = durable.read_bytes()
        parked = durable.with_name('fixture-preserved-update')
        for fault in ('missing', 'malformed'):
            try:
                if fault == 'missing':
                    durable.rename(parked)
                else:
                    durable.write_bytes(b'{malformed')
                notice = cli('status', '--verbose')['release_advisory']
                require(notice['availability'] == 'unknown'
                        and notice['next_action']['kind'] == 'unavailable',
                        'damaged durable evidence recommended another check')
                if fault == 'missing':
                    require(not durable.exists(), 'readonly status recreated missing evidence')
                else:
                    require(durable.read_bytes() == b'{malformed', 'readonly status rewrote malformed evidence')
            finally:
                if parked.exists():
                    parked.rename(durable)
                else:
                    durable.write_bytes(original)
        print('PASS incomplete/missing/malformed advisory evidence requires inspection, not retry; readonly CLI preserves damage', flush=True)

        systemctl('reset-failed', 'agmi.service')
        cli('service', 'start')
        service_pid = pid()
        require(service_pid > 1, 'managed service not started')
        assert_process(service_pid)
        require(property_value('agmi.service', 'RuntimeDirectory') == 'agmi'
                and property_value('agmi.service', 'RuntimeDirectoryMode') == '0700'
                and property_value('agmi.service', 'PrivateTmp') == 'yes', 'wrong managed storage policy')
        require(stat.S_IMODE(SCRATCH.stat().st_mode) == 0o700 and SCRATCH.stat().st_uid == UID,
                'runtime root not private')
        require(digest(pathlib.Path(f'/proc/{service_pid}/exe')) == digest(second), 'update image not running')
        print('PASS actual native install/update preserves config, credential and journal; process observed_match', flush=True)

        # Destruction precedes resumed work; a successful result cannot come
        # from an inference launched before the backing disappeared.
        request = CONTROL / 'delete-private-tmp.pending'
        request.write_text(json.dumps(dict(pid=service_pid)))
        request.replace(CONTROL / 'delete-private-tmp.json')
        wait(lambda: (CONTROL / 'deleted.json').is_file(), 'root did not prove/delete private tmp backing')
        cli('resume')
        wait(lambda: captured_answer(10), 'deleted private tmp prevented model capture/submission')
        assert_process(service_pid)
        require(any(write['route'].endswith('/api/hosted/answer') for write in fixture.writes),
                'no actual loopback submission')
        for call in calls():
            workspace = pathlib.Path(call['cwd'])
            require(workspace.parent == SCRATCH and workspace.name.startswith('agmi-model-'),
                    'native work escaped runtime root')
            require(call['tmpdir'] == call['cwd'] and call['mode'] == 0o700 and call['uid'] == UID,
                    'child TMPDIR/workspace not private and explicit')
        wait(lambda: not list(SCRATCH.glob('agmi-model-*')), 'completed workspaces not cleaned')
        require(any((record.get('completion') or {}).get('outcome') == 'captured' for record in model_records()),
                'submission lacks actual captured native completion')
        print('PASS live inherited/private /tmp backing deleted; new managed capture/submission without restart; private workspace cleanup', flush=True)

        # Hold a genuine answer process, then break allocation for the other
        # lane. Its completion and already accepted effect must still survive.
        hold.touch()
        fixture.rollover(11)
        wait(lambda: any(call['kind'] == 'answer' and call['request_id'] != calls()[0]['request_id']
                         for call in calls()), 'second real native answer never started')
        held = [call for call in calls() if call['kind'] == 'answer'][-1]
        require(pathlib.Path('/proc/' + str(held['pid'])).exists(), 'held model is not running')
        require(pathlib.Path(held['cwd']).is_dir(), 'held workspace missing')

        for index, fault in enumerate(('missing', 'not-directory', 'permission', 'capacity')):
            require(not displaced.exists(), 'unexpected displaced root')
            key = f'{20 + index:064x}'
            require(not fixture.rows('SELECT id FROM operations WHERE kind=? AND work_key=?',
                                     ('judge', key)), 'fresh assignment required')
            deadline = time.monotonic() + 25
            pinned = {}
            before_launches, before_calls = launches(), len(calls())
            if fault in ('missing', 'not-directory'):
                SCRATCH.rename(displaced)
                if fault == 'not-directory':
                    SCRATCH.write_text('fixture non-directory root')
            elif fault == 'permission':
                SCRATCH.chmod(0o500)
            else:
                capacity(True, service_pid)
            fixture.assignment_number = 20 + index
            fixture.assignments = True
            if index:
                fixture.apply_config({'capabilities': {'judge': {'mode': 'active'}}})
                fixture.loaded()
            category = {'permission': 'native_workspace_permission',
                        'capacity': 'native_workspace_capacity'}.get(fault, 'native_workspace_unavailable')
            def failed():
                row = judge_record(key)
                if row is None:
                    return False
                if not pinned:
                    pinned.update(row)
                require(row['id'] == pinned['id'] and row['revision'] == pinned['revision']
                        and row['native']['producer'] == pinned['native']['producer'],
                        'failed-work witness changed attempt identity')
                completion = row['native'].get('completion') or {}
                if not completion:
                    return False
                require(completion.get('reason_code') == category
                        and completion.get('execution') == 'not_started'
                        and completion.get('outcome') == 'not_started'
                        and completion.get('inference_spawned_at') is None
                        and row['native'].get('launch') is None
                        and row['state'] == 'prelaunch_failed',
                        'exact storage failure gained launch/paid authority or wrong classification')
                return True
            wait(failed, 'real ' + fault + ' exact allocation did not fail',
                 seconds=max(0, deadline - time.monotonic()))
            require(launches() == before_launches and len(calls()) == before_calls,
                    'allocation failure launched native child')
            revision = fixture.invoke('config', 'check')['revision']
            serialized = workspace_diagnosis(key, pinned, category, revision, deadline)
            require(str(SCRATCH) not in serialized and 'pk_test_fixture' not in serialized,
                    'doctor leaked private path or credential')
            fixture.cycles(2)
            require(launches() == before_launches and len(calls()) == before_calls,
                    'fault cooldown launched another model')
            assert_process(service_pid)
            fixture.assignments = False
            fixture.apply_config({'capabilities': {'judge': {'mode': 'off'}}})
            fixture.loaded()
            if fault in ('missing', 'not-directory'):
                if fault == 'not-directory':
                    SCRATCH.unlink()
                displaced.rename(SCRATCH)
            elif fault == 'permission':
                SCRATCH.chmod(0o700)
            else:
                capacity(False, service_pid)
            if index == 0:
                hold.unlink()
                wait(lambda: captured_answer(11), 'independent already-running model/effect was cancelled')
                require(any(row['kind'] == 'answer' and row.get('payload')
                            for row in fixture.operations('answer')), 'independent capture missing')
            print('PASS real ' + fault + ' storage fault: NotStarted, zero children, sanitized diagnostics, controller survives', flush=True)
        wait(lambda: not list(SCRATCH.glob('agmi-model-*')), 'held workspace cleanup did not finish')
        require(all(path.read_bytes() == contents for path, contents in preserved.items()
                    if path != fixture.config), 'credential/guidance changed during faults')
        require(identity(fixture.database) == database_identity, 'journal replaced during faults')
        systemctl('stop', 'agmi.service')
        require(not SCRATCH.exists(), 'RuntimeDirectory survived managed shutdown')
        print('PASS independent held native model captures/submits across another lane allocation failure; shutdown removes runtime root', flush=True)
        print('PASS real ENOSPC from private one-inode tmpfs; EDQUOT/EROFS retain typed errno coverage', flush=True)
        print('PASS storage-runtime isolated acceptance', flush=True)
    finally:
        hold.unlink(missing_ok=True)
        # Restore only our exact displaced root before asking systemd to clean it.
        if displaced.exists():
            if SCRATCH.is_file() and not SCRATCH.is_symlink():
                SCRATCH.unlink()
            if not SCRATCH.exists():
                displaced.rename(SCRATCH)
        if SCRATCH.is_dir():
            SCRATCH.chmod(0o700)
        try:
            loaded = [unit for unit in UNITS if property_value(unit, 'LoadState') != 'not-found']
            if loaded:
                systemctl('stop', *loaded)
        finally:
            # No authority pruning: close only fixture processes and sockets.
            fixture.stop()
            fixture.server.shutdown()
            fixture.server.server_close()
            fixture.thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--user-helper', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if args.user_helper:
        helper(binary)
    else:
        root_orchestrator(binary)


if __name__ == '__main__':
    main()
