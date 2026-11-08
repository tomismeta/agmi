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
The second trusted fixture ELF is the same build with an inert appended label;
this exercises distinct release selection, not compatibility across versions.
"""
import argparse
import hashlib
import json
import os
import pathlib
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


def isolation():
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
    for unit in UNITS:
        assert property_value(unit, 'LoadState') == 'not-found', ('existing unit', unit)
    assert not (home / '.local/share/agmi').exists()
    assert not (home / '.config/agmi').exists()
    assert not (home / '.local/bin/agmi').exists()
    assert not (os.statvfs(os.environ.get('TMPDIR') or '/tmp').f_flag & os.ST_NOEXEC), (
        'Installer TMPDIR must allow execution; use --tmpfs /tmp:exec,mode=1777')
    return home


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    home = isolation()  # Refuse before writing anything or stopping any unit.
    config_root = home / '.config/agmi'
    config_root.mkdir(parents=True, mode=0o700)
    fixture = Fixture(str(binary), config_root)
    fixture.capabilities = dict(answer='off', judge='off', mine='off')
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
        envelope = json.loads(result.stdout if success else result.stderr)
        assert envelope['schema'] == 'agmi.cli.v1'
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
        assert error['code'] == 'installer_failed'
        evidence = error['details']
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
