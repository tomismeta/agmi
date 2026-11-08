#!/usr/bin/env python3
"""Actual-CLI administration acceptance; stdlib only, no production actions."""
import argparse
import concurrent.futures
import hashlib
import fcntl
import http.server
import json
import os
import pathlib
import pwd
import subprocess
import sqlite3
import tempfile
import threading
import time
import uuid


def revision(data):
    return hashlib.sha256(data).hexdigest()


def startup_race(binary, root, environment, chain, address, account_keys, lock_root, origin):
    directory = root / 'startup-race'
    directory.mkdir()
    config = directory / 'config.toml'
    base = [binary, '--json', '--config', str(config)]
    def call(*words, data=b''):
        return subprocess.run(base + list(words), input=data, capture_output=True,
                              timeout=15, env=environment)
    assert call('config', 'init').returncode == 0
    token = json.loads(call('config', 'show').stdout)['data']['file_revision']
    race_chain = chain + '-startup'
    other_address = 'poa1' + '1' * 31 + '2'
    for value in (address, other_address):
        account_keys.add(revision(f'{race_chain}\n{value}'.encode()))
    patch = {'state_dir': 'state', 'network': {'chain': race_chain, 'address': address,
             'base_url': origin, 'credential_file': str(root / 'credential')},
             'capabilities': {'answer': 'off', 'judge': 'off', 'mine': 'off'},
             'schedule': {'jitter_seconds': 0}}
    changed = call('config', 'apply', '--expected-revision', token,
                   data=json.dumps(patch).encode())
    assert changed.returncode == 0, changed.stderr
    token = json.loads(changed.stdout)['data']['file_revision']
    lock_root.mkdir(mode=0o700, exist_ok=True)
    account = revision(f'{race_chain}\n{address}'.encode())
    admission = os.open(lock_root / (account + '.admission'), os.O_CREAT | os.O_RDWR, 0o600)
    directory_fd = os.open(directory, os.O_RDONLY)
    child = None
    try:
        fcntl.flock(admission, fcntl.LOCK_EX)
        child = subprocess.Popen(base + ['run', '--once'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=environment)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(directory_fd, fcntl.LOCK_UN)
            except BlockingIOError:
                break
            assert child.poll() is None, 'startup exited before reaching its binding gate'
            assert time.monotonic() < deadline, 'startup did not protect its source snapshot'
            time.sleep(0.01)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            edit = executor.submit(call, 'config', 'apply', '--expected-revision', token,
                                   data=json.dumps({'network': {'address': other_address}}).encode())
            fcntl.flock(admission, fcntl.LOCK_UN)
            stdout, stderr = child.communicate(timeout=15)
            assert child.returncode == 0, stderr
            result = edit.result(timeout=15)
            assert result.returncode != 0
            assert json.loads(result.stderr)['error']['code'] == 'admin_identity_immutable', result.stderr
        status = json.loads(call('status').stdout)['data']
        assert status['initialized'] and status['identity_matches_config']
        assert json.loads(call('config', 'show').stdout)['data']['config']['network']['address'] == address
    finally:
        fcntl.flock(admission, fcntl.LOCK_UN)
        os.close(admission)
        os.close(directory_fd)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=pathlib.Path)
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    chain = 'admin-' + uuid.uuid4().hex
    address = 'poa1' + '1' * 32
    account_keys = set()
    requests = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(self.path)
            self.send_error(503)

        do_POST = do_GET

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    lock_root = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.agmi-account-locks'
    try:
        with tempfile.TemporaryDirectory(prefix='agmi-admin-') as directory:
            root = pathlib.Path(directory)
            config = root / 'config.toml'
            state = root / 'state'
            secret = 'PRIVATE-SENTINEL-' + uuid.uuid4().hex
            base = [binary, '--json', '--config', str(config)]
            environment = dict(os.environ, HOME=str(root / 'home'),
                               XDG_CONFIG_HOME=str(root / 'xdg-config'),
                               XDG_DATA_HOME=str(root / 'xdg-data'))

            def invoke(*words, stdin=b'', expected=None):
                result = subprocess.run(base + list(words), input=stdin, capture_output=True,
                                        timeout=15, env=environment)
                output = result.stdout or result.stderr
                try:
                    envelope = json.loads(output)
                except (ValueError, UnicodeError):
                    raise AssertionError(('non-JSON output', words, result.returncode, output))
                if expected is None:
                    assert result.returncode == 0 and envelope['ok'], (words, envelope)
                    return envelope['data']
                assert result.returncode != 0 and not envelope['ok'], (words, envelope)
                assert envelope['error']['code'] == expected, (words, envelope)
                assert secret.encode() not in result.stdout + result.stderr
                return envelope

            def show():
                data = invoke('config', 'show')
                assert data['file_revision'] == revision(config.read_bytes())
                return data

            def apply(patch, expected=None, dry=False, error=None):
                token = expected if expected is not None else show()['file_revision']
                words = ['config', 'apply', '--expected-revision', token]
                if dry:
                    words.append('--dry-run')
                stdin = patch if isinstance(patch, bytes) else json.dumps(patch).encode()
                return invoke(*words, stdin=stdin, expected=error)

            def guidance(kind='answer', layer='user'):
                return invoke('guidance', 'show', '--kind', kind, '--layer', layer)

            def set_guidance(content, kind='answer', config_rev=None, guidance_rev=None,
                             dry=False, error=None, layer='user'):
                current = guidance(kind, layer) if config_rev is None or guidance_rev is None else None
                words = ['guidance', 'set', '--kind', kind, '--layer', layer,
                         '--expected-config-revision', config_rev if config_rev is not None else current['config_file_revision'],
                         '--expected-revision', guidance_rev if guidance_rev is not None else current['guidance_revision']]
                if dry:
                    words.append('--dry-run')
                return invoke(*words, stdin=content, expected=error)

            invoke('unsupported-' + secret, expected='invalid_arguments')
            schema = invoke('config', 'schema')
            assert not config.exists() and not state.exists()
            settings = {entry['path']: entry for entry in schema['settings']}
            for name in ('network.address', 'state_dir', 'solver.answer.guidance_file',
                         'solver.answer.core_guidance_file', 'solver.judge.core_guidance_file',
                         'solver.judge.harness', 'timeouts.read_http_seconds',
                         'participation.retry_uncertain_answers', 'schedule.mine_each_epoch'):
                assert name in settings, name
            assert settings['network.address']['immutable_when_initialized']
            assert settings['participation.mode']['enum'] == ['strict', 'participation_first', 'manual']
            assert schema['guidance']['layers'] == ['core', 'user']
            assert schema['guidance']['default_layer'] == 'user'
            invoke('config', 'init')
            initial = show()
            assert not state.exists()
            credential = root / 'credential'
            credential.write_text('pk_test_private_fixture')
            credential.chmod(0o600)
            executable = root / 'never-run'
            executable.write_text('#!/bin/sh\ntouch "' + str(root / 'model-called') + '"\nexit 1\n')
            executable.chmod(0o700)
            account_keys.add(revision(f'{chain}\n{address}'.encode()))
            populated = apply({
                'state_dir': 'state',
                'network': {'base_url': f'http://127.0.0.1:{server.server_port}',
                            'chain': chain, 'address': address, 'credential_file': 'credential'},
                'solver': {'answer': {'executable': './never-run'}, 'judge': {'executable': './never-run'}},
            })
            assert populated['saved'] and populated['runtime_applied'] is None
            assert not state.exists()
            assert config.stat().st_mode & 0o777 == 0o600
            populated_bytes = config.read_bytes()
            assert 'credential_file = "credential"' in populated_bytes.decode()
            assert 'executable = "./never-run"' in populated_bytes.decode()
            apply({'schedule': {'poll_seconds': 5}}, expected=initial['file_revision'],
                  error='admin_revision_conflict')
            assert config.read_bytes() == populated_bytes

            # Invalid inputs never change bytes, expose input, initialize state, or run models.
            bad_patches = [b'{', b'[]', b'null', b'"' + secret.encode() + b'"',
                           {'unknown': secret}, {'unknown': None},
                           {'network': {'token': secret}},
                           {'network': {'base_url': 'https://user:' + secret + '@minepoa.com'}},
                           {'solver': {'answer': {'harness': secret}}},
                           {'participation': {'max_unresolved_operations': 0}},
                           {'timeouts': {'read_http_seconds': 0}},
                           {'schedule': {'poll_seconds': -1}},
                           {'excluded_judging_assignments': [secret]},
                           {'timeouts': {'http_seconds': None}},
                           {'solver': {'answer': {'guidance_file': 'missing.md'}}}]
            for patch in bad_patches:
                before = config.read_bytes()
                error = 'admin_guidance_missing' if isinstance(patch, dict) and patch.get('solver', {}).get('answer', {}).get('guidance_file') else 'admin_validation'
                apply(patch, error=error)
                assert config.read_bytes() == before and not state.exists()
            apply(b' ' * 65537, error='admin_input_too_large')
            # Active routes cannot silently fall back to compiled-in core instructions.
            apply({'capabilities': {'answer': 'active'}}, error='admin_validation')
            for kind in ('answer', 'judge'):
                missing_core = guidance(kind, 'core')
                assert missing_core['status'] == 'unconfigured' and missing_core['layer'] == 'core'
                core_text = (secret + '\n' + kind + ' core instructions\n').encode()
                preview = set_guidance(core_text, kind=kind, layer='core', dry=True)
                assert not preview['saved']
                core_path = root / (kind + '-core-guidance.md')
                assert not core_path.exists()
                saved = set_guidance(core_text, kind=kind, layer='core')
                assert saved['saved'] and secret not in json.dumps(saved)
                assert core_path.read_bytes() == core_text
                assert core_path.stat().st_mode & 0o777 == 0o600
                current = guidance(kind, 'core')
                assert current['content'] == core_text.decode()
                assert current['guidance_revision'] == revision(core_text)
                set_guidance(b'stale', kind=kind, layer='core',
                             config_rev=current['config_file_revision'], guidance_rev='missing',
                             error='admin_revision_conflict')
                for invalid in (b'', b' \n', b'\xff'):
                    set_guidance(invalid, kind=kind, layer='core', error='admin_validation')
                assert core_path.read_bytes() == core_text
            assert invoke('guidance', 'show', '--kind', 'answer')['layer'] == 'user'
            before = config.read_bytes()
            dry = apply({'capabilities': {'answer': 'active'},
                         'solver': {'answer': {'model': 'configured-model', 'reasoning': 'medium'}},
                         'participation': {'mode': 'participation_first'},
                         'schedule': {'mine_each_epoch': True}}, dry=True)
            assert dry['dry_run'] and not dry['saved'] and dry['file_revision'] == revision(before)
            assert config.read_bytes() == before and not state.exists()
            apply({'capabilities': {'answer': 'active', 'judge': 'off', 'mine': 'read_only'},
                   'solver': {'answer': {'harness': 'openclaw', 'model': 'configured-model', 'reasoning': 'medium'},
                              'judge': {'harness': 'hermes', 'model': 'judge-model', 'reasoning': 'high'}},
                   'timeouts': {'read_http_seconds': 8},
                   'preparation': {'max_attempts_per_work': 2},
                   'participation': {'mode': 'participation_first', 'uncertainty_grace_seconds': 0,
                                     'max_unresolved_operations': 6, 'allow_judge': True},
                   'schedule': {'mine_each_epoch': True}})
            applied = show()['config']
            assert applied['participation']['mode'] == 'participation_first'
            assert applied['solver']['answer']['model'] == 'configured-model'
            assert applied['schedule']['mine_each_epoch']
            apply({'timeouts': {'read_http_seconds': None}, 'participation': {'mode': None}})
            restored = show()['config']
            assert 'read_http_seconds' not in restored['timeouts']
            assert restored['participation']['mode'] == 'strict'

            # One of two cooperating writers wins; the stale writer cannot silently overwrite it.
            token = show()['file_revision']
            def race(seconds):
                result = subprocess.run(base + ['config', 'apply', '--expected-revision', token],
                                        input=json.dumps({'schedule': {'poll_seconds': seconds}}).encode(),
                                        capture_output=True, timeout=15, env=environment)
                return result.returncode, json.loads(result.stdout or result.stderr)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(race, (7, 9)))
            assert sum(code == 0 for code, _ in outcomes) == 1, outcomes
            assert [data['error']['code'] for code, data in outcomes if code] == ['admin_revision_conflict']

            absent = guidance()
            assert absent['private'] and absent['status'] == 'unconfigured'
            before = config.read_bytes()
            text = (secret + '\nAnswer guidance\n').encode()
            dry = set_guidance(text, dry=True)
            assert not dry['saved'] and config.read_bytes() == before
            assert not (root / 'answer-guidance.md').exists()
            first = set_guidance(text)
            assert first['private'] and first['saved'] and secret not in json.dumps(first)
            answer_path = root / 'answer-guidance.md'
            assert answer_path.read_bytes() == text and answer_path.stat().st_mode & 0o777 == 0o600
            viewed = guidance()
            assert viewed['content'] == text.decode() and viewed['guidance_revision'] == revision(text)
            assert viewed['status'] == 'present'
            before = config.read_bytes()
            set_guidance(b'wrong', config_rev=absent['config_file_revision'], guidance_rev='missing',
                         error='admin_revision_conflict')
            set_guidance(b'wrong', config_rev=viewed['config_file_revision'], guidance_rev='missing',
                         error='admin_revision_conflict')
            assert answer_path.read_bytes() == text and config.read_bytes() == before
            updated = set_guidance(b'Updated private guidance\n')
            assert updated['config_file_revision'] == revision(before)
            assert config.read_bytes() == before
            set_guidance(b'\xff', error='admin_validation')
            set_guidance(b'x' * 65537, error='admin_input_too_large')
            assert answer_path.read_bytes() == b'Updated private guidance\n'
            set_guidance(b'', kind='judge')
            assert guidance('judge')['content'] == ''

            # Ordinary config output, errors and mutation acknowledgments never include guidance.
            assert secret not in json.dumps(show())
            assert secret not in json.dumps(invoke('agents'))
            assert secret not in json.dumps(invoke('logs'))
            assert not state.exists()
            answer_path.unlink()
            missing = guidance()
            assert missing['status'] == 'missing' and missing['guidance_revision'] == 'missing'
            assert show()['guidance_validation'] == 'not_loaded'
            set_guidance(text)
            assert guidance()['content'] == text.decode()


            # Missing/invalid core files block model configuration, not diagnostics or repair.
            core_path = root / 'answer-core-guidance.md'
            core_text = core_path.read_bytes()
            core_path.unlink()
            assert guidance(layer='core')['status'] == 'missing'
            assert show()['guidance_validation'] == 'not_loaded'
            apply({'schedule': {'poll_seconds': 5}}, error='admin_guidance_missing')
            for words in (('status',), ('logs',), ('agents',), ('config', 'show')):
                assert secret not in json.dumps(invoke(*words))
            checked = subprocess.run(base + ['config', 'check'], capture_output=True,
                                     timeout=15, env=environment)
            assert checked.returncode != 0 and secret.encode() not in checked.stdout + checked.stderr
            assert not state.exists()
            set_guidance(core_text, layer='core')
            assert guidance(layer='core')['content'] == core_text.decode()
            assert answer_path.read_bytes() == text, 'core repair overwrote user guidance'
            core_path.write_bytes(b' \n')
            core_path.chmod(0o600)
            apply({'schedule': {'poll_seconds': 5}}, error='admin_validation')
            set_guidance(core_text, layer='core')
            assert invoke('config', 'check') is not None
            # Config/guidance files must not be symlinks, hardlinks, FIFOs or directories.
            preserved = answer_path.read_bytes()
            answer_path.unlink()
            answer_path.symlink_to(credential)
            invoke('guidance', 'show', '--kind', 'answer', expected='admin_unsafe_file')
            set_guidance(b'no', config_rev=show()['file_revision'], guidance_rev='missing', error='admin_unsafe_file')
            assert credential.read_text() == 'pk_test_private_fixture'
            answer_path.unlink()
            os.link(credential, answer_path)
            invoke('guidance', 'show', '--kind', 'answer', expected='admin_unsafe_file')
            answer_path.unlink()
            os.mkfifo(answer_path, 0o600)
            invoke('guidance', 'show', '--kind', 'answer', expected='admin_unsafe_file')
            answer_path.unlink()
            answer_path.mkdir()
            invoke('guidance', 'show', '--kind', 'answer', expected='admin_unsafe_file')
            answer_path.rmdir()
            answer_path.write_bytes(preserved)
            answer_path.chmod(0o644)
            invoke('guidance', 'show', '--kind', 'answer', expected='admin_unsafe_file')
            answer_path.chmod(0o600)
            for target in ('credential', 'config.toml', 'state/state.sqlite3'):
                # The state directory need not exist for the credential/config cases.
                if target.startswith('state/'):
                    state.mkdir(mode=0o700)
                apply({'solver': {'answer': {'guidance_file': target}}}, error='admin_unsafe_target')
            state.rmdir()
            original = config.read_bytes()
            real_config = root / 'original.toml'
            config.rename(real_config)
            config.symlink_to(real_config)
            invoke('config', 'show', expected='admin_unsafe_file')
            config.unlink()
            real_config.rename(config)
            assert config.read_bytes() == original

            # Existing conventional files are not overwritten without their actual revision.
            apply({'solver': {'judge': {'guidance_file': None}}})
            inactive = guidance('judge')
            assert inactive['status'] == 'unconfigured' and inactive['guidance_revision'] == revision(b'')
            set_guidance(b'new judge', kind='judge', config_rev=show()['file_revision'],
                         guidance_rev='missing', error='admin_revision_conflict')
            set_guidance(b'new judge', kind='judge')

            # Initialize only through the actual control CLI, then protect every identity field.
            assert not state.exists()
            invoke('pause')
            database = state / 'state.sqlite3'
            assert database.exists()
            def journal_snapshot():
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
                    return tuple(connection.iterdump())
            # SQLite readers may update shared-memory lock bytes, not journal rows.
            journal_before = journal_snapshot()
            immutable = [{'network': {'address': 'poa1' + '1' * 31 + '2'}},
                         {'network': {'chain': chain + '-other'}},
                         {'network': {'base_url': 'http://127.0.0.1:1'}},
                         {'network': {'credential_file': 'another-credential'}},
                         {'state_dir': 'another-state'}]
            account_keys.add(revision(f'{chain}-other\n{address}'.encode()))
            account_keys.add(revision(f'{chain}\npoa1'.encode() + b'1' * 31 + b'2'))
            for patch in immutable:
                before = config.read_bytes()
                apply(patch, error='admin_identity_immutable')
                assert config.read_bytes() == before
            apply({'participation': {'mode': 'manual'}, 'schedule': {'mine_each_epoch': False}})
            # A saved mutable patch must serialize with final wallet admission.
            token = show()['file_revision']
            before = config.read_bytes()
            account = revision(f'{chain}\n{address}'.encode())
            admission = os.open(lock_root / (account + '.admission'), os.O_RDWR)
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    fcntl.flock(admission, fcntl.LOCK_EX)
                    try:
                        pending = executor.submit(invoke, 'config', 'apply', '--expected-revision', token,
                                                  stdin=json.dumps({'participation': {'mode': 'strict'}}).encode())
                        time.sleep(0.4)
                        assert not pending.done() and config.read_bytes() == before, \
                            'mutable policy save bypassed the final admission gate'
                    finally:
                        fcntl.flock(admission, fcntl.LOCK_UN)
                    assert pending.result(timeout=15)['saved']
            finally:
                os.close(admission)
            set_guidance(b'After initialization\n')
            invoke('config', 'schema')
            show()
            guidance()
            assert journal_snapshot() == journal_before
            startup_race(binary, root, environment, chain, address, account_keys, lock_root,
                         f'http://127.0.0.1:{server.server_port}')
            assert not requests and not (root / 'model-called').exists()
            assert not list(root.glob('.agmi-admin-*.tmp'))
            print(json.dumps({'admin_smoke': 'ok', 'cas_conflict': True, 'private_guidance': True,
                              'core_guidance_required_repairable': True,
                              'immutable_initialized_identity': True, 'network_requests': 0,
                              'model_calls': 0, 'journal_unchanged_by_admin': True,
                              'startup_identity_race_fenced': True, 'mutable_policy_admission_fenced': True}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        for key in account_keys:
            for entry in lock_root.glob(key + '.*'):
                entry.unlink()


if __name__ == '__main__':
    main()
