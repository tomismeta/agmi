#!/usr/bin/env python3
"""Exercise the credential boundary using synthetic tokens and a loopback registry."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread


PUBLISHER = Path(__file__).resolve().parents[1] / 'tools/publish-crate.py'


def check_protocol():
    checksum = 'a' * 64
    registry = {'name': 'crates-io', 'index-url': 'sparse+https://index.crates.io/'}
    publish = {'v': 1, 'kind': 'get', 'registry': registry, 'operation': 'publish',
               'name': 'agmi', 'vers': '0.3.2', 'cksum': checksum}
    requests = [
        {'v': 1, 'kind': 'get', 'registry': registry, 'operation': 'read'},
        dict(publish, cksum='b' * 64),
        publish,
        dict(publish, name='other'),
        dict(publish, vers='0.3.3'),
        dict(publish, registry=dict(registry, **{'index-url': 'sparse+https://other.invalid/'})),
    ]
    env = dict(os.environ, AGMI_CRATE_VERSION='0.3.2', AGMI_CRATE_SHA256=checksum,
               AGMI_CRATES_IO_TOKEN='fixture-credential')
    with subprocess.Popen([sys.executable, str(PUBLISHER), '--cargo-plugin'],
                          env=env, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
        assert json.loads(process.stdout.readline()) == {'v': [1]}
        for request in requests:
            process.stdin.write(json.dumps(request) + '\n')
            process.stdin.flush()
            reply = json.loads(process.stdout.readline())
            if request['operation'] == 'read' or request == publish:
                assert reply['Ok']['cache'] == 'never' and not reply['Ok']['operation_independent']
                assert reply['Ok']['token'] == 'fixture-credential'
            else:
                assert 'Err' in reply and 'fixture-credential' not in json.dumps(reply)
        process.stdin.close()
        assert process.wait(timeout=5) == 0
    print('crates.io credential gate: refused wrong archive, crate, version and registry')


def check_cargo():
    writes = []

    class Registry(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path != '/config.json':
                self.send_error(404)
                return
            body = json.dumps({'api': origin, 'dl': origin}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_PUT(self):
            writes.append(self.path)
            self.send_error(403)

        do_CONNECT = do_POST = do_PUT

    with TemporaryDirectory() as work, ThreadingHTTPServer(('127.0.0.1', 0), Registry) as server:
        root = Path(work)
        (root / 'Cargo.toml').write_text(
            '[package]\nname = "agmi"\nversion = "0.3.2"\nedition = "2024"\n'
            'license = "MIT"\ndescription = "Credential gate fixture"\n'
            'publish = ["crates-io"]\n'
        )
        (root / 'src').mkdir()
        (root / 'src/main.rs').write_text('fn main() {}\n')
        origin = f'http://127.0.0.1:{server.server_port}'
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = dict(os.environ, CARGO_HOME=work, CARGO_TARGET_DIR=str(root / 'target'),
                       CARGO_HTTP_PROXY=origin, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1',
                       __CARGO_TEST_CRATES_IO_URL_DO_NOT_USE_THIS=f'sparse+{origin}/',
                       AGMI_CRATE_VERSION='0.3.2', AGMI_CRATE_SHA256='0' * 64,
                       AGMI_CRATES_IO_TOKEN='fixture-credential')
            subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root,
                           env=env, check=True, timeout=15)
            result = subprocess.run([str(PUBLISHER), '--publish'], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=45)
            assert not writes, writes
            assert result.returncode and 'does not match the qualified SHA-256' in result.stderr, result.stderr
        finally:
            server.shutdown()
            thread.join()
    print('Cargo publish: wrong checksum denied before any upload')


if __name__ == '__main__':
    check_protocol()
    check_cargo()
