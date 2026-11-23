#!/usr/bin/env python3
"""Publish a qualified agmi archive using Cargo's checksum-bound credential request."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


INDEX_URLS = (
    'https://github.com/rust-lang/crates.io-index',
    'sparse+https://index.crates.io/',
)


def fail(message):
    return {'Err': {'kind': 'other', 'message': message}}


def respond(request):
    if not isinstance(request, dict) or request.get('v') != 1 or request.get('kind') != 'get':
        return {'Err': {'kind': 'operation-not-supported'}}
    registry = request.get('registry')
    if (not isinstance(registry, dict) or registry.get('name') not in (None, 'crates-io')
            or registry.get('index-url') not in INDEX_URLS):
        return fail('Only the public crates.io registry is permitted')

    version = os.environ.get('AGMI_CRATE_VERSION', '')
    checksum = os.environ.get('AGMI_CRATE_SHA256', '')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or not re.fullmatch(r'[0-9a-f]{64}', checksum):
        return fail('Set AGMI_CRATE_VERSION and AGMI_CRATE_SHA256 from the qualified release')

    operation = request.get('operation')
    if operation == 'publish':
        if (request.get('name'), request.get('vers')) != ('agmi', version):
            return fail('Cargo publish request does not match the qualified agmi name and version')
        actual = request.get('cksum')
        if not isinstance(actual, str) or not re.fullmatch(r'[0-9a-f]{64}', actual):
            return fail('Cargo publish request did not supply a SHA-256')
        if actual != checksum:
            return fail(f'Cargo archive SHA-256 {actual} does not match the qualified SHA-256 {checksum}')
    elif operation != 'read':
        return {'Err': {'kind': 'operation-not-supported'}}

    token = os.environ.get('AGMI_CRATES_IO_TOKEN')
    if not token:
        return {'Err': {'kind': 'not-found'}}
    # Cargo 1.96 does a Read authentication preflight; never let its response
    # satisfy a later Publish request without Cargo's actual archive checksum.
    return {'Ok': {'kind': 'get', 'token': token, 'cache': 'never', 'operation_independent': False}}


def credential():
    print(json.dumps({'v': [1]}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except ValueError:
            result = fail('Invalid Cargo credential request')
        else:
            result = respond(request)
        print(json.dumps(result), flush=True)


def publish():
    if not subprocess.check_output(['cargo', '--version'], text=True).startswith('cargo 1.96.0 '):
        raise SystemExit('Select Cargo 1.96.0 before publishing')
    provider = json.dumps(str(Path(__file__).resolve()), ensure_ascii=False)
    with tempfile.TemporaryDirectory(prefix='agmi-publish-') as cargo_home:
        env = dict(os.environ, CARGO_HOME=cargo_home)
        env.pop('CARGO_REGISTRY_TOKEN', None)
        env.pop('CARGO_REGISTRIES_CRATES_IO_TOKEN', None)
        result = subprocess.run(
            ['cargo', 'publish', '--locked', '--registry', 'crates-io', '--no-verify',
             '--config', f'registry.credential-provider={provider}'],
            env=env,
        )
    return result.returncode


if __name__ == '__main__':
    if sys.argv[1:] == ['--cargo-plugin']:
        credential()
    elif sys.argv[1:] == ['--publish']:
        raise SystemExit(publish())
    else:
        raise SystemExit('See docs/OPERATIONS.md#cratesio-publication')
