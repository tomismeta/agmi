#!/usr/bin/env python3
"""Assemble notices from the locked, vendored sources for a GitHub release."""

import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tomllib
from urllib.request import urlopen

NOTICE = re.compile(r'(?:licen[cs]es?|notices?|copying|copyright|unlicense|authors)(?:[.\-_].*)?$', re.I)
MUSL = 'https://www.musl-libc.org/releases/musl-1.2.5.tar.gz'
MUSL_SHA = 'a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4'
RSQLITE = ('https://raw.githubusercontent.com/Spxg/sqlite-wasm-rs/'
           '3d8318430bacd7d6a1aafdf5b5e54fb0fee8d451/LICENSE')
RSQLITE_SHA = 'e1c1975c3474cce31722836f101a40ffaf1cc784e4d2f38ce3e77b9712934e78'
RUST_LICENSES = {
    'LICENSE-APACHE': '62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a',
    'LICENSE-MIT': 'b71bd43a069ca0641a9ecfe585ca7b3c53b5cc1608f8b68321168698e28b5ea1',
}


def fetch(url, digest):
    with urlopen(url, timeout=30) as response:
        data = response.read(2 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit(f'Unexpected upstream notice source: {url}')
    return data


def rust_toolchain_channel():
    toolchain = Path(__file__).resolve().parent.parent / 'rust-toolchain.toml'
    return tomllib.loads(toolchain.read_text())['toolchain']['channel']


def main(source, rust_notice, version):
    notices = source / 'third-party-licenses'
    notices.mkdir()
    channel = rust_toolchain_channel()
    for name, digest in RUST_LICENSES.items():
        url = f'https://raw.githubusercontent.com/rust-lang/rust/{channel}/{name}'
        (notices / f'rust-{name}').write_bytes(fetch(url, digest))
    (notices / 'rust-COPYRIGHT-library.html').write_bytes(rust_notice.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(fetch(MUSL, MUSL_SHA)), mode='r:gz') as bundle:
        (notices / 'musl-COPYRIGHT').write_bytes(bundle.extractfile('musl-1.2.5/COPYRIGHT').read())

    packages = tomllib.loads((source / 'Cargo.lock').read_text())['package']
    locked = {(p['name'], p['version']): p['checksum'] for p in packages if 'source' in p}
    vendor = source / 'vendor'
    seen = set()
    lines = []
    for crate in sorted(vendor.iterdir()):
        meta = tomllib.loads((crate / 'Cargo.toml').read_text())['package']
        name, number = key = (meta['name'], meta['version'])
        checksums = json.loads((crate / '.cargo-checksum.json').read_text())
        if key in seen or locked.get(key) != checksums['package']:
            raise SystemExit(f'Vendored dependency does not match Cargo.lock: {crate.name}')
        seen.add(key)
        declared = meta.get('license-file')
        paths = sorted(rel for rel in checksums['files'] if NOTICE.fullmatch(Path(rel).name) or rel == declared)
        if declared and declared not in paths:
            raise SystemExit(f'Missing declared notice: {crate.name}')
        if key == ('rsqlite-vfs', '0.2.0') and not paths:
            # The crate omits its parent project's license; pin its upstream VCS revision.
            extra = notices / crate.name / 'LICENSE'
            extra.parent.mkdir()
            extra.write_bytes(fetch(RSQLITE, RSQLITE_SHA))
        elif not paths:
            raise SystemExit(f'No original notice found: {crate.name}')
        for rel in paths:
            if Path(rel).is_absolute() or '..' in Path(rel).parts:
                raise SystemExit(f'Unsafe notice path: {crate.name}')
            original = crate / rel
            if hashlib.sha256(original.read_bytes()).hexdigest() != checksums['files'][rel]:
                raise SystemExit(f'Vendored notice differs from Cargo checksum: {crate.name}/{rel}')
            target = notices / crate.name / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        license_text = meta.get('license') or declared
        if not license_text:
            raise SystemExit(f'Missing license metadata: {crate.name}')
        lines.append(f'- {name} {number} — {license_text} — https://crates.io/crates/{name}/{number}')
    if seen != locked.keys():
        raise SystemExit('Vendored package set is incomplete')

    companion = f'agmi-{version}-third-party-sources.tar.gz'
    (source / 'THIRD_PARTY.md').write_text(
        '# Third-party software\n\n'
        'License and notice texts, including for Rust and musl, are in `third-party-licenses/`.\n'
        f'Locked crate sources, including MPL-2.0-covered `option-ext`, are available in '
        f'[`{companion}`](https://github.com/tomismeta/agmi/releases/download/v{version}/{companion}).\n'
        'The inventory includes build-time and platform-specific crates; not all are linked.\n\n'
        + '\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Packaged notices for {len(seen)} locked registry crates')


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
