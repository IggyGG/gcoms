#!/usr/bin/env python3
"""Compile an unchanged released application consumer against today's facade.

The original Rust source stays immutable. Only the dependency manifest and lock
select today's local packages, using the same isolated graph as native consumers.
This checks source compatibility; IPC behavior has separate retained-wire tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'release/contracts/application-0.1.49'


def check(output, cargo_config=None):
    contract = json.loads((FIXTURE / 'contract.json').read_text())
    source = (FIXTURE / 'main.rs').read_bytes()
    if (contract['schema'] != 1 or hashlib.sha256(source).hexdigest() != contract['sha256']
            or contract['commit'] != '2313cf6da2c7d29f3ab1f47a99cd4d39f5c1207e'
            or contract['modes'] != ['ipc', 'embedded', 'network-client']):
        raise ValueError('released consumer or its provenance changed')
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=True)
    consumer = ROOT / 'examples/rust-integration'
    environment = dict(os.environ)
    environment.setdefault('CARGO_TARGET_DIR', str(ROOT / 'target/rust-integrations'))
    results = []
    with tempfile.TemporaryDirectory(prefix='released-consumer-', dir=output) as temporary:
        work = Path(temporary); (work / 'src').mkdir()
        (work / 'src/main.rs').write_bytes(source)
        manifest = (consumer / 'Cargo.toml').read_text()
        relative = '../../crates/application'
        if manifest.count(relative) != 1:
            raise ValueError('current isolated facade dependency is ambiguous')
        (work / 'Cargo.toml').write_text(manifest.replace(relative, (ROOT / 'crates/application').as_posix()))
        (work / 'Cargo.lock').write_bytes((consumer / 'Cargo.lock').read_bytes())
        lock = (work / 'Cargo.lock').read_bytes()
        for mode in contract['modes']:
            log = output / (mode + '.log')
            command = ['cargo', 'check']
            if cargo_config: command += ['--config', str(cargo_config)]
            command += ['--locked', '--manifest-path', str(work / 'Cargo.toml'),
                        '--no-default-features', '--features', mode]
            with log.open('wb') as stream:
                subprocess.run(command, cwd=ROOT, env=environment, stdout=stream,
                               stderr=subprocess.STDOUT, check=True)
            if (work / 'Cargo.lock').read_bytes() != lock or (work / 'src/main.rs').read_bytes() != source:
                raise ValueError('retained consumer inputs changed during compilation')
            results.append({'mode': mode, 'passed': True, 'log': log.name,
                            'sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
    report = {'schema': 1, 'passed': True, 'consumer': contract, 'checks': results,
              'scope': 'released Rust application source compatibility in three isolated feature graphs',
              'wire_compatibility_qualified': False, 'stable_major_qualified': False}
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/released-facade')
    parser.add_argument('--cargo-config', type=Path)
    args = parser.parse_args()
    check(args.output, args.cargo_config)
    print('Released application source compiles unchanged in all three feature graphs.')


if __name__ == '__main__': main()
