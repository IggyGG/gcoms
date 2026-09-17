#!/usr/bin/env python3
"""Compare generated Rust contracts and checked-in schema/client artifacts."""
import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--cargo-config');a=p.parse_args()
root=Path(__file__).resolve().parents[1]
base=['cargo']+(['--config',a.cargo_config] if a.cargo_config else [])
def export(args):
    return subprocess.check_output(base+['run','--quiet']+args,cwd=root).decode()
wire=json.loads(export(['-p','gcoms-rpc-contract','--bin','gc-rpc-types']))
for path in ('crates/rpc-contract/schemas/wire.json','packages/gc-rpc/schemas/wire.json'):
    assert wire==json.loads((root/path).read_text()), 'Rust wire schema drift: '+path
addon=json.loads(export(['-p','gcoms-addon-example','--bin','typed-addon-types']))
assert addon==json.loads((root/'examples/typed-addon/browser/contract.json').read_text()), 'Rust addon schema drift'
subprocess.run(['node','packages/gc-rpc/scripts/generate.mjs','--check'],cwd=root,check=True)
subprocess.run(['node','examples/typed-addon/browser/generate.mjs','--check'],cwd=root,check=True)
print('Rust schemas and generated clients agree')
