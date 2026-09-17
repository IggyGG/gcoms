#!/usr/bin/env python3
"""Native CI gate; runners are disposable and contain the pinned toolchain."""
import json, os, subprocess, sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
def run(args):
    subprocess.run(args,cwd=root,check=True)
run([sys.executable,'scripts/check-source.py'])
run([sys.executable,'scripts/check-research-import.py'])
run([sys.executable,'-m','unittest','discover','-s','scripts/tests','-p','*_test.py'])
run(['cargo','fmt','--all','--','--check'])
run(['cargo','test','--workspace','--all-features','--locked','--','--test-threads=1'])
run(['cargo','doc','--workspace','--all-features','--no-deps','--locked'])
run(['cargo','clippy','--workspace','--all-targets','--all-features','--locked','--','-D','warnings'])
run(['npm','ci','--ignore-scripts'])
run(['npm','run','check'])
run(['npm','test'])
run(['npm','run','build'])
run([sys.executable,'scripts/check-vectors.py'])
run([sys.executable,'scripts/check-generated.py'])
run(['cargo','check','-p','gcoms-sdk','--no-default-features','--features','ipc','--locked'])
run(['cargo','check','-p','gcoms-core','--no-default-features','--locked'])
run([sys.executable,'scripts/check-consumers.py'])
if sys.platform=='linux': run(['cargo','deny','check'])
run(['git','diff','--exit-code','--','Cargo.lock','package-lock.json','packages','ui'])
