"""Trusted Kubernetes adapter for normal owners in the isolated Android lab."""
from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import time

from android_release import COMPONENTS, canonical, cached_artifact, digest, prepared_release, promotion_manifest, write_json
from android_release_lab_context import ROOT, identity
from android_release_store import regular_file
import android_release_host as host


# The receiver only installs private, bounded regular files below its owned root.
# Content-addressed artifacts/runtime directories are immutable even on retry.
RECEIVER = r'''import hashlib,os,pathlib,stat,sys,tarfile,tempfile
root=pathlib.Path('/home/lab/.local/state/android-cluster-release')
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:raise ValueError('private guest root required')
count=total=0
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
 for item in archive:
  count+=1;total+=item.size
  parts=item.name.split('/')
  if (not item.isfile() or item.size<0 or item.size>1024**3 or count>4096 or total>4*1024**3
      or any(x in ('','.','..') for x in parts) or item.name.startswith('/') or chr(92) in item.name
      or len(item.name.encode())>2048
      or parts[0] not in ('runtimes','release','commands')):raise ValueError('unsafe guest stage member')
  path=root.joinpath(*parts)
  for parent in list(path.parents)[::-1]:
   if parent==root or root not in parent.parents:continue
   parent.mkdir(mode=0o700,exist_ok=True)
   info=parent.lstat()
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:raise ValueError('unsafe guest stage parent')
  data=archive.extractfile(item);hasher=hashlib.sha256()
  fd,temporary=tempfile.mkstemp(dir=path.parent,prefix='.stage-')
  try:
   with os.fdopen(fd,'wb') as output:
    os.fchmod(output.fileno(),0o700 if item.mode&0o100 else 0o600)
    while chunk:=data.read(1024**2):hasher.update(chunk);output.write(chunk)
    output.flush();os.fsync(output.fileno())
   if path.exists() or path.is_symlink():
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1:raise ValueError('preserve unsafe existing guest stage file')
    with path.open('rb') as old:old_sha=hashlib.file_digest(old,'sha256').hexdigest()
    if old_sha!=hasher.hexdigest():raise ValueError('preserve different immutable guest stage bytes')
   else:
    os.link(temporary,path)
    parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)
  finally:os.unlink(temporary)
'''


def create_lab(config):
    from ghost_lab.cluster_operator import configure
    from ghost_lab.lifecycle import Lab
    settings, _ = configure(config['lab']['settings'])
    return Lab(settings, store=object())


@contextmanager
def reserved_lab(config):
    """Coordinator and Jobs renew the same bounded lifecycle reservations."""
    selected = config['lab']
    android = selected['android_pod']
    if not isinstance(android, str) or not android.startswith('gl-'):
        raise ValueError('Android reservation requires its normal lab instance name')
    names = [selected['network_guest'], android[3:]]
    if (any(not isinstance(n, str) or not re.fullmatch('[a-z][a-z0-9-]{0,39}', n) for n in names) or len(set(names)) != 2):
        raise ValueError('Two distinct normal lab instances are required')
    owner = selected['reservation_id']
    lab = create_lab(config)
    with ExitStack() as stack:
        fences = [stack.enter_context(lab.kube.reservation(n, owner)) for n in sorted(names)]
        def fence():
            for check in fences:
                check()
        fence()
        yield lab, fence
        fence()


def qualified_lab(config, lab=None):
    from ghost_lab.qualification import require
    selected = config['lab']
    expected = identity(config['cluster_lab'])
    lab = lab or create_lab(config)
    settings = lab.settings
    proof = require(lab)
    if proof['network_sha256'] != expected['boundary_sha256']:
        raise ValueError('live cluster lab isolation boundary changed')
    state = lab.state(selected['network_guest'])
    if (state.get('phase') in ('discarded', 'stopped', 'stopping', 'saving', 'restoring')
            or state.get('scratch_released')):
        raise ValueError('lab network guest is unavailable; preserve its original lifecycle state')
    if state['machine_uuid'] != expected['vm_uuid'] or state['resource'] != 'gl-' + selected['network_guest']:
        raise ValueError('lab network VM identity changed')
    vmi = lab.kube.get('vmi', state['resource'], ns=settings.namespace)
    pod = lab.kube.get('pod', selected['android_pod'], ns=settings.namespace)
    if (not vmi or not pod or vmi['metadata'].get('deletionTimestamp') or pod['metadata'].get('deletionTimestamp')
            or vmi.get('status', {}).get('phase') != 'Running' or pod['metadata']['uid'] != expected['android_pod_uid']
            or pod['status'].get('phase') != 'Running' or pod['status'].get('podIP') != expected['android_pod_ip']
            or not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod['status'].get('conditions', []))):
        raise ValueError('declared Android cluster guest changed or is not ready')
    return lab, state


def verified(request, prepared):
    """Verify APK signing, alignment and embedded native bytes in the runner."""
    host.verify(request)
    return {'schema': 1, 'prepared_id': prepared['prepared_id'], 'artifacts': prepared['artifacts'],
            'apk_signature_verified': True}


def runtime_files():
    folder = Path(__file__).resolve().parent
    files = {p.name: p for p in sorted(folder.glob('android_release*.py'))}
    identity_ = hashlib.sha256(canonical({n: digest(p) for n, p in files.items()})).hexdigest()
    return identity_, files


def stage(ssh, envelope):
    config, manifest = envelope['request']['config'], envelope['request']['manifest']
    runtime, scripts = runtime_files()
    files = {'runtimes/' + runtime + '/' + name: source for name, source in scripts.items()}
    for component in COMPONENTS:
        receipt = cached_artifact(config, component, manifest['inputs'][component])
        if receipt is None: raise ValueError('verified artifact is unavailable for guest staging')
        root = Path(config['state']) / 'artifacts' / component / manifest['inputs'][component]
        for name in ('receipt.json', *receipt['files']):
            files['release/artifacts/' + component + '/' + manifest['inputs'][component] + '/' + name] = regular_file(root, name)
    checksum = hashlib.sha256(canonical(envelope)).hexdigest()
    command_path = 'commands/' + checksum + '.json'
    process = subprocess.Popen(ssh + ['python3 -c ' + shlex.quote(RECEIVER)], stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdin, mode='w|') as archive:
            for name, path in files.items():
                item = tarfile.TarInfo(name); item.size = path.stat().st_size
                item.mode = 0o700 if os.access(path, os.X_OK) else 0o600
                with path.open('rb') as stream: archive.addfile(item, stream)
            data = canonical(envelope)
            item = tarfile.TarInfo(command_path); item.size = len(data); item.mode = 0o600
            archive.addfile(item, io.BytesIO(data))
        process.stdin.close()
        if process.wait(timeout=45): raise ValueError('cluster guest staging failed')
    finally:
        if process.poll() is None: process.kill(); process.wait()
    return ROOT / 'runtimes' / runtime / 'android_release_lab_runtime.py', ROOT / command_path, checksum


def remote(request, operation, prepared=None):
    config = request['config']
    prepared = prepared or prepared_release(config, request['manifest']['prepared_id'])
    with reserved_lab(config) as (lab, fence):
        return remote_reserved(request, operation, prepared, lab, fence)


def remote_reserved(request, operation, prepared, lab, fence):
    from ghost_lab.access import tunnel, ssh_command
    config = request['config']
    # Verification precedes guest mutation; only the trusted runner can supply
    # the attestation, through the VM's private pinned SSH identity.
    verification = verified(request, prepared)
    lab, state = qualified_lab(config, lab)
    envelope = {'schema': 1, 'operation': operation, 'request': request,
                'prepared': prepared, 'verification': verification}
    timeout = 395 if operation == 'qualify' else max(1, min(540, request['manifest']['pushed_at'] + 600 - time.time()))
    directory = Path(request['directory']); directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tunnel(lab, state, 22) as port:
        ssh = ssh_command(lab, state, port)
        fence()
        program, command_path, checksum = stage(ssh, envelope)
        fence()
        # stdout is a bounded public proof; detailed guest logs stay private.
        output = directory / (operation + '-guest.json')
        errors = directory / (operation + '-guest-error.log')
        with output.open('wb') as stream, errors.open('wb') as log:
            os.chmod(output, 0o600); os.chmod(errors, 0o600)
            result = subprocess.run(ssh + ['python3 ' + shlex.quote(str(program)) + ' '
                + shlex.quote(str(command_path)) + ' ' + checksum], stdout=stream, stderr=log, timeout=timeout)
        if result.returncode: raise ValueError('cluster guest operation failed; original private evidence retained')
    fence()
    if output.stat().st_size > 1024 * 1024: raise ValueError('guest evidence exceeds its bound')
    value = json.loads(output.read_text())
    if value.get('envelope_sha256') != checksum or value.get('operation') != operation:
        raise ValueError('cluster guest evidence belongs to another command')
    for name, content in value['evidence'].items():
        if name not in ('live.json', 'rollback.json', 'preflight-routing.json'):
            raise ValueError('unexpected guest evidence file')
        write_json(directory / name, content)
    if operation != 'qualify' and value['result'].get('state') == 'failed':
        raise ValueError('original cluster guest operation failed; result retained')
    return value['result']


def qualify(config, manifest):
    prepared = prepared_release(config, manifest['prepared_id'])
    if manifest != promotion_manifest(config, manifest['prepared_id'], manifest['pushed_at']):
        raise ValueError('original qualification manifest changed')
    directory = Path(config['state']) / 'cluster-qualification' / manifest['release_id']
    request = {'config': config, 'manifest': manifest, 'directory': str(directory), 'warm': False}
    value = remote(request, 'qualify', prepared)
    from android_release_network import reference
    if value.get('state') == 'qualified':
        reference(value, prepared['inputs'], cluster_context=config['cluster_lab'])
        write_json(config['baseline_receipt'], value)
    return value


def action(operation, request):
    if operation == 'verify':
        host.verify(request)
    elif operation == 'preflight' and request.get('warm'):
        host.preflight(request)
    elif operation in ('preflight', 'activate', 'readiness', 'rollback'):
        remote(request, operation)
    else:
        raise ValueError('unsupported Android cluster action')


if __name__ == '__main__':
    operation, path = sys.argv[1:]
    action(operation, json.loads(Path(path).read_text()))
