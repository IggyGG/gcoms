"""Explicit, prepared isolated-lab fault fixture; never a normal release action."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from android_release import canonical, digest, prepared_release, write_json
import android_release_host as host
import android_release_lab as adapter
from android_release_lab_context import ROOT, isolated, private_json
import android_release_lab_runtime as runtime

KIND = 'stop-activated-android-app'


def required(config):
    if (config.get('qualification_scope') != 'cluster-isolated'
            or config.get('failure_canary') != KIND):
        raise ValueError('explicit prepared isolated-lab failure canary required')


def guest(path, checksum):
    envelope = private_json(path)
    if (hashlib.sha256(canonical(envelope)).hexdigest() != checksum
            or envelope.get('schema') != 1 or envelope.get('operation') != 'readiness'):
        raise ValueError('original canary envelope changed')
    required(envelope['request']['config'])
    request, _prepared = runtime.validate(envelope)
    config, manifest = request['config'], request['manifest']
    _fleet, target = isolated(config)
    directory = Path(request['directory'])
    os.environ.update(XDG_RUNTIME_DIR='/run/user/1000',
                      DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus')
    with (ROOT / 'release/release.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = directory / 'failed-canary-observation.json'
        started = directory / 'failed-canary-started.json'
        if marker.exists():
            previous = private_json(marker)
            if previous['envelope_sha256'] != checksum:
                raise ValueError('preserve the original canary result binding')
            return previous
        if started.exists():
            raise ValueError('original canary fault outcome uncertain; inspect without replay')
        activation = private_json(directory / 'activate-result.json')
        activated = dict(envelope, operation='activate')
        if (activation['result'].get('state') != 'complete'
                or activation.get('envelope_sha256') != hashlib.sha256(canonical(activated)).hexdigest()):
            raise ValueError('canary requires completed real activation')
        runtime.connect_android(config)
        expected = private_json(directory / target['id'] / 'deployment-request.json')
        actual = {'release_id': manifest['release_id'],
                  'apk_sha256': digest(host.artifact(request, 'apk', 'agent.apk')),
                  'worker_sha256': digest(host.artifact(request, 'worker', target['abi'] + '/worker.so'))}
        if expected != actual or json.loads(host.private_file(config, target, 'deployment-request.json')) != expected:
            raise ValueError('preserve an Android process outside the exact canary release')
        before = private_json(directory / 'android-before.json')
        identity = next(row['identity_sha256'] for row in before if row['target'] == target)
        if host.identity(config, target) != identity:
            raise ValueError('preserve a changed Android identity')
        pid = host.output(host.adb(config, target, 'shell', 'pidof', host.PACKAGE), timeout=5).decode().strip()
        if not pid.isdigit():
            raise ValueError('canary activation has no live Android process')
        installed = host.output(host.adb(config, target, 'shell', 'pm', 'path', host.PACKAGE), timeout=5).decode().strip()
        if not installed.startswith('package:/data/app/') or '\n' in installed or not installed.endswith('/base.apk'):
            raise ValueError('canary has no single installed application path')
        apk = installed.removeprefix('package:')
        installed_sha = host.output(host.adb(config, target, 'shell', 'sha256sum', apk), timeout=5).decode().split()[0]
        if (installed_sha != expected['apk_sha256']
                or host.output(host.adb(config, target, 'shell', 'pidof', host.PACKAGE), timeout=5).decode().strip() != pid):
            raise ValueError('preserve changed canary APK or process ownership')
        write_json(started, {'schema': 1, 'envelope_sha256': checksum,
                            'started_at': time.time(), 'prior_process_id': int(pid)})
        host.command(host.adb(config, target, 'shell', 'am', 'force-stop', host.PACKAGE), timeout=5)
        stopped = subprocess.run(host.adb(config, target, 'shell', 'pidof', host.PACKAGE),
                                 capture_output=True, timeout=5, check=False)
        if stopped.returncode != 1 or stopped.stdout.strip():
            raise ValueError('canary fault did not prove the selected Android process absent')
        proof = {'schema': 1, 'state': 'fault_observed', 'envelope_sha256': checksum,
                 'release_id': manifest['release_id'], 'prepared_id': manifest['prepared_id'],
                 'observed_at': time.time(), 'prior_process_id': int(pid),
                 'process_present': False, 'fault': KIND, 'selected': expected,
                 'identity_sha256': identity, 'requires_functional_restoration': True}
        write_json(marker, proof)
        return proof


def cluster(request):
    config = request['config']
    required(config)
    prepared = prepared_release(config, request['manifest']['prepared_id'])
    directory = Path(request['directory'])
    from ghost_lab.access import tunnel, ssh_command
    with adapter.reserved_lab(config) as (lab, fence):
        verification = adapter.verified(request, prepared)
        lab, state = adapter.qualified_lab(config, lab)
        envelope = {'schema': 1, 'operation': 'readiness', 'request': request,
                    'prepared': prepared, 'verification': verification}
        with tunnel(lab, state, 22) as port:
            ssh = ssh_command(lab, state, port)
            fence()
            program, command_path, checksum = adapter.stage(ssh, envelope)
            program = program.with_name('android_release_lab_canary.py')
            fence()
            error = directory / 'failed-canary-private.log'
            with error.open('wb') as log:
                os.chmod(error, 0o600)
                result = subprocess.run(ssh + ['python3 ' + shlex.quote(str(program)) + ' '
                    + shlex.quote(str(command_path)) + ' ' + checksum], stdout=subprocess.PIPE,
                    stderr=log, timeout=40, check=False)
            if result.returncode or len(result.stdout) > 16384:
                raise ValueError('original canary fault failed or uncertain; preserve private evidence')
        fence()
    proof = json.loads(result.stdout)
    if (proof.get('state') != 'fault_observed' or proof.get('envelope_sha256') != checksum
            or proof.get('release_id') != request['manifest']['release_id']
            or proof.get('process_present') is not False):
        raise ValueError('canary guest proof binding changed')
    write_json(directory / 'failed-canary-observation.json', proof)
    from android_release_catalogue import Catalogue
    catalogue = Catalogue(config)
    archive = catalogue.archive.publish_record(proof)
    catalogue.bind('checkpoints', 'failed-canary/' + proof['release_id'], archive)
    write_json(directory / 'failed-canary-archive.json', archive)
    raise ValueError('activated Android canary has no live worker process; normal rollback required')


if __name__ == '__main__':
    os.umask(0o077)
    if len(sys.argv) == 2:
        cluster(private_json(sys.argv[1]))
    elif len(sys.argv) == 3:
        print(json.dumps(guest(sys.argv[1], sys.argv[2])))
    else:
        raise SystemExit('one cluster request or original guest envelope and checksum required')
