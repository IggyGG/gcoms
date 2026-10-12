"""Guest half of the cluster adapter; accepts only the pinned isolated mapping."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback

from android_release import COMPONENTS, cached_artifact, canonical, digest, write_json
from android_release_lab_context import ROOT, isolated, private_json
import android_release_host as host
import android_release_hub as hub
from android_release_network import reference, routing_horizon


def mapped(config):
    """Only runtime locations change; source/input/target identities stay exact."""
    value = dict(config)
    scripts = Path(__file__).resolve().parent
    value.update(state=str(ROOT / 'release'), hub_home=str(ROOT / 'hub-home'), hub_directory=str(ROOT / 'hub'),
        fleet_config=str(ROOT / 'fleet/controller.json'), fleet_binary=str(ROOT / 'release/controller/active/gdrone-fleet'),
        hub_unit='gchat-android-cluster.service', fleet_unit='gdrone-android-cluster.service',
        network_invitation=str(ROOT.parent / 'android-release-network/network/invitation'),
        adb=str(ROOT / 'tools/platform-tools/adb'), qualification_scope='cluster-isolated',
        baseline_receipt=str(ROOT / 'release/baseline.json'),
        hub_activate=[sys.executable, str(scripts / 'android_release_hub.py'), 'activate'],
        hub_rollback=[sys.executable, str(scripts / 'android_release_hub.py'), 'rollback'])
    return value


def validate(envelope):
    original, prepared = envelope['request'], envelope['prepared']
    manifest, config = original['manifest'], original['config']
    unsigned = {k: v for k, v in prepared.items() if k != 'prepared_id'}
    if (prepared.get('schema') != 1 or prepared.get('kind') != 'android-prepared-release'
            or hashlib.sha256(canonical(unsigned)).hexdigest() != prepared.get('prepared_id')
            or manifest.get('prepared_id') != prepared['prepared_id']
            or prepared['configuration_sha256'] != hashlib.sha256(canonical(config)).hexdigest()
            or any(prepared[key] != manifest[key] for key in ('sources', 'inputs', 'targets', 'configuration_sha256'))
            or prepared['targets'] != config['targets']):
        raise ValueError('mapped prepared source/configuration binding changed')
    unsigned_manifest = {k: v for k, v in manifest.items() if k != 'release_id'}
    if hashlib.sha256(canonical(unsigned_manifest)).hexdigest() != manifest.get('release_id'):
        raise ValueError('mapped original release identity changed')
    value = mapped(config)
    isolated(value)
    for component in COMPONENTS:
        receipt = cached_artifact(value, component, manifest['inputs'][component])
        if receipt is None or hashlib.sha256(canonical(receipt)).hexdigest() != prepared['artifacts'][component]:
            raise ValueError('staged prepared artifact changed')
    verification = envelope['verification']
    if (verification.get('schema') != 1 or verification.get('prepared_id') != prepared['prepared_id']
            or verification.get('artifacts') != prepared['artifacts']
            or verification.get('apk_signature_verified') is not True):
        raise ValueError('trusted runner omitted exact APK verification')
    directory = ROOT / 'release/runs' / manifest['release_id']
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = dict(original, config=value, directory=str(directory))
    return request, prepared


def preflight(request):
    config, manifest = request['config'], request['manifest']
    isolated(config)
    baseline = private_json(config['baseline_receipt'])
    reference(baseline, manifest['inputs'], cluster_context=config['cluster_lab'])
    hub.eligible(config); hub.eligible_controller(config)
    write_json(Path(request['directory']) / 'preflight-routing.json',
               routing_horizon(config, manifest['pushed_at'] + 690))
    for target in config['targets']:
        if target['kind'] == 'android' and host.output(host.adb(config, target, 'get-state')).strip() != b'device':
            raise ValueError('pinned cluster Android guest is offline')


def connect_android(config):
    # SSH sessions need not share an ADB daemon. Reconnect only the Pod whose
    # identity and private network boundary were validated for this command.
    _, target = isolated(config)
    host.output([config['adb'], 'connect', target['serial']], timeout=8)
    if host.output(host.adb(config, target, 'get-state'), timeout=8).strip() != b'device':
        raise ValueError('pinned cluster Android guest is offline')


def execute(envelope):
    if envelope.get('schema') != 1 or envelope.get('operation') not in ('preflight', 'activate', 'readiness', 'rollback', 'qualify'):
        raise ValueError('unknown cluster guest operation')
    request, prepared = validate(envelope)
    config, directory = request['config'], Path(request['directory'])
    operation = envelope['operation']
    os.environ.update(XDG_RUNTIME_DIR='/run/user/1000', DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus')
    write_json(directory / 'request.json', request)
    # A restored coordinator cannot overlap a still-running guest command.
    with (ROOT / 'release/release.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = directory / (operation + '-result.json')
        if marker.exists():
            saved = private_json(marker)
            if saved['envelope_sha256'] != hashlib.sha256(canonical(envelope)).hexdigest():
                raise ValueError('preserve original guest execution binding')
            return saved
        started = directory / (operation + '-started.json')
        if started.exists() and operation in ('activate', 'qualify'):
            raise ValueError('original guest mutation has an uncertain outcome; preserve it for reconciliation')
        write_json(started, {'envelope_sha256': hashlib.sha256(canonical(envelope)).hexdigest(),
                             'started_at': time.time()})
        reference_directory = ROOT / 'release/qualification' / request['manifest']['release_id']
        try:
            connect_android(config)
            if operation == 'qualify':
                from android_release_qualify import _run_reference
                result = _run_reference(config, prepared['prepared_id'], verified_prepared=prepared,
                                        directory=reference_directory)
            else:
                {'preflight': preflight, 'activate': host.activate, 'readiness': host.readiness,
                 'rollback': host.rollback}[operation](request)
                result = {'state': 'complete'}
        except Exception as error:
            write_json(directory / (operation + '-failure-private.json'), {'traceback': traceback.format_exc()})
            result = {'state': 'failed', 'failure_type': type(error).__name__}
            if operation == 'qualify' and (reference_directory / 'result.json').exists():
                result = private_json(reference_directory / 'result.json')
                if result.get('prepared_id') != prepared['prepared_id'] or result.get('state') != 'failed':
                    raise ValueError('guest failure evidence binding changed') from None
        evidence = {}
        for name in ('live.json', 'rollback.json', 'preflight-routing.json'):
            path = directory / name
            if path.exists(): evidence[name] = private_json(path)
        saved = {'schema': 1, 'operation': operation, 'envelope_sha256': hashlib.sha256(canonical(envelope)).hexdigest(),
                 'result': result, 'evidence': evidence, 'completed_at': time.time()}
        write_json(marker, saved)
        return saved


if __name__ == '__main__':
    os.umask(0o077)
    path, checksum = sys.argv[1:]
    value = private_json(path)
    if hashlib.sha256(canonical(value)).hexdigest() != checksum:
        raise ValueError('guest command envelope changed in transit')
    print(json.dumps(execute(value)))
