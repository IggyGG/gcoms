"""Provision normal Android lab owners from immutable cluster/S3 artifacts."""
import argparse
from contextlib import ExitStack
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import uuid

from android_release import canonical, digest, prepared_release, write_json
from android_release_lab import RECEIVER
from android_release_lab_context import ROOT, identity
from android_release_store import Archive, regular_file

NETWORK = Path('/home/lab/.local/state/android-release-network')
RELAYS = ['157.90.35.101', '78.46.219.146', '116.202.84.152', '49.12.172.59', '95.217.200.179']
PORTS = [{'name': 'provider', 'port': 443, 'targetPort': 443},
         {'name': 'dns', 'port': 5353, 'targetPort': 5353, 'protocol': 'UDP'},
         *[{'name': 'relay-' + str(i), 'port': 19440 + i, 'targetPort': 19440 + i} for i in range(1, 6)]]


def validate(plan):
    if plan.get('schema') != 1 or set(plan['guests']) != {'android', 'network'}:
        raise ValueError('explicit Android and network lab pair required')
    parsed = uuid.UUID(plan['owner'])
    if str(parsed) != plan['owner'] or not parsed.int:
        raise ValueError('canonical pipeline owner required')
    names = [row['name'] for row in plan['guests'].values()]
    if (len(set(names)) != 2 or any(not re.fullmatch('[a-z][a-z0-9-]{0,39}', n) for n in [*names, plan['service']])
            or any(n in plan.get('preserved_instances', []) for n in names)):
        raise ValueError('distinct scoped lab names required')
    return plan


def context(lab, plan):
    from ghost_lab.qualification import require
    proof = require(lab)
    network = lab.owned_state(plan['guests']['network']['name'], plan['owner'])
    android = lab.owned_state(plan['guests']['android']['name'], plan['owner'])
    for key, state in [('network', network), ('android', android)]:
        if (state['image'] != plan['guests'][key]['image'] or state.get('scratch_released')
                or state.get('phase') != 'booting' or state['resource'] != 'gl-' + plan['guests'][key]['name']):
            raise ValueError('planned guest image or lifecycle changed')
    vm = lab.kube.get('vm', network['resource'], ns=lab.settings.namespace)
    vmi = lab.kube.get('vmi', network['resource'], ns=lab.settings.namespace)
    pod = lab.kube.get('pod', android['resource'], ns=lab.settings.namespace)
    if (not vm or vm['metadata']['uid'] != network['vm_uid'] or not vmi
            or vmi.get('status', {}).get('phase') != 'Running' or vmi['metadata'].get('deletionTimestamp')
            or not any(o.get('kind') == 'VirtualMachine' and o.get('uid') == network['vm_uid'] for o in vmi['metadata'].get('ownerReferences', []))
            or not pod or pod.get('status', {}).get('phase') != 'Running' or pod['metadata'].get('deletionTimestamp')
            or not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod['status'].get('conditions', []))):
        raise ValueError('both exact owned cluster guests must be ready')
    selected = identity({'schema': 1, 'vm_uuid': network['machine_uuid'], 'android_pod_uid': pod['metadata']['uid'],
                         'android_pod_ip': pod['status']['podIP'], 'boundary_sha256': proof['network_sha256']})
    return selected, network, pod


def service(lab, plan):
    name = plan['service']
    selector = {'ghost.io/instance': 'gl-' + plan['guests']['network']['name']}
    current = lab.kube.get('service', name, ns=lab.settings.namespace)
    if current is None:
        lab.kube.create({'apiVersion': 'v1', 'kind': 'Service',
            'metadata': {'name': name, 'namespace': lab.settings.namespace,
                         'labels': {'app.kubernetes.io/part-of': 'android-cluster-release', 'ghost.io/pipeline': plan['owner']}},
            'spec': {'type': 'ClusterIP', 'selector': selector, 'ports': PORTS}})
        current = lab.kube.get('service', name, ns=lab.settings.namespace)
    spec = current['spec']
    ports = [{k: p[k] for k in ('port', 'targetPort', 'protocol')} for p in spec['ports']]
    expected = [{k: p.get(k, 'TCP') for k in ('port', 'targetPort', 'protocol')} for p in PORTS]
    if (current['metadata'].get('deletionTimestamp') or current['metadata'].get('labels', {}).get('ghost.io/pipeline') != plan['owner']
            or spec.get('type') != 'ClusterIP' or spec.get('selector') != selector or ports != expected
            or spec.get('externalIPs') or spec.get('externalName') or spec.get('loadBalancerIP')):
        raise ValueError('preserve different network Service ownership or exposure')
    address = ipaddress.IPv4Address(spec['clusterIP'])
    if address not in ipaddress.IPv4Network('10.96.0.0/12'):
        raise ValueError('network Service is outside the cluster range')
    return str(address)


def send(ssh, destination, files, values):
    """Use the existing bounded, immutable receiver within one fixed guest root."""
    if destination not in (ROOT, NETWORK): raise ValueError('fixed private guest root required')
    prefixes = sorted({name.split('/')[0] for name in [*files, *values]})
    receiver = RECEIVER.replace(str(ROOT), str(destination)).replace("('runtimes','release','commands')", repr(tuple(prefixes)))
    command = 'umask 077; mkdir -p ' + shlex.quote(str(destination)) + '; python3 -c ' + shlex.quote(receiver)
    process = subprocess.Popen(ssh + [command], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdin, mode='w|') as archive:
            for name, path in files.items():
                item = tarfile.TarInfo(name); item.size = path.stat().st_size
                item.mode = 0o700 if os.access(path, os.X_OK) else 0o600
                with path.open('rb') as stream: archive.addfile(item, stream)
            for name, value in values.items():
                data = canonical(value); item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o600
                archive.addfile(item, io.BytesIO(data))
        process.stdin.close()
        if process.wait(timeout=60): raise ValueError('private guest bootstrap staging failed')
    finally:
        if process.poll() is None: process.kill(); process.wait()


def execute_once(ssh, destination, script, binding, directory):
    # Journal on the guest before mutation. An interrupted attempt requires
    # inspection; neither a new Job nor a lost client reply may replay it.
    runner = '''import hashlib,json,os,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);script=sys.argv[2];binding=sys.argv[3]
marker=root/(script+'.started.json');result=root/(script+'.result.json')
def save(path,value):
 with path.open('x') as stream:
  os.chmod(path,0o600);json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
 fd=os.open(root,os.O_DIRECTORY|os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)
if marker.exists():
 if json.loads(marker.read_text())!={'binding':binding}:raise ValueError('original bootstrap binding changed')
 if not result.exists():raise ValueError('original bootstrap outcome uncertain; inspect retained guest state')
 value=json.loads(result.read_text())
else:
 save(marker,{'binding':binding})
 with (root/(script+'.private.log')).open('wb') as log:
  os.chmod(log.name,0o600)
  child=subprocess.run(['python3',str(root/script)],stdout=subprocess.PIPE,stderr=log,timeout=240)
 if child.returncode:value={'state':'failed','exit_code':child.returncode}
 else:value={'state':'complete','proof':json.loads(child.stdout)}
 save(result,value)
print(json.dumps(value),flush=True)
'''
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    error = directory / (script + '.error.log')
    with error.open('wb') as log:
        os.chmod(error, 0o600)
        result = subprocess.run(ssh + ['python3 -c ' + shlex.quote(runner) + ' ' + ' '.join(map(shlex.quote, [str(destination), script, binding]))],
            stdout=subprocess.PIPE, stderr=log, timeout=270)
    if result.returncode or len(result.stdout) > 65536:
        raise ValueError('guest bootstrap failed or uncertain; original private evidence retained')
    value = json.loads(result.stdout)
    if value.get('state') != 'complete': raise ValueError('original guest bootstrap failed; inspect private guest evidence')
    return value['proof']


def network(lab, plan, selected, state, settings, ssh):
    address = service(lab, plan)
    configuration = {'schema': 1, 'machine_uuid': selected['vm_uuid'], 'guest_ip': address,
                     'relay_ips': RELAYS, 'provider': 'android-lab.triform.cloud', 'native_input': settings['network_input']}
    archive = Archive(settings['archive'])
    root = Path(settings['state']) / 'network-binaries' / settings['network_input']
    if not root.exists(): archive.restore_directory(settings['network_archive'], root, 'lab-network', settings['network_input'])
    receipt = json.loads(regular_file(root, 'receipt.json').read_text())
    if (receipt.get('component') != 'lab-network' or receipt.get('input_sha256') != settings['network_input']
            or set(receipt['files']) != {'gcnode', 'gcoms-catalog', 'gc-network-operator'}):
        raise ValueError('exact network artifact receipt required')
    for name, checksum in receipt['files'].items():
        if digest(regular_file(root, name)) != checksum: raise ValueError('network native bytes changed')
    script = 'android_release_lab_network_bootstrap.py'
    files = {'bin/' + name: regular_file(root, name) for name in ['receipt.json', *receipt['files']]}
    files.update({name: Path(__file__).with_name(name) for name in (script, 'android_release_lab_services.py')})
    files.update({'tls/provider.crt': Path(settings['provider_certificate']), 'tls/provider.key': Path(settings['provider_key'])})
    binding = hashlib.sha256(canonical({'configuration': configuration, 'files': {n: digest(p) for n, p in files.items()}})).hexdigest()
    lab.kube.fence_operations()
    send(ssh, NETWORK, files, {'settings.json': configuration})
    lab.kube.fence_operations()
    return execute_once(ssh, NETWORK, script, binding, Path(settings['state']))


def connect(lab, plan, selected, state, settings, ssh):
    address = service(lab, plan)
    pod = 'gl-' + plan['guests']['android']['name']
    def adb(*args, **kwargs):
        current = lab.kube.get('pod', pod, ns=lab.settings.namespace)
        if current['metadata']['uid'] != selected['android_pod_uid']: raise ValueError('Android Pod changed during routing')
        return lab.kube.run('exec', '-i', pod, '-n', lab.settings.namespace, '--', 'adb', '-s', 'emulator-5556', *args, **kwargs)
    def shell(*args, **kwargs): return adb('shell', *args, **kwargs)
    config = dict(selected, service_ip=address, relay_ips=RELAYS)
    chain = 'GHOST_ANDROID_RELEASE'; marker = '/data/local/tmp/android-cluster-network.json'
    adb('root'); adb('wait-for-device')
    try:
        if shell('id', '-u').stdout.strip() != b'0': raise ValueError('isolated Android admin unavailable')
        old = shell('cat', marker, check=False)
        exists = shell('iptables', '-t', 'nat', '-S', chain, check=False).returncode == 0
        if old.returncode == 0:
            if json.loads(old.stdout) != config: raise ValueError('preserve different Android routing ownership')
        elif exists: raise ValueError('preserve existing unowned Android routing chain')
        lab.kube.fence_operations()
        shell('umask 077; cat > ' + marker, data=config)
        if not exists: shell('iptables', '-t', 'nat', '-N', chain)
        rules = [['-p', 'tcp', '-d', ip + '/32', '--dport', str(19440 + i), '-j', 'DNAT', '--to-destination', address + ':' + str(19440 + i)] for i, ip in enumerate(RELAYS, 1)]
        rules.append(['-p', 'udp', '--dport', '53', '-j', 'DNAT', '--to-destination', address + ':5353'])
        for rule in rules:
            if shell('iptables', '-t', 'nat', '-C', chain, *rule, check=False).returncode:
                shell('iptables', '-t', 'nat', '-A', chain, *rule)
        if shell('iptables', '-t', 'nat', '-C', 'OUTPUT', '-j', chain, check=False).returncode:
            shell('iptables', '-t', 'nat', '-I', 'OUTPUT', '1', '-j', chain)
        shell('settings', 'put', 'global', 'private_dns_mode', 'off')
        resolved = shell('ping', '-c', '1', '-W', '1', 'android-lab.triform.cloud', check=False, timeout=8)
        if address.encode() not in resolved.stdout: raise ValueError('Android provider DNS did not select the isolated Service')
        for index, ip in enumerate(RELAYS, 1):
            result = shell('timeout 3 sh -c "toybox nc -w 1 ' + ip + ' ' + str(19440 + index) + ' </dev/null"', check=False, timeout=8)
            if result.returncode: raise ValueError('isolated relay socket failed')
        return {'schema': 1, 'state': 'network-connected', 'dns_verified': True, 'relay_sockets': 5, 'service_ip': address}
    finally:
        adb('unroot', check=False)


def fleet(lab, plan, selected, state, settings, ssh):
    config = json.loads(Path(settings['release_config']).read_text())
    prepared = prepared_release(config, settings['prepared_id'])
    files = { 'scripts/' + p.name: p for p in Path(__file__).resolve().parent.glob('android_release*.py')}
    script = 'android_release_lab_fleet_bootstrap.py'
    files[script] = Path(__file__).with_name(script)
    for component, name in [('hub', 'gchat'), ('controller', 'gdrone-fleet'), ('apk', 'agent.apk'), ('worker', 'x86_64/worker.so')]:
        prefix = 'artifacts/' + component + '/' + prepared['inputs'][component]
        files[prefix + '/' + name] = regular_file(Path(config['state']) / prefix, name)
    files['tools/platform-tools/adb'] = Path(config['adb'])
    binding = hashlib.sha256(canonical({'context': selected, 'prepared_id': prepared['prepared_id'], 'files': {n: digest(p) for n, p in files.items()}})).hexdigest()
    lab.kube.fence_operations()
    send(ssh, ROOT, files, {'context.json': selected, 'prepared.json': prepared})
    lab.kube.fence_operations()
    return execute_once(ssh, ROOT, script, binding, Path(settings['state']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('action', choices=('network', 'connect', 'fleet', 'inspect'))
    args = parser.parse_args()
    settings = json.loads(args.config.read_text()); plan = validate(settings['plan'])
    from ghost_lab.cluster_operator import configure
    from ghost_lab.lifecycle import Lab
    from ghost_lab.access import tunnel, ssh_command
    configuration, _ = configure(settings['settings'])
    lab = Lab(configuration, store=object())
    with ExitStack() as stack:
        for name in sorted(g['name'] for g in plan['guests'].values()):
            stack.enter_context(lab.operation(name, plan['owner']))
        selected, state, pod = context(lab, plan)
        if args.action == 'inspect': result = {'state': 'ready', 'cluster_lab': selected}
        else:
            with tunnel(lab, state, 22) as port:
                ssh = ssh_command(lab, state, port)
                result = globals()[args.action](lab, plan, selected, state, settings, ssh)
        lab.kube.fence_operations()
        record = {'schema': 1, 'action': args.action, 'cluster_lab': selected, 'result': result}
        write_json(Path(settings['state']) / (args.action + '-result.json'), record)
        archive = Archive(settings['archive'])
        descriptor = archive.publish_record(record)
        print(json.dumps(dict(record, archive=descriptor)), flush=True)


if __name__ == '__main__': main()
