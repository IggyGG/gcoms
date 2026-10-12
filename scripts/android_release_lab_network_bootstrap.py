"""Install only the owned ordinary GC/2 network inside the isolated lab VM."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import socket
import ssl
import subprocess
import time
from urllib.request import Request, urlopen

ROOT = Path('/home/lab/.local/state/android-release-network')


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, timeout=45,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kwargs)


def write(path, data):
    path = Path(path)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError('preserve different existing lab configuration: ' + path.name)
        return
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    write(path, json.dumps(value, sort_keys=True).encode() + b'\n')


def service(name, command, environment=False, privileged=False, owner='lab', writable=ROOT, control_root=None):
    if not name.startswith('android-lab-') or any(c.isspace() or c in '%"\\' for a in command for c in str(a)):
        raise ValueError('owned service requires simple explicit arguments')
    text = ('# android-cluster lab network\n[Unit]\nAfter=network.target android-lab-addresses.service\nRequires=android-lab-addresses.service\n\n[Service]\n'
            'Type=simple\nUser=' + owner + '\nGroup=' + owner + '\nUMask=0077\nRestart=on-failure\nRestartSec=2\n'
            'NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n'
            'ReadWritePaths=' + str(writable) + '\nMemoryMax=512M\nLimitNOFILE=4096\n'
            + ('AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n' if privileged else 'CapabilityBoundingSet=\n')
            + ('EnvironmentFile=' + str((control_root or ROOT / 'control') / 'environment') + '\n' if environment else '')
            + 'ExecStart=' + ' '.join(map(str, command)) + '\n\n[Install]\nWantedBy=multi-user.target\n')
    staged = ROOT / 'units' / (name + '.service')
    write(staged, text.encode())
    destination = Path('/etc/systemd/system') / staged.name
    if destination.exists() and destination.read_text() != text:
        raise ValueError('preserve existing guest service')
    run(['sudo', '-n', 'install', '-m', '644', staged, destination])
    run(['sudo', '-n', 'systemctl', 'daemon-reload'])
    run(['sudo', '-n', 'systemctl', 'enable', '--now', staged.name])


def control(port):
    context = ssl.create_default_context(cafile=str(ROOT / 'control/ca.crt'))
    context.load_cert_chain(ROOT / 'control/client.crt', ROOT / 'control/client.key')
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname='android-lab-control') as stream:
            request = {'id': 1, 'cmd': 'routing_bootstrap', 'version': 2,
                       'token': (ROOT / 'control/token').read_text()}
            stream.sendall(json.dumps(request).encode() + b'\n')
            with stream.makefile('rb') as reader:
                response = reader.readline(16385)
    if len(response) > 16384:
        raise ValueError('relay owner response exceeds bound')
    value = json.loads(response)
    if value.get('ok') is not True:
        raise ValueError('relay owner refused bootstrap')
    encoded = value['data']['routing_bundle_b64']
    return base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))


def main():
    os.umask(0o077)
    if os.getuid() != 1000:
        raise ValueError('run as the isolated lab user')
    settings = json.loads((ROOT / 'settings.json').read_text())
    actual_uuid = subprocess.check_output(['sudo', '-n', 'cat', '/sys/class/dmi/id/product_uuid'], timeout=5).decode().strip().lower()
    if actual_uuid != settings['machine_uuid']:
        raise ValueError('network bootstrap is bound to another VM')
    ips = settings['relay_ips']
    if (len(ips) != 5 or len(set(ips)) != 5 or any(not ipaddress.IPv4Address(x).is_global for x in ips)
            or settings['provider'] != 'android-lab.triform.cloud'):
        raise ValueError('five owned public relay aliases and the dedicated TLS provider required')
    receipt = json.loads((ROOT / 'bin/receipt.json').read_text())
    for name, sha in receipt['files'].items():
        if name not in ('gcnode', 'gcoms-catalog', 'gc-network-operator') or hashlib.sha256((ROOT / 'bin' / name).read_bytes()).hexdigest() != sha:
            raise ValueError('lab native binary differs from cluster build receipt')
    for directory in ('control', 'units', 'network', 'catalog', 'publisher', 'relays'):
        (ROOT / directory).mkdir(mode=0o700, exist_ok=True)
    control_root = ROOT / 'control'
    if not (control_root / 'ca.crt').exists():
        run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
             '-nodes', '-days', '30', '-subj', '/CN=Android isolated control CA',
             '-keyout', control_root / 'ca.key', '-out', control_root / 'ca.crt'])
    for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        if not (control_root / (name + '.crt')).exists():
            run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                 '-nodes', '-subj', '/CN=android-lab-control', '-keyout', control_root / (name + '.key'),
                 '-out', control_root / (name + '.csr')])
            write(control_root / (name + '.ext'), ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=' + usage + '\nsubjectAltName=DNS:android-lab-control\n').encode())
            run(['openssl', 'x509', '-req', '-days', '30', '-in', control_root / (name + '.csr'),
                 '-CA', control_root / 'ca.crt', '-CAkey', control_root / 'ca.key', '-CAcreateserial',
                 '-extfile', control_root / (name + '.ext'), '-out', control_root / (name + '.crt')])
    if not (control_root / 'token').exists():
        write(control_root / 'token', secrets.token_hex(32).encode())
    write(control_root / 'environment', b'GC_CONTROL_TOKEN=' + (control_root / 'token').read_bytes() + b'\n')
    run(['sudo', '-n', 'loginctl', 'enable-linger', 'lab'])
    run(['sudo', '-n', 'install', '-d', '-m', '755', '/opt/android-lab'])
    run(['sudo', '-n', 'install', '-m', '755', ROOT / 'bin/gcnode', '/opt/android-lab/gcnode'])
    # Separate ordinary relay clients retain their own source identities at
    # the TLS proxy. The normal provider per-source rate limits stay intact.
    origins = '''import subprocess
for index in range(1,6):
 rule=['-p','tcp','-d','127.0.0.1/32','--dport','443','-m','owner','--uid-owner',str(3000+index),'-j','SNAT','--to-source','127.90.'+str(index)+'.1']
 if subprocess.run(['iptables','-t','nat','-C','POSTROUTING',*rule],capture_output=True).returncode:
  subprocess.run(['iptables','-t','nat','-A','POSTROUTING',*rule],check=True)
'''
    write(ROOT / 'provider-sources.py', origins.encode())
    run(['sudo', '-n', 'install', '-m', '755', ROOT / 'provider-sources.py', '/opt/android-lab/provider-sources.py'])
    for address in ips:
        run(['sudo', '-n', 'ip', 'address', 'replace', address + '/32', 'dev', 'lo'])
    addresses = ('# android-cluster lab network\n[Unit]\nAfter=network.target\n\n[Service]\n'
                 'Type=oneshot\nRemainAfterExit=yes\nCapabilityBoundingSet=CAP_NET_ADMIN\n'
                 + ''.join('ExecStart=/usr/sbin/ip address replace ' + address + '/32 dev lo\n' for address in ips)
                 + 'ExecStart=/usr/bin/python3 /opt/android-lab/provider-sources.py\n'
                 + '\n[Install]\nWantedBy=multi-user.target\n')
    staged = ROOT / 'units/android-lab-addresses.service'
    write(staged, addresses.encode())
    destination = Path('/etc/systemd/system/android-lab-addresses.service')
    if destination.exists() and destination.read_text() != addresses:
        raise ValueError('preserve existing guest address service')
    run(['sudo', '-n', 'install', '-m', '644', staged, destination])
    run(['sudo', '-n', 'systemctl', 'daemon-reload'])
    run(['sudo', '-n', 'systemctl', 'enable', '--now', destination.name])
    hosts_line = '127.0.0.1 android-lab.triform.cloud\n'
    if hosts_line not in Path('/etc/hosts').read_text():
        run(['sudo', '-n', 'tee', '-a', '/etc/hosts'], input=hosts_line.encode())
    founders, controls = [], []
    for index, address in enumerate(ips, 1):
        relay = ROOT / 'relays' / str(index)
        relay.mkdir(mode=0o700, exist_ok=True)
        if not (relay / 'passphrase').exists():
            write(relay / 'passphrase', secrets.token_urlsafe(32).encode())
        if not (relay / 'identity').exists():
            run([ROOT / 'bin/gcnode', 'keygen', '--out', relay / 'identity', '--pass-file', relay / 'passphrase'])
        user = 'android-lab-relay-' + str(index)
        private_root = Path('/var/lib') / user
        try:
            account = pwd.getpwnam(user)
            if account.pw_uid != 3000 + index or account.pw_shell != '/usr/sbin/nologin':
                raise ValueError('preserve another guest relay account')
        except KeyError:
            run(['sudo', '-n', 'useradd', '--system', '--uid', str(3000 + index), '--no-create-home',
                 '--home-dir', private_root, '--shell', '/usr/sbin/nologin', user])
        for directory in (private_root, private_root / 'control', private_root / 'network'):
            run(['sudo', '-n', 'install', '-d', '-m', '700', '-o', user, '-g', user, directory])
        for source, destination in [(relay / 'identity', private_root / 'identity'), (relay / 'passphrase', private_root / 'passphrase'),
                *[(control_root / n, private_root / 'control' / n) for n in ('server.crt', 'server.key', 'ca.crt', 'environment')]]:
            # Fresh bootstrap is journaled by the cluster before invocation.
            run(['sudo', '-n', 'install', '-m', '600', '-o', user, '-g', user, source, destination])
        control_files = private_root / 'control'
        service(user, ['/opt/android-lab/gcnode', 'serve', '--keystore', private_root / 'identity',
            '--pass-file', private_root / 'passphrase', '--port', str(19440 + index), '--schedule', 'gc2', '--no-router-mapping',
            '--advertise-addr', address + ':' + str(19440 + index), '--control-port', str(20440 + index),
            '--control-server-cert', control_files / 'server.crt', '--control-server-key', control_files / 'server.key',
            '--control-client-ca', control_files / 'ca.crt', '--metrics', private_root / 'metrics.jsonl',
            '--network-config', private_root / 'network/installed.json',
            '--network-invitation-file', private_root / 'network/invitation', '--dns-opt-out'], environment=True,
            owner=user, writable=private_root, control_root=control_files)
        deadline = time.monotonic() + 20
        while True:
            try:
                bundle = control(20440 + index)
                break
            except (OSError, ValueError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.5)
        if bundle[:6] != b'GCRB\x02\x01' or len(bundle) != 161:
            raise ValueError('one normal GC/2 listener introduction required')
        founders.append({'name': f'r{index}.relays.gchat.boo', 'service_id': list(bundle[25:57]),
                         'address_hints': [address + ':' + str(19440 + index)]})
        controls.append({'address': '127.0.0.1:' + str(20440 + index), 'server_name': 'android-lab-control',
            'ca_file': str(control_root / 'ca.crt'), 'client_cert_file': str(control_root / 'client.crt'),
            'client_key_file': str(control_root / 'client.key'), 'bearer_token_file': str(control_root / 'token')})
    operator = ROOT / 'bin/gc-network-operator'
    network = ROOT / 'network'
    if not (network / 'seed').exists():
        run([operator, 'keygen', network / 'seed', network / 'public'])
    if not (network / 'defaults.json').exists():
        now = int(time.time())
        save(network / 'defaults.json', {'version': 1, 'network_id': 'gchat.boo', 'sequence': 1,
            'issued_at': now, 'expires_at': now + 86400, 'provider_urls': ['https://' + settings['provider'] + '/'],
            'founders': founders, 'dns_domain': 'gchat.boo'})
    if not (network / 'signed.json').exists():
        run([operator, 'sign', network / 'defaults.json', network / 'seed', '-', network / 'signed.json'])
    save(network / 'installed.json', {'trusted_key_b64': base64.urlsafe_b64encode((network / 'public').read_bytes()).decode().rstrip('='),
                                    'signed_defaults': json.loads((network / 'signed.json').read_text())})
    if not (network / 'invitation').exists():
        save(network / 'grant-request.json', {'network_id': 'gchat.boo', 'provider_urls': ['https://' + settings['provider'] + '/'],
            'expires_at': json.loads((network / 'defaults.json').read_text())['expires_at'], 'scopes': ['bootstrap', 'invitations'], 'max_names': 0})
        run([operator, 'grant', network / 'grants.json', network / 'grant-request.json', network / 'invitation'])
    save(ROOT / 'catalog.json', {'listen': '127.0.0.1:18080', 'public_base_url': 'https://' + settings['provider'],
        'state_dir': str(ROOT / 'catalog'), 'ephemeral_test_mode': False, 'channels': [],
        'relay_bootstrap': {'relay_controls': controls},
        'network': {'network_id': 'gchat.boo', 'defaults_file': str(network / 'signed.json'),
            'verification_key_file': str(network / 'public'), 'grants_file': str(network / 'grants.json'),
            'state_dir': str(ROOT / 'publisher'), 'names_enabled': False, 'spaceship_credentials_file': None}})
    service('android-lab-catalog', [ROOT / 'bin/gcoms-catalog', ROOT / 'catalog.json'])
    service('android-lab-provider', ['/usr/bin/python3', ROOT / 'android_release_lab_services.py'], privileged=True)
    for index in range(1, 6):
        user = 'android-lab-relay-' + str(index)
        for name in ('installed.json', 'invitation'):
            run(['sudo', '-n', 'install', '-m', '600', '-o', user, '-g', user,
                 network / name, Path('/var/lib') / user / 'network' / name])
    time.sleep(2)
    run(['sudo', '-n', 'systemctl', 'restart', *['android-lab-relay-' + str(i) + '.service' for i in range(1, 6)]])
    time.sleep(2)
    code = (network / 'invitation').read_text().strip()[6:]
    grant = json.loads(base64.urlsafe_b64decode(code + '=' * (-len(code) % 4)))['grant']
    request = Request('https://' + settings['provider'] + '/v1/relay-provisions',
        data=json.dumps({'request_id': secrets.token_urlsafe(16), 'supported_versions': [3]}).encode(),
        headers={'Authorization': 'Bearer ' + grant, 'Content-Type': 'application/json'})
    with urlopen(request, timeout=20) as response:
        provision = json.loads(response.read(4097))
    encoded = provision['routing_bundle_b64']
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    if provision.get('routing_protocol') != 'gc2' or raw[:6] != b'GCRB\x02\x05' or len(raw) != 781:
        raise ValueError('provider did not authenticate five normal relay introductions')
    result = {'schema': 1, 'state': 'network-ready', 'native_input': receipt['input_sha256'],
              'tls_verified': True, 'relays': 5, 'fixture': False, 'provider': settings['provider']}
    save(ROOT / 'ready.json', result)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
