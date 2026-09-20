#!/usr/bin/env python3
"""One disconnected actual-GChat validity quartet, never a privacy qualification.

Privileged operations are confined to ephemeral net/mount/PID namespaces.
Applications and probes run as the invoking owner. No host network route, link,
firewall, service, or production relay is changed. Failed attempts are retained.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import random
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

from privacy_packets import sha256, write_new

SCOPE = 'isolated_gchat_daemon_explicit_bootstrap_v1'
WORKLOADS = ('idle', 'chat', 'bulk', 'mixed')
CLIENT = '11.231.97.2'
FIXTURE = '11.231.97.1'
RELAYS = [f'11.231.97.{n}' for n in range(10, 14)]
CLIENT6 = 'fd42:231:97::2'
FIXTURE6 = 'fd42:231:97::1'


def run(command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True, capture_output=True, text=True,
                          timeout=kwargs.pop('timeout', 30), **kwargs).stdout


def links():
    return json.loads(run(['ip', '-j', 'address', 'show']))


def link_identity(rows):
    return sorted((r['ifindex'], r['ifname'], r.get('address')) for r in rows)


def until(fn, deadline, name):
    error = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            error = str(exc)
        time.sleep(.1)
    raise RuntimeError(f'{name} deadline; last error: {error}')


def wait_until(deadline):
    while time.monotonic() < deadline:
        time.sleep(max(0, min(.1, deadline - time.monotonic())))


def build_binding(build):
    manifest = build / 'build.json'
    data = json.loads(manifest.read_text())
    if data.get('passed') is not True:
        raise ValueError('source-bound passing build manifest required')
    for name in ('gcoms', 'gchat'):
        source = data['sources'][name]
        if not source['unchanged'] or not source['revision'] or not source['snapshot_sha256']:
            raise ValueError('source binding incomplete')
    for name in ('gcnode', 'gchat', 'fleet_probe'):
        path = build / 'bin' / name
        if sha256(path) != data['artifacts'][name]['sha256'] or path.stat().st_size != data['artifacts'][name]['size']:
            raise ValueError(f'changed artifact {name}')
    return {'path': str(build), 'manifest_sha256': sha256(manifest),
            'sources': {n: {k: data['sources'][n][k] for k in ('revision', 'snapshot_sha256')}
                        for n in ('gcoms', 'gchat')}, 'artifacts': data['artifacts']}


class Worker:
    def __init__(self, spec):
        self.spec = spec
        self.original_root = Path(spec['out'])
        self.root = Path('/mnt')
        self.uid, self.gid = spec['uid'], spec['gid']
        self.children = []
        self.events = []
        self.result = {'schema': 1, 'scope': SCOPE, 'workload': spec['workload'],
                       'seed': spec['seed'], 'diagnostic_only': True, 'release_qualified': False,
                       'config': spec['config'], 'build': spec['build'], 'completed': False}
        self.capture = self.loop_capture = self.holder = None
        self.clients = []
        self.rpc_deadline = None
        self.env = {'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8',
                    'HOME': '/mnt/home', 'TMPDIR': '/mnt/tmp', 'XDG_RUNTIME_DIR': '/mnt/run',
                    'TOKIO_WORKER_THREADS': '2'}

    def event(self, kind, **facts):
        record = {'event': kind, 'unix_seconds': time.time(), **facts}
        self.events.append(record)
        with (self.root / 'events.jsonl').open('a') as out:
            out.write(json.dumps(record) + '\n')

    def private(self, path, contents):
        path.write_bytes(contents if isinstance(contents, bytes) else contents.encode())
        path.chmod(0o600)
        os.chown(path, self.uid, self.gid)

    def owner(self, command):
        return ['setpriv', '--reuid', str(self.uid), '--regid', str(self.gid), '--clear-groups',
                '--no-new-privs', '--', *map(str, command)]

    def spawn(self, role, command, *, observer=False, owner=True, env=None):
        prefix = self.ns if observer else []
        command = [*prefix, *(self.owner(command) if owner else list(map(str, command)))]
        log = (self.root / f'{role}.log').open('xb')
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   env=self.env | (env or {}), start_new_session=True)
        log.close()
        self.children.append((role, process))
        self.event('process_start', role=role, pid=process.pid, observer=observer,
                   owner_uid=self.uid if owner else 0, argv=command)
        return process

    def stop(self, process, sig=signal.SIGTERM):
        if process is None or process.poll() is not None:
            return
        process.send_signal(sig)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.result.setdefault('forced_kills', []).append(process.pid)
            process.kill()
            process.wait(timeout=5)

    def topology(self):
        if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == self.spec['host_netns']:
            raise RuntimeError('worker must enter a new privileged network namespace')
        if [r['ifname'] for r in links()] != ['lo']:
            raise RuntimeError('fixture namespace was not empty')
        run(['mount', '--make-rprivate', '/'])
        run(['mount', '--bind', self.original_root, '/mnt'])
        for name in ('home', 'tmp', 'run', 'c0', 'c1', *[f'r{i}' for i in range(4)]):
            path = self.root / name
            path.mkdir(mode=0o700)
            os.chown(path, self.uid, self.gid)
        self.private(self.root / 'resolver', f'nameserver {FIXTURE}\noptions attempts:1 timeout:1\n')
        self.private(self.root / 'nsswitch', 'passwd: files\ngroup: files\nhosts: files dns\n')
        run(['mount', '--bind', self.root / 'resolver', '/etc/resolv.conf'])
        run(['mount', '--bind', self.root / 'nsswitch', '/etc/nsswitch.conf'])
        # glibc can consult nscd before NSS dispatch. Hide its host pathname if present.
        if Path('/run/nscd').exists():
            run(['mount', '-t', 'tmpfs', '-o', 'size=64k,nodev,nosuid,noexec', 'none', '/run/nscd'])
        run(['ip', 'link', 'set', 'lo', 'up'])
        self.holder = subprocess.Popen(['unshare', '--net', '--', sys.executable, '-u', '-c',
            'import os,time;print(os.readlink("/proc/self/ns/net"),flush=True);time.sleep(1800)'],
            stdout=subprocess.PIPE, text=True)
        self.children.append(('namespace_holder', self.holder))
        if not select.select([self.holder.stdout], [], [], 5)[0]:
            raise RuntimeError('observer namespace not ready')
        observer_net = self.holder.stdout.readline().strip()
        self.ns = ['nsenter', '--target', str(self.holder.pid), '--net', '--']
        if len({observer_net, self.spec['host_netns'], os.readlink('/proc/self/ns/net')}) != 3:
            raise RuntimeError('network namespaces are not distinct')
        run(['ip', 'link', 'add', 'fixture0', 'type', 'veth', 'peer', 'name', 'client0', 'netns', str(self.holder.pid)])
        for address in [FIXTURE, *RELAYS]:
            run(['ip', 'addr', 'add', address + '/24', 'dev', 'fixture0'])
        run(['ip', '-6', 'addr', 'add', FIXTURE6 + '/64', 'dev', 'fixture0', 'nodad'])
        run(['ip', 'link', 'set', 'fixture0', 'up'])
        run([*self.ns, 'ip', 'link', 'set', 'lo', 'up'])
        run([*self.ns, 'ip', 'addr', 'add', CLIENT + '/24', 'dev', 'client0'])
        run([*self.ns, 'ip', '-6', 'addr', 'add', CLIENT6 + '/64', 'dev', 'client0', 'nodad'])
        run([*self.ns, 'ip', 'link', 'set', 'client0', 'up'])
        offloads = {}
        for prefix, interface in (([], 'fixture0'), (self.ns, 'client0')):
            run([*prefix, 'ethtool', '-K', interface, 'tso', 'off', 'gso', 'off', 'gro', 'off'])
            offloads[interface] = run([*prefix, 'ethtool', '-k', interface])
        self.result['boundary'] = {'host_netns': self.spec['host_netns'],
            'fixture_netns': os.readlink('/proc/self/ns/net'), 'observer_netns': observer_net,
            'private_mount_namespace': os.readlink('/proc/self/ns/mnt') != self.spec['host_mountns'],
            'resolver_sha256': sha256(self.root / 'resolver'), 'nsswitch_sha256': sha256(self.root / 'nsswitch'),
            'offloads': offloads, 'before': self.inventory()}
        self.assert_topology(self.result['boundary']['before'])

    def inventory(self):
        return {'observer_links': json.loads(run([*self.ns, 'ip', '-j', 'address', 'show'])),
                'fixture_links': links(),
                'observer_routes': {af: json.loads(run([*self.ns, 'ip', af, '-j', 'route', 'show', 'table', 'all'])) for af in ('-4', '-6')},
                'fixture_routes': {af: json.loads(run(['ip', af, '-j', 'route', 'show', 'table', 'all'])) for af in ('-4', '-6')}}

    @staticmethod
    def assert_topology(value):
        if {x['ifname'] for x in value['observer_links']} != {'lo', 'client0'} or {x['ifname'] for x in value['fixture_links']} != {'lo', 'fixture0'}:
            raise RuntimeError('undeclared interface')
        for scope in ('observer_routes', 'fixture_routes'):
            for rows in value[scope].values():
                if any(r.get('dst') == 'default' or r.get('gateway') for r in rows):
                    raise RuntimeError('external/default route')

    def start_capture(self, interface, name):
        path = self.root / (name + '.pcap')
        out, log = path.open('xb'), (self.root / (name + '.capture.log')).open('xb')
        proc = subprocess.Popen([*self.ns, 'tcpdump', '--immediate-mode', '-n', '-U', '-i', interface,
            '-s', '0', '-B', '4096', '--time-stamp-precision=micro', '-w', '-'], stdout=out, stderr=log)
        out.close(); log.close()
        self.children.append((name + '_capture', proc))
        until(lambda: b'listening on' in (self.root / (name + '.capture.log')).read_bytes(),
              time.monotonic() + 5, 'capture readiness')
        if proc.poll() is not None:
            raise RuntimeError('capture exited before workload')
        return proc

    def sentinel(self, phase):
        for family, address in ((socket.AF_INET, FIXTURE), (socket.AF_INET6, FIXTURE6)):
            token = f'gchat-capture-{phase}-{family}-{self.spec["run_nonce"]}'.encode()
            with socket.socket(family, socket.SOCK_DGRAM) as server:
                server.bind((address, 0)); server.settimeout(5)
                command = ['python3', '-c', 'import socket,sys;s=socket.socket(int(sys.argv[1]),socket.SOCK_DGRAM);s.sendto(sys.argv[4].encode(),(sys.argv[2],int(sys.argv[3])))', str(family), address, str(server.getsockname()[1]), token.decode()]
                run([*self.ns, *self.owner(command)], env=self.env)
                if server.recv(4096) != token:
                    raise RuntimeError('sentinel not received')
            # Immediate delivery plus a drain observation, not a fixed sleep alone.
            until(lambda: token in (self.root / 'observer.pcap').read_bytes(),
                  time.monotonic() + 5, 'captured sentinel')
            self.result.setdefault('sentinels', []).append(token.decode())
        backend = ('backend-only-' + self.spec['run_nonce']).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0)); s.settimeout(2)
            s.sendto(backend, s.getsockname())
            if s.recv(1024) != backend:
                raise RuntimeError('backend sentinel failed')
        self.result['backend_sentinel'] = backend.decode()

    def control(self, relay, command):
        with socket.create_connection(('127.0.0.1', 19500 + relay), timeout=5) as stream:
            stream.sendall((json.dumps({'id': 1, 'cmd': command, 'version': 2}) + '\n').encode())
            reader = stream.makefile('rb')
            for _ in range(100):
                value = json.loads(reader.readline(1048577))
                if value.get('id') == 1:
                    if not value.get('ok'):
                        raise RuntimeError(str(value))
                    return value['data']
        raise RuntimeError('control receipt missing')

    def relay(self, i, bootstrap=None):
        folder = self.root / f'r{i}'
        binary = Path(self.spec['build']['path']) / 'bin/gcnode'
        if not (folder / 'key').exists():
            run(self.owner([binary, 'keygen', '--out', folder / 'key', '--pass-file', self.root / 'pass']), env=self.env)
        return self.spawn(f'relay{i}' + ('-configured' if bootstrap else ''), [binary, 'serve',
            '--keystore', folder / 'key', '--pass-file', self.root / 'pass', '--port', 24500 + i,
            '--advertise-addr', f'{RELAYS[i]}:{24500+i}', '--control-port', 19500 + i,
            '--schedule', 'gchat-files', '--no-router-mapping', '--metrics', folder / 'metrics.jsonl'],
            env={'GC_ROUTING_BOOTSTRAP': str(bootstrap)} if bootstrap else {})

    def prepare(self):
        self.private(self.root / 'pass', uuid.uuid4().hex + '\n')
        relays = [self.relay(i) for i in range(4)]
        records = []
        for i in range(4):
            value = until(lambda: self.control(i, 'routing_bootstrap'), time.monotonic() + 30, 'relay startup')
            encoded = value['routing_bundle_b64']
            raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
            if raw[:5] != b'GCRB\x02' or len(raw) != 6 + raw[5] * 155 or not raw[5]:
                raise RuntimeError('invalid GCRB2 introduction')
            records.append(raw[6:161])
        for p in relays:
            self.stop(p)
        self.private(self.root / 'bootstrap', b'GCRB\x02\x04' + b''.join(records))
        for i in range(4):
            self.relay(i, self.root / 'bootstrap')
            until(lambda: self.control(i, 'status'), time.monotonic() + 30, 'configured relay startup')
        self.result['bootstrap_sha256'] = sha256(self.root / 'bootstrap')
        # Exclude the inbox relay from each client's initial guard candidates.
        for client, inbox in ((0, 2), (1, 3)):
            folder = self.root / f'c{client}'
            (folder / 'fixtures').mkdir(mode=0o700); os.chown(folder / 'fixtures', self.uid, self.gid)
            card = self.control(inbox, 'provision_client_relay')['private_card_b64']
            self.private(folder / 'card', card + '\n')
            self.private(folder / 'bootstrap', b'GCRB\x02\x03' + b''.join(r for i, r in enumerate(records) if i != inbox))
        self.result['private_inputs'] = {str(p.relative_to(self.root)): sha256(p) for p in
            [self.root / 'bootstrap', self.root / 'resolver', self.root / 'nsswitch',
             *[self.root / f'c{i}' / n for i in (0, 1) for n in ('bootstrap', 'card')]]}

    def start_client(self, i):
        folder = self.root / f'c{i}'
        binary = Path(self.spec['build']['path']) / 'bin/gchat'
        command = [binary, 'daemon', '--home', folder, '--store', folder / 'profile',
            '--chat-archive', folder / 'archive', '--socket', folder / 'protocol.sock',
            '--passphrase-file', self.root / 'pass', '--listen', f'127.0.0.1:{24600+i}',
            '--advertise', f'127.0.0.1:{24600+i}', '--inbox-relay-file', folder / 'card',
            '--gc2-carrier', '--no-network-bootstrap', '--create']
        p = self.spawn(f'client{i}', command, observer=i == 0,
            env={'GC_ROUTING_BOOTSTRAP': str(folder / 'bootstrap'), 'GC_GC2_CARRIER': 'true',
                 'GCHAT_FILE_DIAGNOSTICS': '1', 'GCHAT_PROTOCOL_METRICS': str(folder / 'metrics.jsonl')})
        self.clients.append(p)
        self.spawn(f'probe{i}', [Path(self.spec['build']['path']) / 'bin/fleet_probe', '--serve',
            folder / 'protocol.chat', folder / 'fixtures', folder / 'probe.sock'])

    def probe(self, i, request):
        def exact(stream, n):
            result = b''
            while len(result) < n:
                chunk = stream.recv(n - len(result))
                if not chunk:
                    raise RuntimeError('probe closed early')
                result += chunk
            return result
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            remaining = self.rpc_deadline - time.monotonic() if self.rpc_deadline else 30
            if remaining <= 0:
                raise TimeoutError('declared IPC phase deadline elapsed')
            stream.settimeout(remaining)
            stream.connect(str(self.root / f'c{i}/probe.sock'))
            raw = json.dumps(request).encode()
            stream.sendall(struct.pack('!I', len(raw)) + raw)
            length = struct.unpack('!I', exact(stream, 4))[0]
            if length > 1048576:
                raise RuntimeError('oversize probe response')
            answer = json.loads(exact(stream, length))
        if not answer.get('ok'):
            raise RuntimeError(str(answer))
        return answer['value']

    def request(self, i, kind, **values):
        return self.probe(i, {'action': 'request', 'request': {'kind': kind, **values}})

    def files(self, i, action='list', **values):
        if action == 'list':
            values.setdefault('conversation', None)
        return self.request(i, 'files', request={'action': action, **values})['snapshot']

    def submit(self, i, text, conversation=None):
        operation = uuid.uuid4().hex
        command = text.split()[0] if text.startswith('/') else 'message'
        self.event('operation_requested', client=i, operation_id=operation, command=command)
        try:
            value = self.request(i, 'submit', operation_id=operation, text=text, conversation=conversation)
            self.event('operation_response', client=i, operation_id=operation, command=command)
            return value
        except Exception as error:
            self.event('operation_response_unobserved', client=i, operation_id=operation, command=command, error=str(error))
            raise

    def readiness(self, i):
        observations = []
        for line in (self.root / f'client{i}.log').read_text().splitlines():
            if not line.startswith('{'):
                continue
            try:
                value = json.loads(line)
                if value.get('event') == 'file_diagnostics':
                    observations.append(value)
            except ValueError:
                pass
        if not observations:
            return None
        status = observations[-1]['protocol']['transport']
        if (status.get('protocol') == 'gchat' and status.get('profile_id') == 22
                and status.get('bootstrap_version') == 2 and status.get('routing_ready') is True
                and status.get('usable_terminal_routes', 0) > 0
                and status.get('interactive_subscriptions', 0) >= 2
                and status.get('bulk_subscriptions', 0) >= 2):
            return status
        return None

    def membership(self):
        expected = {p.pid: role for role, p in self.children if p.poll() is None}
        namespace = self.result['boundary']['observer_netns']
        members = []
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                if os.readlink(path / 'ns/net') == namespace:
                    pid = int(path.name)
                    if pid not in expected:
                        raise RuntimeError(f'undeclared observer process {pid}')
                    members.append({'pid': pid, 'role': expected[pid],
                                    'effective_uid': int((path / 'status').read_text().split('Uid:')[1].split()[1])})
            except FileNotFoundError:
                continue
        if not any(m['role'] == 'client0' and m['effective_uid'] == self.uid for m in members):
            raise RuntimeError('actual owner daemon missing from observed namespace')
        return members

    def exercise(self):
        self.capture = self.start_capture('client0', 'observer')
        self.loop_capture = self.start_capture('lo', 'loopback')
        self.result['capture_started_epoch'] = time.time()
        self.sentinel('before')
        start = time.monotonic()
        self.result['application_started_epoch'] = time.time()
        for i in (0, 1):
            self.start_client(i)
        deadline = start + self.spec['config']['warmup_seconds'] - 10
        self.rpc_deadline = deadline
        statuses = []
        for i in (0, 1):
            until(lambda i=i: self.request(i, 'snapshot'), deadline, 'daemon IPC startup')
            self.files(i, 'configure', quota_bytes=str(16 * 1024 * 1024), retention_days=7)
            status = until(lambda i=i: self.readiness(i), deadline, 'protected two-class readiness')
            statuses.append(status)
        self.result['readiness'] = statuses
        channel = self.submit(0, '/create #capture observed')['conversation']
        def invitation():
            response = self.submit(0, '/invite', channel)['output']
            return response['link'] if not response.get('localOnly', True) else None
        link = until(invitation, deadline, 'shareable remote invitation')
        self.submit(1, f'/join {link} receiver')
        self.result['boundary']['members'] = self.membership()
        self.event('channel_joined')
        # Same startup allowance and process lifetime for all four fresh states.
        if time.monotonic() >= deadline:
            raise RuntimeError('setup exceeded matched startup allowance')
        begin = start + self.spec['config']['warmup_seconds']
        end = begin + self.spec['config']['seconds']
        wait_until(begin)
        self.rpc_deadline = end
        self.result['measurement_started_epoch'] = time.time()
        self.event('measurement_start')
        chat = []
        transfer = None
        chat_count = self.spec['config']['chat_count'] if self.spec['workload'] in ('chat', 'mixed') else 0
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        try:
            if self.spec['workload'] in ('bulk', 'mixed'):
                def send_file():
                    ident = '6cf0205789c54f47b55019a912551973'
                    name = 'matched-file.bin'
                    expected = self.probe(0, {'action': 'generate', 'name': name,
                        'size': self.spec['config']['file_bytes'], 'seed': self.spec['seed']})
                    self.event('file_import', id=ident, **expected)
                    self.probe(0, {'action': 'import', 'id': ident, 'conversation': channel, 'name': name})
                    def offered():
                        return next((f for f in self.files(1)['files'] if f['id'] == ident), None)
                    offer = until(offered, end - 2, 'file offer')
                    if offer['state'] != 'offered' or offer['verified_bytes'] != '0':
                        raise RuntimeError('file downloaded before explicit acceptance')
                    self.event('file_offered', id=ident)
                    self.files(1, 'accept', id=ident)
                    self.event('file_accepted', id=ident)
                    until(lambda: next((f for f in self.files(1)['files'] if f['id'] == ident and f['state'] == 'complete'), None), end - 1, 'file completion')
                    verified = self.probe(1, {'action': 'export', 'id': ident, 'name': 'received.bin', **expected})
                    self.event('file_export_verified', id=ident, **verified)
                    return {'id': ident, **verified}
                transfer = pool.submit(send_file)
            def message(index):
                token = f'capture:{self.spec["seed"]}:{index}'
                self.event('chat_attempted', id=token)
                self.submit(0, token, channel)
                self.event('chat_submitted', id=token)
                def received(i, text):
                    return any(m['body'] == text for m in self.request(i, 'history', conversation=channel, before=None, limit=100)['page']['messages'])
                until(lambda: received(1, token), end - 1, 'chat receiver delivery')
                self.submit(1, 'ack:' + token, channel)
                until(lambda: received(0, 'ack:' + token), end - 1, 'returned chat acknowledgement')
                self.event('chat_acknowledged', id=token)
                return token
            for index in range(chat_count):
                wait_until(begin + 10 + index * 20)
                chat.append(pool.submit(message, index))
            self.result['file'] = transfer.result(timeout=max(.1, end - time.monotonic())) if transfer else None
            self.result['chat_acknowledged'] = [job.result(timeout=max(.1, end - time.monotonic())) for job in chat]
            wait_until(end)
            self.result['measurement_finished_epoch'] = time.time()
            self.event('measurement_end')
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        self.result['boundary']['members_at_shutdown'] = self.membership()
        self.result['application_stop_requested_epoch'] = time.time()
        for p in self.clients:
            self.stop(p)
        self.result['application_finished_epoch'] = time.time()
        self.result['application_returncodes'] = [p.returncode for p in self.clients]
        self.sentinel('after')
        wait_until(time.monotonic() + .3)
        self.stop(self.capture, signal.SIGINT)
        self.stop(self.loop_capture, signal.SIGINT)
        self.result['capture_finished_epoch'] = time.time()
        self.result['capture_returncode'] = self.capture.returncode
        self.result['loopback_capture_returncode'] = self.loop_capture.returncode
        self.result['boundary']['after'] = self.inventory()
        self.assert_topology(self.result['boundary']['after'])
        self.result['completed'] = True

    def execute(self):
        def interrupted(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        try:
            self.topology()
            self.prepare()
            self.exercise()
        except BaseException as exc:
            self.result['failure'] = f'{type(exc).__name__}: {exc}'
            import traceback
            traceback.print_exc()
        finally:
            # Stop producer daemons before capture; capture survives through final drain.
            for role, process in reversed(self.children):
                if 'capture' not in role and role != 'namespace_holder':
                    self.stop(process)
            self.stop(self.capture, signal.SIGINT)
            self.stop(self.loop_capture, signal.SIGINT)
            self.result.setdefault('capture_finished_epoch', time.time())
            self.stop(self.holder)
            self.result['children'] = [{'role': role, 'pid': p.pid, 'returncode': p.poll()} for role, p in self.children]
            self.result['children_stopped'] = all(p.poll() is not None for _, p in self.children)
            self.result['capture_returncode'] = self.capture.poll() if self.capture else None
            self.result['loopback_capture_returncode'] = self.loop_capture.poll() if self.loop_capture else None
            self.result['application_returncodes'] = [p.poll() for p in self.clients]
            for name in ('observer.pcap', 'observer.capture.log', 'loopback.pcap', 'loopback.capture.log', 'events.jsonl', 'client0.log', 'client1.log', *[f'r{i}/metrics.jsonl' for i in range(4)]):
                path = self.original_root / name
                if path.exists():
                    self.result.setdefault('evidence', {})[name] = sha256(path)
            (self.original_root / 'worker.json').write_text(json.dumps(self.result, indent=2) + '\n')
            for folder, dirs, files in os.walk(self.original_root):
                for name in [folder, *[str(Path(folder) / n) for n in dirs + files]]:
                    os.chown(name, self.uid, self.gid, follow_symlinks=False)
        return 0 if self.result['completed'] and self.result['children_stopped'] and not self.result.get('forced_kills') else 1


def main():
    if sys.argv[1:2] == ['--worker']:
        return Worker(json.loads(Path(sys.argv[2]).read_text())).execute()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--seed', type=int, default=20260920)
    parser.add_argument('--warmup-seconds', type=int, default=180)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--file-bytes', type=int, default=65536)
    args = parser.parse_args()
    if not 60 <= args.warmup_seconds <= 300 or not 45 <= args.seconds <= 300 or not 1024 <= args.file_bytes <= 1048576:
        parser.error('bounded calibration requires warmup 60..300 s, measurement 45..300 s, file 1 KiB..1 MiB')
    if os.geteuid() == 0:
        parser.error('launch outer controller as the ordinary owning user')
    root = args.out.resolve(); root.mkdir(mode=0o700, parents=True, exist_ok=False)
    build = build_binding(args.build.resolve())
    write_new(root / 'build.json', (args.build / 'build.json').read_text())
    config = {'warmup_seconds': args.warmup_seconds, 'seconds': args.seconds,
        'file_bytes': args.file_bytes, 'chat_count': 2, 'chat_offsets_seconds': [10, 30],
        'profile_id': 22, 'bootstrap_version': 2, 'entries': 2,
        'network_bootstrap': False, 'local_fixture': False, 'cadence': 'production',
        'state': 'fresh', 'observed_role': 'sender', 'retention_days': 7, 'quota_bytes': 16777216}
    order = list(WORKLOADS); random.Random(args.seed).shuffle(order)
    plan = {'schema': 1, 'scope': SCOPE, 'order': order, 'seed': args.seed, 'config': config,
        'build': build, 'tooling': {n: sha256(Path(__file__).with_name(n)) for n in
            ('privacy-client-capture.py', 'privacy_client_packets.py', 'privacy_client_manifest.py', 'privacy_packets.py')},
        'decoder': run(['tshark', '--version']).splitlines()[0],
        'capture_tool': run(['tcpdump', '--version']).splitlines()[0],
        'diagnostic_only': True, 'release_qualified': False}
    write_new(root / 'plan.json', json.dumps(plan, indent=2) + '\n')
    (root / 'tooling').mkdir(mode=0o700)
    for name, digest in plan['tooling'].items():
        data = Path(__file__).with_name(name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('tooling changed while retaining source snapshot')
        (root / 'tooling' / name).write_bytes(data)
    reports = []
    from privacy_client_manifest import validate_capture, validate_quartet
    for workload in order:
        out = root / workload; out.mkdir(mode=0o700)
        before = links()
        spec = {'out': str(out), 'build': build, 'config': config, 'workload': workload,
                'seed': args.seed, 'uid': os.getuid(), 'gid': os.getgid(), 'run_nonce': uuid.uuid4().hex,
                'host_netns': os.readlink('/proc/self/ns/net'), 'host_mountns': os.readlink('/proc/self/ns/mnt')}
        write_new(out / 'spec.json', json.dumps(spec, indent=2) + '\n')
        watchdog = args.warmup_seconds + args.seconds + 240
        command = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=10', str(watchdog),
            'unshare', '--net', '--mount', '--pid', '--fork', '--mount-proc', '--kill-child',
            '--propagation', 'private', '--', sys.executable, str(Path(__file__).resolve()),
            '--worker', str(out / 'spec.json')]
        with (out / 'controller.log').open('xb') as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        after = links()
        boundary = {'host_links_unchanged': link_identity(before) == link_identity(after),
                    'before': before, 'after': after, 'worker_returncode': completed.returncode,
                    'build_unchanged': build_binding(args.build.resolve()) == build,
                    'tooling_unchanged': all(sha256(Path(__file__).with_name(n)) == h for n, h in plan['tooling'].items())}
        write_new(out / 'outer.json', json.dumps(boundary, indent=2) + '\n')
        report = validate_capture(out, plan)
        write_new(out / 'validity.json', json.dumps(report, indent=2, allow_nan=False) + '\n')
        reports.append(report)
        print(json.dumps({'workload': workload, 'measurement_valid': report['measurement_valid'], 'error': report.get('error')}), flush=True)
        if not boundary['host_links_unchanged'] or not report['measurement_valid']:
            break  # Preserve failed preflight/capture; never spend a matrix on invalid input.
    report = validate_quartet(reports, plan)
    write_new(root / 'quartet.json', json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report['measurement_valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
