#!/usr/bin/env python3
"""Disconnected real-daemon turnover journey; no privacy/fleet qualification."""
import argparse, base64, concurrent.futures, hashlib, importlib.util, json, os
from pathlib import Path
import select, signal, socket, subprocess, sys, threading, time, uuid
ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / 'scripts/privacy-client-capture.py').is_file())
HELPER = ROOT / 'scripts/privacy-client-capture.py'
sys.path.insert(0, str(HELPER.parent))
spec = importlib.util.spec_from_file_location('capture_boundary', HELPER)
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
run, links, until, sha256 = base.run, base.links, base.until, base.sha256
FIXTURE, FIXTURE6 = base.FIXTURE, base.FIXTURE6
RELAYS = tuple(f'11.231.97.{n}' for n in range(10, 16))
CLIENT, CLIENT6 = base.CLIENT, base.CLIENT6
SCOPE = 'actual_gchat_disconnected_fivehop_turnover_v2'

def fixture_links(rows, routes):
    """Allow only the kernel's inert IPIP fallback in addition to fixture links.

    Some cluster kernels create tunl0 in every new netns. Keep the raw inventory
    in receipts; this exception must never admit an addressed/up/routed tunnel.
    """
    result = []
    for row in rows:
        if row.get('ifname') != 'tunl0':
            result.append(row)
            continue
        if (row.get('link_type') != 'ipip' or row.get('operstate') != 'DOWN'
                or row.get('flags') != ['NOARP'] or row.get('addr_info') != []
                or row.get('address') != '0.0.0.0'
                or row.get('broadcast') != '0.0.0.0' or row.get('master')
                or row.get('link') is not None
                or any(route.get('dev') == 'tunl0' for family in routes.values() for route in family)):
            raise RuntimeError('unexpected active or configured fallback tunnel')
    return result

class Journey(base.Worker):
    relay_addresses = RELAYS

    def __init__(self, spec):
        super().__init__(spec)
        self.result.update(scope=SCOPE, privacy_qualified=False, release_qualified=False,
                           relay_count=len(self.relay_addresses), route_relay_hops=5)
        self.origin = time.monotonic(); self.roles = {}; self.latest = {}; self.chat_count = 0
        if self.spec['config'].get('mode') in ('carrier-cap', 'entry-loss'):
            self.env['GCOMS_GC2_LIFECYCLE'] = '1'

    def event(self, kind, **facts):
        super().event(kind, elapsed=time.monotonic() - self.origin, **facts)

    def spawn(self, role, command, **kwargs):
        generation = self.roles.get(role, 0); self.roles[role] = generation + 1
        actual = role if generation == 0 else f'{role}-reopen-{generation}'
        self.latest[role] = actual
        return super().spawn(actual, command, **kwargs)

    def topology(self):
        if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == self.spec['host_netns']:
            raise RuntimeError('worker must enter a new privileged network namespace')
        initial_links = links()
        initial_routes = {af: json.loads(run(['ip', af, '-j', 'route', 'show', 'table', 'all'])) for af in ('-4', '-6')}
        if ([r['ifname'] for r in fixture_links(initial_links, initial_routes)] != ['lo']
                or any(initial_routes.values())):
            raise RuntimeError('fixture namespace was not empty')
        self.result['initial_namespace'] = {'links': initial_links, 'routes': initial_routes}
        run(['mount', '--make-rprivate', '/'])
        run(['mount', '--bind', self.original_root, '/mnt'])
        count = 10 if self.spec['config'].get('mode') == 'multi-party' else 2
        for name in ('home', 'tmp', 'run', *[f'c{i}' for i in range(count)], *[f'r{i}' for i in range(len(self.relay_addresses))]):
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
            'import os,time;print(os.readlink("/proc/self/ns/net"),flush=True);time.sleep(18000)'],
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

    @staticmethod
    def assert_topology(value):
        checked = dict(value)
        for scope in ('observer', 'fixture'):
            checked[scope + '_links'] = fixture_links(value[scope + '_links'], value[scope + '_routes'])
        base.Worker.assert_topology(checked)


    def prepare(self):
        if self.spec['config'].get('mode') == 'carrier-cap':
            # Start only while credentials will remain fresh beyond 1800 s.
            now=time.time()
            if now % 3600 > 900:
                next_window=(int(now)//3600+1)*3600+5
                self.event('fresh_authority_window_wait', until_unix=next_window)
                while time.time()<next_window: time.sleep(min(2,next_window-time.time()))
        super().prepare()
        if self.spec['config'].get('mode') == 'multi-party':
            raw = (self.root / 'bootstrap').read_bytes()
            records = [raw[6+i*155:6+(i+1)*155] for i in range(raw[5])]
            for client in range(2, 10):
                folder = self.root / f'c{client}'
                (folder / 'fixtures').mkdir(mode=0o700)
                os.chown(folder / 'fixtures', self.uid, self.gid)
                inbox = (client + 2) % len(records)
                card = self.control(inbox, 'provision_client_relay')['private_card_b64']
                self.private(folder / 'card', card + '\n')
                self.private(folder / 'bootstrap', b'GCRB\x02' + bytes([len(records)-1]) +
                             b''.join(r for i, r in enumerate(records) if i != inbox))
                for name in ('card', 'bootstrap'):
                    self.result['private_inputs'][f'c{client}/{name}'] = sha256(folder / name)
        if host := self.spec.get('fixture_host'):
            process = self.spawn('network-config', [host['path'], 'network',
                self.root / 'bootstrap', self.root / 'network.json'],
                env={'GCHAT_FIXTURE_NETNS': self.result['boundary']['fixture_netns'],
                     'GCHAT_FIXTURE_HOST_NETNS': self.spec['host_netns']})
            if process.wait(timeout=30) != 0:
                raise RuntimeError('fixture signed network generation failed')
            self.result['fixture_network_sha256'] = sha256(self.root / 'network.json')

    def lifecycle(self, i):
        path=self.root/(self.latest[f'client{i}']+'.log')
        rows=[]
        for line in path.read_text(errors='replace').splitlines():
            if line.startswith('gc2_entry_lifecycle '):
                row=json.loads(line.removeprefix('gc2_entry_lifecycle '))
                if row['role']=='client': rows.append(row)
        return rows

    def carrier_cap(self, channel):
        starts={}
        for i in (0,1):
            rows=self.lifecycle(i)
            ready={r['id'] for r in rows if r['phase']=='class_muxes_ready'}
            starts[i]=[r for r in rows if r['phase']=='started' and r['id'] in ready and
                r['max_lifetime_ms']==1800000 and 1799000<=r['deadline_after_start_ms']<=1800000 and
                r['authority_expires_at']>r['unix_ms']/1000+1860]
            if len(starts[i])!=2: raise RuntimeError('two fresh 1800-second entry drivers required per client')
        ends=[r['unix_ms']/1000+r['deadline_after_start_ms']/1000 for rows in starts.values() for r in rows]
        first,last=min(ends),max(ends)
        if last-first>60 or first-time.time()<120: raise RuntimeError('carrier deadlines are not a usable bounded application window')
        self.event('carrier_cap_planned', first_deadline=first, last_deadline=last, client_entries=starts)
        self.wait(first-60)
        transfer=self.start_file(channel,self.spec['config']['file_bytes'],'carrier-cap')
        self.wait(first-1)
        before=self.file_info(transfer)
        if before['state']=='complete': raise RuntimeError('file completed before carrier cap')
        self.event('immediate_pre_cap_file_state', **before)
        # One deadline includes the carrier-end interval and all setup/admission.
        deadline=time.monotonic()+max(0,first-time.time())+300
        self.wait(first+1)
        self.rpc_deadline=deadline
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            chat=pool.submit(self.chat,channel,'turnover:carrier-cap',max(.1,deadline-time.monotonic()))
            def recovered():
                self.sample()
                evidence={}
                for i in (0,1):
                    rows=self.lifecycle(i)
                    evidence[i]=validated_cap_ends(starts[i],rows)
                    if evidence[i] is None: return False
                    old={r['id'] for r in starts[i]}
                    fresh={r['id'] for r in rows if r['phase']=='class_muxes_ready' and r['id'] not in old and r['unix_ms']/1000>=first}
                    if len(fresh)<2: return False
                if not all(self.readiness(i) for i in (0,1)): return False
                if int(self.file_info(transfer)['verified_bytes'])<=int(before['verified_bytes']): return False
                return evidence
            evidence=until(recovered,deadline,'actual carrier cap and both-class/file recovery')
            chat.result(timeout=max(.1,deadline-time.monotonic()))
        self.rpc_deadline=None
        self.event('carrier_cap_recovered', client_ends=evidence, seconds=time.time()-first)
        self.finish_file(transfer)
        self.reopen(1)
        self.probe(1,{'action':'export','id':transfer['id'],'name':'reopened-'+transfer['name'],**{k:transfer[k] for k in ('size','sha256')}})
        self.result['carrier_cap']={'client_starts':starts,'client_ends':evidence,'file':transfer,'actual_elapsed_1800_seconds':True,'authority_still_fresh':True}
        self.event('carrier_cap_passed', **self.result['carrier_cap'])

    def entry_loss(self, channel):
        # Close only fixture client0's established relay sockets. Relays keep
        # their queues and authority; connectivity is usable throughout.
        rows=self.lifecycle(0)
        ended={r['id'] for r in rows if r['phase'] not in ('started','class_muxes_ready')}
        ready=[r for r in rows if r['phase']=='class_muxes_ready' and r['id'] not in ended]
        if len(ready)!=2: raise RuntimeError('two live entry publications required before loss')
        self.wait(max(r['unix_ms']/1000 for r in ready)+31)
        transfer=self.start_file(channel,self.spec['config']['file_bytes'],'entry-loss')
        before=until(lambda:self.file_info(transfer) if int(self.file_info(transfer)['verified_bytes'])>0 else None,
                     time.monotonic()+120,'file progress before entry loss')
        if before['state']=='complete': raise RuntimeError('file completed before entry loss')
        if any(r['authority_expires_at']<=time.time()+120 for r in ready):
            raise RuntimeError('entry-loss fixture lacks fresh authority for recovery')
        identity=self.request(0,'snapshot')['snapshot']['instance']['id']
        started=time.monotonic(); reset_ms=int(time.time()*1000)
        self.event('entry_loss_requested', old_entries=ready, verified_bytes=before['verified_bytes'])
        # The observed namespace is disconnected and contains only this fixture
        # client. The exact destination list excludes every non-fixture address.
        command=[*self.ns,'ss','-K','dst',RELAYS[0]]
        for address in RELAYS[1:]: command += ['or','dst',address]
        (self.root/'entry-loss-sockets.log').write_text(run(command))
        deadline=started+300; self.rpc_deadline=deadline
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            chat=pool.submit(self.chat,channel,'turnover:entry-loss',max(.1,deadline-time.monotonic()))
            def recovered():
                evidence=validated_replacements(ready,self.lifecycle(0),reset_ms)
                if evidence is None or not self.readiness(0): return None
                if int(self.file_info(transfer)['verified_bytes'])<=int(before['verified_bytes']): return None
                return evidence
            evidence=until(recovered,deadline,'replacement entries and retained subscription/file progress')
            chat.result(timeout=max(.1,deadline-time.monotonic()))
        seconds=time.monotonic()-started
        self.rpc_deadline=None
        if self.request(0,'snapshot')['snapshot']['instance']['id']!=identity:
            raise RuntimeError('entry loss changed retained client identity')
        self.event('entry_loss_recovered',seconds=seconds,**evidence)
        self.finish_file(transfer)
        self.reopen(1)
        self.probe(1,{'action':'export','id':transfer['id'],'name':'reopened-'+transfer['name'],**{k:transfer[k] for k in ('size','sha256')}})
        self.result['entry_loss']={'recovery_seconds':seconds,'r03_10s_passed':seconds<=10,
            'same_identity':True,'file':transfer,'replacements':evidence,
            'scope':'established fixture TCP reset; not credential or carrier-cap expiry'}

    def start_client(self, i):
        if host := self.spec.get('fixture_host'):
            return self.start_fixture_client(i, host)
        if self.roles.get(f'client{i}', 0) == 0:
            return super().start_client(i)
        if any(role.startswith(f'probe{i}') and child.poll() is None for role, child in self.children):
            raise RuntimeError('previous owner probe is still running')
        probe_socket = self.root / f'c{i}/probe.sock'
        if probe_socket.exists():
            if not probe_socket.is_socket():
                raise RuntimeError('unexpected file at private probe socket')
            probe_socket.unlink()
        # Reopen the existing profile. Do not inject the original, now possibly
        # expired fixture bootstrap or silently create a replacement profile.
        folder = self.root / f'c{i}'
        binary = Path(self.spec['build']['path']) / 'bin/gchat'
        command = [binary, 'daemon', '--home', folder, '--store', folder / 'profile',
            '--chat-archive', folder / 'archive', '--socket', folder / 'protocol.sock',
            '--passphrase-file', self.root / 'pass', '--listen', f'127.0.0.1:{24600+i}',
            '--advertise', f'127.0.0.1:{24600+i}', '--gc2-carrier', '--no-network-bootstrap']
        p = self.spawn(f'client{i}', command, observer=i == 0,
            env={'GC_GC2_CARRIER': 'true', 'GCHAT_FILE_DIAGNOSTICS': '1',
                 'GCHAT_PROTOCOL_METRICS': str(folder / 'metrics.jsonl')})
        self.clients.append(p)
        self.spawn(f'probe{i}', [Path(self.spec['build']['path']) / 'bin/fleet_probe', '--serve',
            folder / 'protocol.chat', folder / 'fixtures', folder / 'probe.sock'])

    def start_fixture_client(self, i, host):
        fresh = self.roles.get(f'client{i}', 0) == 0
        folder = self.root / f'c{i}'
        if any(role.startswith(f'probe{i}') and child.poll() is None for role, child in self.children):
            raise RuntimeError('previous owner probe is still running')
        endpoint = folder / 'probe.sock'
        if endpoint.exists():
            if not endpoint.is_socket():
                raise RuntimeError('unexpected file at private probe socket')
            endpoint.unlink()
        command = [host['path'], 'serve', '--home', folder,
            '--passphrase-file', self.root / 'pass', '--network', self.root / 'network.json',
            '--listen', f'127.0.0.1:{24600+i}']
        environment = {
            'GCHAT_FIXTURE_NETNS': self.result['boundary']['observer_netns' if i == 0 else 'fixture_netns'],
            'GCHAT_FIXTURE_HOST_NETNS': self.spec['host_netns'],
            'GCHAT_FILE_DIAGNOSTICS': '1', 'GCHAT_PROTOCOL_METRICS': str(folder / 'metrics.jsonl'),
        }
        if fresh:
            command += ['--create', '--inbox-card', folder / 'card']
            environment['GC_ROUTING_BOOTSTRAP'] = str(folder / 'bootstrap')
        process = self.spawn(f'client{i}', command, observer=i == 0, env=environment)
        self.clients.append(process)
        self.spawn(f'probe{i}', [Path(self.spec['build']['path']) / 'bin/fleet_probe', '--serve',
            folder / 'protocol.chat', folder / 'fixtures', folder / 'probe.sock'])

    def status(self, i):
        log = self.root / f'{self.latest.get(f"client{i}", f"client{i}")}.log'
        if not log.exists(): return None
        with log.open('rb') as stream:
            stream.seek(max(0, log.stat().st_size - 1048576))
            rows = stream.read().decode(errors='replace').splitlines()
        for row in reversed(rows):
            try:
                value = json.loads(row)
                if value.get('event') == 'file_diagnostics':
                    if time.time()-value['unix_seconds']>15: return None
                    return value['protocol']['transport']
            except (ValueError, KeyError): pass
        return None

    def readiness(self, i):
        status = self.status(i)
        return status if status and status.get('profile_id') == 46 and status.get('bootstrap_version') == 2 and status.get('usable_terminal_routes', 0) > 0 and status.get('interactive_subscriptions', 0) >= getattr(self, 'expected_subscriptions', 2) and status.get('bulk_subscriptions', 0) >= getattr(self, 'expected_subscriptions', 2) else None

    def sample(self):
        self.event('transport_sample', clients=[self.status(i) for i in (0,1)])
        if int(time.time()) // 30 != getattr(self, 'directory_sample', None):
            self.directory_sample = int(time.time()) // 30
            redacted = []
            for i in range(len(self.relay_addresses)):
                encoded = self.control(i, 'routing_bootstrap')['routing_bundle_b64']
                raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
                if raw[:5] != b'GCRB\x02' or len(raw) != 6 + 155 * raw[5]: raise RuntimeError('unexpected current bundle')
                redacted.append({'relay': i, 'introductions': [
                    {'service_id_sha256': hashlib.sha256(raw[j+19:j+51]).hexdigest(),
                     'expires_at': int.from_bytes(raw[j+147:j+155], 'big')}
                    for j in range(6, len(raw), 155)]})
            self.event('retained_control_directory_sample', relays=redacted,
                       scope='raw authenticated retained seeds, not the fresh GCD2 response')

    def wait(self, wall_deadline):
        while time.time() < wall_deadline:
            self.sample(); time.sleep(min(2, max(0, wall_deadline-time.time())))

    def history(self, i, channel, token):
        rows = self.request(i, 'history', conversation=channel, before=None, limit=200)['page']['messages']
        return [m for m in rows if m['body'] == token]

    def join_invitation(self, i, code, nickname):
        # Follow the same inspect/explicit-network-acceptance path as the UI.
        # Combined invitations are larger than ordinary chat command input.
        preview = self.request(i, 'networks', request={'kind':'inspect', 'code':code})['response']
        if preview.get('kind') != 'preview' or preview['preview'].get('newNetwork'):
            raise RuntimeError('fixture invitation must target its existing network')
        network = preview['preview']['network']['id']
        operation = uuid.uuid4().hex
        self.event('operation_requested', client=i, operation_id=operation, command='network_join')
        response = self.request(i, 'networks', request={'kind':'join', 'code':code,
            'nickname':nickname, 'accepted_network':network, 'operation_id':operation})['response']
        if response.get('kind') != 'result' or response.get('network') != network:
            raise RuntimeError('invitation did not return the accepted network')
        result = response['response']
        if result.get('kind') != 'applied' or not result.get('conversation'):
            raise RuntimeError('invitation join did not confirm channel membership')
        self.event('operation_response', client=i, operation_id=operation, command='network_join')
        return result

    def chat(self, channel, token, seconds=120):
        started = time.monotonic()
        previous_deadline=self.rpc_deadline
        self.rpc_deadline=min(previous_deadline, started+seconds) if previous_deadline else started+seconds
        try:
            for sender, receiver, body in ((0, 1, token), (1, 0, 'reply:'+token)):
                message_started = time.monotonic()
                self.event('chat_attempted', token=body, sender=sender)
                self.submit(sender, body, channel)
                self.event('chat_locally_accepted', token=body, sender=sender)
                receipt=until(lambda:self.delivery(sender,receiver,channel,body),
                              self.rpc_deadline,'recipient display and authenticated sender ACK')
                self.event('chat_delivery_verified', sender=sender, message_id=receipt['id'],
                           seconds=time.monotonic()-message_started,
                           round_seconds=time.monotonic()-started)
            self.chat_count += 1
            self.event('chat_acknowledged', token=token, seconds=time.monotonic()-started)
        finally:
            self.rpc_deadline=previous_deadline

    def delivery(self, sender, receiver, channel, token, expected_id=None):
        sent=self.history(sender,channel,token)
        received=self.history(receiver,channel,token)
        if len(sent)>1 or len(received)>1:
            raise RuntimeError('duplicate application message')
        if not sent or not received: return None
        if (not sent[0]['mine'] or received[0]['mine'] or not sent[0]['id'] or
                sent[0]['id']!=received[0]['id'] or
                (expected_id is not None and sent[0]['id']!=expected_id)):
            raise RuntimeError('application message identity changed')
        return sent[0] if sent[0].get('delivery')=='delivered' else None

    def start_file(self, channel, size, label):
        ident = uuid.uuid4().hex; name = label+'.bin'
        expected = self.probe(0, {'action':'generate','name':name,'size':size,'seed':self.spec['seed'] ^ int.from_bytes(hashlib.sha256(label.encode()).digest()[:8], 'big')})
        self.probe(0, {'action':'import','id':ident,'conversation':channel,'name':name})
        def offered(): return next((f for f in self.files(1)['files'] if f['id']==ident),None)
        offer = until(offered,time.monotonic()+180,'file offer')
        if offer['state']!='offered' or offer['verified_bytes']!='0': raise RuntimeError('download before acceptance')
        self.files(1,'accept',id=ident)
        self.event('file_accepted',id=ident,label=label,**expected)
        return {'id':ident,'name':name,**expected}

    def file_info(self, transfer):
        return next((f for f in self.files(1)['files'] if f['id']==transfer['id']),None)

    def finish_file(self, transfer, seconds=1200):
        deadline=time.monotonic()+seconds; last=None
        self.event('file_completion_deadline', id=transfer['id'], seconds=seconds, scope='correctness, not latency qualification')
        while time.monotonic()<deadline:
            info=self.file_info(transfer)
            if time.monotonic()>=deadline:
                raise RuntimeError('independent file completion deadline')
            if info is not None:
                current=(info['state'], info['verified_bytes'])
                if current!=last:
                    self.event('file_progress',id=transfer['id'],state=current[0],verified_bytes=current[1]);last=current
                if info['state']=='complete': break
            self.sample();time.sleep(2)
        else: raise RuntimeError('independent file completion deadline')
        expected={k:transfer[k] for k in ('size','sha256')}
        result=self.probe(1,{'action':'export','id':transfer['id'],'name':'export-'+transfer['name'],**expected})
        self.event('file_export_verified',id=transfer['id'],**result)
        return result

    def reopen(self, i, abrupt=False):
        before=self.request(i,'snapshot')['snapshot']['instance']['id']
        process=next(p for role,p in reversed(self.children) if role.startswith(f'client{i}') and p.poll() is None)
        self.stop(process, signal.SIGKILL if abrupt else signal.SIGTERM)
        self.event('client_stopped_for_reopen', client=i, abrupt=abrupt, returncode=process.returncode)
        for role, child in self.children:
            if role.startswith(f'probe{i}') and child.poll() is None: self.stop(child)
        self.start_client(i)
        after=until(lambda:self.request(i,'snapshot'),time.monotonic()+120,'same-identity daemon reopen')['snapshot']['instance']['id']
        if before!=after: raise RuntimeError('identity changed on reopen')
        self.event('same_identity_reopen',client=i)
        until(lambda:self.readiness(i),time.monotonic()+300,'reopened both classes')

    def file_recovery(self, channel):
        transfer=self.start_file(channel,self.spec['config']['file_bytes'],'interrupted')
        threshold=max(1,transfer['size']//10)
        def partial():
            info=self.file_info(transfer)
            if info and info['state']=='complete':
                raise RuntimeError('file completed before the intended interruption')
            return info if info and int(info['verified_bytes'])>=threshold else None
        before=until(partial,time.monotonic()+300,'verified partial file before abrupt stop')
        self.event('file_before_abrupt_stop',id=transfer['id'],verified_bytes=before['verified_bytes'])
        self.reopen(1,abrupt=True)
        after=self.file_info(transfer)
        if after is None or int(after['verified_bytes'])<int(before['verified_bytes']):
            raise RuntimeError('verified pieces regressed after abrupt process termination')
        self.event('file_after_abrupt_reopen',id=transfer['id'],verified_bytes=after['verified_bytes'])
        self.chat(channel,'turnover:file-resume-chat')
        self.finish_file(transfer, self.spec['config'].get('file_completion_seconds', 1200))
        self.reopen(1)
        self.probe(1,{'action':'export','id':transfer['id'],'name':'reopened-'+transfer['name'],
                      **{k:transfer[k] for k in ('size','sha256')}})
        self.result['file_recovery']={'file':transfer,'before_verified_bytes':before['verified_bytes'],
            'after_verified_bytes':after['verified_bytes'],'abrupt_stop':True,'hash_verified_after_reopen':True}

    def admitted_sender_reopen(self, channel):
        identities=[self.request(i,'snapshot')['snapshot']['instance']['id'] for i in (0,1)]
        def stop_client(i):
            for role, process in reversed(self.children):
                if (role.startswith(f'client{i}') or role.startswith(f'probe{i}')) and process.poll() is None:
                    self.stop(process)
        stop_client(1)
        token='turnover:admitted-before-sender-reopen'
        self.rpc_deadline=time.monotonic()+180
        self.submit(0,token,channel)
        self.event('chat_accepted_receiver_offline',token=token)
        admitted=self.history(0,channel,token)
        if len(admitted)!=1 or admitted[0].get('delivery')!='local_accepted':
            raise RuntimeError('offline admission must remain pending')
        pending_id=admitted[0]['id']
        stop_client(0)
        for i in (0,1):
            self.start_client(i)
            value=until(lambda i=i:self.request(i,'snapshot'),time.monotonic()+120,'admitted profile reopen')
            if value['snapshot']['instance']['id']!=identities[i]: raise RuntimeError('admitted reopen changed identity')
        self.rpc_deadline=time.monotonic()+300
        until(lambda:self.delivery(0,1,channel,token,pending_id),self.rpc_deadline,
              'retained admitted ID displayed and authenticated ACK without resubmission')
        self.event('admitted_chat_reopen_passed',token=token,message_id=pending_id,
                   no_resubmission=True,same_identities=True)
        self.chat_count+=1
        self.rpc_deadline=None

    def archive_failure(self, channel):
        if not self.spec.get('fixture_host'):
            raise RuntimeError('archive fault requires the explicitly isolated fixture host')
        archive=self.root/'c1'/'archive'
        if not archive.is_file() or archive.is_symlink():
            raise RuntimeError('receiver fixture archive is not a regular file')
        retained=archive.with_name('archive.before-failure')
        if retained.exists(): raise RuntimeError('archive fault backup already exists')
        identity=self.request(1,'snapshot')['snapshot']['instance']['id']
        before=sha256(archive)
        archive.rename(retained)
        archive.mkdir(mode=0o700)  # Atomic replacement of this directory must fail.
        token='turnover:archive-failure:'+uuid.uuid4().hex
        try:
            self.submit(0,token,channel)
            admitted=self.history(0,channel,token)
            if len(admitted)!=1: raise RuntimeError('archive-fault send was not admitted exactly once')
            pending_id=admitted[0]['id']
            visible=False; acked=False; storage_notice=False
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                messages=self.history(0,channel,token)
                acked=acked or any(m.get('delivery')=='delivered' for m in messages)
                visible=visible or bool(self.history(1,channel,token))
                snapshot=self.request(1,'snapshot')['snapshot']
                storage_notice=storage_notice or any(e.get('id')=='archive' and
                    e.get('code')=='local_storage_unavailable' for e in snapshot.get('providerErrors',[]))
                time.sleep(.2)
            if sha256(retained)!=before: raise RuntimeError('retained archive backup changed')
            self.event('archive_failure_observed',message_id=pending_id,
                       visible_before_archive_commit=visible,sender_delivered=acked,
                       storage_notice=storage_notice)
            for role, process in reversed(self.children):
                if (role.startswith('client1') or role.startswith('probe1')) and process.poll() is None:
                    self.stop(process,signal.SIGKILL)
        finally:
            archive.rmdir()
            retained.rename(archive)
        self.start_client(1)
        snapshot=until(lambda:self.request(1,'snapshot'),time.monotonic()+120,'archive-fault same-identity reopen')
        if snapshot['snapshot']['instance']['id']!=identity: raise RuntimeError('archive fault changed identity')
        deadline=time.monotonic()+120
        recovered=None
        while time.monotonic()<deadline:
            recovered=self.delivery(0,1,channel,token,pending_id)
            if recovered: break
            time.sleep(.2)
        self.result['archive_failure']={'message_id':pending_id,'sender_delivered_during_failure':acked,
            'visible_before_archive_commit':visible,'recovered_after_abrupt_stop':bool(recovered),
            'storage_notice':storage_notice,'same_identity':True,'original_archive_sha256':before}
        if visible or not recovered:
            raise RuntimeError('receiver archive failure published uncommitted history or lost an acknowledged message')
        if not storage_notice:
            raise RuntimeError('receiver archive failure did not expose an actionable storage notice')

    def multi_party(self):
        """Ten actual application clients; every message requires all nine receivers."""
        clients = list(range(10))
        deadline = time.monotonic() + 1200
        self.rpc_deadline = deadline
        self.event('multi_party_setup', clients=10, seconds=1200)
        for i in clients:
            self.start_client(i)
        for i in clients:
            until(lambda i=i: self.request(i, 'snapshot'), deadline, 'ten-client IPC startup')
            until(lambda i=i: self.readiness(i), deadline, 'ten-client protected readiness')
        channel = self.submit(0, '/create #participants participant0')['conversation']
        joins = []
        for i in clients[1:]:
            def invitation():
                output = self.submit(0, '/invite', channel)['output']
                return output['link'] if not output.get('localOnly', True) else None
            code = until(invitation, deadline, 'participant remote invitation')
            started = time.monotonic()
            result = self.join_invitation(i, code, f'participant{i}')
            if result['conversation'] != channel:
                raise RuntimeError('participant joined another channel')
            seconds = time.monotonic() - started
            joins.append({'client': i, 'seconds': seconds, 'r04_30s_passed': seconds <= 30})
            self.event('participant_joined', **joins[-1])
        self.expected_subscriptions = 4
        for i in clients:
            until(lambda i=i: self.readiness(i), deadline, 'all participants subscribed in both classes')
        self.result['multi_party'] = {'clients': 10, 'joins': joins, 'rounds': [],
            'scope': 'ten actual GChat clients through six protected relays; clients are not qualified relay forwarders'}
        for round_number in range(2):
            # One fixed correctness budget, with the five-second latency ceiling
            # measured independently from each simultaneous user action.
            self.rpc_deadline = time.monotonic() + 180
            barrier = threading.Barrier(len(clients), timeout=10)
            def send(i):
                token = f'participants:{round_number}:{i}:{uuid.uuid4().hex}'
                barrier.wait()
                started = time.monotonic()
                self.submit(i, token, channel)
                return {'sender': i, 'token': token, 'started': started,
                        'acceptance_seconds': time.monotonic()-started}
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)) as pool:
                pending = list(pool.map(send, clients))
            completed = []
            self.result['multi_party']['rounds'].append(completed)
            while pending:
                if time.monotonic() >= self.rpc_deadline:
                    raise TimeoutError('ten-client delivery correctness deadline elapsed')
                for item in list(pending):
                    rows = [self.history(i, channel, item['token']) for i in clients]
                    message = validated_group_delivery(rows, item['sender'])
                    observed = time.monotonic()
                    if observed >= self.rpc_deadline:
                        raise TimeoutError('ten-client delivery observed after correctness deadline')
                    if message:
                        seconds = observed-item['started']
                        record = dict(sender=item['sender'], message_id=message['id'],
                            recipients=9, acceptance_seconds=item['acceptance_seconds'],
                            seconds=seconds, r02_5s_passed=seconds <= 5)
                        completed.append(record)
                        self.event('group_delivery_verified', round=round_number, **record)
                        pending.remove(item)
                if pending:
                    time.sleep(.2)
        self.rpc_deadline = None
        self.result['boundary']['after'] = self.inventory()
        self.assert_topology(self.result['boundary']['after'])
        self.result['completed'] = True

    def exercise(self):
        # Header-only connection lifecycle evidence. This does not replace the
        # all-packet privacy observer or label encrypted flows as entry drivers.
        capture_log=(self.root/'connections.capture.log').open('xb')
        self.capture=subprocess.Popen([*self.ns,'tcpdump','--immediate-mode','-n','-U','-i','client0',
            '-s','96','-w',str(self.root/'connections.pcap'),
            'tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0'],stdout=capture_log,stderr=subprocess.STDOUT,env=self.env)
        capture_log.close();self.children.append(('connection_capture',self.capture))
        self.result['application_started_epoch']=time.time()
        if self.spec['config'].get('mode') == 'multi-party':
            return self.multi_party()
        setup_deadline=time.monotonic()+300
        self.rpc_deadline=setup_deadline
        self.event('setup_deadline', seconds=300)
        for i in (0,1): self.start_client(i)
        for i in (0,1):
            until(lambda i=i:self.request(i,'snapshot'),setup_deadline,'IPC startup')
            quota=3*1024*1024*1024 if self.spec['config'].get('mode')=='file-recovery' else 1024*1024*1024
            self.files(i,'configure',quota_bytes=str(quota),retention_days=7)
            until(lambda i=i:self.readiness(i),setup_deadline,'protected both-class readiness')
        channel=self.submit(0,'/create #turnover sender')['conversation']
        def invite():
            value=self.submit(0,'/invite',channel)['output']
            return value['link'] if not value.get('localOnly',True) else None
        self.join_invitation(1,until(invite,setup_deadline,'remote invite'),'receiver')
        self.expected_subscriptions=4
        for i in (0,1): until(lambda i=i:self.readiness(i),setup_deadline,'contact AND channel, both classes')
        self.rpc_deadline=None
        self.chat(channel,'turnover:warmup')
        if self.spec['config'].get('mode') == 'archive-failure':
            self.archive_failure(channel)
            self.result['boundary']['after']=self.inventory();self.assert_topology(self.result['boundary']['after'])
            self.result['completed']=True
            return
        small=self.start_file(channel,65536,'warmup');self.finish_file(small,300)
        self.reopen(1)
        self.probe(1,{'action':'export','id':small['id'],'name':'reopened-'+small['name'],**{k:small[k] for k in ('size','sha256')}})
        self.admitted_sender_reopen(channel)
        if self.spec['config'].get('mode') == 'file-recovery':
            self.file_recovery(channel)
        if self.spec['config'].get('mode') in ('smoke','file-recovery'):
            self.result['chat_acknowledged']=self.chat_count
            self.result['credential_cycles']=[]
            self.result['turnover_qualified']=False
            self.result['boundary']['after']=self.inventory();self.assert_topology(self.result['boundary']['after'])
            self.result['completed']=True
            return
        if self.spec['config'].get('mode') == 'entry-loss':
            self.entry_loss(channel)
            self.result['chat_acknowledged']=self.chat_count
            self.result['boundary']['after']=self.inventory(); self.assert_topology(self.result['boundary']['after'])
            self.result['completed']=True
            return
        if self.spec['config'].get('mode') == 'carrier-cap':
            self.carrier_cap(channel)
            self.result['chat_acknowledged']=self.chat_count
            self.result['boundary']['after']=self.inventory(); self.assert_topology(self.result['boundary']['after'])
            self.result['completed']=True
            return
        cycles=[]
        for generation in range(self.spec['config']['expiries']):
            boundary=(int(time.time())//3600+1)*3600
            if boundary-time.time()<120: boundary+=3600
            self.event('credential_boundary_planned',generation=generation,expires_at=boundary)
            self.wait(boundary-60)
            transfer=self.start_file(channel,self.spec['config']['file_bytes'],f'generation-{generation}')
            before=self.file_info(transfer)
            self.event('pre_expiry_file_state',generation=generation,expires_at=boundary,verified_bytes=before['verified_bytes'],state=before['state'])
            if before['state']=='complete': raise RuntimeError('file did not span intended credential expiry')
            self.wait(boundary-1)
            before=self.file_info(transfer)
            self.event('immediate_pre_expiry_file_state', generation=generation, verified_bytes=before['verified_bytes'], state=before['state'])
            if before['state']=='complete': raise RuntimeError('file finished before the authenticated credential boundary')
            self.wait(boundary+5)
            self.rpc_deadline=time.monotonic()+300
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                chat=pool.submit(self.chat,channel,f'turnover:expiry:{generation}',300)
                deadline=time.monotonic()+300
                recovered=False
                while time.monotonic()<deadline:
                    self.sample()
                    info=self.file_info(transfer)
                    if all(self.readiness(i) for i in (0,1)) and int(info['verified_bytes'])>int(before['verified_bytes']):
                        recovered=True;break
                    time.sleep(2)
                if not recovered: raise RuntimeError('both-class/file recovery exceeded 300 seconds after real credential expiry')
                chat.result(timeout=max(.1,deadline-time.monotonic()))
            self.rpc_deadline=None
            self.finish_file(transfer)
            self.reopen(1)
            self.probe(1,{'action':'export','id':transfer['id'],'name':'reopened-'+transfer['name'],**{k:transfer[k] for k in ('size','sha256')}})
            cycles.append({'generation':generation,'credential_expiry':boundary,'file':transfer})
            self.event('credential_cycle_passed',**cycles[-1])
        self.result['credential_cycles']=cycles
        self.result['chat_acknowledged']=self.chat_count
        self.result['boundary']['after']=self.inventory();self.assert_topology(self.result['boundary']['after'])
        self.result['completed']=True

def validated_cap_ends(starts, rows):
    ends=[]
    for start in starts:
        observed=[r for r in rows if r['id']==start['id'] and r['phase'] in ('deadline_elapsed','transport_ended','dropped','completed')]
        if not observed: return None
        if len(observed)!=1: raise RuntimeError('duplicate driver completion')
        end=observed[0]
        if (end['phase']!='deadline_elapsed' or not start['deadline_after_start_ms']-1<=end['elapsed_ms']<=start['deadline_after_start_ms']+60000 or
                end['unix_ms']>=start['authority_expires_at']*1000 or
                start['max_lifetime_ms']!=1800000 or
                start['authority_expires_at']*1000-start['unix_ms']<=1860000):
            raise RuntimeError('driver did not reach the actual carrier cap with fresh authority')
        ends.append(end)
    return ends


def validated_replacements(old_ready, rows, reset_ms):
    old={r['id'] for r in old_ready}
    if len(old)!=2: raise RuntimeError('two distinct original entry publications required')
    ends=[r for r in rows if r['id'] in old and r['phase'] not in ('started','class_muxes_ready')]
    if len(ends)<2: return None
    if (len(ends)!=2 or {r['id'] for r in ends}!=old or
            any(r['phase']!='transport_ended' or r['unix_ms']<reset_ms for r in ends)):
        raise RuntimeError('old entry did not end from the declared transport loss')
    fresh=[r for r in rows if r['phase']=='class_muxes_ready' and r['id'] not in old and r['unix_ms']>=reset_ms]
    dead={r['id'] for r in rows if r['phase'] not in ('started','class_muxes_ready')}
    fresh=[r for r in fresh if r['id'] not in dead]
    if len({r['id'] for r in fresh})<2: return None
    return {'ended':ends,'ready':fresh}


def validated_group_delivery(histories, sender):
    """A local receipt or any proper subset of recipients is insufficient."""
    if len(histories) != 10 or not 0 <= sender < 10:
        raise ValueError('ten participants and one valid sender required')
    if any(len(rows) > 1 for rows in histories):
        raise RuntimeError('duplicate group message')
    if not all(histories):
        return None
    sent = histories[sender][0]
    if not sent.get('id') or any(rows[0].get('id') != sent['id'] or
            rows[0].get('mine') is not (i == sender) for i, rows in enumerate(histories)):
        raise RuntimeError('group message identity or authorship changed')
    return sent if sent.get('delivery') == 'delivered' else None


def main():
    if sys.argv[1:2]==['--worker']:
        return Journey(json.loads(Path(sys.argv[2]).read_text())).execute()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--expiries',type=int,default=3,choices=(1,2,3))
    parser.add_argument('--mode',choices=('smoke','file-recovery','archive-failure','credential-expiry','carrier-cap','entry-loss','multi-party'),default='credential-expiry')
    parser.add_argument('--file-bytes',type=int)
    parser.add_argument('--release-check',action='store_true',
                        help='file-recovery only: 16 MiB, 180s completion, 600s total; large-file runs stay separate')
    parser.add_argument('--file-completion-seconds',type=int,
                        help='predeclared file-recovery completion budget, 60..3600 seconds; no latency qualification')
    parser.add_argument('--fixture-host',type=Path,
                        help='source-bound turnover_daemon example with fixture-owned signed network trust')
    args=parser.parse_args()
    if os.geteuid()==0: parser.error('run controller as ordinary owner')
    if args.release_check and (args.mode!='file-recovery' or
            args.file_bytes not in (None,16*1024*1024) or args.file_completion_seconds not in (None,180)):
        parser.error('release check requires file-recovery with 16 MiB and 180 seconds')
    if args.file_bytes is None: args.file_bytes=16*1024*1024 if args.release_check else 256*1024*1024
    if args.file_completion_seconds is None: args.file_completion_seconds=180 if args.release_check else 1200
    maximum=1024*1024*1024 if args.mode=='file-recovery' else 256*1024*1024
    minimum=16*1024*1024 if args.release_check else 64*1024*1024
    if not minimum<=args.file_bytes<=maximum: parser.error('file size exceeds the selected fixture bounds')
    if not 60<=args.file_completion_seconds<=3600: parser.error('file completion budget must be between 60 and 3600 seconds')
    if args.mode!='file-recovery' and args.file_completion_seconds!=1200: parser.error('custom file completion budget is only for file-recovery')
    root=args.out.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    build=base.build_binding(args.build.resolve())
    before=links();tool_hash=sha256(Path(__file__));helper_hash=sha256(HELPER)
    config={'release_check':args.release_check,'mode':args.mode,'lifecycle_diagnostics':args.mode in ('carrier-cap','entry-loss'),'expiries':args.expiries,'file_bytes':args.file_bytes,'file_completion_seconds':args.file_completion_seconds,'production_credential_seconds':3600,'production_carrier_cap_seconds':1800,'recovery_seconds':300}
    spec={'out':str(root),'build':build,'config':config,'workload':'turnover','seed':20260920,
          'uid':os.getuid(),'gid':os.getgid(),'run_nonce':uuid.uuid4().hex,
          'host_netns':os.readlink('/proc/self/ns/net'),'host_mountns':os.readlink('/proc/self/ns/mnt')}
    if args.fixture_host:
        host=args.fixture_host.resolve()
        spec['fixture_host']={'path':str(host),'sha256':sha256(host),'size':host.stat().st_size}
    (root/'spec.json').write_text(json.dumps(spec,indent=2)+'\n')
    (root/'driver.py').write_bytes(Path(__file__).read_bytes())
    (root/'boundary-helper.py').write_bytes(HELPER.read_bytes())
    timeout=1800 if args.mode in ('entry-loss','multi-party') else 900 if args.mode in ('smoke','archive-failure') else 1200+args.file_completion_seconds if args.mode=='file-recovery' else 3600*(args.expiries+1)+900
    if args.release_check: timeout=600
    command=['sudo','-n','timeout','--signal=TERM','--kill-after=20',str(timeout),
             'unshare','--net','--mount','--pid','--fork','--mount-proc','--kill-child','--propagation','private','--',
             sys.executable,str(Path(__file__).resolve()),'--worker',str(root/'spec.json')]
    with (root/'controller.log').open('xb') as log: result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
    after=links();worker=json.loads((root/'worker.json').read_text()) if (root/'worker.json').exists() else {}
    retired={worker.get('boundary',{}).get(name) for name in ('fixture_netns','observer_netns')} - {None}
    residual=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            if os.readlink(proc/'ns/net') in retired: residual.append(int(proc.name))
        except (FileNotFoundError,PermissionError): pass
    evidence={name:sha256(root/name) for name in ('worker.json','events.jsonl','connections.pcap','connections.capture.log','controller.log') if (root/name).exists()}
    evidence.update({p.name:sha256(p) for p in root.glob('client*.log')})
    report={'evidence':evidence,'retired_namespace_pids':residual,'scope':SCOPE,'worker_exit':result.returncode,'host_links_unchanged':base.link_identity(before)==base.link_identity(after),
            'host_before':before,'host_after':after,'build_unchanged':base.build_binding(args.build.resolve())==build,
            'tooling_unchanged':sha256(Path(__file__))==tool_hash and sha256(HELPER)==helper_hash,
            'driver_sha256':tool_hash,'helper_sha256':helper_hash,'worker':worker,
            'privacy_qualified':False,'release_qualified':False,
            'scope_limits':['explicit private bootstrap, not installed signed-network onboarding',
                            'same-ID recipient history and sender delivery ACK; native exact-wire regression remains separate',
                            'smoke mode omits credential and carrier expiry and does not qualify latency ceilings',
                            'real carrier lifetime requires connection-lifecycle evidence; elapsed time alone does not qualify its cause']}
    report['passed']=not residual and result.returncode==0 and worker.get('completed') is True and worker.get('children_stopped') is True and all(report[k] for k in ('host_links_unchanged','build_unchanged','tooling_unchanged'))
    if host := spec.get('fixture_host'):
        report['fixture_host']=host
        report['fixture_host_unchanged']=sha256(Path(host['path']))==host['sha256']
        report['scope_limits'].append('real GChat core/service in a qualification host; not an installed desktop executable')
        report['passed']=report['passed'] and report['fixture_host_unchanged']
    (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'failure':worker.get('failure'),'report':str(root/'report.json')}),flush=True)
    return 0 if report['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
