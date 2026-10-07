#!/usr/bin/env python3
"""Disconnected real-daemon turnover journey; no privacy/fleet qualification."""
import argparse, base64, concurrent.futures, hashlib, importlib.util, json, os
from pathlib import Path
import select, signal, socket, subprocess, sys, tempfile, threading, time, uuid
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
LOAD_SETUP_WORKERS = 4

def parallel_setup(function, items):
    # Independent profiles/listeners/channels only; preserve input order and
    # stop queued work on failure before advancing to the unchanged campaign.
    with concurrent.futures.ThreadPoolExecutor(max_workers=LOAD_SETUP_WORKERS) as pool:
        futures={pool.submit(function,item):index for index,item in enumerate(items)}
        results=[None]*len(futures)
        try:
            for future in concurrent.futures.as_completed(futures):
                results[futures[future]]=future.result()
        except BaseException:
            for future in futures:future.cancel()
            raise
        return results

def bounded_control(relay, command, deadline):
    def remaining():
        value=deadline-time.monotonic()
        if value<=0:raise TimeoutError('relay control deadline')
        return value
    with socket.create_connection(('127.0.0.1',19500+relay),timeout=remaining()) as stream:
        stream.settimeout(remaining())
        stream.sendall((json.dumps({'id':1,'cmd':command,'version':2})+'\n').encode())
        pending=b'';rows=0
        while rows<100:
            stream.settimeout(remaining())
            chunk=stream.recv(65536)
            if not chunk:raise RuntimeError('relay control closed before receipt')
            pending+=chunk
            while b'\n' in pending:
                row,pending=pending.split(b'\n',1);rows+=1
                if len(row)>1048576:raise ValueError('oversize relay control receipt')
                value=json.loads(row)
                if value.get('id')==1:
                    if not value.get('ok'):raise RuntimeError('relay control rejected command')
                    remaining()
                    return value['data']
                if rows>=100:break
            if len(pending)>1048576:raise ValueError('oversize relay control receipt')
    raise RuntimeError('relay control receipt missing')

def wait_restarted_relay(process, relay, deadline, control=bounded_control):
    while time.monotonic()<deadline:
        if process.poll() is not None:raise RuntimeError('restarted relay exited before readiness')
        try:
            encoded=control(relay,'routing_bootstrap',deadline)['routing_bundle_b64']
        except OSError:
            # Connection refusal while the fresh process binds its control
            # listener is expected. Invalid/rejected receipts are not retried.
            time.sleep(min(.1,max(0,deadline-time.monotonic())))
            continue
        bootstrap_records(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
        if time.monotonic()>=deadline:break
        if process.poll() is not None:raise RuntimeError('restarted relay exited during readiness')
        return time.monotonic()
    raise TimeoutError('restarted relay control not ready within 30 seconds')

def bootstrap_records(raw):
    if len(raw)<6 or raw[:5]!=b'GCRB\x02' or not 1<=raw[5]<=8 or len(raw)!=6+155*raw[5]:
        raise ValueError('invalid bounded fixture routing bundle')
    records=[raw[6+i*155:6+(i+1)*155] for i in range(raw[5])]
    if len({r[:83] for r in records})!=len(records):
        raise ValueError('duplicate fixture routing identity')
    return records

def bootstrap_bytes(records):
    raw=b'GCRB\x02'+bytes([len(records)])+b''.join(records)
    bootstrap_records(raw)
    return raw

def renewed_records(previous, incoming, now):
    # Address, service principal and stable re-entry authority are retained.
    # Entry/transit authority rotates at the production hour boundary.
    if [r[:83] for r in incoming]!=[r[:83] for r in previous]:
        raise ValueError('fixture introduction changed its verified relay identity')
    for old,new in zip(previous,incoming):
        expiry=int.from_bytes(new[147:155],'big')
        if expiry<=now:
            raise TimeoutError('fixture routing introductions expired')
        if expiry>now+3600 or expiry<int.from_bytes(old[147:155],'big'):
            raise ValueError('fixture routing introduction lifetime or rollback')
        if expiry==int.from_bytes(old[147:155],'big') and old!=new:
            raise ValueError('fixture routing authority changed within one epoch')
    return incoming

def replace_private(path, raw, uid, gid):
    # Readers always observe a complete owner-only bundle, including rollover.
    with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as out:
        temporary=Path(out.name)
        try:
            os.fchmod(out.fileno(),0o600);os.fchown(out.fileno(),uid,gid)
            out.write(raw);out.flush()
            os.replace(temporary,path)
        finally:
            temporary.unlink(missing_ok=True)

class FixtureRoutingRenewal:
    def __init__(self, root, clients, contributions, control, uid, gid):
        self.root,self.control,self.uid,self.gid=root,control,uid,gid
        self.contributions=contributions
        self.operator=bootstrap_records((root/'bootstrap').read_bytes())
        self.contributed=[bootstrap_records((root/f'c{i+2}/contribution').read_bytes())[0]
                          for i in range(contributions)]
        self.clients={root/f'c{i}/bootstrap':bootstrap_records((root/f'c{i}/bootstrap').read_bytes())
                      for i in range(clients)}
        self.stop=threading.Event();self.error=None;self.thread=None
        self.receipt={'cycles':0,'changed_bundles':0,'operator_relays':len(self.operator),
                      'contributions':contributions,'clients':clients,'stopped':False}

    def refresh(self, now=None):
        now=time.time() if now is None else now
        operators=[]
        for i in range(len(self.operator)):
            encoded=self.control(i,'routing_bootstrap')['routing_bundle_b64']
            operators.append(bootstrap_records(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))[0])
        operators=renewed_records(self.operator,operators,now)
        contributions=renewed_records(self.contributed,
            [bootstrap_records((self.root/f'c{i+2}/contribution').read_bytes())[0]
             for i in range(self.contributions)],now)
        by_identity={r[:83]:r for r in operators+contributions}
        if any(r[:83] not in by_identity for rows in self.clients.values() for r in rows):
            raise ValueError('fixture client references an unverified relay identity')
        bundles={self.root/'bootstrap':operators}
        bundles.update({path:[by_identity[r[:83]] for r in old] for path,old in self.clients.items()})
        for path,records in bundles.items():
            raw=bootstrap_bytes(records)
            if path.read_bytes()!=raw:
                replace_private(path,raw,self.uid,self.gid)
                self.receipt['changed_bundles']+=1
        self.operator,self.contributed=operators,contributions
        self.receipt.update(cycles=self.receipt['cycles']+1,
            expires_at=min(int.from_bytes(r[147:155],'big') for r in operators+contributions))

    def start(self):
        deadline=time.monotonic()+30
        while True:
            try:
                self.refresh();break
            except (OSError,RuntimeError):
                if time.monotonic()>=deadline:raise
                time.sleep(1)
        def run():
            unavailable=None
            while not self.stop.wait(5 if unavailable is None else 1):
                try:
                    self.refresh();unavailable=None
                except (OSError,RuntimeError) as error:
                    unavailable=time.monotonic() if unavailable is None else unavailable
                    if time.monotonic()-unavailable<30:continue
                    self.error=f'fixture routing refresh unavailable for 30 seconds: {type(error).__name__}'
                    return
                except Exception as error:
                    self.error=f'fixture routing refresh rejected: {error}'
                    return
        self.thread=threading.Thread(target=run,name='fixture-routing-renewal',daemon=True)
        self.thread.start()

    def check(self):
        if self.error:raise RuntimeError(self.error)

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=10)
            if self.thread.is_alive():raise RuntimeError('fixture routing renewal did not stop')
        self.receipt['stopped']=True
        self.check()

def load_relay_capacity(config):
    if config.get('mode') != 'relay-load':
        return []
    circuits = config['relay_circuits']
    connections = config['relay_connections']
    if (type(circuits) is not int or type(connections) is not int
            or not 1 <= circuits <= 4096 or not 2 * circuits <= connections <= 8192):
        raise ValueError('relay capacity requires 1..4096 circuits and twice that many connections, at most 8192')
    return ['--relay-circuits', str(circuits), '--relay-connections', str(connections)]

def load_channel_members(topology='fleet-four-channels'):
    if topology == 'single-channel':
        return [list(range(64))]
    if topology != 'fleet-four-channels':
        raise ValueError('unknown load topology')
    # The operator belongs to every fleet channel; the other 63 clients each
    # belong to one. Both topologies deliver to 63 recipients per round.
    return [[0, *range(1+index,64,4)] for index in range(4)]

def validated_load_delivery(seen, members, sender, sent):
    if sender not in members or len(set(members)) != len(members):
        raise ValueError('invalid load channel membership')
    if set(seen) != set(members) or not sent:
        return None
    if len(sent) != 1:
        raise RuntimeError('duplicated application command')
    message=sent[0]
    if any(row['id'] != message['id'] or row['mine'] != (client == sender)
           for client,row in seen.items()) or message['mine'] is not True:
        raise RuntimeError('command identity or authorship changed')
    return message if message.get('delivery') == 'delivered' else None

def observe_load_recipient(item, client, history):
    rows=history(client,item['channel'],item['token'])
    observed=time.monotonic()
    if len(rows)>1:
        raise RuntimeError('duplicated application command')
    return client, ({'id':rows[0]['id'],'mine':rows[0]['mine'],
        'seconds':observed-item['started']} if rows else None)

def incomplete_load_commands(pending, now):
    """Bounded failure evidence, without message content or capabilities."""
    rows=[]
    for item in pending[:64]:
        future=item['submission']
        submission='pending'
        if future.done():
            if future.cancelled():submission='cancelled'
            elif future.exception() is not None:submission='failed'
            else:submission='accepted' if future.result() else 'refused'
        rows.append({'channel_index':item['index'],'sender':item['sender'],
            'age_seconds':max(0,now-item['started']),'submission':submission,
            'observed_clients':sorted(item['seen']),
            'missing_clients':sorted(set(item['members'])-set(item['seen'])),
            'sender_delivery':item.get('sender_delivery','unobserved')})
    return {'pending_commands':len(pending),'commands':rows}

def relay_load_counts(paths, started_unix, completed_unix):
    data_accepted=forwarding_accepted=refusals=0
    for path in paths:
        for line in path.read_text().splitlines():
            row=json.loads(line)
            if not started_unix<=row.get('ts',0)/1000<=completed_unix:continue
            if row.get('event')=='gchat_push_accepted' and row.get('kind') in ('data','duplicate'):
                data_accepted+=1
            if row.get('event')=='gc2_forward_accepted':forwarding_accepted+=1
            if row.get('event')=='gc2_forward_refused' or (row.get('event')=='gchat_queue_refused'
                and row.get('reason') in ('queue_full','store_capacity','replay_capacity')):refusals+=1
    return data_accepted,forwarding_accepted,refusals

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
        self.process_lock = threading.RLock()
        if self.spec['config'].get('mode') in ('carrier-cap', 'entry-loss'):
            self.env['GCOMS_GC2_LIFECYCLE'] = '1'

    def execute(self):
        status=super().execute()
        if self.spec['config']['mode']=='relay-load':
            # Final immutable metrics include rotated journals and counters
            # after every producer has stopped; no profile/card is exported.
            evidence=self.result.setdefault('evidence',{})
            paths=list(self.original_root.glob('r*/metrics.jsonl*'))
            paths.extend(self.original_root/f'c{i+2}/contribution.json' for i in range(32))
            for path in paths:
                if path.is_file():evidence[str(path.relative_to(self.original_root))]=sha256(path)
            (self.original_root/'worker.json').write_text(json.dumps(self.result,indent=2)+'\n')
        return status

    def event(self, kind, **facts):
        with self.process_lock:
            super().event(kind, elapsed=time.monotonic() - self.origin, **facts)

    def spawn(self, role, command, **kwargs):
        if role.startswith('relay') and len(command) > 1 and command[1] == 'serve':
            command = [*command, *load_relay_capacity(self.spec['config'])]
        with self.process_lock:
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
        count = 64 if self.spec['config'].get('mode') == 'relay-load' else 10 if self.spec['config'].get('mode') == 'multi-party' else 2
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
        if self.spec['config'].get('mode') == 'relay-load':
            for i in range(32):
                run(['ip', 'addr', 'add', f'11.231.97.{100+i}/24', 'dev', 'fixture0'])
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
        if self.spec['config'].get('mode') in ('multi-party', 'relay-load'):
            raw = (self.root / 'bootstrap').read_bytes()
            records = [raw[6+i*155:6+(i+1)*155] for i in range(raw[5])]
            count = 64 if self.spec['config'].get('mode') == 'relay-load' else 10
            def provision(client):
                folder = self.root / f'c{client}'
                (folder / 'fixtures').mkdir(mode=0o700)
                os.chown(folder / 'fixtures', self.uid, self.gid)
                inbox = (client + 2) % len(records)
                card = self.control(inbox, 'provision_client_relay')['private_card_b64']
                self.private(folder / 'card', card + '\n')
                self.private(folder / 'bootstrap', b'GCRB\x02' + bytes([len(records)-1]) +
                             b''.join(r for i, r in enumerate(records) if i != inbox))
                return {f'c{client}/{name}':sha256(folder/name) for name in ('card','bootstrap')}
            for inputs in parallel_setup(provision,range(2,count)):
                self.result['private_inputs'].update(inputs)
        if host := self.spec.get('fixture_host'):
            process = self.spawn('network-config', [host['path'], 'network',
                self.root / 'bootstrap', self.root / 'network.json'],
                env={'GCHAT_FIXTURE_NETNS': self.result['boundary']['fixture_netns'],
                     'GCHAT_FIXTURE_HOST_NETNS': self.spec['host_netns']})
            if process.wait(timeout=30) != 0:
                raise RuntimeError('fixture signed network generation failed')
            self.result['fixture_network_sha256'] = sha256(self.root / 'network.json')
        if self.spec['config'].get('mode') == 'relay-load':
            self.prepare_contributions()
            pools = [self.control(i, 'status')['relay_diagnostics']['forwarding']
                     for i in range(len(self.relay_addresses))]
            if any(pool['limit'] != self.spec['config']['relay_circuits']
                   or pool['bulk_limit'] != pool['limit'] - 1 for pool in pools):
                raise RuntimeError('relay forwarding pools do not match configured load capacity')
            self.result['relay_capacity'] = {'circuits': self.spec['config']['relay_circuits'],
                'connections': self.spec['config']['relay_connections'], 'forwarding_pools': pools}
            self.event('load_relay_capacity_verified', circuits=self.spec['config']['relay_circuits'],
                       connections=self.spec['config']['relay_connections'], relays=len(pools))
        if self.spec.get('fixture_host') and self.spec['config']['mode'] in ('relay-load','relay-preflight'):
            load=self.spec['config']['mode']=='relay-load'
            self.routing_renewal=FixtureRoutingRenewal(self.root,64 if load else 2,32 if load else 0,
                                                      self.control,self.uid,self.gid)
            self.routing_renewal.start()
            self.result['fixture_routing_renewal']=self.routing_renewal.receipt

    def prepare_contributions(self):
        host = self.spec['fixture_host']['path']
        started=time.monotonic()
        def prepare(i):
            folder = self.root / f'c{i+2}'
            env = {'GCHAT_FIXTURE_NETNS': self.result['boundary']['fixture_netns'],
                   'GCHAT_FIXTURE_HOST_NETNS': self.spec['host_netns']}
            self.spawn(f'contribution{i}', [host, 'contribute', '--listen', f'11.231.97.{100+i}:{24700+i}',
                '--bootstrap', self.root / 'bootstrap', '--introduction', folder / 'contribution',
                '--verified', folder / 'verified', '--diagnostics', folder / 'contribution.json'], env=env)
            until(lambda: (folder / 'contribution').is_file(), time.monotonic()+30, 'contribution listener')
            verifier = self.spawn(f'contribution-proof{i}', [host, 'verify', folder / 'contribution', folder / 'verified'],
                observer=True, env=env | {'GCHAT_FIXTURE_NETNS':self.result['boundary']['observer_netns']})
            if verifier.wait(timeout=30) != 0:
                raise RuntimeError('independent contribution listener verification failed')
            until(lambda: json.loads((folder/'contribution.json').read_text())['published'] if (folder/'contribution.json').is_file() else False,
                  time.monotonic()+10, 'contribution publication')
            raw = (folder / 'contribution').read_bytes()
            if len(raw)!=161 or raw[:6]!=b'GCRB\x02\x01':
                raise RuntimeError('invalid contribution introduction')
            return raw[6:]
        records=parallel_setup(prepare,range(32))
        for i in range(64):
            path=self.root/f'c{i}/bootstrap'
            seeds=path.read_bytes()[6:]
            # Five distinct operator seeds plus three independently verified
            # contributions, within the existing eight-introduction wire cap.
            selected=[records[(i*3+j)%len(records)] for j in range(3)]
            self.private(path,b'GCRB\x02\x08'+seeds+b''.join(selected))
        self.result['contributions']={'count':32,'listener_proofs':32,
            'setup_workers':LOAD_SETUP_WORKERS,'setup_seconds':time.monotonic()-started,
            'scope':'source-bound core contribution services colocated with application clients; native device guards and provider admission qualified separately'}

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
            '--listen', f'127.0.0.1:{24600+i}', '--fixture-invitations']
        environment = {
            'GCHAT_FIXTURE_NETNS': self.result['boundary']['observer_netns' if i == 0 else 'fixture_netns'],
            'GCHAT_FIXTURE_HOST_NETNS': self.spec['host_netns'],
            'GCHAT_FILE_DIAGNOSTICS': '1', 'GCHAT_PROTOCOL_METRICS': str(folder / 'metrics.jsonl'),
            'GCOMS_TRANSPORT_DIAGNOSTICS': '1',
        }
        if fresh:
            command += ['--create', '--inbox-card', folder / 'card']
            environment['GC_ROUTING_BOOTSTRAP'] = str(folder / 'bootstrap')
        # Reopen has neither startup seeds nor a fixture renewal watcher;
        # authenticated re-entry must use the encrypted retained directory.
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

    def request(self, i, kind, **values):
        renewal=getattr(self,'routing_renewal',None)
        if renewal:renewal.check()
        response=super().request(i,kind,**values)
        if renewal:renewal.check()
        return response

    def readiness(self, i, subscriptions=None):
        status = self.status(i)
        expected=subscriptions if subscriptions is not None else getattr(self, 'expected_subscriptions', 2)
        return status if status and status.get('profile_id') == 46 and status.get('bootstrap_version') == 2 and status.get('usable_terminal_routes', 0) > 0 and status.get('interactive_subscriptions', 0) >= expected and status.get('bulk_subscriptions', 0) >= expected else None

    def sample(self, restarting=()):
        if renewal:=getattr(self,'routing_renewal',None):renewal.check()
        self.event('transport_sample', clients=[self.status(i) for i in (0,1)])
        if int(time.time()) // 30 != getattr(self, 'directory_sample', None):
            self.directory_sample = int(time.time()) // 30
            redacted = []
            for i in range(len(self.relay_addresses)):
                if i in restarting:
                    redacted.append({'relay':i,'restart_pending':True})
                    continue
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
            message = str(result.get('message', result.get('notice', ''))).replace(code, '[private invitation]')
            raise RuntimeError('invitation join did not confirm channel membership: '
                               + str(result.get('kind')) + ' ' + message[:240])
        self.event('operation_response', client=i, operation_id=operation, command='network_join')
        return result

    def remote_invitation(self, channel):
        if self.spec.get('fixture_host'):
            # The disconnected fixture has no HTTPS invitation provider.
            # Exercise the released single-use SDK admission path for setup;
            # this does not qualify provider-backed reusable invitations.
            snapshot = self.request(0, 'snapshot')['snapshot']
            name = next(row['name'].lstrip('#') for row in snapshot['conversations'] if row['id'] == channel)
            remaining = self.rpc_deadline-time.monotonic() if self.rpc_deadline else 30
            # The namespace controller is root; the private SDK endpoint is
            # deliberately restricted to the profile's ordinary owner.
            code = ('import socket,sys; s=socket.socket(socket.AF_UNIX); '
                    's.settimeout(30); s.connect(sys.argv[1]); '
                    's.sendall(sys.stdin.buffer.read()); s.shutdown(socket.SHUT_WR); '
                    'f=s.makefile("rb"); sys.stdout.buffer.write(f.read(1048576))')
            response=subprocess.run(['setpriv','--reuid',str(self.uid),'--regid',str(self.gid),
                '--clear-groups','--no-new-privs','--',sys.executable,'-c',code,
                str(self.root/'c0/fixture-invitations.sock')],
                input=json.dumps({'channel':name}).encode(),capture_output=True,
                timeout=max(.001,min(30,remaining)),check=True,env=self.env)
            value=json.loads(response.stdout)
            if 'error' in value: raise RuntimeError(value['error'])
        else:
            value=self.submit(0, '/invite person', channel)['output']
        if 'link' not in value or 'localOnly' not in value:
            raise AssertionError('invitation response did not contain a routable invitation')
        return value['link'] if not value['localOnly'] else None

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
            code = until(lambda:self.remote_invitation(channel), deadline, 'participant remote invitation')
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

    def prepare_load_channels(self, setup):
        groups=[]
        for index,members in enumerate(load_channel_members(self.spec['config']['load_topology'])):
            channel=self.submit(0,f'/create #relay-load{index} operator')['conversation']
            groups.append({'index':index,'channel':channel,'members':members})
        def enroll(group):
            # MLS membership changes remain ordered within each channel.
            # Different channels and member profiles have independent state.
            for client in group['members'][1:]:
                code=until(lambda:self.remote_invitation(group['channel']),setup,'64-client invitation')
                if self.join_invitation(client,code,f'participant{client}')['conversation'] != group['channel']:
                    raise RuntimeError('participant joined another channel')
                self.event('load_member_joined',client=client,channel_index=group['index'])
            return group
        return parallel_setup(enroll,groups)

    def restart_load_relay(self, relay):
        started=time.monotonic()
        receipt={'relay':relay,'started_unix':time.time(),'ready':False}
        self.result['relay_restart_readiness']=receipt
        self.event('load_relay_restart_started',relay=relay)
        process=next(p for role,p in reversed(self.children) if role.startswith(f'relay{relay}') and p.poll() is None)
        self.stop(process)
        process=self.relay(relay,self.root/'bootstrap')
        spawned=time.monotonic()
        receipt['stop_and_spawn_seconds']=spawned-started
        self.event('load_relay_restarted',relay=relay)
        ready=wait_restarted_relay(process,relay,spawned+30)
        receipt.update(ready=True,control_ready_seconds=ready-spawned,
                       observed_downtime_seconds=ready-started,ready_unix=time.time())
        self.event('load_relay_control_ready',**receipt)
        return receipt

    def relay_load(self):
        clients=list(range(64))
        setup_started=time.monotonic();setup=setup_started+2400
        self.rpc_deadline=setup
        for i in clients:
            self.start_client(i)
            # Stagger unauthenticated TLS admission without relaxing its
            # original eight-connections-per-source protection.
            time.sleep(.2)
        def ready(i):
            until(lambda i=i:self.request(i,'snapshot'),setup,'64-client IPC startup')
            until(lambda i=i:self.readiness(i),setup,'64-client protected readiness')
        parallel_setup(ready,clients)
        for i in (0,1): self.files(i,'configure',quota_bytes=str(32*1024*1024),retention_days=7)
        groups=self.prepare_load_channels(setup)
        self.expected_subscriptions=4
        def subscribed(i):
            expected=2+2*len(groups) if i==0 else 4
            until(lambda i=i,expected=expected:self.readiness(i,expected),setup,'64-client subscription readiness')
        parallel_setup(subscribed,clients)
        self.result['load_setup']={'clients':64,'workers':LOAD_SETUP_WORKERS,
                                  'seconds':time.monotonic()-setup_started}
        duration=self.spec['config']['load_seconds']
        began=time.monotonic(); end=began+duration; began_unix=time.time()
        self.rpc_deadline=end+120
        records=[]; attempts=0; refused=0; pending=[]; restart=None
        transfer=self.start_file(groups[0]['channel'],self.spec['config']['file_bytes'],'release-payload')
        self.event('relay_load_started',clients=64,contributions=32,seconds=duration,file=transfer,
            channels=len(groups),channel_members=[len(g['members']) for g in groups])
        next_send=began; sender=0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as sends, \
                concurrent.futures.ThreadPoolExecutor(max_workers=16) as observations, \
                concurrent.futures.ThreadPoolExecutor(max_workers=1) as recovery:
            while time.monotonic()<end or pending:
                now=time.monotonic()
                if restart is not None and restart.done():
                    restart.result()  # Surface exit, invalid receipt or bounded readiness failure.
                if now>end+120:
                    self.result['relay_load_incomplete']=incomplete_load_commands(pending,now)
                    raise TimeoutError('load delivery did not drain within its bound')
                if now<end and now>=next_send:
                    if len(pending)+len(groups)>64:
                        self.result['relay_load_incomplete']=incomplete_load_commands(pending,now)
                        raise RuntimeError('load command backlog exceeded its bound')
                    def send(item):
                        try:
                            self.submit(item['sender'],item['token'],item['channel'])
                            return True
                        except RuntimeError as error:
                            if not any(word in str(error).lower() for word in ('overloaded','full','refused','backing off')): raise
                            return False
                    for group in groups:
                        item={**group,'sender':group['members'][sender%len(group['members'])],
                            'token':f'@all relay-load:{sender}:{uuid.uuid4().hex}',
                            'started':time.monotonic(),'seen':{}}
                        item['submission']=sends.submit(send,item)
                        pending.append(item)
                    attempts+=len(groups)
                    sender+=1; next_send=began+sender*10
                checks=[]
                for item in list(pending):
                    submission=item['submission']
                    if submission.done() and not submission.result():
                        refused+=1;pending.remove(item);continue
                    for i in item['members']:
                        if i in item['seen']: continue
                        checks.append((item,observations.submit(observe_load_recipient,item,i,self.history)))
                for item,check in checks:
                    client,row=check.result()
                    if row is not None: item['seen'][client]=row
                for item in list(pending):
                    if not item['submission'].done():continue
                    if not item['submission'].result():
                        refused+=1;pending.remove(item);continue
                    sent=self.history(item['sender'],item['channel'],item['token'])
                    item['sender_delivery']=sent[0].get('delivery') if len(sent)==1 else 'absent'
                    message=validated_load_delivery(item['seen'],item['members'],item['sender'],sent)
                    if message:
                        record={'sender':item['sender'],'channel_index':item['index'],
                            'recipients':len(item['members'])-1,'id':message['id'],
                            'recipient_seconds':[row['seconds'] for i,row in item['seen'].items() if i!=item['sender']],
                            'authenticated_ack_seconds':time.monotonic()-item['started']}
                        records.append(record); pending.remove(item)
                        self.event('load_command_delivered',**record)
                if restart is None and now-began>=duration/2:
                    restart=recovery.submit(self.restart_load_relay,0)
                if restart is not None and restart.done():restart.result()
                self.sample(restarting=(0,) if restart is not None and not restart.done() else ())
                for i in clients:
                    process=next(p for role,p in reversed(self.children) if role.startswith(f'client{i}-') or role==f'client{i}')
                    if process.poll() is not None: raise RuntimeError('load client exited')
                time.sleep(.2)
            if restart is None:raise RuntimeError('load relay restart was not exercised')
            restart.result()
        completed_unix=time.time();observed_seconds=time.monotonic()-began
        self.finish_file(transfer,120)
        latencies=sorted(value for record in records for value in record['recipient_seconds'])
        if not latencies: raise RuntimeError('no commands delivered')
        p95=latencies[min(len(latencies)-1,(len(latencies)*95+99)//100-1)]
        carried=sum(json.loads((self.root/f'c{i+2}/contribution.json').read_text())['transferred_bytes'] for i in range(32))
        data_accepted,forwarding_accepted,relay_refusals=relay_load_counts(
            self.root.glob('r*/metrics.jsonl*'),began_unix,completed_unix)
        relay_fraction=relay_refusals/max(1,data_accepted+forwarding_accepted+relay_refusals)
        self.result['relay_load']={'clients':64,'seconds':duration,'commands':len(records),'attempts':attempts,
            'started_unix':began_unix,'completed_unix':completed_unix,'observed_seconds':observed_seconds,
            'topology':self.spec['config']['load_topology'],'channels':len(groups),
            'channel_members':[len(g['members']) for g in groups],'recipient_deliveries_per_round':63,
            'application_refusals':refused,'application_refusal_fraction':refused/max(1,attempts),'recipient_p95_seconds':p95,
            'authenticated_commands':records,'file':transfer,'relay_restart':True,'contribution_transferred_bytes':carried,
            'relay_data_accepted':data_accepted,'relay_forwarding_accepted':forwarding_accepted,'relay_refusals':relay_refusals,'relay_refusal_fraction':relay_fraction,
            'qualified_duration':duration>=1800,'provider_policy_qualified':False}
        if refused/max(1,attempts)>=.01 or relay_fraction>=.01 or p95>=5 or carried==0:
            raise RuntimeError('relay load gate failed: refusal, latency or contribution forwarding')
        self.result['boundary']['after']=self.inventory(); self.assert_topology(self.result['boundary']['after'])
        self.result['completed']=True

    def exercise(self):
        try:
            return self.exercise_with_renewal()
        finally:
            if renewal:=getattr(self,'routing_renewal',None):renewal.close()

    def exercise_with_renewal(self):
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
        if self.spec['config'].get('mode') == 'relay-load':
            return self.relay_load()
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
        self.join_invitation(1,until(lambda:self.remote_invitation(channel),setup_deadline,'remote invite'),'receiver')
        self.expected_subscriptions=4
        for i in (0,1): until(lambda i=i:self.readiness(i),setup_deadline,'contact AND channel, both classes')
        self.rpc_deadline=None
        self.chat(channel,'turnover:warmup')
        if self.spec['config'].get('mode')=='relay-preflight':
            transfer=self.start_file(channel,5235248,'release-preflight')
            # Client1 owns its inbox on relay3. Exercise terminal lease loss,
            # including route repair, before the full traffic campaign.
            process=next(p for role,p in reversed(self.children) if role.startswith('relay3') and p.poll() is None)
            self.stop(process);self.relay(3,self.root/'bootstrap')
            self.chat(channel,'turnover:preflight-restarted',120)
            self.finish_file(transfer,180)
            self.routing_renewal.check()
            self.result['relay_preflight']={'clients':2,'file':transfer,'relay_restart':True,
                'restarted_relay':3,'terminal_inbox_restart':True,
                'chat_acknowledged':self.chat_count,'credential_rollover_qualified':False}
            self.result['boundary']['after']=self.inventory();self.assert_topology(self.result['boundary']['after'])
            self.result['completed']=True
            return
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
    parser.add_argument('--mode',choices=('smoke','file-recovery','archive-failure','credential-expiry','carrier-cap','entry-loss','multi-party','relay-load','relay-preflight'),default='credential-expiry')
    parser.add_argument('--load-seconds',type=int,default=1800,help='relay-load only; shorter runs cannot qualify the release')
    parser.add_argument('--load-single-channel',action='store_true',help='retain the separate 64-member admission diagnostic')
    parser.add_argument('--load-relay-circuits',type=int,
                        help='relay-load only; default 2048 matches the live operator fleet')
    parser.add_argument('--load-relay-connections',type=int,
                        help='relay-load only; default 4096 matches the live operator fleet')
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
    if args.mode=='relay-load' and (not args.fixture_host or not 60<=args.load_seconds<=1800): parser.error('relay-load requires the fixture host and 60..1800 seconds')
    if args.mode=='relay-preflight' and not args.fixture_host:parser.error('relay-preflight requires the fixture host')
    if args.mode != 'relay-load' and (args.load_single_channel or args.load_relay_circuits is not None or args.load_relay_connections is not None):
        parser.error('relay capacity overrides require relay-load')
    if args.mode == 'relay-load':
        args.load_relay_circuits = 2048 if args.load_relay_circuits is None else args.load_relay_circuits
        args.load_relay_connections = 4096 if args.load_relay_connections is None else args.load_relay_connections
        try:
            load_relay_capacity({'mode':args.mode, 'relay_circuits':args.load_relay_circuits,
                                 'relay_connections':args.load_relay_connections})
        except ValueError as error:
            parser.error(str(error))
    if args.file_bytes is None: args.file_bytes=5235248 if args.mode in ('relay-load','relay-preflight') else 16*1024*1024 if args.release_check else 256*1024*1024
    if args.file_completion_seconds is None: args.file_completion_seconds=180 if args.release_check else 1200
    maximum=1024*1024*1024 if args.mode=='file-recovery' else 256*1024*1024
    minimum=5235248 if args.mode in ('relay-load','relay-preflight') else 16*1024*1024 if args.release_check else 64*1024*1024
    if not minimum<=args.file_bytes<=maximum: parser.error('file size exceeds the selected fixture bounds')
    if not 60<=args.file_completion_seconds<=3600: parser.error('file completion budget must be between 60 and 3600 seconds')
    if args.mode!='file-recovery' and args.file_completion_seconds!=1200: parser.error('custom file completion budget is only for file-recovery')
    root=args.out.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    build=base.build_binding(args.build.resolve())
    before=links();tool_hash=sha256(Path(__file__));helper_hash=sha256(HELPER)
    config={'release_check':args.release_check,'mode':args.mode,'lifecycle_diagnostics':args.mode in ('carrier-cap','entry-loss'),'expiries':args.expiries,'file_bytes':args.file_bytes,'file_completion_seconds':args.file_completion_seconds,'production_credential_seconds':3600,'production_carrier_cap_seconds':1800,'recovery_seconds':300}
    if args.mode=='relay-load': config.update(load_seconds=args.load_seconds,relay_schedule='gc2',
        load_topology='single-channel' if args.load_single_channel else 'fleet-four-channels',
        relay_circuits=args.load_relay_circuits,relay_connections=args.load_relay_connections)
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
    if args.mode=='relay-load': timeout=2400+args.load_seconds+300
    if args.mode=='relay-preflight':timeout=300
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
    if args.mode=='relay-load':
        evidence.update({name:digest for name,digest in worker.get('evidence',{}).items()
                         if name.startswith('r') and '/metrics.jsonl' in name
                         or name.startswith('c') and name.endswith('/contribution.json')})
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
