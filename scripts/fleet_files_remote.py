#!/usr/bin/env python3
"""Isolated host operations for fleet-files.py; never targets an installed relay.

Only a new run directory, named units, namespace, veth and exact firewall rules
belong to this worker. The private test volume is retained after cleanup.
"""
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time

IPS = ['95.217.200.179', '95.217.118.227', '135.181.6.55', '157.90.35.101',
       '78.46.219.146', '65.109.79.94', '116.202.84.152', '49.12.172.59']
PORT, CONTROL = 24433, 29443
GIB = 1024 ** 3

def run(argv, *, input=None, check=True, timeout=60):
    p = subprocess.run([str(a) for a in argv], input=input, text=True,
                       capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{argv[0]} failed ({p.returncode}): {p.stderr[-2000:]}')
    return p

def private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(data)

def preflight():
    folders = {p: shutil.disk_usage(p).free for p in ('/var/tmp', '/home')}
    return {'hostname': socket.gethostname(), 'machine': os.uname().machine, 'unix_seconds': time.time(),
            'free_bytes': folders, 'cpus': os.cpu_count(),
            'memory_available_kib': int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))),
            'ports': run(['ss', '-H', '-ltn', 'sport', '=', f':{PORT}']).stdout + run(['ss', '-H', '-ltn', 'sport', '=', f':{CONTROL}']).stdout,
            'forwarding': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
            'production': run(['systemctl', 'show', 'ghost-relay.service', '--property=ActiveState,MainPID,NRestarts,ExecMainStartTimestampMonotonic']).stdout,
            'tools': {name: shutil.which(name) for name in ('python3','ip','iptables','tc','systemd-run','mkfs.ext4','mount','umount')}}

class Host:
    def __init__(self, request):
        self.id = request['run_id']
        if not re.fullmatch(r'ff-[a-z0-9-]{1,32}', self.id):
            raise ValueError('invalid run id')
        self.index = request['host']
        if type(self.index) is not int or not 0 <= self.index < 8:
            raise ValueError('invalid host index')
        base = request['base']
        if base not in ('/var/tmp', '/home'):
            raise ValueError('invalid test base')
        self.root = Path(base) / 'gcoms-fleet' / self.id
        if self.root.is_symlink() or self.root.resolve() != self.root:
            raise ValueError('test root must not contain symlinks')
        self.data = self.root / 'data'
        self.tag = 'gff' + hashlib.sha256(self.id.encode()).hexdigest()[:8]
        self.ns = self.tag
        self.veth = self.tag + 'h'
        self.chain = self.tag.upper()
        self.ip = IPS[self.index]
        self.gateway = f'10.253.249.{4*self.index+1}'
        self.inside = f'10.253.249.{4*self.index+2}'
        self.net = f'10.253.249.{4*self.index}/30'
        self.request = request

    def owned(self):
        marker = json.loads((self.root / 'owner.json').read_text())
        if marker != {'run_id': self.id, 'host': self.index}:
            raise ValueError('run ownership mismatch')

    def unit(self, name):
        if not re.fullmatch(r'(relay|anchor|client[01]|probe[01]|probe-[a-f0-9]{12})', name):
            raise ValueError('invalid unit role')
        return f'{self.tag}-{name}.service'

    def nsrun(self, argv, **kwargs):
        return run(['ip', 'netns', 'exec', self.ns, *argv], **kwargs)

    def service(self, name, argv, *, env=(), pipe=None, timeout=90):
        command = ['systemd-run', '--quiet', f'--unit={self.unit(name)}', f'--slice={self.tag}.slice',
                   '-p', f'NetworkNamespacePath=/run/netns/{self.ns}',
                   '-p', 'RuntimeMaxSec=7h', '-p', 'TimeoutStopSec=20',
                   '-p', 'KillMode=control-group', '-p', 'UMask=0077',
                   '-p', 'NoNewPrivileges=yes', '-p', 'CapabilityBoundingSet=',
                   '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=read-only',
                   '-p', f'ReadWritePaths={self.data}',
                   '-p', f'WorkingDirectory={self.data}', '-p', 'TasksMax=256',
                   '-p', 'Environment=TOKIO_WORKER_THREADS=2']
        for value in env:
            command += ['-p', f'Environment={value}']
        if pipe is not None:
            command += ['--pipe', '--wait', '--collect']
        else:
            command += ['-p', f'StandardOutput=append:{self.data}/{name}.log',
                        '-p', f'StandardError=append:{self.data}/{name}.log']
        return run([*command, *argv], input=pipe, timeout=timeout)

    def rules(self):
        # Exact inverses are persisted before insertion; cleanup never flushes
        # a shared table/chain or changes a host's forwarding policy.
        c, v, address = self.chain, self.veth, self.inside
        specs = [('filter', ['-N', c]), ('nat', ['-N', c])]
        specs += [('filter', ['-A', c, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])]
        # A colocated client may learn this relay through peer discovery. Keep
        # its public test address reachable inside this namespace as well.
        specs += [('filter', ['-A', c, '-s', address, '-d', address, '-p', 'tcp', '--dport', str(PORT), '-j', 'ACCEPT']),
                  ('nat', ['-A', c, '-s', address, '-p', 'tcp', '-j', 'DNAT', '--to-destination', f'{address}:{PORT}'])]
        for peer in IPS:
            specs += [('filter', ['-A', c, '-s', address, '-d', peer, '-p', 'tcp', '--dport', str(PORT), '-j', 'ACCEPT']),
                      ('filter', ['-A', c, '-s', peer, '-d', address, '-p', 'tcp', '--dport', str(PORT), '-j', 'ACCEPT']),
                      ('nat', ['-A', c, '-s', peer, '-p', 'tcp', '-j', 'DNAT', '--to-destination', f'{address}:{PORT}'])]
        specs += [('filter', ['-A', c, '-j', 'DROP']),
                  ('filter', ['-I', 'FORWARD', '1', '-i', v, '-j', c]),
                  ('filter', ['-I', 'FORWARD', '1', '-o', v, '-j', c]),
                  ('nat', ['-I', 'PREROUTING', '1', '-d', self.ip, '-p', 'tcp', '--dport', str(PORT), '-j', c]),
                  ('nat', ['-I', 'POSTROUTING', '1', '-s', address, '-j', 'SNAT', '--to-source', self.ip])]
        return specs

    def install(self):
        self.owned()
        info = preflight()
        if info['ports'] or info['forwarding'] != '1':
            raise RuntimeError('ports occupied or host forwarding disabled')
        if shutil.disk_usage(self.root).free < 40*GIB:
            raise RuntimeError('test filesystem needs 40 GiB free')
        if run(['ip', '-4', 'route', 'show', self.net]).stdout.strip():
            raise RuntimeError('test subnet is already routed')
        if (self.root / 'rules.json').exists():
            raise RuntimeError('installation already attempted; use retained cleanup record')
        if self.ns in run(['ip','netns','list']).stdout.split() or run(['ip','link','show',self.veth],check=False).returncode==0:
            raise RuntimeError('test namespace or interface already exists')
        for table in ('filter','nat'):
            if run(['iptables','-w','-t',table,'-S',self.chain],check=False).returncode==0:
                raise RuntimeError('test firewall chain already exists')
        private(self.root / 'before.json', json.dumps(info))
        self.data.mkdir(mode=0o700)
        image = self.root / 'data.ext4'
        with image.open('xb') as stream:
            stream.truncate(32*GIB)
        run(['mkfs.ext4', '-q', '-m', '0', image], timeout=120)
        run(['mount', '-o', 'loop,nodev,nosuid', image, self.data])
        os.chmod(self.data, 0o700)
        private(self.root / 'rules.json', json.dumps(self.rules()))
        run(['ip', 'netns', 'add', self.ns])
        run(['ip', 'link', 'add', self.veth, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', self.ns])
        run(['ip', 'addr', 'add', self.gateway+'/30', 'dev', self.veth])
        run(['ip', 'link', 'set', self.veth, 'up'])
        self.nsrun(['ip', 'link', 'set', 'lo', 'up'])
        self.nsrun(['ip', 'addr', 'add', self.inside+'/30', 'dev', 'eth0'])
        self.nsrun(['ip', 'link', 'set', 'eth0', 'up'])
        self.nsrun(['ip', 'route', 'add', 'default', 'via', self.gateway])
        # Shape only the namespace's egress; no production interface qdisc changes.
        self.nsrun(['tc','qdisc','add','dev','eth0','root','handle','1:','htb','default','10'])
        self.nsrun(['tc','class','add','dev','eth0','parent','1:','classid','1:10','htb','rate','50mbit','ceil','50mbit'])
        self.nsrun(['tc','qdisc','add','dev','eth0','parent','1:10','handle','10:','netem','delay','0ms'])
        for table, spec in self.rules():
            run(['iptables', '-w', '-t', table, *spec])
        self.service('anchor', ['/usr/bin/sleep', '7h'])
        run(['systemctl', 'set-property', '--runtime', f'{self.tag}.slice', 'CPUQuota=200%', 'MemoryMax=4G', 'TasksMax=768'])
        private(self.data / 'passphrase', secrets.token_hex(32)+'\n')
        (self.root / 'heartbeat').touch()
        watch = dict(self.request, action='watchdog')
        private(self.root / 'watchdog.json', json.dumps(watch))
        run(['systemd-run', '--quiet', f'--unit={self.tag}-watchdog', '-p', 'RuntimeMaxSec=8h',
             '/usr/bin/python3', self.root/'worker.py', '--watchdog', self.root/'watchdog.json'])
        return {'installed': True, 'tag': self.tag, 'namespace': self.ns}

    def relay(self, bootstrap=False):
        self.owned()
        node = self.root / 'bin/gcnode'
        key = self.data / 'relay.key'
        if not key.exists():
            run([node, 'keygen', '--out', key, '--pass-file', self.data/'passphrase'])
        env = []
        if (self.data / 'bootstrap').exists():
            env.append(f'GC_ROUTING_BOOTSTRAP={self.data}/bootstrap')
        self.service('relay', [node, 'serve', '--keystore', key, '--pass-file', self.data/'passphrase',
                              '--port', str(PORT), '--advertise-addr', f'{self.ip}:{PORT}',
                              '--control-port', str(CONTROL), '--metrics', self.data/'relay-metrics.jsonl'], env=env)
        return {'started': True}

    def control(self, command):
        self.owned()
        if command not in ('routing_bootstrap', 'provision_client_relay', 'status'):
            raise ValueError('unsupported control command')
        script = '''import json,socket,sys
s=socket.create_connection(('127.0.0.1',29443),timeout=30)
s.sendall((json.dumps({'id':1,'cmd':sys.argv[1]})+'\\n').encode())
f=s.makefile('rb')
for _ in range(64):
 line=f.readline(1048577)
 if len(line)>1048576: raise RuntimeError('control response too large')
 v=json.loads(line)
 if v.get('id')==1:
  print(json.dumps(v)); break
else: raise RuntimeError('control response missing')
'''
        value = json.loads(self.nsrun(['python3', '-c', script, command], timeout=45).stdout)
        if not value.get('ok'):
            raise RuntimeError('test relay control failed: '+str(value.get('error')))
        return value['data']

    def bootstrap(self, encoded):
        self.owned()
        raw = base64.b64decode(encoded, validate=True)
        if not 6 < len(raw) < 16384 or raw[:5] != b'GCRB\x01':
            raise ValueError('invalid private bootstrap')
        fd = os.open(self.data/'bootstrap', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(raw)
        run(['systemctl', 'stop', self.unit('relay')])
        run(['systemctl', 'reset-failed', self.unit('relay')], check=False)
        return self.relay()

    def client(self, slot, relay_card=None):
        self.owned()
        if slot not in (0, 1): raise ValueError('invalid client slot')
        folder = self.data / f'c{slot}'
        folder.mkdir(mode=0o700, exist_ok=True)
        (folder / 'fixtures').mkdir(mode=0o700, exist_ok=True)
        if relay_card is not None:
            private(folder/'relay.card', relay_card+'\n')
        if not (folder/'relay.card').exists(): raise ValueError('missing isolated relay card')
        client_bootstrap=folder/'bootstrap'
        if not client_bootstrap.exists():
            bundle=(self.data/'bootstrap').read_bytes()
            if bundle[:6]!=b'GCRB\x01\x08' or len(bundle)!=990: raise ValueError('expected eight isolated introductions')
            records=[bundle[6+i*123:6+(i+1)*123] for i in range(8) if i!=self.index]
            client_bootstrap.write_bytes(b'GCRB\x01'+bytes([7])+b''.join(records))
        command = [self.root/'bin/gchat', 'daemon', '--home', folder,
                   '--store', folder/'profile', '--chat-archive', folder/'archive',
                   '--socket', folder/'protocol.sock', '--passphrase-file', self.data/'passphrase',
                   '--listen', f'127.0.0.1:{24440+slot}', '--advertise', f'127.0.0.1:{24440+slot}',
                   '--inbox-relay-file', folder/'relay.card', '--no-network-bootstrap']
        if not (folder/'profile').exists(): command.append('--create')
        self.service(f'client{slot}', command, env=[f'GC_ROUTING_BOOTSTRAP={client_bootstrap}', 'GCHAT_FILE_DIAGNOSTICS=1', f'GCHAT_PROTOCOL_METRICS={self.data}/client{slot}-metrics.jsonl'])
        probe_unit = self.unit(f'probe{slot}')
        if run(['systemctl','is-active',probe_unit], check=False).returncode:
            sock = folder/'probe.sock'
            if sock.exists(): sock.unlink()
            self.service(f'probe{slot}', [self.root/'bin/fleet_probe','--serve',folder/'protocol.chat',folder/'fixtures',sock])
        return {'started': True}

    def probe(self, slot, payload):
        self.owned()
        if slot not in (0, 1): raise ValueError('invalid client slot')
        folder = self.data/f'c{slot}'
        raw = json.dumps(payload).encode()
        if len(raw)>65536: raise ValueError('probe input too large')
        def read_exact(stream, n):
            output = b''
            while len(output)<n:
                block = stream.recv(n-len(output))
                if not block: raise RuntimeError('probe closed early')
                output += block
            return output
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(950)
            stream.connect(str(folder/'probe.sock'))
            stream.sendall(struct.pack('!I',len(raw))+raw)
            size = struct.unpack('!I',read_exact(stream,4))[0]
            if size>1024*1024: raise RuntimeError('probe output too large')
            return json.loads(read_exact(stream,size))

    def status(self):
        self.owned()
        (self.root/'heartbeat').touch()
        units = {}
        for role in ('relay','client0','client1'):
            raw = run(['systemctl','show',self.unit(role), '--property=ActiveState,MainPID,NRestarts,MemoryCurrent,MemoryPeak,CPUUsageNSec,ControlGroup']).stdout
            item = dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
            cg = Path('/sys/fs/cgroup') / item.get('ControlGroup','').lstrip('/')
            item['cpu_stat'] = (cg/'cpu.stat').read_text() if (cg/'cpu.stat').exists() else ''
            pid = item.get('MainPID','0')
            item['fds'] = len(list(Path(f'/proc/{pid}/fd').iterdir())) if pid != '0' and Path(f'/proc/{pid}/fd').exists() else 0
            units[role] = item
        return {'units': units, 'production': preflight()['production'],
                'disk_free': shutil.disk_usage(self.data).free, 'host_free': shutil.disk_usage(self.root).free,
                'link': json.loads(self.nsrun(['ip','-s','-j','link','show','eth0']).stdout),
                'qdisc': json.loads(self.nsrun(['tc','-s','-j','qdisc','show','dev','eth0']).stdout),
                'connections': self.nsrun(['ss','-H','-tn']).stdout,
                'slice': run(['systemctl','show',f'{self.tag}.slice','--property=MemoryCurrent,CPUUsageNSec,ControlGroup']).stdout}

    def reachability(self):
        self.owned()
        script = '''import json,socket,sys
from concurrent.futures import ThreadPoolExecutor
def probe(ip):
 try:
  with socket.create_connection((ip,24433),timeout=3): return True
 except OSError: return False
peers=json.loads(sys.argv[1])
with ThreadPoolExecutor(max_workers=8) as pool:
 print(json.dumps(dict(zip(peers,pool.map(probe,peers)))))
'''
        return json.loads(self.nsrun(['python3','-c',script,json.dumps(IPS)]).stdout)

    def fault(self, kind, slot=0):
        self.owned()
        if slot not in (0,1): raise ValueError('invalid slot')
        if kind in ('kill_client','stop_client','stop_relay'):
            role = 'relay' if kind == 'stop_relay' else f'client{slot}'
            if kind == 'kill_client':
                run(['systemctl','kill','--signal=SIGKILL',self.unit(role)])
            run(['systemctl','stop',self.unit(role)], check=False)
            run(['systemctl','reset-failed',self.unit(role)], check=False)
        elif kind in ('netem','clear_netem','blackhole'):
            args = {'netem': ['delay','100ms','20ms','loss','1%'],
                    'clear_netem': ['delay','0ms'], 'blackhole':['loss','100%']}[kind]
            self.nsrun(['tc','qdisc','replace','dev','eth0','parent','1:10','handle','10:','netem',*args])
        else:
            raise ValueError('unknown fault')
        return {'injected': kind}

    def cache_fault(self, slot, ident, mode):
        self.owned()
        if slot not in (0,1) or not re.fullmatch('[a-f0-9]{32}',ident): raise ValueError('invalid cache selection')
        if run(['systemctl','show',self.unit(f'client{slot}'),'--property=MainPID','--value']).stdout.strip()!='0':
            raise ValueError('cache faults require a stopped client')
        folder=self.data/f'c{slot}'/'archive.pieces'/ident
        if not folder.is_dir() or folder.resolve()!=folder: raise ValueError('missing owned share directory')
        pieces=sorted(folder.glob('*.piece'),key=lambda p:int(p.stem))
        if mode in ('even','odd'):
            for p in pieces:
                if int(p.stem)%2 != (0 if mode=='even' else 1): p.unlink()
        elif mode=='corrupt':
            if not pieces: raise ValueError('no retained piece to corrupt')
            with pieces[0].open('r+b') as stream:
                stream.seek(-1,2); value=stream.read(1); stream.seek(-1,2)
                stream.write(bytes([value[0]^1])); stream.flush(); os.fsync(stream.fileno())
        elif mode=='full':
            backup=self.data/f'fault-{slot}-{ident}'
            shutil.copytree(folder,backup)
            marker=self.root/f'mount-{slot}-{ident}.json'
            private(marker,json.dumps({'path':str(folder)}))
            run(['mount','-t','tmpfs','-o','size=512k,mode=700,nodev,nosuid','fleet-cache-fault',folder])
            for p in backup.iterdir(): shutil.copy2(p,folder/p.name)
        elif mode=='restore':
            marker=self.root/f'mount-{slot}-{ident}.json'
            if not marker.exists(): raise ValueError('no owned fault mount')
            if os.path.ismount(folder): run(['umount',folder])
            marker.unlink()
        else: raise ValueError('unsupported cache fault')
        return {'mode':mode,'pieces':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.glob('*.piece')}}

    def mutate_fixture(self, slot, name):
        self.owned()
        if slot not in (0,1) or not re.fullmatch('[a-zA-Z0-9_.-]{1,128}',name) or name in ('.','..'):
            raise ValueError('invalid fixture name')
        path=self.data/f'c{slot}'/'fixtures'/name
        with path.open('r+b') as stream:
            first=stream.read(1)
            if not first: raise ValueError('empty fixture')
            stream.seek(0); stream.write(bytes([first[0]^1])); stream.flush(); os.fsync(stream.fileno())
        return {'mutated':True}

    def cleanup(self):
        self.owned()
        result = {'errors': []}
        units = run(['systemctl', 'list-units', '--all', '--plain', '--no-legend', f'{self.tag}-*.service']).stdout
        for line in units.splitlines():
            unit = line.split()[0]
            if unit.startswith(self.tag+'-') and unit.endswith('.service') and 'watchdog' not in unit:
                p = run(['systemctl','stop',unit], check=False)
                if p.returncode: result['errors'].append('stop '+unit)
                run(['systemctl','reset-failed',unit],check=False)
        run(['systemctl','stop',f'{self.tag}.slice'],check=False)
        run(['systemctl','revert',f'{self.tag}.slice'],check=False)
        rules = self.root/'rules.json'
        if rules.exists():
            for table, original in reversed(json.loads(rules.read_text())):
                spec = list(original)
                if spec[0] == '-N': spec[0] = '-X'
                else:
                    if spec[0] == '-I': del spec[2]
                    spec[0] = '-D'
                # Already-removed entries are harmless on repeat cleanup.
                run(['iptables','-w','-t',table,*spec], check=False)
        if rules.exists():
            run(['ip','link','del',self.veth], check=False)
            run(['ip','netns','del',self.ns], check=False)
        for marker in self.root.glob('mount-*.json'):
            path=Path(json.loads(marker.read_text())['path'])
            if not path.is_relative_to(self.data): raise ValueError('invalid owned mount')
            if os.path.ismount(path): run(['umount',path])
        if os.path.ismount(self.data):
            p = run(['umount',self.data], check=False)
            if p.returncode: result['errors'].append('unmount')
        result['production'] = preflight()['production']
        result['namespace_removed'] = self.ns not in run(['ip','netns','list']).stdout.split()
        result['veth_removed'] = run(['ip','link','show',self.veth], check=False).returncode != 0
        result['rules_removed'] = all(self.chain not in run(['iptables','-w','-t',table,'-S']).stdout for table in ('filter','nat'))
        result['volume_unmounted'] = not os.path.ismount(self.data)
        (self.root/'cleanup.json').write_text(json.dumps(result, indent=2)+'\n')
        return result

    def traffic(self):
        self.owned()
        counts=Counter()
        path=self.data/'relay-metrics.jsonl'
        if path.exists():
            with path.open() as stream:
                for line in stream:
                    if len(line)>65536: raise ValueError('oversized metric')
                    value=json.loads(line); counts[value['event']]+=1
        diagnostics={}
        for slot in (0,1):
            path=self.data/f'client{slot}.log'
            samples=[]
            if path.exists():
                with path.open() as stream:
                    for line in stream:
                        if len(line)>65536 or not line.startswith('{'): continue
                        try: value=json.loads(line)
                        except ValueError: continue
                        if value.get('event')=='file_diagnostics': samples.append(value)
            diagnostics[str(slot)]={'samples':len(samples),
                'max_buffered_bytes':max((v['buffered_bytes'] for v in samples),default=0),
                'max_pending_pulls':max((v['pending_pulls'] for v in samples),default=0),
                'max_pending_actions':max((v['pending_actions'] for v in samples),default=0)}
            # Counters restart with the daemon. Sum each process's maximum;
            # summing every observation would count the same retry repeatedly.
            processes={}
            for sample in samples:
                counters=processes.setdefault(sample['pid'],{})
                for key in ('verified_pieces','rejected_pieces','retries','received_blocks',
                            'received_bytes','send_failures','send_timeouts'):
                    counters[key]=max(counters.get(key,0),sample.get(key,0))
            diagnostics[str(slot)]['counters']={key:sum(p.get(key,0) for p in processes.values())
                for key in ('verified_pieces','rejected_pieces','retries','received_blocks',
                            'received_bytes','send_failures','send_timeouts')}
        return {'events':dict(counts),'file_diagnostics':diagnostics}

def main(request):
    if request['action'] == 'preflight': return preflight()
    host = Host(request)
    action = request['action']
    if action == 'install': return host.install()
    if action == 'relay': return host.relay()
    if action == 'control': return host.control(request['command'])
    if action == 'bootstrap': return host.bootstrap(request['bundle'])
    if action == 'client': return host.client(request['slot'], request.get('relay_card'))
    if action == 'probe': return host.probe(request['slot'], request['payload'])
    if action == 'status': return host.status()
    if action == 'reachability': return host.reachability()
    if action == 'traffic': return host.traffic()
    if action == 'fault': return host.fault(request['kind'], request.get('slot',0))
    if action == 'cache_fault': return host.cache_fault(request['slot'],request['id'],request['mode'])
    if action == 'mutate_fixture': return host.mutate_fixture(request['slot'],request['name'])
    if action == 'cleanup': return host.cleanup()
    if action == 'watchdog':
        host.owned()
        deadline = time.monotonic()+7*3600
        while time.monotonic() < deadline:
            time.sleep(15)
            if (host.root/'cleanup.json').exists(): return {'cleaned': True}
            if time.time()-(host.root/'heartbeat').stat().st_mtime > 300: break
        return host.cleanup()
    raise ValueError('unknown host action')

if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) == 3 and sys.argv[1] == '--watchdog':
            request = json.loads(Path(sys.argv[2]).read_text())
        else:
            payload = sys.stdin.buffer.read(2*1024*1024+1)
            if len(payload)>2*1024*1024: raise ValueError('request too large')
            request = json.loads(payload)
        print(json.dumps({'ok': True, 'value': main(request)}))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        sys.exit(1)
