#!/usr/bin/env python3
"""Source-bound real-fleet file tests on isolated listeners (standard library only).

The default campaign is 16 clients / four hours. Canary runs never qualify it.
Raw evidence is private; failures and missing observations are never filled in.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
from fleet_files_remote import IPS, GIB

ROOT = Path(__file__).resolve().parents[1]
CAPACITY_CASES = ((4*1024*1024,600),(32*1024*1024,1200),
                  (256*1024*1024,3600),(GIB,14400))
REQUIRED_CASES = ['coverage', 'boundaries', 'unaccepted', 'pause_resume', 'receiver_restart',
                  'import_resume', 'source_change', 'relay_restart', 'path_outage', 'loss_delay',
                  'multisource_late_join', 'multisource_simultaneous', 'missing_source', 'corruption', 'disk_full',
                  'quota', 'membership_removal', 'pm_isolation', 'credential_renewal',
                  'archive_reopen', 'chat_mixed', 'large_files']

def atomic(path, value):
    temp = path.with_suffix(path.suffix+'.new')
    with temp.open('w') as stream:
        json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temp.replace(path)

def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def percentile(values, quantile):
    if not values: return None
    return sorted(values)[max(0, math.ceil(len(values)*quantile)-1)]

def analyze(manifest, events):
    """Derive verdicts from observations, never from requested runtime or size."""
    failures = [e for e in events if e['event'] in ('failure','budget_stop','unexpected_exit')]
    cases = {name: 'not_run' for name in REQUIRED_CASES}
    for e in events:
        if e['event'] == 'case': cases[e['name']] = e['result']
    transfers = {}
    for e in events:
        if 'transfer' in e:
            t = transfers.setdefault(e['transfer'], {'receivers': {}})
            if e['event'] == 'transfer': t.update(e)
            if e['event'] == 'accepted': t['receivers'][str(e['client'])] = {'accepted': e['elapsed']}
            if e['event'] == 'export_verified':
                receiver = t['receivers'].setdefault(str(e['client']), {})
                valid = 'accepted' in receiver and e['elapsed'] >= receiver['accepted'] and e.get('size') == t.get('size') and e.get('sha256') == t.get('sha256') and e.get('verified') is True
                receiver.update({'exported': e['elapsed'], 'valid': valid})
                if valid:
                    seconds=e['elapsed']-receiver['accepted']
                    receiver.update({'seconds':seconds,'goodput_bytes_per_second':t['size']/seconds if seconds>0 else None})
                if not valid: failures.append({'event':'failure','error':'export verification mismatch','transfer':e['transfer']})
    cancelled={(e['transfer'],str(e['client'])) for e in events if e['event']=='cancelled'}
    for key, t in transfers.items():
        required=set(map(str,t.get('expected_receivers',[]))) | set(t['receivers'])
        for recipient in required:
            if (key,str(recipient)) in cancelled: continue
            state = t['receivers'].get(str(recipient), {})
            if not state.get('valid'):
                failures.append({'event':'failure','error':'expected export missing','transfer':key,'client':recipient})
            elif t.get('size',0) <= 1024*1024 and state['exported']-state.get('accepted',state['exported']) > 300:
                failures.append({'event':'failure','error':'small file exceeded five minutes','transfer':key,'client':recipient})
            elif t.get('size',0) >= GIB and state['exported']-state['accepted'] > 14400:
                failures.append({'event':'failure','error':'1 GiB file exceeded four hours','transfer':key,'client':recipient})
    windows = {e['name']:e for e in events if e['event']=='window_end'}
    measured = windows.get('mixed',{}).get('duration',0)
    baseline = [e['seconds'] for e in events if e['event']=='chat_ack' and e['phase']=='baseline']
    mixed = [e['seconds'] for e in events if e['event']=='chat_ack' and e['phase']=='mixed' and not e.get('fault_window')]
    sent = {e['message'] for e in events if e['event']=='chat_sent'}
    acknowledged = {e['message'] for e in events if e['event']=='chat_ack'}
    if sent-acknowledged: failures.append({'event':'failure','error':'chat acknowledgments missing','count':len(sent-acknowledged)})
    b95, m95 = percentile(baseline,.95), percentile(mixed,.95)
    if b95 is not None and m95 is not None and (m95 > max(2*b95,b95+2) or max(mixed)>120):
        failures.append({'event':'failure','error':'mixed chat latency gate failed'})
    cleanup = {e['host']:e for e in events if e['event']=='cleanup'}
    clean = set(cleanup)==set(range(8)) and all(e.get('passed') for e in cleanup.values())
    isolated_removed = set(cleanup)==set(range(8)) and all(
        not e.get('errors') and all(e.get(key) is True for key in
            ('namespace_removed','veth_removed','rules_removed','volume_unmounted'))
        for e in cleanup.values())
    ready={e['client'] for e in events if e['event']=='client_ready'}
    traffic={e['host'] for e in events if e['event']=='relay_traffic' and e.get('events',{}).get('gchat_sub_attached',0)>0}
    protocol_ready = {e['client'] for e in events if e['event']=='client_ready' and qualified_transport(e.get('transport', {}))}
    observed_protocol = ready == protocol_ready and bool(ready)
    diagnostic_clients=set()
    for event in events:
        if event['event']=='relay_traffic':
            for slot, stats in event.get('file_diagnostics',{}).items():
                if stats['samples']>0: diagnostic_clients.add(event['host']*2+int(slot))
                if stats['max_buffered_bytes']>4*1024*1024 or stats['max_pending_pulls']>8 or stats['max_pending_actions']>128:
                    failures.append({'event':'failure','error':'file engine resource bound exceeded','host':event['host'],'slot':slot})
    large=[t for t in transfers.values() if t.get('label','').startswith('large-')]
    corpus=len([t for t in large if t.get('size')==GIB])==4 and len([t for t in large if t.get('size')==256*1024*1024])==4
    pairs={(t['sender']//2,int(client)//2) for t in transfers.values() if t.get('label','').startswith('coverage-') for client,receipt in t['receivers'].items() if receipt.get('valid')}
    covered=pairs=={(a,b) for a in range(8) for b in range(8) if a!=b}
    partial_cases=('pause_resume','receiver_restart','quota','relay_restart','path_outage','loss_delay')
    recovery_evidence={name:False for name in partial_cases}
    fault_evidence={name:False for name in (*partial_cases,'missing_source','multisource_late_join','multisource_simultaneous')}
    for e in events:
        t=transfers.get(e.get('transfer'),{})
        if e['event']=='fault_precondition' and e.get('name') in partial_cases:
            valid=t.get('label')==e['name'] and e.get('size')==t.get('size') and 0<e.get('verified_bytes',0)<t.get('size',0) and e.get('state') in ('downloading','waiting_for_peers')
            receipt=t.get('receivers',{}).get(str(e.get('client')), {})
            fault_evidence[e['name']] |= valid and receipt.get('valid',False) and receipt['accepted']<=e['elapsed']<receipt['exported']
        if e['event']=='recovery_progress' and e.get('name') in partial_cases:
            receipt=t.get('receivers',{}).get(str(e.get('client')), {})
            before,after=e.get('verified_before',-1),e.get('verified_after',-1)
            started,seconds=e.get('started_elapsed',-1),e.get('seconds',-1)
            progressed=0<=before<after<=t.get('size',0)
            completed=e.get('state')=='complete' and before==after==t.get('size',-1)
            precondition=any(p['event']=='fault_precondition' and p.get('name')==e['name']
                and p.get('transfer')==e.get('transfer') and p.get('client')==e.get('client')
                and p.get('elapsed',float('inf'))<=started for p in events)
            recovery_evidence[e['name']] |= (t.get('label')==e['name'] and precondition
                and receipt.get('valid',False) and (progressed or completed)
                and e.get('state') in ('downloading','waiting_for_peers','complete')
                and 0<=seconds<=300 and abs(e['elapsed']-started-seconds)<=0.02
                and receipt['accepted']<=started<=e['elapsed']<=receipt['exported'])
        if e['event']=='source_unavailable':
            receipt=t.get('receivers',{}).get(str(e.get('client')), {})
            fault_evidence['missing_source'] |= t.get('label')=='missing-source' and e.get('stopped_before_acceptance') is True and e.get('verified_bytes')==0 and receipt.get('valid',False) and receipt['accepted']<=e['elapsed']<receipt['exported']
        if e['event']=='simultaneous_sources':
            receipt=t.get('receivers',{}).get(str(e.get('client')), {})
            fault_evidence['multisource_simultaneous'] |= (
                t.get('label')=='simultaneous' and e.get('verified_sources',0)>=2
                and e.get('both_enabled_before_acceptance') is True
                and receipt.get('valid',False) and receipt['exported']<=e['elapsed'])
    for ident,t in transfers.items():
        parts=[e for e in events if e['event']=='source_contribution' and e.get('transfer')==ident]
        if len(parts)!=2: continue
        first,second=parts
        receipt=t['receivers'].get(str(first.get('client')), {})
        fault_evidence['multisource_late_join'] |= (
            t.get('label')=='complementary' and first.get('client')==second.get('client')
            and first.get('source')!=second.get('source')
            and all(e.get('exclusive_source') is True for e in parts)
            and first.get('verified_before')==0
            and 0<first.get('verified_after',0)<t.get('size',0)
            and second.get('verified_before')==first['verified_after']
            and second.get('verified_after')==t.get('size') and receipt.get('valid',False)
            and receipt['accepted']<=first['elapsed']<receipt['exported']<=second['elapsed'])
    complete = manifest['phase']=='campaign' and measured>=14400 and windows.get('baseline',{}).get('duration',0)>=1800 and covered and ready==set(range(16)) and diagnostic_clients==set(range(16)) and traffic==set(range(8)) and corpus and all(v=='pass' for v in cases.values()) and all(fault_evidence.values()) and clean and b95 is not None and m95 is not None
    cross_host=any(t.get('sender') is not None and t['sender']//2!=int(client)//2 and receipt.get('valid') for t in transfers.values() for client,receipt in t['receivers'].items())
    complete = complete and observed_protocol
    complete = complete and all(recovery_evidence.values())
    reopened=any(e['event']=='canary_reopen' and e.get('verified') is True
                 and e.get('same_instance') is True and e.get('size')==65536
                 and transfers.get(e.get('transfer'),{}).get('size')==65536
                 and transfers.get(e.get('transfer'),{}).get('receivers',{}).get(str(e.get('client')),{}).get('valid')
                 and transfers[e['transfer']].get('sender',-1)//2 != e.get('client',-1)//2
                 and e.get('elapsed',-1)>=transfers[e['transfer']]['receivers'][str(e['client'])]['exported']
                 and e.get('sha256')==transfers.get(e.get('transfer'),{}).get('sha256')
                 for e in events)
    canary_ok=manifest['phase']=='canary' and len(ready)==2 and observed_protocol and cross_host and reopened and clean and not failures
    capacity_sizes={t.get('size') for t in transfers.values() if t.get('label','').startswith('capacity-')
                    and any(r.get('valid') for r in t['receivers'].values())}
    capacity_ok=(manifest['phase']=='capacity' and len(ready)==2 and observed_protocol and reopened
                 and capacity_sizes=={4*1024*1024,32*1024*1024,256*1024*1024,GIB}
                 and windows.get('baseline',{}).get('duration',0)>=300
                 and b95 is not None and m95 is not None and clean and not failures)
    coverage_ok=manifest['phase']=='coverage' and covered and ready==set(range(16)) and observed_protocol and cases['coverage']==cases['boundaries']=='pass' and clean and not failures
    timings={}
    for transfer in transfers.values():
        for receipt in transfer['receivers'].values():
            if receipt.get('valid'):
                timings.setdefault(str(transfer['size']),[]).append(receipt)
    file_metrics={size:{'exports':len(receipts),
        'completion_p50_seconds':percentile([r['seconds'] for r in receipts],.5),
        'completion_p95_seconds':percentile([r['seconds'] for r in receipts],.95),
        'goodput_p50_bytes_per_second':percentile([r['goodput_bytes_per_second'] for r in receipts if r['goodput_bytes_per_second'] is not None],.5)}
        for size,receipts in timings.items()}
    return {'schema':1,'verdict':'pass' if complete and not failures else ('fail' if failures else 'incomplete'),
            'phase_passed':(complete and not failures) or canary_ok or capacity_ok or coverage_ok,
            'scope':f"isolated {manifest.get('protocol','GC')} test listeners; {len(ready)} Linux clients observed",
            'observed_clients':len(ready),
            'protocol_ready_clients':len(protocol_ready),
            'canary_reopen_verified':reopened,
            'capacity_sizes_verified':sorted(capacity_sizes),
            'largest_offered_file_bytes':max((t.get('size',0) for t in transfers.values()),default=0),
            'largest_verified_file_bytes':max(map(int,timings),default=0),
            'observed_mixed_seconds':measured,'verified_directed_host_pairs':len(pairs),'cases':cases,'failures':failures,
            'fault_evidence':fault_evidence,
            'recovery_progress_evidence':recovery_evidence,
            'transfers':transfers,'file_metrics_by_size':file_metrics,
            'file_diagnostics_by_host':{str(e['host']):e.get('file_diagnostics',{}) for e in events if e['event']=='relay_traffic'},
            'chat':{'sent':len(sent),'acknowledged':len(acknowledged),
            'baseline_p95_seconds':b95,'mixed_p95_seconds':m95},'cleanup_complete':clean,
            'isolated_resources_removed':isolated_removed}

def qualified_transport(status):
    return (status.get('protocol') == 'gchat' and status.get('profile_id') == 22
            and status.get('bootstrap_version') == 2 and status.get('routing_ready') is True
            and status.get('ready_entries', 0) > 0 and status.get('usable_terminal_routes', 0) > 0
            and status.get('interactive_subscriptions', 0) >= 2 and status.get('bulk_subscriptions', 0) >= 2)

class Campaign:
    def __init__(self, directory, manifest):
        self.directory = directory
        self.manifest = manifest
        self.run_id = manifest['run_id']
        self.lock = threading.RLock()
        self.start = time.monotonic()
        self.events = []
        self.stop = threading.Event()
        self.monitor_stop = threading.Event()
        self.fault_until = 0.0
        self.channels = {}
        self.clients = []
        self.nodes = []
        self.jobs = ThreadPoolExecutor(max_workers=32)
        self.chat_jobs = ThreadPoolExecutor(max_workers=16)
        self.monitor = None
        self.transfer_number = 0
        self.chat_sequence = 0
        self.chat_pending = {}
        self.chat_seen = set()
        self.expected_units = set()
        self.intended_stops = set()
        self.admission_locks = [threading.Lock() for _ in range(16)]

    def event(self, event, **facts):
        value = {'event':event,'elapsed':round(time.monotonic()-self.start,3),**facts}
        with self.lock:
            self.events.append(value)
            with (self.directory/'events.jsonl').open('a') as stream:
                stream.write(json.dumps(value,sort_keys=True)+'\n'); stream.flush()
        if event in ('stage','case','failure','budget_stop'):
            print(json.dumps(value),flush=True)
        return value

    def ssh(self, host, argv, payload=None, timeout=1000):
        command = ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                   '-o','ConnectTimeout=10','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',
                   '-o','ControlMaster=auto','-o','ControlPersist=60','-o','ControlPath=ssh-%C',
                   'root@'+IPS[host],shlex.join([str(a) for a in argv])]
        p = subprocess.run(command, input=payload, text=True, capture_output=True,
                           cwd=self.directory, timeout=timeout)
        if p.returncode: raise RuntimeError(f'host {host+1}: command failed ({p.returncode}): {p.stderr[-1000:]} {p.stdout[-1000:]}')
        return p.stdout

    def remaining(self, deadline, label):
        if self.stop.is_set(): raise RuntimeError(label+': campaign stopped')
        seconds=deadline-time.monotonic()
        if seconds<=0: raise RuntimeError(label+': deadline exceeded')
        return seconds

    def remote(self, host, action, *, deadline=None, **values):
        node = self.nodes[host]
        role = None
        if action == 'fault' and values.get('kind') in ('stop_client','kill_client','stop_relay'):
            role = 'relay' if values['kind']=='stop_relay' else f'client{values.get("slot",0)}'
        elif action == 'bootstrap':
            role = 'relay'
        if role:
            with self.lock: self.intended_stops.add((host,role))
        request = {'run_id':self.run_id,'host':host,'base':node['base'],'action':action,**values}
        timeout=1000 if deadline is None else min(1000,self.remaining(deadline,action))
        result = json.loads(self.ssh(host,['python3',node['root']+'/worker.py'],json.dumps(request),timeout=timeout))
        if deadline is not None and time.monotonic()>deadline:
            raise RuntimeError(action+': deadline exceeded')
        if not result.get('ok'): raise RuntimeError(f'host {host+1}: {result.get("error")}')
        if action in ('client','relay','bootstrap'):
            role = f'client{values["slot"]}' if action=='client' else 'relay'
            with self.lock: self.intended_stops.discard((host,role))
        return result['value']

    def probe(self, client, payload, *, deadline=None):
        result = self.remote(client//2,'probe',slot=client%2,payload=payload,deadline=deadline)
        if not result.get('ok'): raise RuntimeError(f'client {client}: {result.get("error")}')
        return result['value']

    def request(self, client, kind, *, deadline=None, **values):
        return self.probe(client,{'action':'request','request':{'kind':kind,**values}},deadline=deadline)

    def files(self, client, action='list', *, deadline=None, **values):
        if action=='list': values.setdefault('conversation',None)
        return self.request(client,'files',request={'action':action,**values},deadline=deadline)['snapshot']

    def submit(self, client, text, conversation=None):
        started=time.monotonic()
        command=text.split()[0] if text.startswith('/') else 'message'
        try:
            result=self.request(client,'submit',operation_id=uuid.uuid4().hex,conversation=conversation,text=text)
            self.event('operation_completed',client=client,command=command,seconds=time.monotonic()-started)
            return result
        except Exception as exc:
            self.event('operation_failed',client=client,command=command,seconds=time.monotonic()-started,error=str(exc))
            raise

    def parallel(self, calls):
        futures = [self.jobs.submit(call) for call in calls]
        return [future.result() for future in futures]

    def until(self, function, timeout, label, interval=2, *, deadline=None):
        deadline = min(time.monotonic()+timeout, float('inf') if deadline is None else deadline)
        last = None
        while time.monotonic()<deadline and not self.stop.is_set():
            try:
                value = function()
                if time.monotonic()>deadline: raise RuntimeError('response arrived after deadline')
                if value: return value
            except Exception as exc: last = str(exc)
            self.stop.wait(min(interval,max(0,deadline-time.monotonic())))
        reason = 'campaign stopped' if self.stop.is_set() else 'deadline exceeded'
        raise RuntimeError(f'{label}: {reason}'+(f' ({last})' if last else ''))

    def prepare(self, build):
        report = json.loads((build/'build.json').read_text())
        if not report.get('passed'): raise ValueError('build report did not pass')
        for name, item in report['artifacts'].items():
            if sha(build/'bin'/name)!=item['sha256']: raise ValueError('artifact binding mismatch')
        self.event('stage',name='preflight')
        worker = (ROOT/'scripts/fleet_files_remote.py').read_text()
        # Execute the same worker's read-only preflight before selecting storage.
        receipt = self.parallel([lambda i=i: json.loads(self.ssh(i,['python3','-c',worker],json.dumps({'action':'preflight'})))['value'] for i in range(8)])
        for i, info in enumerate(receipt):
            if info['machine']!='x86_64' or info['ports'] or info['memory_available_kib']<5*1024*1024 or not all(info['tools'].values()):
                raise RuntimeError(f'host {i+1} preflight failed')
            base = max(info['free_bytes'],key=info['free_bytes'].get)
            if info['free_bytes'][base]<40*GIB: raise RuntimeError(f'host {i+1} lacks disk headroom')
            root = base+'/gcoms-fleet/'+self.run_id
            self.nodes.append({'host':i,'base':base,'root':root,'before':info})
        self.manifest.update({'hosts':self.nodes,'build':report,'worker_sha256':sha(ROOT/'scripts/fleet_files_remote.py')})
        atomic(self.directory/'manifest.json',self.manifest)
        def upload(i):
            node = self.nodes[i]
            code = "import os,pathlib,json,sys; os.umask(0o077); p=pathlib.Path(sys.argv[1]); p.parent.mkdir(exist_ok=True); p.mkdir(); (p/'bin').mkdir(); (p/'owner.json').write_text(json.dumps({'run_id':sys.argv[2],'host':int(sys.argv[3])}))"
            self.ssh(i,['python3','-c',code,node['root'],self.run_id,str(i)])
            # stdin file copy avoids remote shell expansion and preserves private mode.
            for source, target in [(ROOT/'scripts/fleet_files_remote.py','worker.py'),*[(build/'bin'/n,'bin/'+n) for n in report['artifacts']]]:
                command = ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ControlMaster=auto','-o','ControlPersist=60','-o','ControlPath=ssh-%C','root@'+IPS[i],
                           shlex.join(['python3','-c',"import sys,os; p=sys.argv[1]; f=open(p,'xb'); f.write(sys.stdin.buffer.read()); f.close(); os.chmod(p,0o700)",node['root']+'/'+target])]
                with source.open('rb') as stream:
                    subprocess.run(command,stdin=stream,cwd=self.directory,check=True,timeout=180,capture_output=True)
            check = self.ssh(i,['sha256sum',*[node['root']+'/bin/'+n for n in report['artifacts']]])
            if [line.split()[0] for line in check.splitlines()] != [v['sha256'] for v in report['artifacts'].values()]:
                raise RuntimeError('remote executable verification failed')
            return self.remote(i,'install')
        self.parallel([lambda i=i:upload(i) for i in range(8)])
        self.monitor = threading.Thread(target=self.monitor_hosts,daemon=True)
        self.monitor.start()
        self.parallel([lambda i=i:self.remote(i,'relay') for i in range(8)])
        exports = self.parallel([lambda i=i:self.until(lambda:self.remote(i,'control',command='routing_bootstrap'),90,'relay startup') for i in range(8)])
        records=[]
        for item in exports:
            raw=base64.urlsafe_b64decode(item['routing_bundle_b64']+'===')
            if raw[:5]!=b'GCRB\x02' or raw[5]<1 or len(raw)!=6+raw[5]*155: raise RuntimeError('bad GChat relay bootstrap')
            records.append(raw[6:161])
        bundle=base64.b64encode(b'GCRB\x02'+bytes([8])+b''.join(records)).decode()
        self.manifest['bootstrap_expiry_unix']=max(int.from_bytes(r[147:155],'big') for r in records)
        atomic(self.directory/'manifest.json',self.manifest)
        self.parallel([lambda i=i:self.remote(i,'bootstrap',bundle=bundle) for i in range(8)])
        self.parallel([lambda i=i:self.until(lambda:self.remote(i,'control',command='status'),90,'relay restart readiness') for i in range(8)])
        paths=self.parallel([lambda i=i:self.remote(i,'reachability') for i in range(8)])
        self.event('tcp_coverage',paths=paths)
        if not all(all(path.values()) and len(path)==8 for path in paths):
            raise RuntimeError('isolated relay TCP mesh is incomplete')
        with self.lock: self.expected_units.update((i,'relay') for i in range(8))
        self.event('stage',name='relays_ready',count=8)

    def monitor_hosts(self):
        missing = {}
        errors = {}
        with ThreadPoolExecutor(max_workers=8) as executor:
            while not self.monitor_stop.is_set():
                futures={executor.submit(self.remote,i,'status'):i for i in range(8)}
                total=0
                for f in as_completed(futures):
                    i=futures[f]
                    try:
                        status=f.result()
                        errors[i]=0
                        self.event('host_sample',host=i,**status)
                        total+=status['link'][0]['stats64']['tx']['bytes']
                        if status['host_free']<5*GIB or status['disk_free']<GIB:
                            self.event('budget_stop',host=i,error='disk headroom exhausted'); self.stop.set()
                        if status['production'] != self.nodes[i]['before']['production']:
                            self.event('failure',host=i,error='production service state changed'); self.stop.set()
                        with self.lock:
                            expected=self.expected_units-self.intended_stops
                        for role,unit in status['units'].items():
                            key=(i,role)
                            absent=key in expected and unit.get('ActiveState') not in ('active','activating')
                            missing[key]=missing.get(key,0)+1 if absent else 0
                            if missing[key]==3:
                                self.event('unexpected_exit',host=i,role=role,state=unit.get('ActiveState'))
                                self.stop.set()
                    except Exception as exc:
                        self.event('monitor_error',host=i,error=str(exc))
                        errors[i]=errors.get(i,0)+1
                        if errors[i]==3:
                            self.event('budget_stop',host=i,error='host monitoring unavailable'); self.stop.set()
                if total>200*GIB:
                    self.event('budget_stop',error='aggregate wire budget exceeded'); self.stop.set()
                self.monitor_stop.wait(15)

    def start_client(self, client):
        relay=(client//2+1+3*(client%2))%8
        card=self.until(lambda:self.remote(relay,'control',command='provision_client_relay'),120,'provision client')['private_card_b64']
        self.remote(client//2,'client',slot=client%2,relay_card=card)
        self.until(lambda:self.request(client,'snapshot'),120,'client startup')
        self.files(client,'configure',quota_bytes=str(8*GIB),retention_days=7)
        self.clients.append(client)
        with self.lock: self.expected_units.add((client//2,f'client{client%2}'))
        status = self.wait_transport(client)
        self.event('client_ready',client=client,inbox_host=relay,transport=status)

    def wait_transport(self, client, *, deadline=None):
        started = time.time()
        deadline=min(time.monotonic()+120,float('inf') if deadline is None else deadline)
        def observation():
            latest = self.remote(client//2, 'traffic',deadline=deadline)['file_diagnostics'][str(client%2)].get('latest') or {}
            status = (latest.get('protocol') or {}).get('transport') or {}
            if latest.get('unix_seconds', 0) < started or not qualified_transport(status):
                raise RuntimeError('client has no fresh usable GChat route and both-class subscriptions')
            return status
        return self.until(observation, 120, 'GChat transport readiness',deadline=deadline)

    def channel(self, title, members):
        owner=members[0]
        channel=self.submit(owner,f'/create #{title} c{owner}')['conversation']
        for member in members[1:]:
            invite=self.invitation(owner,channel)
            self.submit(member,f'/join {invite} c{member}')
        self.channels[title]={'id':channel,'members':members}
        return channel

    def invitation(self, owner, channel):
        def reachable():
            output=self.submit(owner,'/invite',channel)['output']
            return output['link'] if not output.get('localOnly',True) else None
        return self.until(reachable,180,'reachable invitation',interval=10)

    def prepare_transfer(self, sender, receivers, size, channel, label):
        with self.lock:
            self.transfer_number+=1; number=self.transfer_number
        ident=hashlib.sha256(f'{self.run_id}:{number}'.encode()).hexdigest()[:32]
        name=f'{label}-{number}.bin'
        started=time.monotonic()
        expected=self.probe(sender,{'action':'generate','name':name,'size':size,'seed':number})
        self.probe(sender,{'action':'import','id':ident,'conversation':channel,'name':name})
        self.event('transfer',transfer=ident,sender=sender,expected_receivers=receivers,size=size,sha256=expected['sha256'],label=label,import_seconds=time.monotonic()-started)
        return {'id':ident,'sender':sender,'receivers':receivers,'size':size,'sha256':expected['sha256'],'name':name,'channel':channel}

    def offer(self, transfer, receiver):
        ident=transfer['id']
        def offered():
            return next((f for f in self.files(receiver)['files'] if f['id']==ident),None)
        info=self.until(offered,180,'file offer')
        if info['state']!='offered' or info['verified_bytes']!='0': raise RuntimeError('offer downloaded without acceptance')
        return info

    def activate(self, transfer, receiver, action='accept', *, deadline=None):
        # Serialize local admission on each receiver, including fault resumes.
        # Network completion never holds this lock. Fault recovery includes
        # admission in the caller's restoration deadline; initial admission
        # retains its separate fifteen-minute allowance.
        started=time.monotonic(); deadline=min(started+900,float('inf') if deadline is None else deadline)
        lock=self.admission_locks[receiver]
        if not lock.acquire(timeout=self.remaining(deadline,'file admission lock')):
            raise RuntimeError('file admission lock deadline')
        try:
            def slot():
                active=[f for f in self.files(receiver,deadline=deadline)['files']
                        if f['id']!=transfer['id'] and f['state'] in ('downloading','waiting_for_peers')]
                return len(active)<2
            self.until(slot,self.remaining(deadline,'file admission slot'),'file admission slot',deadline=deadline)
            self.files(receiver,action,id=transfer['id'],deadline=deadline)
            self.event('admission',transfer=transfer['id'],client=receiver,action=action,
                       seconds=time.monotonic()-started)
            if action=='accept': self.event('accepted',transfer=transfer['id'],client=receiver)
        finally: lock.release()

    def accept(self, transfer, receiver):
        self.offer(transfer,receiver)
        self.activate(transfer,receiver)

    def finish_transfer(self, transfer, receiver, deadline):
        last=0
        while time.monotonic()<deadline and not self.stop.is_set():
            try:
                info=next(f for f in self.files(receiver)['files'] if f['id']==transfer['id'])
                current=int(info['verified_bytes'])
                if current<last: raise RuntimeError('verified progress regressed')
                if current!=last:
                    self.event('progress',transfer=transfer['id'],client=receiver,verified_bytes=current,state=info['state']); last=current
                if info['state']=='complete':
                    result=self.probe(receiver,{'action':'export','id':transfer['id'],'name':'received-'+transfer['name'],'size':transfer['size'],'sha256':transfer['sha256']})
                    self.event('repair_verified' if transfer.get('audit') else 'export_verified',transfer=transfer['id'],client=receiver,**result)
                    return
                if info['state'] in ('failed','cancelled'): raise RuntimeError('unexpected terminal file state: '+str(info))
            except Exception as exc:
                if time.monotonic()>self.fault_until: raise
                self.event('expected_fault_observation',client=receiver,error=str(exc))
            self.stop.wait(5)
        if self.stop.is_set():
            raise RuntimeError(f'transfer {transfer["id"]}: campaign stopped')
        raise RuntimeError(f'transfer {transfer["id"]} did not complete by deadline')

    def transfer(self, sender, receiver, size, channel, label, timeout=300):
        transfer=self.prepare_transfer(sender,[receiver],size,channel,label)
        self.accept(transfer,receiver)
        self.finish_transfer(transfer,receiver,time.monotonic()+timeout)
        return transfer

    def case(self, name, function):
        try:
            value=function()
            self.event('case',name=name,result='pass')
            return value
        except Exception as exc:
            self.event('case',name=name,result='fail',error=str(exc))
            self.event('failure',case=name,error=str(exc))
            raise

    def chat_tick(self, phase, send=False):
        if send:
            for title, item in list(self.channels.items()):
                if not title.startswith('load'): continue
                members=item['members']
                for position, client in enumerate(members):
                    recipient=members[(position+1)%len(members)]
                    self.chat_sequence+=1
                    token=f'fleet:{self.run_id}:{self.chat_sequence}:{client}:{recipient}'
                    body=(token+' '+'x'*128)[:128]
                    self.chat_pending[token]={'client':client,'receiver':recipient,'channel':item['id'],'started':time.monotonic(),'phase':phase,'echoed':False,'body':body,'submitted':False,'operation':uuid.uuid4().hex}
                    self.event('chat_sent',message=token,client=client,receiver=recipient,phase=phase)
        def submit_pending(pending):
            if not pending['submitted']:
                try:
                    self.request(pending['client'],'submit',operation_id=pending['operation'],conversation=pending['channel'],text=pending['body'])
                    pending['submitted']=True
                except Exception as exc:
                    if time.monotonic()>self.fault_until: raise
                    self.event('expected_fault_observation',client=pending['client'],error=str(exc))
        for future in [self.chat_jobs.submit(submit_pending,p) for p in self.chat_pending.values() if not p['submitted']]:
            future.result()
        polls=[]
        for title,item in list(self.channels.items()):
            if not title.startswith('load'): continue
            for client in item['members']:
                polls.append((client,item))
        def poll(client,item):
                try:
                    page=self.request(client,'history',conversation=item['id'],before=None,limit=200)['page']
                    for message in page['messages']:
                        body=message['body']
                        token=body.split(' ')[0]
                        if token.startswith('ack:'):
                            pending=self.chat_pending.get(token[4:])
                            if pending and pending['client']==client and token not in self.chat_seen:
                                self.chat_seen.add(token)
                                self.event('chat_ack',message=token[4:],phase=pending['phase'],seconds=time.monotonic()-pending['started'],fault_window=time.monotonic()<self.fault_until)
                        else:
                            pending=self.chat_pending.get(token)
                            if pending and pending['receiver']==client and not pending['echoed']:
                                self.submit(client,'ack:'+token,item['id']); pending['echoed']=True
                except Exception as exc:
                    if time.monotonic()>self.fault_until: raise
                    self.event('expected_fault_observation',client=client,error=str(exc))
        for future in [self.chat_jobs.submit(poll,client,item) for client,item in polls]:
            future.result()

    def chat_window(self, name, seconds, callback=None):
        start=time.monotonic(); next_send=start
        self.event('stage',name=name,duration_seconds=seconds)
        while time.monotonic()-start<seconds and not self.stop.is_set():
            now=time.monotonic()
            self.chat_tick(name,send=now>=next_send)
            if now>=next_send: next_send=now+30
            if callback: callback(now-start)
            self.stop.wait(2)
        duration=time.monotonic()-start
        self.event('window_end',name=name,duration=duration)

    def execute(self):
        self.event('stage',name='two_client_canary')
        for client in (0,8): self.start_client(client)
        channel=self.channel('fleet',[0,8])
        canary=self.transfer(0,8,65536,channel,'canary')
        before=self.request(8,'snapshot')['snapshot']['instance']['id']
        self.restart(8)
        after=self.request(8,'snapshot')['snapshot']['instance']['id']
        if before!=after: raise RuntimeError('canary reopen changed instance identity')
        result=self.probe(8,{'action':'export','id':canary['id'],'name':'reopened-'+canary['name'],
                             'size':canary['size'],'sha256':canary['sha256']})
        self.event('canary_reopen',transfer=canary['id'],client=8,same_instance=True,**result)
        if self.manifest['phase']=='canary': return
        if self.manifest['phase']=='capacity':
            self.capacity(channel)
            return
        for client in (2,4,6,10,12,14): self.start_client(client)
        for client in (1,3,5,7,9,11,13,15): self.start_client(client)
        for client in self.clients:
            if client in (0,8): continue
            invite=self.invitation(0,channel)
            self.submit(client,f'/join {invite} c{client}')
        self.channels['fleet']['members']=list(range(16))
        for group in range(4): self.channel(f'load{group}',list(range(group,16,4)))
        self.event('stage',name='sixteen_clients_ready',clients=16)
        self.case('coverage',lambda:self.coverage(channel))
        self.case('boundaries',lambda:self.boundaries(channel))
        if self.manifest['phase']=='coverage': return
        self.chat_window('baseline',1800)
        self.full_campaign(channel)

    def capacity(self, channel):
        self.channels['loadcapacity']={'id':channel,'members':[0,8]}
        self.chat_window('baseline',300)
        for size,timeout in CAPACITY_CASES:
            t=self.prepare_transfer(0,[8],size,channel,f'capacity-{size}')
            self.accept(t,8)
            start=time.monotonic(); deadline=start+timeout; next_send=start
            future=self.jobs.submit(self.finish_transfer,t,8,deadline)
            while not future.done() and not self.stop.is_set() and time.monotonic()<deadline:
                now=time.monotonic()
                self.chat_tick('mixed',send=now>=next_send)
                if now>=next_send: next_send=now+30
                self.stop.wait(2)
            future.result(timeout=120)
            self.event('capacity_complete',size=size,seconds=time.monotonic()-start)
        # Drain acknowledgments from the final file interval before cleanup.
        self.until(lambda:(self.chat_tick('mixed') or all('ack:'+key in self.chat_seen for key in self.chat_pending)),120,'capacity chat drain')

    def coverage(self, channel):
        for distance in range(1,8):
            self.parallel([lambda i=i:self.transfer(2*i,2*((i+distance)%8),65536,channel,f'coverage-{i}-{distance}') for i in range(8)])

    def boundaries(self, channel):
        for n in (0,1,1024,11263,11264,11265,262143,262144,262145,1048576):
            self.transfer(0,8,n,channel,f'boundary-{n}')

    def full_campaign(self, channel):
        self.large=[]
        for i in range(8):
            sender=i; receiver=i+8
            size=GIB if i<4 else 256*1024*1024
            self.large.append(self.prepare_transfer(sender,[receiver],size,channel,f'large-{i}'))
        for t in self.large: self.accept(t,t['receivers'][0])
        started=time.monotonic(); deadline=started+14400
        futures=[self.jobs.submit(self.finish_transfer,t,t['receivers'][0],deadline) for t in self.large]
        faults=self.jobs.submit(self.fault_suite,channel,started)
        small=[]; next_small=0
        def tick(elapsed):
            nonlocal next_small
            if elapsed>=next_small and elapsed<13500 and time.monotonic()>self.fault_until:
                round_number=int(elapsed//600)
                size=(1024,65536,1048576)[round_number%3]
                for group in range(4):
                    item=self.channels[f'load{group}']; members=item['members']
                    for i, client in enumerate(members):
                        small.append(self.jobs.submit(self.transfer,client,members[(i+1)%4],size,item['id'],f'small-{round_number}-{client}'))
                next_small=elapsed+600
            for future in list(small):
                if future.done():
                    small.remove(future)
                    try: future.result()
                    except Exception as exc: self.event('failure',case='small_files',error=str(exc))
        self.chat_window('mixed',14400,tick)
        self.stop.set()
        for future in futures+small:
            try: future.result(timeout=960)
            except Exception as exc: self.event('failure',case='large_files' if future in futures else 'small_files',error=str(exc))
        try: faults.result(timeout=960)
        except Exception as exc: self.event('failure',case='fault_suite',error=str(exc))
        if not any(e['event']=='budget_stop' for e in self.events):
            self.stop.clear()  # final local audit, no new transfer workload
            self.case('archive_reopen',self.archive_audit)
        all_exported={e.get('transfer') for e in self.events if e['event']=='export_verified'}
        self.event('case',name='large_files',result='pass' if all(t['id'] in all_exported for t in self.large) else 'fail')
        expiry=self.manifest['bootstrap_expiry_unix']-self.manifest['started_unix']
        after={e['client'] for e in self.events if e['event']=='export_verified' and e['elapsed']>expiry+300}
        self.event('case',name='credential_renewal',result='pass' if after==set(range(16)) else 'fail',clients_after_initial_expiry=sorted(after))
        self.event('case',name='chat_mixed',result='pass' if any(e['event']=='chat_ack' and e['phase']=='mixed' for e in self.events) else 'fail')

    def info(self, client, ident, *, deadline=None):
        return next(f for f in self.files(client,deadline=deadline)['files'] if f['id']==ident)

    def restart(self, client, kill=False, *, deadline=None):
        self.remote(client//2,'fault',kind='kill_client' if kill else 'stop_client',slot=client%2,deadline=deadline)
        self.remote(client//2,'client',slot=client%2,deadline=deadline)
        self.until(lambda:self.request(client,'snapshot',deadline=deadline),120,'retained client reopen',deadline=deadline)
        self.wait_transport(client,deadline=deadline)

    def expect_error(self, function, text=None):
        try: function()
        except Exception as exc:
            if text and text.lower() not in str(exc).lower(): raise
            return str(exc)
        raise RuntimeError('operation unexpectedly succeeded')

    def active_transfer(self, sender, receiver, label, channel=None):
        # Fresh data is required: the original large corpus can have completed
        # before the fault suite's 30-minute start.
        t=self.prepare_transfer(sender,[receiver],256*1024*1024,
                                channel or self.channels['fleet']['id'],label)
        self.accept(t,receiver)
        def partial():
            info=self.info(receiver,t['id'])
            current=int(info['verified_bytes'])
            return info if info['state'] in ('downloading','waiting_for_peers') and 0<current<t['size'] else None
        info=self.until(partial,300,'active partial transfer',interval=1)
        self.event('fault_precondition',name=label,transfer=t['id'],client=receiver,
                   verified_bytes=int(info['verified_bytes']),size=t['size'],state=info['state'])
        return t

    def pause_resume(self):
        client=8; t=self.active_transfer(0,client,'pause_resume')
        self.files(client,'pause',id=t['id'])
        first=self.info(client,t['id'])
        if first['state']!='paused' or not 0<int(first['verified_bytes'])<t['size']:
            raise RuntimeError('pause did not hold an incomplete transfer')
        self.stop.wait(10)
        if self.info(client,t['id'])['verified_bytes']!=first['verified_bytes']:
            raise RuntimeError('paused transfer advanced')
        started=time.monotonic()
        self.activate(t,client,'resume',deadline=started+300)
        self.finish_recovery(t,client,'pause_resume',started)

    def finish_recovery(self, transfer, receiver, name, started):
        # Progress must resume within five minutes of restoration. Completing
        # the fresh 256 MiB fixture uses the same budget as capacity qualification.
        deadline=started+300
        before=int(self.info(receiver,transfer['id'],deadline=deadline)['verified_bytes'])
        def progressed():
            info=self.info(receiver,transfer['id'],deadline=deadline)
            current=int(info['verified_bytes'])
            return info if current!=before or (info['state']=='complete' and current==transfer['size']) else None
        info=self.until(progressed,max(0,deadline-time.monotonic()),name+' recovery progress',deadline=deadline)
        observed=time.monotonic()
        if observed>started+300: raise RuntimeError(name+' recovery progress: deadline exceeded')
        if int(info['verified_bytes'])<before: raise RuntimeError('recovery lost verified pieces')
        self.event('recovery_progress',name=name,transfer=transfer['id'],client=receiver,
                   elapsed=round(observed-self.start,3),started_elapsed=started-self.start,seconds=observed-started,
                   verified_before=before,verified_after=int(info['verified_bytes']),state=info['state'])
        self.finish_transfer(transfer,receiver,started+dict(CAPACITY_CASES)[transfer['size']])

    def receiver_restart(self):
        client=9; t=self.active_transfer(1,client,'receiver_restart')
        before=int(self.info(client,t['id'])['verified_bytes'])
        started=time.monotonic()
        self.restart(client,kill=True,deadline=started+300)
        after=int(self.info(client,t['id'],deadline=started+300)['verified_bytes'])
        if after<before: raise RuntimeError('restart lost verified pieces')
        self.finish_recovery(t,client,'receiver_restart',started)

    def partial_import(self, label, client=7):
        ident=uuid.uuid4().hex; name=f'{label}-{ident}.bin'; channel=self.channels['fleet']['id']
        expected=self.probe(client,{'action':'generate','name':name,'size':786433,'seed':12345})
        self.probe(client,{'action':'partial_import','id':ident,'conversation':channel,'name':name})
        return client,ident,name,channel,expected

    def import_resume(self):
        client,ident,name,channel,expected=self.partial_import('resume')
        before=self.info(client,ident)['verified_bytes']
        self.restart(client,kill=True)
        if self.info(client,ident)['verified_bytes']!=before: raise RuntimeError('import progress lost')
        self.probe(client,{'action':'import','id':ident,'conversation':channel,'name':name})
        self.probe(client,{'action':'export','id':ident,'name':'export-'+name,**expected})

    def source_change(self):
        client,ident,name,channel,_=self.partial_import('changed')
        self.remote(client//2,'mutate_fixture',slot=client%2,name=name)
        self.expect_error(lambda:self.probe(client,{'action':'import','id':ident,'conversation':channel,'name':name}))
        self.files(client,'cancel',id=ident)

    def unaccepted(self, channel):
        t=self.prepare_transfer(2,[],1048576,channel,'unaccepted')
        self.until(lambda:any(f['id']==t['id'] for f in self.files(10)['files']),180,'unaccepted offer')
        self.stop.wait(30)
        info=self.info(10,t['id'])
        if info['state']!='offered' or info['verified_bytes']!='0': raise RuntimeError('unaccepted bytes downloaded')

    def relay_restart(self):
        t=self.active_transfer(7,15,'relay_restart')
        self.remote(3,'fault',kind='stop_relay'); self.stop.wait(60)
        started=time.monotonic()
        self.remote(3,'relay',deadline=started+300)
        self.until(lambda:self.remote(3,'control',command='status',deadline=started+300),120,'relay restart',deadline=started+300)
        # Client 15's assigned inbox is relay 3, so this proves recovery of an
        # affected receiver rather than an unrelated healthy pair.
        self.finish_recovery(t,15,'relay_restart',started)
        self.transfer(7,15,65536,self.channels['fleet']['id'],'after-relay-restart')

    def network_fault(self, kind, seconds):
        t=self.active_transfer(10,2,'path_outage' if kind=='blackhole' else 'loss_delay')
        try:
            self.remote(5,'fault',kind=kind)
            self.stop.wait(seconds)
        finally:
            started=time.monotonic()
            self.remote(5,'fault',kind='clear_netem',deadline=started+300)
        self.finish_recovery(t,2,'path_outage' if kind=='blackhole' else 'loss_delay',started)
        self.transfer(10,2,65536,self.channels['fleet']['id'],'after-'+kind)

    def multisource(self, simultaneous=False):
        label='simultaneous' if simultaneous else 'complementary'
        channel=self.channel('recovery-'+label,[4,0,8])
        t=self.prepare_transfer(0,[4,8,12],(32 if simultaneous else 4)*1024*1024,channel,label)
        for client in (4,8):
            self.accept(t,client); self.finish_transfer(t,client,time.monotonic()+900)
        self.remote(0,'fault',kind='stop_client',slot=0)
        try:
            retained=[]
            for client,mode in ((4,'even'),(8,'odd')):
                self.remote(client//2,'fault',kind='stop_client',slot=client%2)
                retained.append(self.remote(client//2,'cache_fault',slot=client%2,id=t['id'],mode=mode))
                self.remote(client//2,'client',slot=client%2)
                self.until(lambda client=client:self.request(client,'snapshot'),120,'seeder reopen')
                self.wait_transport(client)
            self.event('complementary_pieces',transfer=t['id'],retained=[list(x['pieces']) for x in retained])
            sets=[{int(name.removesuffix('.piece')) for name in row['pieces']} for row in retained]
            if sets[0]&sets[1] or sets[0]|sets[1]!=set(range(t['size']//262144)) or not all(sets):
                raise RuntimeError('seeds are not a complete complementary partition')
            for client in (4,8):
                if self.info(client,t['id'])['state']!='paused':
                    raise RuntimeError('pruned seed resumed before late join')
            invite=self.invitation(4,channel); self.submit(12,f'/join {invite} c12')
            if simultaneous:
                for client in (4,8): self.activate(t,client,'resume')
                self.accept(t,12)
                self.finish_transfer(t,12,time.monotonic()+900)
                count=int(self.info(12,t['id']).get('verified_sources',0))
                if count<2: raise RuntimeError('simultaneous run did not verify pieces from both sources')
                self.event('simultaneous_sources',transfer=t['id'],client=12,
                           verified_sources=count,both_enabled_before_acceptance=True)
                return
            self.accept(t,12)
            # Expose each disjoint inventory alone. Neither seed can repair
            # itself from the other before contributing to the late receiver.
            self.activate(t,4,'resume')
            expected=len(sets[0])*262144
            self.until(lambda:int(self.info(12,t['id'])['verified_bytes'])==expected,
                       900,'first complementary source contribution',interval=1)
            self.files(4,'pause',id=t['id'])
            if self.info(4,t['id'])['state']!='paused': raise RuntimeError('first seed was not held')
            self.event('source_contribution',transfer=t['id'],client=12,source=4,
                       verified_before=0,verified_after=expected,exclusive_source=True)
            self.activate(t,8,'resume')
            self.finish_transfer(t,12,time.monotonic()+900)
            self.event('source_contribution',transfer=t['id'],client=12,source=8,
                       verified_before=expected,verified_after=t['size'],exclusive_source=True)
        finally:
            self.remote(0,'client',slot=0)

    def missing_source(self):
        channel=self.channels['fleet']['id']
        t=self.prepare_transfer(3,[11],4*1024*1024,channel,'missing-source')
        self.offer(t,11)
        self.remote(1,'fault',kind='stop_client',slot=1)
        try:
            self.accept(t,11)
            self.until(lambda:self.info(11,t['id'])['state']=='waiting_for_peers',300,'no source waiting state')
            self.stop.wait(30)
            info=self.info(11,t['id'])
            if info['state'] not in ('downloading','waiting_for_peers') or info['verified_bytes']!='0':
                raise RuntimeError('unavailable source produced file progress')
            self.event('source_unavailable',transfer=t['id'],client=11,verified_bytes=0,
                       stopped_before_acceptance=True)
        finally: self.remote(1,'client',slot=1)
        self.finish_transfer(t,11,time.monotonic()+900)

    def corruption(self):
        t=self.transfer(6,14,1048576,self.channels['fleet']['id'],'corruption')
        self.remote(7,'fault',kind='stop_client',slot=0)
        self.remote(7,'cache_fault',slot=0,id=t['id'],mode='corrupt')
        self.remote(7,'client',slot=0)
        self.until(lambda:self.request(14,'snapshot'),120,'corrupt cache reopen')
        info=self.info(14,t['id'])
        if int(info['verified_bytes'])>=t['size']: raise RuntimeError('corrupt bytes trusted after reopen')
        if info['state']=='paused': self.activate(t,14,'resume')
        self.finish_transfer(dict(t,name='repaired-'+t['name'],audit=True),14,time.monotonic()+900)

    def disk_full(self):
        client,ident,name,channel,expected=self.partial_import('disk-full',client=15)
        self.remote(7,'fault',kind='stop_client',slot=1)
        self.remote(7,'cache_fault',slot=1,id=ident,mode='full')
        try:
            self.remote(7,'client',slot=1)
            self.until(lambda:self.request(client,'snapshot'),120,'bounded cache reopen')
            self.expect_error(lambda:self.probe(client,{'action':'import','id':ident,'conversation':channel,'name':name}),'space')
            self.request(client,'snapshot')
        finally:
            self.remote(7,'fault',kind='stop_client',slot=1)
            self.remote(7,'cache_fault',slot=1,id=ident,mode='restore')
            self.remote(7,'client',slot=1)
        self.until(lambda:self.request(client,'snapshot'),120,'cache repair reopen')
        if int(self.info(client,ident)['verified_bytes'])<262144: raise RuntimeError('disk failure lost good piece')
        self.probe(client,{'action':'import','id':ident,'conversation':channel,'name':name})
        self.probe(client,{'action':'export','id':ident,'name':'export-'+name,**expected})

    def quota(self):
        client=13; t=self.active_transfer(5,client,'quota')
        self.files(client,'pause',id=t['id'])
        before=self.info(client,t['id'])
        if before['state']!='paused' or not 0<int(before['verified_bytes'])<t['size']:
            raise RuntimeError('quota test requires retained incomplete data')
        try:
            self.files(client,'configure',quota_bytes=str(1024*1024),retention_days=7)
            self.expect_error(lambda:self.files(client,'prepare',id=uuid.uuid4().hex,conversation=self.channels['fleet']['id'],name='quota.bin',size_bytes=str(2*1024*1024)))
            after=self.info(client,t['id'])
            if int(after['verified_bytes'])<int(before['verified_bytes']): raise RuntimeError('quota evicted active data')
        finally:
            started=time.monotonic()
            self.files(client,'configure',quota_bytes=str(8*GIB),retention_days=7,deadline=started+300)
        self.activate(t,client,'resume',deadline=started+300)
        self.finish_recovery(t,client,'quota',started)

    def membership(self):
        channel=self.channel('revocation',[1,5,9])
        t=self.active_transfer(1,5,'membership_removal',channel)
        self.submit(1,'/kick c5',channel)
        self.until(lambda:self.info(5,t['id'])['state']=='paused',180,'revoked download pause')
        before=self.info(5,t['id'])['verified_bytes']
        self.stop.wait(30)
        if self.info(5,t['id'])['verified_bytes']!=before: raise RuntimeError('revoked transfer advanced')
        self.expect_error(lambda:self.files(5,'resume',id=t['id']))
        self.files(5,'cancel',id=t['id'])
        if self.info(5,t['id'])['state']!='cancelled': raise RuntimeError('cancellation did not persist')
        self.event('cancelled',transfer=t['id'],client=5,reason='membership withdrawal scenario')

    def pm(self):
        channel=self.channels['fleet']['id']
        pm=self.submit(1,'/query c9',channel)['conversation']
        t=self.transfer(1,9,65536,pm,'private')
        if any(f['id']==t['id'] for f in self.files(5)['files']): raise RuntimeError('PM descriptor escaped scope')
        self.expect_error(lambda:self.files(5,'accept',id=t['id']))

    def fault_suite(self, channel, start):
        if self.stop.wait(max(0,start+1800-time.monotonic())): return
        cases=[('unaccepted',lambda:self.unaccepted(channel)),('pause_resume',self.pause_resume),
               ('receiver_restart',self.receiver_restart),('import_resume',self.import_resume),
               ('source_change',self.source_change),('relay_restart',self.relay_restart),
               ('path_outage',lambda:self.network_fault('blackhole',60)),
               ('loss_delay',lambda:self.network_fault('netem',900)),
               ('multisource_late_join',self.multisource),
               ('multisource_simultaneous',lambda:self.multisource(simultaneous=True)),
               ('missing_source',self.missing_source),
               ('corruption',self.corruption),('disk_full',self.disk_full),('quota',self.quota),
               ('membership_removal',self.membership),('pm_isolation',self.pm)]
        for name, operation in cases:
            if self.stop.is_set(): break
            self.fault_until=time.monotonic()+1800
            self.event('fault_start',name=name)
            try: self.case(name,operation)
            except Exception: pass  # retain failure and exercise independent scenarios
            finally:
                self.fault_until=time.monotonic()+300
                self.event('fault_end',name=name)
            if self.stop.wait(30): break

    def archive_audit(self):
        for client in self.clients:
            before=self.request(client,'snapshot')['snapshot']
            self.restart(client)
            after=self.request(client,'snapshot')['snapshot']
            if before['instance']['id']!=after['instance']['id']: raise RuntimeError('instance identity changed')
            for channel in self.channels.values():
                if client not in channel['members']: continue
                page=self.request(client,'history',conversation=channel['id'],before=None,limit=200)['page']
                if any('GCAPP1' in m['body'] or 'application/vnd.gcoms.pieces' in m['body'] for m in page['messages']):
                    raise RuntimeError('file protocol record persisted as chat')

    def cleanup(self):
        self.stop.set()
        self.monitor_stop.set()
        if self.monitor: self.monitor.join(timeout=65)
        for i in range(len(self.nodes)):
            node=self.nodes[i]
            try:
                # Collect only diagnostic files, never profile keys or fixture bytes.
                code="import pathlib,tarfile,sys; p=pathlib.Path(sys.argv[1]); t=tarfile.open(fileobj=sys.stdout.buffer,mode='w|'); [(t.add(f,arcname=f.name)) for f in p.glob('*.log') if f.is_file()]; [(t.add(f,arcname=f.name)) for f in p.glob('*metrics.jsonl') if f.is_file()]; t.close()"
                cmd=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','root@'+IPS[i],shlex.join(['python3','-c',code,node['root']+'/data'])]
                with (self.directory/f'host-{i+1}-logs.tar').open('wb') as out:
                    subprocess.run(cmd,stdout=out,stderr=subprocess.PIPE,timeout=90,check=True)
                self.event('relay_traffic',host=i,**self.remote(i,'traffic'))
            except Exception as exc:
                self.event('collection_error',host=i,error=str(exc))
            try:
                result=self.remote(i,'cleanup')
                passed=not result['errors'] and all(result[x] for x in ('namespace_removed','veth_removed','rules_removed','volume_unmounted')) and result['production']==node['before']['production']
                self.event('cleanup',host=i,passed=passed,**result)
            except Exception as exc:
                self.event('cleanup',host=i,passed=False,error=str(exc))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    start=sub.add_parser('run')
    start.add_argument('--build',type=Path,required=True)
    start.add_argument('--output',type=Path,required=True)
    start.add_argument('--run-id',default='ff-'+time.strftime('%Y%m%d-%H%M%S'))
    start.add_argument('--phase',choices=('canary','capacity','coverage','campaign'),default='campaign')
    for command in ('analyze','cleanup'):
        item=sub.add_parser(command); item.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    directory=args.output.resolve()
    if args.command=='analyze':
        manifest=json.loads((directory/'manifest.json').read_text())
        events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
        report=analyze(manifest,events); atomic(directory/'report.json',report)
        print(json.dumps(report,indent=2)); return 0 if report['verdict']=='pass' else 1
    if args.command=='cleanup':
        manifest=json.loads((directory/'manifest.json').read_text()); campaign=Campaign(directory,manifest)
        campaign.nodes=manifest['hosts']; campaign.cleanup()
        cleanup=[e for e in campaign.events if e['event']=='cleanup']
        return 0 if len(cleanup)==8 and all(e.get('passed') for e in cleanup) else 1
    directory.mkdir(parents=True,exist_ok=False)
    (directory/'tools').mkdir()
    for name in ('fleet_files.py','fleet_files_remote.py'):
        shutil.copy2(ROOT/'scripts'/name,directory/'tools'/name)
    manifest={'schema':1,'run_id':args.run_id,'phase':args.phase,'protocol':'GChat','schedule':'gchat-files','profile':'file-transfer-22',
              'clients':16,'soak_seconds':14400,'large_sizes':[256*1024*1024,GIB],
              'coordinator_sha256':sha(Path(__file__)),'started_unix':time.time()}
    atomic(directory/'manifest.json',manifest)
    campaign=Campaign(directory,manifest)
    try:
        campaign.prepare(args.build.resolve()); campaign.execute()
    except BaseException as exc:
        campaign.event('failure',error=f'{type(exc).__name__}: {exc}')
    finally:
        campaign.stop.set()
        campaign.jobs.shutdown(wait=True,cancel_futures=True)
        campaign.chat_jobs.shutdown(wait=True,cancel_futures=True)
        campaign.cleanup()
        report=analyze(manifest,campaign.events); atomic(directory/'report.json',report)
    print(json.dumps({'report':str(directory/'report.json'),'verdict':report['verdict']}),flush=True)
    return 0 if report['phase_passed'] else 1

if __name__=='__main__': sys.exit(main())
