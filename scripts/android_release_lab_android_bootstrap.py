"""Initial signed Android install on the explicitly owned cluster emulator."""
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path('/home/lab/.local/state/android-cluster-release')
sys.path.insert(0,str(ROOT/'scripts'))
from android_release import digest,write_json
import android_release_host as host
import android_release_hub as hub
os.umask(0o077)
os.environ.update(XDG_RUNTIME_DIR='/run/user/1000',DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus')
config=json.loads((ROOT/'host-config.json').read_text());prepared=json.loads((ROOT/'prepared.json').read_text())
context=json.loads((ROOT/'context.json').read_text())
from android_release_lab_context import identity
identity(context)
if subprocess.check_output(['sudo','-n','cat','/sys/class/dmi/id/product_uuid'],timeout=5).decode().strip().lower()!=context['vm_uuid']:
 raise ValueError('Android bootstrap belongs to another VM')
hub.eligible(config);hub.eligible_controller(config)
target=next(x for x in config['targets'] if x['kind']=='android')
folder=ROOT/'android-bootstrap';folder.mkdir(mode=0o700,exist_ok=True)

def run(argv,timeout=45):
 result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=timeout)
 if result.returncode:
  with (folder/'private.log').open('ab') as log:log.write(result.stdout[-16384:]+result.stderr[-16384:])
  raise ValueError('Android bootstrap command failed; retained private guest log')
 return result.stdout

run([config['adb'],'connect',target['serial']])
assert run(host.adb(config,target,'get-state')).strip()==b'device'

worker=ROOT/'artifacts/worker'/prepared['inputs']['worker']/'x86_64/worker.so'
apk=ROOT/'artifacts/apk'/prepared['inputs']['apk']/'agent.apk'
publication=folder/'gdrone-android-x64.so'
if not publication.exists():publication.write_bytes(worker.read_bytes())
assert digest(publication)==digest(worker)
if not (folder/'published.json').exists():
 run([config['fleet_binary'],'publish','--config',config['fleet_config'],'--channel','android-x64','--file',publication])
 write_json(folder/'published.json',{'sha256':digest(worker),'at':time.time()})
fleet=json.loads(Path(config['fleet_config']).read_text());until=time.monotonic()+30
while True:
 releases=json.loads((Path(fleet['state'])/'releases.json').read_text())
 if releases.get('active',{}).get('android-x64',{}).get('publication',{}).get('sha256')==digest(worker):break
 if time.monotonic()>=until:raise TimeoutError('initial worker publication not selected')
 time.sleep(.5)
expected={'release_id':hashlib.sha256(('cluster-bootstrap/'+prepared['prepared_id']).encode()).hexdigest(),
 'apk_sha256':digest(apk),'worker_sha256':digest(worker)}
profile=folder/'profile.json'
if profile.exists():
 previous=json.loads(profile.read_text())
 provider=subprocess.run(['systemctl','--user','is-active','android-cluster-bootstrap-mint.service'],capture_output=True,timeout=5)
 if provider.returncode or host.route_expiry(previous)<=time.time()+210:
  assert previous['target']==target['channel']
  run([config['fleet_binary'],'revoke-profile','--config',config['fleet_config'],'--profile',previous['profileId']])
  history=folder/'history'/str(time.time_ns());history.mkdir(mode=0o700,parents=True)
  profile.rename(history/'profile.json')
  for name in ['deployment-request.json','mint-private.log','private.log']:
   if (folder/name).exists():(folder/name).rename(history/name)
  write_json(history/'cancelled.json',{'profile_id':previous['profileId'],'at':time.time()})
  subprocess.run(['systemctl','--user','stop','android-cluster-bootstrap-mint.service'],capture_output=True,timeout=10)
if not profile.exists():
 run(['systemd-run','--user','--collect','--unit=android-cluster-bootstrap-mint','--property=RuntimeMaxSec=600',
  '--property=TimeoutStopSec=5','--property=StandardOutput=append:'+str(folder/'mint-private.log'),
  '--property=StandardError=append:'+str(folder/'mint-private.log'),config['fleet_binary'],'mint-ds',
  '--config',config['fleet_config'],'--channel','android-x64','--output',profile,'--network-invitation',config['network_invitation'],'--keep-alive','600'])
 until=time.monotonic()+45
 while not profile.exists():
  if time.monotonic()>=until:raise TimeoutError('initial normal profile mint failed')
  time.sleep(.5)
value=json.loads(profile.read_text());assert value['target']=='android-x64'
assert host.route_expiry(value)>time.time()+180
write_json(folder/'deployment-request.json',expected)
run(host.adb(config,target,'root'));run(host.adb(config,target,'wait-for-device'))
try:
 assert run(host.adb(config,target,'shell','id','-u')).strip()==b'0'
 probe=subprocess.run(host.adb(config,target,'shell','pm','path',host.PACKAGE),capture_output=True,timeout=15)
 if probe.returncode not in (0,1) or probe.stderr.strip():raise ValueError('Android package inventory failed')
 installed=probe.stdout.decode().strip()
 if probe.returncode==1 and installed:raise ValueError('ambiguous existing Android package')
 if installed:
  assert installed.startswith('package:/data/app/') and '\n' not in installed
  assert run(host.adb(config,target,'shell','sha256sum',installed.removeprefix('package:'))).decode().split()[0]==digest(apk),'preserve different installed package'
 else:run(host.adb(config,target,'install',apk))
 uid=run(host.adb(config,target,'shell','stat','-c','%u','/data/user/0/'+host.PACKAGE)).decode().strip();assert uid.isdigit()
 run(host.adb(config,target,'shell','mkdir','-p','/data/user/0/'+host.PACKAGE+'/files'))
 run(host.adb(config,target,'shell','chown',uid+':'+uid,'/data/user/0/'+host.PACKAGE+'/files'))
 for source,name in [(profile,'dropship-config.json'),(folder/'deployment-request.json','deployment-request.json')]:
  destination='/data/user/0/'+host.PACKAGE+'/files/'+name
  run(host.adb(config,target,'push',source,destination));run(host.adb(config,target,'shell','chown',uid+':'+uid,destination));run(host.adb(config,target,'shell','chmod','600',destination))
 run(host.adb(config,target,'shell','am','start','-n',host.PACKAGE+'/.MainActivity'))
 until=time.monotonic()+180
 while True:
  try:
   receipt=json.loads(host.private_file(config,target,'deployment-ready.json'))
   pid=run(host.adb(config,target,'shell','pidof',host.PACKAGE)).decode().strip();host.ready(receipt,expected,pid)
   result={'schema':1,'state':'bootstrap_worker_ready','worker_bytes':worker.stat().st_size,
    'apk_sha256':digest(apk),'worker_sha256':digest(worker),'process_id':int(pid),
    'identity_sha256':host.identity(config,target),'vm_uuid':context['vm_uuid'],'android_pod_uid':context['android_pod_uid'],
    'scope':'Initial worker readiness only; not the fresh interrupted 42 MiB qualification'}
   write_json(folder/'result.json',result);print(json.dumps(result),flush=True);break
  except (ValueError,OSError,subprocess.CalledProcessError):
   if time.monotonic()>=until:raise TimeoutError('initial Android worker did not become ready')
   time.sleep(1)
finally:run(host.adb(config,target,'unroot'))
