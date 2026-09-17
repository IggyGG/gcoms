#!/usr/bin/env python3
"""Check an application against inspected crates using a loopback sparse registry.

Only GComs packages are synthesized. Third-party index entries and archives come
from Cargo's existing crates.io cache (or public crates.io when --offline is absent).
The application lockfile keeps canonical crates.io identities and archive checksums.
"""
import argparse, hashlib, http.server, json, os, re, subprocess, tarfile, tempfile, threading, tomllib, urllib.request
from pathlib import Path
from urllib.parse import unquote
p=argparse.ArgumentParser()
p.add_argument('--application',type=Path,required=True)
p.add_argument('--manifest',default='Cargo.toml')
p.add_argument('--packages',type=Path,required=True)
p.add_argument('--target-dir',type=Path,required=True)
p.add_argument('--offline',action='store_true')
p.add_argument('--command',choices=['check','test','clippy','build','metadata'],default='check')
a=p.parse_args()
application=a.application.resolve(); packages=a.packages.resolve()
cargo_home=Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))
entries={}; archives={}; checksums={}
def index_path(name):
    if len(name)<=2: return str(len(name))+'/'+name
    if len(name)==3: return '3/'+name[0]+'/'+name
    return name[:2]+'/'+name[2:4]+'/'+name
for path in sorted(packages.glob('gcoms-*.crate')):
    raw=path.read_bytes()
    with tarfile.open(path) as tar:
        member=next(m for m in tar.getmembers() if m.name.count('/')==1 and m.name.endswith('/Cargo.toml'))
        manifest=tomllib.loads(tar.extractfile(member).read().decode())
    pkg=manifest['package'];deps=[]
    tables=[(None,manifest)]+list(manifest.get('target',{}).items())
    for target,table in tables:
        for key,kind in [('dependencies','normal'),('dev-dependencies','dev'),('build-dependencies','build')]:
            for name,value in table.get(key,{}).items():
                if isinstance(value,str): value={'version':value}
                assert 'path' not in value, 'package contains an unnormalized path dependency'
                deps.append({'name':name,'package':value.get('package'),'req':value['version'],'features':value.get('features',[]),'optional':value.get('optional',False),'default_features':value.get('default-features',True),'target':target,'kind':kind,'registry':None})
    checksum=hashlib.sha256(raw).hexdigest()
    key=(pkg['name'],pkg['version']);archives[key]=raw;checksums[key]=checksum
    entries[index_path(pkg['name'])]=json.dumps({'name':pkg['name'],'vers':pkg['version'],'deps':deps,'cksum':checksum,'features':{},'features2':manifest.get('features',{}),'yanked':False,'links':pkg.get('links'),'rust_version':pkg.get('rust-version'),'v':2}).encode()+b'\n'
assert entries, 'no package archives supplied'
lock_path=(application/a.manifest).parent/'Cargo.lock'
lock=lock_path.read_text()
lock=re.sub(r'\n\[\[patch\.unused\]\][\s\S]*','\n',lock)
blocks=lock.split('[[package]]')
for i,block in enumerate(blocks[1:],1):
    name=re.search(r'^name = "([^"]+)"',block,re.M).group(1)
    version=re.search(r'^version = "([^"]+)"',block,re.M).group(1)
    if name.startswith('gcoms-'):
        checksum=checksums[(name,version)]
        block=re.sub(r'^(source|checksum) = .*\n','',block,flags=re.M)
        block=block.replace('version = "'+version+'"\n','version = "'+version+'"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "'+checksum+'"\n',1)
        blocks[i]=block
lock_path.write_text('[[package]]'.join(blocks))
def public_get(url):
    if a.offline: raise FileNotFoundError('third-party dependency is not cached')
    with urllib.request.urlopen(url,timeout=30) as response: return response.read()
class Registry(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        path=unquote(self.path).split('?',1)[0]
        try:
            if path=='/index/config.json':
                raw=json.dumps({'dl':f'http://127.0.0.1:{self.server.server_port}/crates/{{crate}}/{{version}}/download'}).encode()
            elif path.startswith('/index/'):
                key=path[len('/index/'):]
                if '..' in key or not re.fullmatch(r'[A-Za-z0-9_/-]+',key): raise ValueError('path')
                if key in entries: raw=entries[key]
                else:
                    cache=next(iter((cargo_home/'registry/index').glob('index.crates.io-*/.cache/'+key)),None)
                    if cache:
                        raw=b'\n'.join(part for part in cache.read_bytes().split(b'\0') if part.startswith(b'{"name":'))+b'\n'
                    else: raw=public_get('https://index.crates.io/'+key)
            elif (match:=re.fullmatch(r'/crates/([A-Za-z0-9_-]+)/([A-Za-z0-9_.+\-]+)/download',path)):
                name,version=match.groups();key=(name,version)
                if key in archives:raw=archives[key]
                else:
                    file=name+'-'+version+'.crate'
                    cache=next(iter((cargo_home/'registry/cache').glob('index.crates.io-*/'+file)),None)
                    raw=cache.read_bytes() if cache else public_get('https://static.crates.io/crates/'+name+'/'+file)
            else: raise ValueError('path')
        except Exception:
            self.send_error(404);return
        self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Registry)
threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='gcoms-registry-') as temporary:
        config=Path(temporary)/'registry.toml'
        config.write_text('[source.crates-io]\nreplace-with="preview"\n[source.preview]\nregistry="sparse+http://127.0.0.1:'+str(server.server_port)+'/index/"\n')
        args=['cargo',a.command,'--config',str(config),'--manifest-path',a.manifest,'--locked']
        if a.command=='metadata': args+=['--all-features','--format-version=1']
        else: args+=['--workspace','--all-features','--target-dir',str(a.target_dir.resolve())]
        if a.command=='clippy':args+=['--all-targets','--','-D','warnings']
        if a.command=='test':args+=['--','--test-threads=1']
        subprocess.run(args,cwd=application,check=True)
finally: server.shutdown();server.server_close()
