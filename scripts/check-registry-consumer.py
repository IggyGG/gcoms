#!/usr/bin/env python3
"""Check an application through a loopback registry without editing its sources.

Canonical lockfile changes are exported for review, never written to the original
application. Only cached third-party packages are used when --offline is selected.
"""
import argparse, hashlib, http.server, json, os, re, subprocess, tarfile, tempfile, threading, tomllib, urllib.request, uuid
import sys
from pathlib import Path
from urllib.parse import unquote
from source_snapshot import snapshot, unchanged


def qualify(a, application, packages, cargo_home):
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
    # Cargo may reuse a sparse-index cache without contacting this server. A
    # recycled loopback port must never identify different preview archives.
    identity=json.dumps([[name,version,checksum] for (name,version),checksum in sorted(checksums.items())],separators=(',',':'))
    registry_prefix='/preview/'+hashlib.sha256(identity.encode()).hexdigest()
    lock_path=(application/a.manifest).parent/'Cargo.lock'
    lock=lock_path.read_text()
    lock=re.sub(r'\n\[\[patch\.unused\]\][\s\S]*','\n',lock)
    blocks=lock.split('[[package]]')
    for i,block in enumerate(blocks[1:],1):
        name=re.search(r'^name = "([^"]+)"',block,re.M).group(1)
        version=re.search(r'^version = "([^"]+)"',block,re.M).group(1)
        if (name,version) in checksums:
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
                if not path.startswith(registry_prefix+'/'): raise ValueError('registry identity')
                path=path[len(registry_prefix):]
                if path=='/index/config.json':
                    raw=json.dumps({'dl':f'http://127.0.0.1:{self.server.server_port}{registry_prefix}/crates/{{crate}}/{{version}}/download'}).encode()
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
            config.write_text('[source.crates-io]\nreplace-with="preview"\n[source.preview]\nregistry="sparse+http://127.0.0.1:'+str(server.server_port)+registry_prefix+'/index/"\n')
            locked=[] if a.command=='update' else ['--locked']
            args=['cargo',a.command,'--config',str(config),'--manifest-path',a.manifest,*locked]
            if a.command=='metadata': args+=['--all-features','--format-version=1']
            elif a.command=='update':
                for name in (a.update_packages or '').split(','):
                    if name: args+=['-p',name]
            else: args+=['--workspace','--all-features','--target-dir',str(a.target_dir.resolve())]
            if a.command=='clippy':args+=['--all-targets','--','-D','warnings']
            if a.command=='test':args+=['--','--test-threads=1']
            try:
                subprocess.run(args,cwd=application,check=True)
            except subprocess.CalledProcessError as error:
                # Surface the underlying tool output for the caller; the
                # exception alone hides the actual gate failure.
                if error.stdout: sys.stderr.write(error.stdout if isinstance(error.stdout,str) else error.stdout.decode(errors='replace'))
                if error.stderr: sys.stderr.write(error.stderr if isinstance(error.stderr,str) else error.stderr.decode(errors='replace'))
                raise
    finally: server.shutdown();server.server_close()

    return lock_path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--application',type=Path,required=True)
    p.add_argument('--manifest',default='Cargo.toml')
    p.add_argument('--packages',type=Path,required=True)
    p.add_argument('--target-dir',type=Path,required=True)
    p.add_argument('--offline',action='store_true')
    p.add_argument('--command',choices=['check','test','clippy','build','metadata','update'],default='check')
    p.add_argument('--update-packages',default='')
    p.add_argument('--lockfile-output',type=Path)
    a=p.parse_args()
    original=a.application.resolve();packages=a.packages.resolve()
    target=a.target_dir.resolve();target.mkdir(parents=True,exist_ok=True)
    cargo_home=Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))
    manifest=Path(a.manifest)
    if manifest.is_absolute() or '..' in manifest.parts or not (original/manifest).resolve().is_relative_to(original):
        p.error('--manifest must stay inside the application')
    run_id=uuid.uuid4().hex;report_dir=target/'reports'/run_id;report_dir.mkdir(parents=True)
    report={'status':'failed','command':a.command,'manifest':a.manifest,'published':False}
    hashes={}
    try:
        with tempfile.TemporaryDirectory(prefix='gc-registry-') as temporary:
            application=Path(temporary)/'application'
            hashes=snapshot(original,application)
            report['source_files_sha256']=hashes
            report['package_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(packages.glob('*.crate'))}
            lock=qualify(a,application,packages,cargo_home)
            exported=report_dir/'Cargo.lock'
            exported.write_bytes(lock.read_bytes())
            report.update(status='passed',lockfile=str(exported),lockfile_sha256=hashlib.sha256(exported.read_bytes()).hexdigest())
            if a.lockfile_output:
                destination=a.lockfile_output.resolve()
                if destination.is_relative_to(original):
                    raise ValueError('--lockfile-output must be outside the original application')
                destination.parent.mkdir(parents=True,exist_ok=True)
                with destination.open('xb') as output:output.write(exported.read_bytes())
    except Exception as error:
        report['error']=str(error)
        report['status']='failed'
        raise
    finally:
        report['source_unchanged']=bool(hashes) and unchanged(original,hashes)
        if hashes and not report['source_unchanged']:report['status']='source_changed'
        (report_dir/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
        (target/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['status']!='passed':raise SystemExit('Source changed during registry qualification')
    print('Registry qualification passed; originals unchanged; reviewed lockfile:',report['lockfile'])


if __name__=='__main__':
    main()
