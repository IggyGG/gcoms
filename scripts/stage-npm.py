#!/usr/bin/env python3
"""Resolve unpublished GComs tarballs through a loopback-only staging registry."""
import argparse, base64, hashlib, http.server, json, subprocess, tarfile, threading, tempfile, uuid
from source_snapshot import snapshot, unchanged
from pathlib import Path
from urllib.parse import unquote
p=argparse.ArgumentParser()
p.add_argument('--gchat',type=Path,required=True)
p.add_argument('--packages',type=Path,required=True)
p.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'target/npm-stage')
a=p.parse_args()
archives={}
for name in ('rpc','rpc-codegen'):
    path=a.packages.resolve()/f'gcoms-{name}-0.1.0.tgz'
    with tarfile.open(path) as tar: meta=json.load(tar.extractfile('package/package.json'))
    data=path.read_bytes()
    archives['@gcoms/'+name]=(path,meta,data)
class Registry(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        selected=unquote(self.path).split('?',1)[0].lstrip('/')
        if selected.startswith('archives/'):
            name=selected.removeprefix('archives/')
            item=next((i for i in archives.values() if i[0].name==name),None)
            if item is None: self.send_error(404);return
            payload=item[2];kind='application/octet-stream'
        elif selected in archives:
            path,meta,data=archives[selected]
            version=dict(meta)
            version['dist']={'tarball':f'http://127.0.0.1:{self.server.server_port}/archives/{path.name}', 'integrity':'sha512-'+base64.b64encode(hashlib.sha512(data).digest()).decode(), 'shasum':hashlib.sha1(data).hexdigest()}
            payload=json.dumps({'name':selected,'dist-tags':{'latest':meta['version']},'versions':{meta['version']:version}}).encode();kind='application/json'
        else: self.send_error(404);return
        self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Registry)
threading.Thread(target=server.serve_forever,daemon=True).start()
original=a.gchat.resolve()
report_dir=a.output.resolve()/uuid.uuid4().hex
if report_dir.is_relative_to(original):
    p.error('--output must be outside the application checkout')
report_dir.mkdir(parents=True,exist_ok=False)
report={'status':'failed','published':False,'archives_sha256':{item[0].name:hashlib.sha256(item[2]).hexdigest() for item in archives.values()}}
hashes={}
try:
    with tempfile.TemporaryDirectory(prefix='gchat-npm-resolution-') as temporary:
        workspace=Path(temporary)/'gchat'
        hashes=snapshot(original,workspace)
        report['source_files_sha256']=hashes
        lock_path=workspace/'package-lock.json'
        lock=json.loads(lock_path.read_text())
        for name,(path,meta,data) in archives.items():
            item=lock['packages']['node_modules/'+name]
            item['resolved']=f'http://127.0.0.1:{server.server_port}/archives/{path.name}'
            item['integrity']='sha512-'+base64.b64encode(hashlib.sha512(data).digest()).decode()
        lock_path.write_text(json.dumps(lock,indent=2)+'\n')
        flags=['--ignore-scripts','--no-audit','--no-fund',f'--@gcoms:registry=http://127.0.0.1:{server.server_port}/']
        subprocess.run(['npm','install','--package-lock-only',*flags],cwd=workspace,check=True)
        subprocess.run(['npm','ci',*flags],cwd=workspace,check=True)
        for action in ('check','test','build'):
            subprocess.run(['npm','run',action],cwd=workspace,check=True)
        lock=json.loads(lock_path.read_text())
        for name,(path,meta,data) in archives.items():
            item=lock['packages']['node_modules/'+name]
            short=name.split('/')[1]
            item['resolved']=f'https://registry.npmjs.org/@gcoms/{short}/-/{short}-{meta["version"]}.tgz'
            assert not item.get('link') and item.get('integrity'), 'GComs must resolve to an inspected archive'
        for key,item in lock['packages'].items():
            assert not key.startswith('../'), 'package path escapes workspace'
            assert not item.get('resolved','').startswith('http://127.0.0.1:'), 'unrecognized staging URL'
        proposal=report_dir/'package-lock.json'
        proposal.write_text(json.dumps(lock,indent=2)+'\n')
        report['proposed_lockfile_sha256']=hashlib.sha256(proposal.read_bytes()).hexdigest()
        report['status']='passed'
except Exception as error:
    report['error']=str(error)
    raise
finally:
    server.shutdown();server.server_close()
    report['source_unchanged']=bool(hashes) and unchanged(original,hashes)
    if not report['source_unchanged']: report['status']='source_changed'
    (report_dir/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
if report['status']!='passed': raise SystemExit('Source changed during npm qualification')
print(f'GChat npm qualification passed. Review proposed lockfile at {report_dir}; original checkout unchanged.')
