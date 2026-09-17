#!/usr/bin/env python3
"""Resolve unpublished GComs tarballs through a loopback-only staging registry."""
import argparse, base64, hashlib, http.server, json, subprocess, tarfile, threading, tempfile, shutil
from pathlib import Path
from urllib.parse import unquote
p=argparse.ArgumentParser()
p.add_argument('--gchat',type=Path,required=True)
p.add_argument('--packages',type=Path,required=True)
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
try:
    with tempfile.TemporaryDirectory(prefix='gchat-npm-resolution-') as temporary:
        workspace=Path(temporary)
        for relative in ('package.json','ui/package.json','apps/client/package.json'):
            target=workspace/relative;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(a.gchat/relative,target)
        subprocess.run(['npm','install','--ignore-scripts','--package-lock-only',f'--@gcoms:registry=http://127.0.0.1:{server.server_port}/'],cwd=workspace,check=True)
        shutil.copyfile(workspace/'package-lock.json',a.gchat/'package-lock.json')
finally: server.shutdown();server.server_close()
lock_path=a.gchat/'package-lock.json'
lock=json.loads(lock_path.read_text())
for item in lock['packages'].values():
    resolved=item.get('resolved','')
    if resolved.startswith('http://127.0.0.1:'):
        short=Path(resolved).name.removeprefix('gcoms-').removesuffix('-0.1.0.tgz')
        assert short in ('rpc','rpc-codegen')
        item['resolved']=f'https://registry.npmjs.org/@gcoms/{short}/-/{short}-0.1.0.tgz'
for key,item in lock['packages'].items():
    assert not key.startswith('../'), 'package path escapes workspace'
    if key.startswith('node_modules/@gcoms/'):
        assert not item.get('link') and item.get('integrity'), 'GComs must resolve to an inspected archive'
lock_path.write_text(json.dumps(lock,indent=2)+'\n')
print('GChat lockfile resolved from inspected tarballs; canonical public registry URLs retained.')
