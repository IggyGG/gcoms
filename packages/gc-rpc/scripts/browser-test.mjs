// A private local fixture: real native router/journal, real HTTP and Chromium,
// actual generated TS and wasm-bindgen clients. Never contacts a deployed peer.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, chmod, rm, access } from 'node:fs/promises';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { createServer } from 'vite';
import { chromium } from '@playwright/test';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(packageRoot, '../..');
const browserRoot = join(root, 'examples/typed-addon/browser');
const binary = join(process.env.CARGO_TARGET_DIR ?? join(root, 'target'), 'debug/typed-addon-server');
await access(binary);
await access(join(browserRoot, 'pkg/gcoms_addon_example_bg.wasm'));
const scratch = await mkdtemp(join(tmpdir(), 'gc-rpc-browser-'));
await chmod(scratch, 0o700);
const socket = join(scratch, 'addon.rpc');
const secret = join(scratch, 'secret');
await writeFile(secret, randomBytes(32), { mode: 0o600 });
const cookie = randomBytes(24).toString('hex');
const backend = spawn(binary, [socket, join(scratch, 'journal'), secret], { stdio: ['ignore', 'ignore', 'pipe'] });
let stderr = ''; backend.stderr.on('data', b => { stderr += b; });
let browser; let server;
let loseNext = false; let wrongNext = false;
const submissions = [];
function exchange(request) {
  return new Promise((resolve, reject) => {
    const stream = connect(socket); let bytes = Buffer.alloc(0); let length;
    stream.setTimeout(5000, () => stream.destroy(new Error('native fixture timeout')));
    stream.on('error', reject);
    stream.on('connect', () => { const body = Buffer.from(JSON.stringify(request)); const header = Buffer.alloc(4); header.writeUInt32BE(body.length); stream.write(header); stream.write(body); });
    stream.on('data', chunk => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > 16384) { stream.destroy(new Error('fixture frame too large')); return; }
      if (length === undefined && bytes.length >= 4) length = bytes.readUInt32BE(0);
      if (length !== undefined && bytes.length >= length + 4) { try { resolve(JSON.parse(bytes.subarray(4, length + 4))); } catch (error) { reject(error); } stream.destroy(); }
    });
  });
}
try {
  for (let n = 0;; n++) {
    try { await access(socket); break; } catch { if (n > 100 || backend.exitCode !== null) throw new Error(`native fixture did not start: ${stderr}`); await new Promise(r => setTimeout(r, 50)); }
  }
  server = await createServer({ root: browserRoot, configFile: false, cacheDir: join(scratch, 'vite'),
    resolve: { alias: { '@gcoms/rpc': join(packageRoot, 'src/index.ts') } },
    server: { host: '127.0.0.1', port: 0, fs: { allow: [browserRoot, packageRoot] } },
    plugins: [{ name: 'authenticated-instance-fixture', configureServer(vite) {
      vite.middlewares.use('/rpc', async (req, res) => {
        if (req.method !== 'POST' || req.headers.origin !== `http://${req.headers.host}` || req.headers.cookie !== `fixture=${cookie}`) { res.statusCode = 403; res.end(); return; }
        try {
          let body = ''; for await (const chunk of req) { body += chunk; if (Buffer.byteLength(body) > 16000) throw new Error('request bound'); }
          const request = JSON.parse(body);
          assert.equal(request.instance, 'greeting-example'); assert.equal(request.service, 'example.greeting'); assert.equal(request.version, 1);
          if (request.invocation.action === 'call' && request.method === 'uppercase') submissions.push(request.invocation.operation.id);
          const reply = await exchange(request);
          if (loseNext && request.invocation.action === 'call' && request.method === 'uppercase') { loseNext = false; res.statusCode = 502; res.end('simulated lost upstream reply'); return; }
          if (wrongNext) { wrongNext = false; reply.instance = 'different-instance'; }
          res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.end(JSON.stringify(reply));
        } catch { res.statusCode = 502; res.end(); }
      });
    } }],
  });
  console.log('native fixture ready');
  await server.listen(); const url = server.resolvedUrls.local[0];
  browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {}) });
  const context = await browser.newContext();
  await context.addCookies([{ name: 'fixture', value: cookie, url, httpOnly: true, sameSite: 'Strict' }]);
  const page = await context.newPage(); const errors = []; page.on('pageerror', error => errors.push(error.message));
  const load = async () => { await page.goto(url); await page.waitForFunction(() => !!window.example); await page.evaluate(() => window.example.ready); };
  await load(); console.log('browser clients ready');
  assert.deepEqual(await page.evaluate(() => window.example.tsGreet('Ada')), { text: 'Hello, Ada!' });
  assert.equal(await page.evaluate(() => window.example.rustGreet('Rust')), 'Hello, Rust!');
  assert.deepEqual(await page.evaluate(() => window.example.tsUppercase('hello λ')), { text: 'HELLO Λ' });
  assert.equal(await page.evaluate(() => window.example.rustUppercase('rust λ')), 'RUST Λ');
  console.log('begin lost-reply check');
  loseNext = true;
  assert.match(await page.evaluate(async () => { try { await window.example.tsUppercase('lost ts reply'); return 'unexpected success'; } catch (e) { return String(e); } }), /Gateway returned HTTP 502/);
  const tsId = submissions.at(-1);
  await load();
  assert.deepEqual(await page.evaluate(id => window.example.tsResume(id), tsId), { text: 'LOST TS REPLY' });
  assert.equal(submissions.filter(id => id === tsId).length, 1);
  console.log('begin lost-reply check');
  loseNext = true;
  assert.match(await page.evaluate(async () => { try { await window.example.rustUppercase('lost rust reply'); return 'unexpected success'; } catch (e) { return String(e); } }), /[Gg]ateway returned HTTP 502/);
  const rustId = submissions.at(-1);
  await load();
  const saved = await page.evaluate(id => {
    const entries = Object.keys(localStorage).filter(k => k.startsWith('gc-rpc:greeting-example:handle-v1:')).map(k => JSON.parse(localStorage.getItem(k)));
    return JSON.stringify(entries.find(h => h.operation.id === id));
  }, rustId);
  assert.equal(await page.evaluate(h => window.example.rustResume(h), saved), 'LOST RUST REPLY');
  assert.equal(submissions.filter(id => id === rustId).length, 1);
  const retained = await page.evaluate(() => JSON.stringify(localStorage));
  assert.ok(!retained.includes('lost ts reply') && !retained.includes('lost rust reply'));
  wrongNext = true;
  assert.match(await page.evaluate(async () => { try { await window.example.tsGreet('x'); return 'unexpected success'; } catch (e) { return String(e); } }), /binding/);
  wrongNext = true;
  assert.match(await page.evaluate(async () => { try { await window.example.rustGreet('x'); return 'unexpected success'; } catch (e) { return String(e); } }), /binding/);
  const denied = await browser.newContext(); const unauth = await denied.newPage(); await unauth.goto(url);
  assert.equal(await unauth.evaluate(async () => (await fetch('/rpc', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status), 403);
  await denied.close(); assert.deepEqual(errors, []);
  console.log(JSON.stringify({ browser: 'Chromium', rustWasm: 'pass', typescript: 'pass', authenticatedGateway: 'pass', lostReplyReload: 'pass', correlation: 'pass', submissions: submissions.length }));
} finally {
  console.log('closing browser fixture');
  await browser?.close(); await server?.close();
  if (backend.exitCode === null) { const exited = once(backend, 'exit'); backend.kill('SIGINT'); await exited; }
  await rm(scratch, { recursive: true, force: true });
}
