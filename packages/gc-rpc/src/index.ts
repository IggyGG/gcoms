import type { Invocation, OperationHandle, Outcome, Reply, ReplyBody, Request, RpcError as WireError } from './wire';
import { validRequest, validReply, validHandle } from './validators.js';
export type * from './wire';
export const isRequest: Guard<Request> = (value: unknown): value is Request => validRequest(value);
export const isReply: Guard<Reply> = (value: unknown): value is Reply => validReply(value);

export class RpcError extends Error {
  constructor(public readonly code: WireError['code'] | 'outcome_unknown', message: string, public readonly handle?: OperationHandle) { super(message); this.name = 'RpcError'; }
}
export class ServiceError<E> extends Error {
  constructor(public readonly detail: E) { super('Service rejected the request'); this.name = 'ServiceError'; }
}
export type Guard<T> = (value: unknown) => value is T;
export interface Method<A, R, E> {
  id: string; kind: 'query' | 'operation' | 'session';
  args: Guard<A>; output: Guard<R>; error: Guard<E>;
}
export interface Transport {
  readonly destination: string;
  readonly limit: number;
  exchange(request: Request): Promise<unknown>;
}
export interface HandleStore {
  retain(handle: OperationHandle): void;
  list(): OperationHandle[];
  forget(handle: OperationHandle): void;
}
const same = (a: OperationHandle, b: OperationHandle) => a.destination === b.destination && a.instance === b.instance && a.service === b.service && a.version === b.version && a.method === b.method && a.operation.id === b.operation.id;
export class MemoryHandles implements HandleStore {
  private entries: OperationHandle[] = [];
  retain(handle: OperationHandle) {
    if (this.entries.some(h => same(h, handle))) return;
    if (this.entries.length >= 4096) throw new RpcError('busy', 'Retained operation handle limit');
    this.entries.push(structuredClone(handle));
  }
  list() { return structuredClone(this.entries); }
  forget(handle: OperationHandle) { this.entries = this.entries.filter(h => !same(h, handle)); }
}
/** One key per operation avoids lost handles when multiple tabs write at once. */
export class BrowserHandles implements HandleStore {
  constructor(private readonly storage: Storage, private readonly prefix = 'gc-rpc:handle:v1:') {}
  private key(h: OperationHandle) { return this.prefix + encodeURIComponent(JSON.stringify([h.destination, h.instance, h.service, h.version, h.method, h.operation.id])); }
  retain(h: OperationHandle) {
    if (!validHandle(h)) throw new RpcError('invalid_request', 'Invalid operation handle');
    if (this.storage.getItem(this.key(h)) === null && this.list().length >= 4096) throw new RpcError('busy', 'Retained handle limit');
    try { this.storage.setItem(this.key(h), JSON.stringify(h)); } catch { throw new RpcError('storage', 'Could not retain operation handle'); }
  }
  list(): OperationHandle[] {
    const handles: OperationHandle[] = [];
    try {
      for (let i = 0; i < this.storage.length; i++) {
        const key = this.storage.key(i);
        if (!key?.startsWith(this.prefix)) continue;
        const h: unknown = JSON.parse(this.storage.getItem(key) ?? 'null');
        if (!validHandle(h)) throw new Error('Invalid handle');
        handles.push(h as OperationHandle);
      }
    } catch { throw new RpcError('storage', 'Could not read saved operation handles'); }
    return handles;
  }
  forget(h: OperationHandle) { this.storage.removeItem(this.key(h)); }
}
export interface Prepared<A, R, E> { handle: OperationHandle; args: A; method: Method<A, R, E> }
const byteLength = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

export class RpcClient {
  constructor(public readonly transport: Transport, public readonly instance: string, public readonly service: string, public readonly version: number, public readonly handles: HandleStore = new MemoryHandles()) {}
  private request(method: string, invocation: Invocation): Request { return { rpc: 1, id: crypto.randomUUID(), instance: this.instance, service: this.service, version: this.version, method, invocation }; }
  private async exchange(request: Request): Promise<ReplyBody> {
    if (!validRequest(request)) throw new RpcError('invalid_request', 'Invalid RPC request');
    if (byteLength(request) > this.transport.limit) throw new RpcError('payload_too_large', 'Request exceeds transport limit');
    const value = await this.transport.exchange(request);
    if (!validReply(value)) throw new RpcError('protocol', 'Invalid RPC reply');
    const reply = value as Reply;
    if (byteLength(reply) > this.transport.limit) throw new RpcError('payload_too_large', 'Reply exceeds transport limit');
    if (reply.rpc !== 1 || reply.id !== request.id || reply.instance !== request.instance || reply.service !== request.service || reply.version !== request.version || reply.method !== request.method) throw new RpcError('protocol', 'Reply binding does not match request');
    if (reply.body.state === 'failed') throw new RpcError(reply.body.error.code, reply.body.error.message);
    return reply.body;
  }
  async call<A, R, E>(method: Method<A, R, E>, args: A): Promise<R> {
    if (method.kind === 'operation') return this.startAndWait(this.prepare(method, args));
    if (!method.args(args)) throw new RpcError('invalid_request', 'Arguments do not match service contract');
    const body = await this.exchange(this.request(method.id, { action: 'call', args, operation: null }));
    if (body.state !== 'done') throw new RpcError('protocol', 'Nonterminal query result');
    return this.result(method, body.outcome);
  }
  prepare<A, R, E>(method: Method<A, R, E>, args: A): Prepared<A, R, E> {
    if (method.kind !== 'operation' || !method.args(args)) throw new RpcError('invalid_request', 'Invalid operation arguments');
    return { method, args: structuredClone(args), handle: { destination: this.transport.destination, instance: this.instance, service: this.service, version: this.version, method: method.id, operation: { id: crypto.randomUUID(), deadline: String(Math.floor(Date.now() / 1000) + 600) } } };
  }
  private checkHandle(h: OperationHandle) {
    if (!validHandle(h) || h.destination !== this.transport.destination || h.instance !== this.instance || h.service !== this.service || h.version !== this.version) throw new RpcError('instance', 'Operation belongs to another attachment');
  }
  async start<A, R, E>(p: Prepared<A, R, E>): Promise<ReplyBody> {
    this.checkHandle(p.handle);
    if (p.handle.method !== p.method.id || p.method.kind !== 'operation' || !p.method.args(p.args)) throw new RpcError('invalid_request', 'Invalid prepared operation');
    this.handles.retain(p.handle);
    return this.exchange(this.request(p.handle.method, { action: 'call', args: p.args, operation: p.handle.operation }));
  }
  async status(handle: OperationHandle): Promise<ReplyBody> { this.checkHandle(handle); return this.exchange(this.request(handle.method, { action: 'status', operation_id: handle.operation.id })); }
  async resume<A, R, E>(method: Method<A, R, E>, handle: OperationHandle): Promise<R> {
    if (method.id !== handle.method || method.kind !== 'operation') throw new RpcError('invalid_request', 'Handle method mismatch');
    for (let i = 0; i < 1500; i++) {
      const body = await this.status(handle);
      if (body.state !== 'running') return this.finish(method, handle, body);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new RpcError('timeout', 'Wait timed out; operation may still complete', handle);
  }
  async startAndWait<A, R, E>(p: Prepared<A, R, E>): Promise<R> {
    const body = await this.start(p);
    return body.state === 'running' ? this.resume(p.method, p.handle) : this.finish(p.method, p.handle, body);
  }
  private finish<A, R, E>(method: Method<A, R, E>, handle: OperationHandle, body: ReplyBody): R {
    if (body.state === 'done') return this.result(method, body.outcome);
    if (body.state === 'failed') throw new RpcError(body.error.code, body.error.message, handle);
    throw new RpcError(body.state === 'outcome_unknown' ? 'outcome_unknown' : 'unavailable', body.state === 'outcome_unknown' ? 'Operation was interrupted after admission; it will not run again automatically' : 'Operation result is unavailable', handle);
  }
  private result<A, R, E>(method: Method<A, R, E>, outcome: Outcome): R {
    if (outcome.kind === 'error') {
      if (!method.error(outcome.value)) throw new RpcError('protocol', 'Invalid service error');
      throw new ServiceError(outcome.value);
    }
    if (!method.output(outcome.value)) throw new RpcError('protocol', 'Invalid method result');
    return outcome.value;
  }
}

export function httpTransport(path: string, limit = 16 * 1024 * 1024): Transport {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') || path.includes('#')) throw new RpcError('invalid_request', 'Use a same-origin gateway path');
  return { destination: path, limit, async exchange(request) {
    let response: Response;
    try { response = await fetch(path, { method: 'POST', credentials: 'same-origin', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request), signal: AbortSignal.timeout(150_000) }); }
    catch { throw new RpcError('transport', 'Gateway unavailable; recover using the original operation handle'); }
    if (!response.ok) throw new RpcError(response.status === 401 || response.status === 403 ? 'unauthorized' : 'transport', `Gateway returned HTTP ${response.status}`);
    if (!response.body) throw new RpcError('protocol', 'Empty gateway response');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let length = 0;
    try {
      for (;;) { const { done, value } = await reader.read(); if (done) break; length += value.length; if (length > limit) { await reader.cancel(); throw new RpcError('payload_too_large', 'Gateway response exceeds limit'); } chunks.push(value); }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new RpcError('protocol', 'Invalid gateway JSON'); }
  } };
}
