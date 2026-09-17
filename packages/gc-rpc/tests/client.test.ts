import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { MemoryHandles, RpcClient, RpcError, ServiceError, isRequest, isReply, type Method, type Request, type ReplyBody, type Transport } from '../src/index';

const method: Method<{ value: string }, string, { code: string }> = {
  id: 'echo', kind: 'operation',
  args: (v): v is { value: string } => !!v && typeof v === 'object' && 'value' in v && typeof v.value === 'string',
  output: (v): v is string => typeof v === 'string',
  error: (v): v is { code: string } => !!v && typeof v === 'object' && 'code' in v && typeof v.code === 'string',
};
function reply(r: Request, body: ReplyBody) { const { invocation: _, ...binding } = r; return { ...binding, body }; }

describe('typed RPC recovery', () => {
  it('accepts the exact Rust-generated cross-language wire fixtures', () => {
    const { fixtures } = JSON.parse(readFileSync(new URL('../schemas/wire.json', import.meta.url), 'utf8'));
    expect(isRequest(fixtures.request)).toBe(true);
    expect(isReply(fixtures.reply)).toBe(true);
    expect(fixtures.request.invocation.operation.deadline).toBe('18446744073709551615');
    expect(fixtures.request.invocation.args.text).toBe('  λ\ntext  ');
  });
  it('retains before sending and resumes a lost reply without another call', async () => {
    const handles = new MemoryHandles(); const sent: Request[] = [];
    const transport: Transport = { destination: '/rpc', limit: 16000, async exchange(request) {
      expect(handles.list()).toHaveLength(1); sent.push(request);
      if (request.invocation.action === 'call') throw new Error('reply lost');
      return reply(request, { state: 'done', outcome: { kind: 'ok', value: 'hello' } });
    } };
    const client = new RpcClient(transport, 'instance', 'example.echo', 1, handles);
    const p = client.prepare(method, { value: 'secret message' });
    await expect(client.start(p)).rejects.toThrow('reply lost');
    expect(JSON.stringify(handles.list())).not.toContain('secret message');
    const reopened = new RpcClient(transport, 'instance', 'example.echo', 1, handles);
    expect(await reopened.resume(method, handles.list()[0])).toBe('hello');
    expect(sent.map(r => r.invocation.action)).toEqual(['call', 'status']);
  });
  it('rejects mismatched replies and malformed method results', async () => {
    const client = new RpcClient({ destination: '/rpc', limit: 16000, async exchange(r) { return { ...reply(r, { state: 'done', outcome: { kind: 'ok', value: 'x' } }), instance: 'other' }; } }, 'instance', 'example.echo', 1);
    await expect(client.call({ ...method, kind: 'query' }, { value: 'x' })).rejects.toMatchObject({ code: 'protocol' });
    const invalid = new RpcClient({ destination: '/rpc', limit: 16000, async exchange(r) { return reply(r, { state: 'done', outcome: { kind: 'ok', value: 12 } }); } }, 'instance', 'example.echo', 1);
    await expect(invalid.call({ ...method, kind: 'query' }, { value: 'x' })).rejects.toMatchObject({ code: 'protocol' });
  });
  it('surfaces typed service errors and honest uncertainty', async () => {
    const client = new RpcClient({ destination: '/rpc', limit: 16000, async exchange(r) { return reply(r, { state: 'done', outcome: { kind: 'error', value: { code: 'denied' } } }); } }, 'instance', 'example.echo', 1);
    await expect(client.call({ ...method, kind: 'query' }, { value: 'x' })).rejects.toBeInstanceOf(ServiceError);
    const uncertain = new RpcClient({ destination: '/rpc', limit: 16000, async exchange(r) { return reply(r, { state: 'outcome_unknown' }); } }, 'instance', 'example.echo', 1);
    const p = uncertain.prepare(method, { value: 'x' });
    await expect(uncertain.startAndWait(p)).rejects.toMatchObject({ code: 'outcome_unknown', handle: p.handle });
  });
  it('does not send if handles cannot be retained or the attachment differs', async () => {
    let sends = 0;
    const client = new RpcClient({ destination: '/rpc', limit: 16000, async exchange(r) { sends++; return reply(r, { state: 'running' }); } }, 'instance', 'example.echo', 1, { retain() { throw new RpcError('storage', 'full'); }, list: () => [], forget() {} });
    const p = client.prepare(method, { value: 'x' });
    await expect(client.start(p)).rejects.toMatchObject({ code: 'storage' });
    p.handle.instance = 'other';
    await expect(client.status(p.handle)).rejects.toMatchObject({ code: 'instance' });
    expect(sends).toBe(0);
  });
  it('validates bounded IDs and lossless u64 deadline strings', () => {
    const request: Request = { rpc: 1, id: 'request-123456789', instance: 'instance', service: 'example.echo', version: 1, method: 'echo', invocation: { action: 'call', args: {}, operation: { id: 'operation-12345678', deadline: '18446744073709551615' } } };
    expect(isRequest(request)).toBe(true);
    for (const invalid of ['18446744073709551616', '01', '-1', 12]) {
      expect(isRequest({ ...request, invocation: { ...request.invocation, operation: { id: 'operation-12345678', deadline: invalid } } })).toBe(false);
    }
    expect(isRequest({ ...request, id: 'short' })).toBe(false);
    expect(isReply(reply(request, { state: 'running' }))).toBe(true);
    expect(isReply({ ...reply(request, { state: 'running' }), unexpected: true })).toBe(false);
  });
});
