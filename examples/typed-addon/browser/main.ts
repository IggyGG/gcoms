import { BrowserHandles, RpcClient, httpTransport } from '@gcoms/rpc';
import { createGreetingClient, methods, SERVICE, SERVICE_VERSION } from './rpc-api';
import init, { rust_greet, rust_uppercase, rust_resume } from './pkg/gcoms_addon_example.js';

const instance = 'greeting-example';
const handles = new BrowserHandles(localStorage, 'greeting:ts:handle:');
const rpc = new RpcClient(httpTransport('/rpc'), instance, SERVICE, SERVICE_VERSION, handles);
const client = createGreetingClient(rpc);
const ready = init().then(() => {
  const result = document.querySelector<HTMLParagraphElement>('#result')!;
  const name = document.querySelector<HTMLInputElement>('#name')!;
  document.querySelector('#typescript')!.addEventListener('click', async () => {
    try { result.textContent = (await client.greet({ name: name.value })).text; } catch (error) { result.textContent = String(error); }
  });
  document.querySelector('#rust')!.addEventListener('click', async () => {
    try { result.textContent = await rust_greet(instance, name.value); } catch (error) { result.textContent = String(error); }
  });
  result.textContent = 'Both clients are ready';
});

// The browser fixture drives these same public client APIs; no fake RPC runtime.
Object.assign(window, { example: {
  ready,
  tsGreet: (name: string) => client.greet({ name }),
  tsUppercase: (text: string) => client.uppercase({ text }),
  tsHandles: () => handles.list(),
  tsResume: (id: string) => rpc.resume(methods.uppercase, handles.list().find(h => h.operation.id === id)!),
  rustGreet: (name: string) => rust_greet(instance, name),
  rustUppercase: (text: string) => rust_uppercase(instance, text),
  rustResume: (handle: string) => rust_resume(instance, handle),
} });
