import { readFileSync } from 'node:fs';
import { serviceBindings, output } from '@gcoms/rpc-codegen';
const contract = JSON.parse(readFileSync(new URL('./contract.json', import.meta.url), 'utf8'));
const generated = serviceBindings(contract.service, contract.typescript, 'createGreetingClient');
output(new URL('./rpc-api.ts', import.meta.url), generated.source);
output(new URL('./rpc-validators.js', import.meta.url), generated.validators);
