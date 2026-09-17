import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { serviceBindings } from '@gcoms/rpc-codegen';
const original = JSON.parse(readFileSync(new URL('../../../examples/typed-addon/browser/contract.json', import.meta.url), 'utf8'));
describe('portable generated method names', () => {
  it('rejects IDs that cannot become standalone validator exports or safe object keys', () => {
    for (const id of ['1method', '__proto__']) {
      const contract = structuredClone(original);
      contract.service.methods[0].id = id;
      expect(() => serviceBindings(contract.service, contract.typescript)).toThrow('lowercase letter');
    }
  });
  it('rejects a query that would replace an operation preparation helper', () => {
    const contract = structuredClone(original);
    contract.service.methods[0].id = 'prepare_uppercase';
    expect(() => serviceBindings(contract.service, contract.typescript)).toThrow('collision');
  });
});
