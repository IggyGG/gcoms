import Ajv2020 from 'ajv/dist/2020.js';
import standalone from 'ajv/dist/standalone/index.js';
import { readFileSync, writeFileSync } from 'node:fs';

/** Build-time only: generated ESM validators use no runtime code generation. */
export function validators(schemas) {
  const ajv = new Ajv2020({ strict: false, strictNumbers: true, code: { source: true, esm: true, lines: true }, allErrors: false, formats: { uint16: true, uint32: true, uint64: true, uint: true, int64: true } });
  const exports = {};
  for (const [name, schema] of Object.entries(schemas)) {
    ajv.addSchema(schema, name);
    exports[name] = name;
  }
  let source = standalone(ajv, exports);
  // Ajv emits this tiny helper as CommonJS even for ESM. Inline code-point
  // counting so browser bundles need neither require nor the Ajv runtime.
  source = source.replace(/const (func\d+) = require\("ajv\/dist\/runtime\/ucs2length"\)\.default;/g, 'const $1 = value => [...value].length;');
  if (source.includes('require(')) throw new Error('Unsupported standalone validator runtime helper');
  return '// @ts-nocheck\n// Generated from Rust JSON schemas. Do not edit.\n' + source;
}

export function output(path, contents, check = process.argv.includes('--check')) {
  if (check) {
    if (readFileSync(path, 'utf8') !== contents) throw new Error(`Generated artifact drift: ${path}`);
  } else writeFileSync(path, contents);
}

/** Generate methods and guards from one Rust service descriptor. */
export function serviceBindings(service, declarations, clientName = 'createServiceClient') {
  const exposed = new Set();
  for (const method of service.methods) {
    if (!/^[a-z][a-z0-9_]{0,79}$/.test(method.id)) throw new Error('Method IDs must start with a lowercase letter');
    const names = method.kind === 'operation' ? [method.id, 'prepare_' + method.id] : [method.id];
    for (const name of names) {
      if (exposed.has(name)) throw new Error(`Generated client method collision: ${name}`);
      exposed.add(name);
    }
  }
  const schemas = {};
  const methods = [];
  const functions = [];
  for (const method of service.methods) {
    const stem = method.id;
    for (const field of ['args', 'output', 'error']) schemas[`${stem}_${field}`] = method[`${field}_schema`];
    const types = [method.args_typescript, method.output_typescript, method.error_typescript];
    methods.push(`${JSON.stringify(stem)}: { id: ${JSON.stringify(stem)}, kind: ${JSON.stringify(method.kind)}, args: (value: unknown): value is ${types[0]} => guards.${stem}_args(value), output: (value: unknown): value is ${types[1]} => guards.${stem}_output(value), error: (value: unknown): value is ${types[2]} => guards.${stem}_error(value) } satisfies Method<${types.join(', ')}>`);
    functions.push(`${JSON.stringify(stem)}: (args: ${types[0]}) => rpc.call(methods.${stem}, args)`);
    if (method.kind === 'operation') functions.push(`${JSON.stringify('prepare_' + stem)}: (args: ${types[0]}) => rpc.prepare(methods.${stem}, args)`);
  }
  const source = `// Generated from Rust service definitions. Do not edit.\nimport { RpcClient, type Method } from '@gcoms/rpc';\nimport * as guards from './rpc-validators.js';\n${declarations}\nexport const SERVICE = ${JSON.stringify(service.name)};\nexport const SERVICE_VERSION = ${service.version};\nexport const methods = {\n${methods.join(',\n')}\n};\nexport function ${clientName}(rpc: RpcClient) { return {\n${functions.join(',\n')}\n}; }\n`;
  return { source, validators: validators(schemas) };
}

