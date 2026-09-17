// Generated from Rust service definitions. Do not edit.
import { RpcClient, type Method } from '@gcoms/rpc';
import * as guards from './rpc-validators.js';
export type Greeting = { text: string, };

export const SERVICE = "example.greeting";
export const SERVICE_VERSION = 1;
export const methods = {
"greet": { id: "greet", kind: "query", args: (value: unknown): value is { name: string, } => guards.greet_args(value), output: (value: unknown): value is { text: string, } => guards.greet_output(value), error: (value: unknown): value is string => guards.greet_error(value) } satisfies Method<{ name: string, }, { text: string, }, string>,
"uppercase": { id: "uppercase", kind: "operation", args: (value: unknown): value is { text: string, } => guards.uppercase_args(value), output: (value: unknown): value is { text: string, } => guards.uppercase_output(value), error: (value: unknown): value is string => guards.uppercase_error(value) } satisfies Method<{ text: string, }, { text: string, }, string>
};
export function createGreetingClient(rpc: RpcClient) { return {
"greet": (args: { name: string, }) => rpc.call(methods.greet, args),
"uppercase": (args: { text: string, }) => rpc.call(methods.uppercase, args),
"prepare_uppercase": (args: { text: string, }) => rpc.prepare(methods.uppercase, args)
}; }
