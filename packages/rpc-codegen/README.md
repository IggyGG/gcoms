# @gcoms/rpc-codegen

Build-time generation for GComs typed services. Export a service schema with the
Rust contract, then call `serviceBindings` and `validators` from this package.
`output` generates shared wire types. See the typed-addon generator in GComs and
the GChat schema generation script for complete examples.

Ajv and Node filesystem APIs are used only during generation. Do not import this
package into browser application code; use the generated files and `@gcoms/rpc`.
Generated schema validators reject invalid arguments, results and service errors.

Developer preview. MIT OR Apache-2.0.
