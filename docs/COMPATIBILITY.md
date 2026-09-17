# Naming and compatibility

| Previous name | Public name |
| --- | --- |
| `gc-core`, `gc-protocol`, `gc-crypto`, etc. | `gcoms-core`, `gcoms-protocol`, `gcoms-crypto`, etc. |
| `gc-sdk`, `gc-rpc` | `gcoms-sdk`, `gcoms-rpc` |
| `ghost-private-fs` | `gcoms-private-fs` |
| `@ghost/gc-rpc` | `@gcoms/rpc` |
| `@ghost/gc-rpc/generator` | `@gcoms/rpc-codegen` |
| `gc-client` application repository | GChat |

Update dependency names and Rust import paths. Remove private sibling dependencies.
Use the code generator as a build dependency, not as a browser runtime export.
GComs 0.1.0 is a preview; public Rust APIs and package versions use semantic versioning,
while wire versions change only through an explicit protocol compatibility decision.

GComs no longer chooses an operated network. Replace `InstalledNetwork::built_in()`
with caller-supplied `InstalledNetwork::from_json(...)`; pass it to
`NetworkClient::for_profile(profile, installed)`. The CLI accepts `--network-config`.
GChat owns its bundled default configuration. Retained network sequence, consent,
profile paths and invitation state remain local and are not reset for branding.

Private host migration needs an explicit adapter for `ComponentAuthority`.
Validate the same identity, purpose, component membership, expiry, signature and
revocation rules before returning success. Existing Ghost deployment code remains
on its private release until that adapter and native integration are qualified.

Do not rename `GCAPP1`, GC/1 cell tags, existing `ghost.*` signature domains/media
types, service names, IPC tags, archive magic, or GChat's existing profile paths.
These are protocol or persisted compatibility identifiers, not product copy.
