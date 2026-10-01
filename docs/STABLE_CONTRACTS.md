# Stable contract preparation

The supported application entry point is `gcoms`: `Application`,
`ApplicationBuilder`, `Backend`, `MessageDelivery` and `Files`, with the documented
`ipc,files`, `network-client,files` and `embedded,files,gc2-carrier` integrations.
The SDK 1.0 candidate preserves these interfaces and their existing exports.
It does not require existing applications to migrate or bundle GChat. Low-level
implementation exports remain available; their presence does not extend the
application facade's eventual major-version compatibility promise.

An unchanged consumer from published SDK 0.1.49 is retained with its original
source commit and SHA-256 in `release/contracts/application-0.1.49`. Native CI
compiles those exact Rust bytes against today's facade in three independent
feature graphs, before measuring the current consumers. Its manifest and lock
select today's packages; this is a source compatibility check, not a claim that
an old executable uses a new protocol. The existing fixed-byte IPC23 requests
and handshake tests separately protect released IPC clients. IPC26 remains the
current protocol; unpublished IPC24/25 are rejected.

Typed service methods keep their IDs, lifecycle and authorization. New optional
methods provide an unsupported default so released handlers compile unchanged.
Capabilities advertise support and never grant access. A transport timeout after
admission remains an uncertain outcome; it is not authority to repeat a mutation.
Recipient delivery still requires authenticated recipient acknowledgments.

SDK 1.0 is not yet declared. Qualification requires all four native consumer
matrices and eight Android/Apple client/relay/base/push combinations, archive
consumers, the version-bound size limits, installed application recovery and rollback,
fresh deployed relay observations and the automated subsequent release. Original
failures remain failures. Version reservation or upload alone cannot satisfy
these gates. Compatibility fixes may continue while these gates run; a breaking
supported contract requires a new major and a documented coexistence period.

For the initial feature release, the owner approved a maximum 20% size increase
against the retained same-toolchain baselines on 2026-10-01. The actual SDK package
version automatically restores a maximum 5% regression at 1.0, including 1.0
prereleases and subsequent majors. All native/mobile measurements use the shared
policy and retain its hash and effective ceiling. Original failed workflows are
not relabeled; the approved policy requires fresh native qualification.

The hosted profile retains 64 members, covered acknowledgments, Topic pending
while an authorized member is offline, and the ordinary ten-second recovery
target with visible catch-up for large membership backlogs.
