# GComs network client

This crate validates signed network defaults, retains monotonic trust state and
manages invitation-scoped discovery and names. The library embeds no operated
network or provider URLs. Its host supplies `InstalledNetwork` from independently
trusted configuration, then passes it to `NetworkClient::for_profile(profile,
installed)` or `NetworkClient::open(state_directory, installed)`.

An invitation is authorization to use a network, not a trust root. Import it with
`import_invitation` or the bounded private-file helper after installing the expected
network identity. Defaults are checked for identity, signature, validity interval
and sequence; retained state prevents rollback. Do not delete that state to work
around an expired or unavailable provider.

The node CLI accepts `--network-config /path/to/trusted-network.json` alongside
its invitation/provider options. GChat supplies its own signed bundled defaults.
Independent applications must choose their own trust distribution, rotation and
operator support process. Public configuration contains public keys and signed
data; invitation secrets and local credentials belong in private storage.

Tests use locally served TLS fixtures and synthetic provider names. See the
repository SPEC.md, SECURITY.md and TESTING.md for limits and platform coverage.
Licensed under MIT OR Apache-2.0; this is a developer preview.
