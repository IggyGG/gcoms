# Developer-preview release

The public release unit is GComs source and Rust/npm packages plus the separate
GChat source and qualified native artifacts. Forgejo is authoritative. A clean
history preserves source attribution and private originals; it is not a rights or
secret audit by itself.

## Preparation

1. Run TESTING.md, archive/consumer checks, current advisories and license review.
2. Review IMPORT.json and NOTICE.md against the retained source history. Confirm
   distribution rights for code, logos, fonts and bundled data.
3. Fill release/publication.json with the actual public Forgejo/companion URLs,
   maintainers and private security/conduct contacts. Update repository metadata,
   README links and package metadata together.
4. Qualify exact-source native platforms and the operated network. Record evidence
   and signing identities; do not substitute private historical performance results.
5. Run `python3 scripts/check-release.py`. Missing inputs fail closed.

## Publication

Create signed, annotated preview tags only after required checks pass. Publish
Rust crates in dependency order (the package-consumer script prints the set); publish
`@gcoms/rpc-codegen` and `@gcoms/rpc` from inspected tarballs with declarations and
licenses. Install from the actual registries in an empty consumer and GChat checkout.
Then build/sign native GChat artifacts against those registry versions, attach
checksums/provenance and publish release notes on Forgejo. Keep registry credentials
in protected release-runner secrets, never in source or untrusted pull-request jobs.

The initial version is 0.1.0, explicitly labeled developer preview. Do not overwrite
an existing registry version or tag. A bad package needs a new version and advisory
or deprecation as appropriate; preserve the original artifact and evidence.

## Remaining external decisions

Public endpoints and contacts, publisher accounts/certificates, distribution rights,
operator capacity and native acceptance must be supplied/confirmed by the project
owner. This repository intentionally contains no fabricated publishing identity.
Tests cannot establish those decisions. Independent crypto/privacy review and
mobile support remain outside the preview's qualified claims.

Pre-publication application lockfiles can be qualified using
`scripts/check-registry-consumer.py`. It serves inspected `.crate` archives and
Cargo-cached third-party packages through a loopback sparse registry, while retaining
canonical crates.io identities and checksums in the application lockfile. Re-run it
after changing any package archive; do not publish stale application checksums.
