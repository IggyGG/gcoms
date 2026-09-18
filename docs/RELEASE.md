# Signed developer-preview releases

Local Forgejo is authoritative. Public GitHub mirrors are `IggyGG/gcoms` and
`IggyGG/gchat`; the website remains on its current host and deploys from Forgejo.
The initial version is 0.1.0, explicitly labeled developer preview.

Targets are Linux x86_64, Windows 11 x86_64 with native MSVC, and macOS Apple
Silicon/Intel on GitHub-hosted runners. Every advertised installer must be signed;
macOS additionally requires notarization and stapling. The unavailable local Mac
is not required. A target is qualified only by evidence for its actual release
source and artifacts, not by historical development builds.

`release/publication.json` records public mirror URLs separately from private
Forgejo configuration. Public delivery is authorized; signing enrollment, private
reporting contacts, rights/operator reviews, and qualification results must still
be supplied and verified. Missing values are not fabricated.

1. Validate both repositories, source/history inventories, dependencies, licenses,
   generated APIs, package archives, and external consumers.
2. Publish inspected GComs Rust/npm packages in dependency order. Verify downloads
   and clean GChat registry builds; review final lockfiles before freezing source.
3. Create a new source-bound candidate and complete native, installer, network,
   fuzz/soak, and signing checks. See [release evidence](RELEASE_EVIDENCE.md).
4. Verify preflight, create signed annotated tags, and publish the canonical
   Forgejo releases. Copy identical artifacts and notes to GitHub, then verify
   their public hashes and installation behavior.
5. Update GChat's download manifest and deploy its static website from Forgejo.
   Keep previous versions available for rollback. Never replace published bytes.

GChat owns the executable [delivery runbook](https://github.com/IggyGG/gchat/blob/main/docs/PUBLIC_DELIVERY.md)
and [installation guide](https://github.com/IggyGG/gchat/blob/main/docs/INSTALL.md).
The candidate, preflight, and published stages remain distinct. Only actual
passed checks qualify a release; scripts do not convert incomplete work into
approval or claim an independent security audit.
