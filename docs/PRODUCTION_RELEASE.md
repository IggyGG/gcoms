# Production release policy

On 2026-09-20 the owner selected production rollout and removed statistical privacy thresholds and mandatory 24-hour campaigns as release gates. Releases use bounded delivery, authentication, persistence/reopen, artifact-signature and rollback checks. Reuse source-bound completed checks for unchanged code; extended research and soak campaigns run separately and never impose a minimum release duration. Failed historical evidence stays failed.

Linux is the current released desktop platform. Windows, macOS and mobile qualification are deferred. Gh0st signs Linux artifacts with the pinned release key; this is self-signed distribution, not public-CA certification.

## Privacy improvements still outstanding

Production status does not mean traffic-analysis resistance is qualified. The four profile-22 comparisons (idle/chat and matched bulk/mixed, for time windows and connection observations) are improvement targets, not release vetoes. Existing unfavorable/calibration reports remain retained. Further work includes reducing observable activity and volume differences, establishing repeatable whole-client measurements across startup, DNS/HTTPS bootstrap, protected catalog access, reconnect/reopen and connection lifetimes, and measuring adverse-link behavior without pooled-relay substitutions. No <=0.55 claim is made.

## Data and protocol selection

GC/2 uses profile 22 explicitly. Start the desktop with `gchat-desktop --gc2-carrier`; use a separate `--home` for an existing legacy installation. Existing legacy profiles are not silently converted, reset or overwritten. Authentication, exact retained outboxes, signed capabilities and expiry checks remain enforced. The production relays retain their identity/TLS keys; current bootstrap credentials are generated from those identities, never converted from legacy authority.

## Receipt scope

Production executables are bound to GComs 726172785baacc25781d427c75faada5f8849d6b and GChat 0b599cfaa880828b5b0a04c99467c5616afc5b2c. Later policy/documentation/tooling commits do not relabel the frozen native CI or artifact source. The original signing receipt calls its trust policy `self-signed-preview`; the key and signed bytes are unchanged, while this owner decision changes deployment status to production.
