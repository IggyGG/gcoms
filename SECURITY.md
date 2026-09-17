# Security policy

This is a developer preview. It has not received an independent, end-to-end
security review. Passing tests is not a claim of anonymity, traffic-analysis
resistance, production availability, or security against a compromised endpoint.

Do not post unpatched security issues, private keys, invitations, contact cards,
archives or user data in public issues. The private reporting address must be
configured in release/publication.json before this repository is made public.
Until then, this checkout is release preparation and has no public reporting SLA.

A useful report describes the affected version, expected boundary, observed
behavior and a minimal disposable fixture. Maintainers triage privately, agree a
remediation and disclosure timeline with the reporter, and publish an advisory
with affected versions and mitigation. Only the current preview release receives
fixes; pre-1.0 APIs may change with documented migration instructions.

Report dependency vulnerabilities through the same channel. Release checks cover
source inventories, dependency advisories, artifact contents, and supported native
platforms. An advisory database outage is an incomplete check, not a passing result.
