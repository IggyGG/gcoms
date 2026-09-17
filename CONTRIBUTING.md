# Contributing

Start with README.md and TESTING.md. Open an issue describing the observable
problem or proposal before a large change. Small fixes may go directly to a pull
request on the project's authoritative Forgejo repository.

Keep protocol changes separate from application behavior. Include compatibility,
authorization, persistence and error behavior in API changes. Run the documented
checks against the combined workspace. Include commands, platform and results in
the pull request; never include credentials, contact cards, invitations or private
message archives in reports. Use disposable local fixtures for tests.

Generated files must be regenerated from their source schemas. Tests should prove
observable behavior, including loss/recovery where relevant. Do not make a flaky
test green by weakening its assertion or changing an authorization boundary.

Unless you explicitly state otherwise, intentionally submitted contributions are
licensed under MIT OR Apache-2.0, without additional terms. You must have the right
to contribute them. Preserve third-party copyright and license notices. A license
choice does not grant rights to the project names or logos.

Maintainers review changes and publish tagged releases. A pull request author
should obtain independent review before merging security-sensitive changes. The
initial maintainer roster and public reporting channels must be set in the release
configuration before public publication.
