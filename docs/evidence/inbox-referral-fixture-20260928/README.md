# Protected inbox fixture renewal

The five-relay fixture seeded the client but left each relay's public referral directory empty. When the initial client introductions expire, retained guards can renew only their own introductions. Three fresh guards cannot provide the independent relays needed for a five-hop route.

The fixture now explicitly configures the five public relay introductions, separately from the client directory, and runs the existing authenticated relay referral refresh task. The original fresh-start test remains. A second test shortens only the initial client authority, lets it expire, and obtains the private inbox card and legacy-card control through the normal transport. The legacy control obtains a current introduction from its fixture service rather than reusing an expired initial seed. Production code, authority rules, and the existing 240/120-second test deadlines are unchanged.

Five focused cases pass, one explicitly authorized live probe stays ignored, and strict all-feature/all-target node Clippy passes on 817 unchanged source paths. The paired disposable control passes with public referrals and fails without them. Both earlier 15-second diagnostic timeouts and the missing-Clippy-component attempt are retained. The original Windows failure remains a failure: this reproduces a fixture defect without claiming its exact wall-clock cause was proven from that log.

This is affected-test validation, not a relabeling of any full native or signed release receipt. `summary.json` binds the final test bytes and retained evidence.
