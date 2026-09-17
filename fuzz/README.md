# Coverage-guided parser fuzzing

This isolated workspace uses cargo-fuzz/libFuzzer. It complements the older
`gcfuzz` random mutation harness; those mutation counts are not coverage metrics.
With a nightly Rust toolchain and cargo-fuzz installed:

```sh
cargo +nightly fuzz run cells -- -max_len=16384 -max_total_time=60
```

The target performs bounded local cell parsing and checks successful re-encoding.
It never contacts a network. Keep minimized regression fixtures free of private
data. Corpus/artifacts are ignored; add reviewed small fixtures to conformance.
A smoke run is not a completed fuzz campaign or security review.
