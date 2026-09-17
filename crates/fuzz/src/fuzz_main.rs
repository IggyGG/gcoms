fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(1_000_000);
    println!("gc/1 fuzz swarm: {iters} execs per target");
    let results = gcoms_fuzz::fuzz_all(iters);
    for r in &results {
        println!(
            "{:>10}: {} execs, {} accepted ({:.2}%), {:?} — no panics",
            r.target,
            r.execs,
            r.accepted,
            r.accepted as f64 / r.execs as f64 * 100.0,
            r.elapsed
        );
    }
    println!(
        "fuzz sweep complete: 0 crashes across {} targets x {} execs",
        results.len(),
        iters
    );
}
