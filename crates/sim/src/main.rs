use gcoms_sim::{cover_sweep, run, SimConfig};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|a| a == "--cover").unwrap_or(false) {
        let rows = cover_sweep(&[3000], &[0.1, 0.2, 0.3, 0.5], 60);
        println!(
            "{:>9} {:>10} {:>12} {:>9} {:>9} {:>9} {:>11} {:>10}",
            "round_ms",
            "cover_prob",
            "mode",
            "idle_fpr",
            "active_tpr",
            "best_acc",
            "idle_KiB/s",
            "verdict"
        );
        for r in &rows {
            let mode = if r.rate_matched { "matched" } else { "naive" };
            let verdict = if r.best_accuracy >= 0.95 {
                "DETECTABLE"
            } else if r.best_accuracy >= 0.75 {
                "borderline"
            } else {
                "blurred"
            };
            println!(
                "{:>9} {:>10.1} {:>12} {:>9.3} {:>9.3} {:>9.3} {:>11.2} {:>10}",
                r.round_ms,
                r.cover_prob,
                mode,
                r.idle_fpr,
                r.active_tpr,
                r.best_accuracy,
                r.idle_kibps,
                verdict
            );
        }
        return ExitCode::SUCCESS;
    }
    let nodes: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(5000);
    let msgs: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(5);

    let mut cfg = if nodes >= 1000 {
        SimConfig::full()
    } else {
        SimConfig::quick()
    };
    cfg.nodes = nodes;
    cfg.message_times_ms = (1..=msgs)
        .map(|i| 20_000 + (i - 1) * (cfg.duration_ms - 30_000) / msgs.max(1))
        .collect();

    let started = std::time::Instant::now();
    let report = run(&cfg);
    println!(
        "nodes={} messages={} sim_ms={}",
        cfg.nodes,
        cfg.message_times_ms.len(),
        cfg.duration_ms
    );
    println!("wall_clock_ms={}", started.elapsed().as_millis());
    println!("delivery_ratio={:.4}", report.delivery_ratio);
    println!(
        "latency_ms p50={} p90={} p99={} max={}",
        report.p50_ms, report.p90_ms, report.p99_ms, report.max_ms
    );
    println!("dup_ratio={:.3}", report.dup_ratio);
    println!("per_node_kibps_p99={:.2}", report.per_node_kibps_p99);
    println!("hops_mean={:.2}", report.hops_mean);
    println!("avg_view_len={:.1}", report.avg_view_len);
    println!("dropped_offline={}", report.dropped_offline);

    let gates = [
        ("delivery >= 0.995", report.delivery_ratio >= 0.995),
        ("p99 <= 15000ms", report.p99_ms <= 15_000),
        ("bandwidth <= 128 KiB/s", report.per_node_kibps_p99 <= 128.0),
        ("dup_ratio <= 0.35", report.dup_ratio <= 0.35),
    ];
    println!();
    for (name, pass) in gates {
        println!("gate {}: {}", name, if pass { "PASS" } else { "FAIL" });
    }
    let all = gates.iter().all(|(_, p)| *p);
    println!("G-M5 overall: {}", if all { "PASS" } else { "FAIL" });
    if all {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
