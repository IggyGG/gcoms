use gcoms_sim::{run, SimConfig};

#[test]
fn quick_sim_meets_delivery_and_latency() {
    let cfg = SimConfig::quick();
    let r = run(&cfg);
    assert!(r.delivery_ratio >= 0.95, "delivery {r:?}");
    assert!(r.p99_ms <= 15_000, "p99 {}", r.p99_ms);
}

#[test]
fn churn_does_not_collapse_delivery() {
    let mut cfg = SimConfig::quick();
    cfg.churn_per_hour = 0.6;
    cfg.avg_downtime_ms = 30_000;
    let r = run(&cfg);
    assert!(r.delivery_ratio >= 0.90, "delivery under churn {r:?}");
}

#[test]
fn larger_mesh_scales() {
    let mut cfg = SimConfig::quick();
    cfg.nodes = 1000;
    cfg.duration_ms = 45_000;
    cfg.message_times_ms = vec![15_000, 30_000];
    let r = run(&cfg);
    assert!(r.delivery_ratio >= 0.95, "delivery {r:?}");
    assert!(r.p99_ms <= 15_000, "p99 {}", r.p99_ms);
}
