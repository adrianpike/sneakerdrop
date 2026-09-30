//! Every scenario, shortened, across a few seeds. For longer soak runs use
//! `cargo run --release -p sneakerdrop-sim -- sweep`.

use sneakerdrop_sim::{Config, run};

fn check(scenario: &str, seeds: std::ops::Range<u64>) {
    for seed in seeds {
        let mut cfg = Config::scenario(scenario, seed).unwrap();
        cfg.steps = 24 * 7;
        let report = run(cfg);
        assert!(report.ok(), "{report}");
        let m = &report.metrics;
        assert!(
            m.sealed_sent > 0 && m.delivered > 0,
            "scenario did nothing: {report}"
        );
    }
}

#[test]
fn baseline() {
    check("baseline", 0..3);
}

#[test]
fn radio() {
    check("radio", 0..2);
}

#[test]
fn morse() {
    check("morse", 0..2);
}

#[test]
fn hostile() {
    check("hostile", 0..2);
}

#[test]
fn chaos() {
    check("chaos", 0..2);
}

#[test]
fn pow() {
    check("pow", 0..2);
}

#[test]
fn badclock_diverges_only_as_specified() {
    let mut cfg = Config::badclock(1);
    cfg.steps = 24 * 7;
    cfg.p_compose = 0.03;
    let report = run(cfg);
    assert!(report.ok(), "{report}");
    // The lagging node rejects long-lived records (spec §7.2), yet every
    // other node still converges and delivers.
    assert!(report.metrics.bad_clock_horizon_rejects > 0, "{report}");
}

#[test]
fn adversaries_are_exercised() {
    let mut cfg = Config::hostile(3);
    cfg.steps = 24 * 7;
    let report = run(cfg);
    let m = &report.metrics;
    assert!(report.ok(), "{report}");
    assert!(
        m.forged_detected > 0,
        "no forged sealed messages were detected: {report}"
    );
    assert!(
        m.rejected.get("malformed").copied().unwrap_or(0) > 0,
        "{report}"
    );
    assert!(
        m.rejected.get("expired").copied().unwrap_or(0) > 0,
        "replays not exercised: {report}"
    );
}

#[test]
fn runs_are_deterministic() {
    let go = || {
        let mut cfg = Config::chaos(42);
        cfg.steps = 48;
        format!("{:?}", run(cfg).metrics)
    };
    assert_eq!(go(), go());
}
