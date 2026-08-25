//! End-to-end tests against the real `guardian` binary.
//!
//! These spawn the actual process, send real UDP vitals packets at it, and read
//! the real HTTP surface. That round trip matters: the stale-reading bug (a
//! dead node's last good breathing value suppressing the apnea alarm forever)
//! passed every unit test and was caught here.
//!
//! No HTTP client dependency — the requests are small enough to write by hand.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Guardian under test, torn down on drop so a failing assertion cannot leak
/// the process.
struct Harness {
    child: Child,
    udp: SocketAddr,
    http: SocketAddr,
    sender: UdpSocket,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Ask the OS for a free port. The socket is closed before the child binds, so
/// there is a small race; the ports are per-test and retried on startup.
fn free_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

impl Harness {
    fn start(extra: &[&str]) -> Self {
        let udp_port = free_port();
        let http_port = free_port();
        let udp = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port));
        let http = SocketAddr::from((Ipv4Addr::LOCALHOST, http_port));

        let child = Command::new(env!("CARGO_BIN_EXE_guardian"))
            .args(["--udp-port", &udp_port.to_string()])
            .args(["--http-bind", &http.to_string()])
            .args(extra)
            // Suppressed to keep test output readable; every assertion below
            // reports the /status or /alerts body it actually saw.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn guardian");

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
        let h = Harness {
            child,
            udp,
            http,
            sender,
        };
        h.await_ready();
        h
    }

    /// Poll /healthz until the child is serving.
    fn await_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.try_request("GET", "/healthz").is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("guardian did not become ready on {}", self.http);
    }

    fn try_request(&self, method: &str, path: &str) -> Option<String> {
        let mut stream = TcpStream::connect_timeout(&self.http, Duration::from_millis(500)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .ok()?;
        let mut body = String::new();
        stream.read_to_string(&mut body).ok()?;
        let split = body.find("\r\n\r\n")?;
        Some(body[split + 4..].to_string())
    }

    fn get(&self, path: &str) -> serde_json::Value {
        let raw = self.try_request("GET", path).expect("request failed");
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("bad JSON from {path}: {e}\n{raw}"))
    }

    fn post(&self, path: &str) -> serde_json::Value {
        let raw = self.try_request("POST", path).expect("request failed");
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("bad JSON from {path}: {e}\n{raw}"))
    }

    fn send(&self, packet: &[u8]) {
        self.sender.send_to(packet, self.udp).expect("send vitals");
    }

    /// Send `node`'s reading repeatedly for `dur`, keeping it alive.
    fn stream(&self, packets: &[Vec<u8>], dur: Duration) {
        let deadline = Instant::now() + dur;
        while Instant::now() < deadline {
            for p in packets {
                self.send(p);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait until `pred` holds over the active alert list, or fail.
    fn await_alerts(&self, what: &str, timeout: Duration, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + timeout;
        let mut last = String::new();
        while Instant::now() < deadline {
            last = self.get("/alerts")["active"].to_string();
            if pred(&last) {
                return last;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("timed out waiting for {what}; active alerts were {last}");
    }
}

/// Record a staged scenario, then replay it into a fresh Guardian and assert it
/// reproduces the same alerts.
///
/// This is the workflow the fall heuristic needs: a staged fall (a weighted
/// cushion, a volunteer onto a mattress) is expensive to reproduce physically,
/// so it has to be capturable once and replayable against every later change.
#[test]
fn a_recorded_scenario_replays_to_the_same_alerts() {
    let dir = std::env::temp_dir().join(format!("guardian-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let capture = dir.join("fall-then-stillness.jsonl");

    // Stage: normal breathing, one fall, then present-but-not-breathing.
    {
        let rec = Harness::start(&[
            "--record",
            capture.to_str().unwrap(),
            "--apnea-timeout-secs",
            "2",
            "--node-silent-timeout-secs",
            "30",
        ]);
        rec.stream(
            &[vitals(1, true, false, 16.0, 72.0)],
            Duration::from_secs(1),
        );
        rec.send(&vitals(1, true, true, 16.0, 72.0));
        rec.stream(&[vitals(1, true, false, 0.0, 0.0)], Duration::from_secs(4));
        rec.await_alerts(
            "fall and apnea while recording",
            Duration::from_secs(6),
            |a| a.contains("fall") && a.contains("no_breathing"),
        );
    } // recorder dropped and killed; capture flushed per packet

    let packets = std::fs::read_to_string(&capture).expect("capture written");
    let lines = packets.lines().filter(|l| !l.trim().is_empty()).count();
    assert!(
        lines > 50,
        "expected a substantial capture, got {lines} packets"
    );

    // Replay into a fresh instance that has never seen a live node.
    let replayed = Harness::start(&[
        "--apnea-timeout-secs",
        "2",
        "--node-silent-timeout-secs",
        "30",
    ]);
    let status = Command::new(env!("CARGO_BIN_EXE_guardian-replay"))
        .arg(&capture)
        .args(["--target", &replayed.udp.to_string()])
        .args(["--speed", "2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run guardian-replay");
    assert!(status.success(), "replay exited with {status}");

    let active = replayed.await_alerts("replayed fall and apnea", Duration::from_secs(8), |a| {
        a.contains("fall") && a.contains("no_breathing")
    });
    assert!(active.contains("fall") && active.contains("no_breathing"));

    std::fs::remove_dir_all(&dir).ok();
}

/// `--inspect` describes a capture without sending anything.
#[test]
fn replay_inspect_summarises_without_sending() {
    let dir = std::env::temp_dir().join(format!("guardian-inspect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let capture = dir.join("inspect.jsonl");

    {
        let rec = Harness::start(&[
            "--record",
            capture.to_str().unwrap(),
            "--node-silent-timeout-secs",
            "30",
        ]);
        rec.stream(
            &[vitals(4, true, false, 14.0, 70.0)],
            Duration::from_secs(1),
        );
    }

    let out = Command::new(env!("CARGO_BIN_EXE_guardian-replay"))
        .arg(&capture)
        .arg("--inspect")
        .output()
        .expect("run guardian-replay --inspect");
    assert!(out.status.success());

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("nodes: {4:"), "summary was: {text}");
    assert!(
        text.contains("presence in 100% of packets"),
        "summary was: {text}"
    );
    assert!(text.contains("14.0 BPM"), "summary was: {text}");

    std::fs::remove_dir_all(&dir).ok();
}

/// A capture with nothing usable in it must fail loudly rather than sit silent.
#[test]
fn replay_rejects_an_empty_capture() {
    let dir = std::env::temp_dir().join(format!("guardian-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let capture = dir.join("empty.jsonl");
    std::fs::write(&capture, "").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_guardian-replay"))
        .arg(&capture)
        .output()
        .expect("run guardian-replay");
    assert!(
        !out.status.success(),
        "must not exit 0 on an unusable capture"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Write an executable notify script that appends each alert to a log file.
fn notify_script(dir: &std::path::Path, log: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("notify.sh");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n             printf '%s|%s|%s\\n' \"$GUARDIAN_ALERT_KIND\" \"$GUARDIAN_TRANSITION\"              \"$GUARDIAN_SEVERITY\" >> {}\n",
            log.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

/// A fall must actually reach the notify command, not just the log.
#[test]
fn alerts_reach_the_notify_command() {
    let dir = std::env::temp_dir().join(format!("guardian-notify-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("delivered.txt");
    let script = notify_script(&dir, &log);

    let h = Harness::start(&[
        "--notify-command",
        script.to_str().unwrap(),
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "30",
        "--repeat-alert-secs",
        "0",
    ]);

    h.send(&vitals(1, true, false, 16.0, 72.0));
    h.send(&vitals(1, true, true, 16.0, 72.0));
    h.await_alerts("fall", Duration::from_secs(5), |a| a.contains("fall"));

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut delivered = String::new();
    while Instant::now() < deadline {
        delivered = std::fs::read_to_string(&log).unwrap_or_default();
        if delivered.contains("fall") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        delivered.contains("fall|raised|care"),
        "notify command did not receive the fall: {delivered:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// An unacknowledged care alert must keep notifying, and stop once acked.
#[test]
fn unacknowledged_alerts_are_repeated_until_acknowledged() {
    let dir = std::env::temp_dir().join(format!("guardian-repeat-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("delivered.txt");
    let script = notify_script(&dir, &log);

    let h = Harness::start(&[
        "--notify-command",
        script.to_str().unwrap(),
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "30",
        "--repeat-alert-secs",
        "1",
    ]);

    h.send(&vitals(1, true, false, 16.0, 72.0));
    h.send(&vitals(1, true, true, 16.0, 72.0));
    h.await_alerts("fall", Duration::from_secs(5), |a| a.contains("fall"));

    let count_reminders = |log: &std::path::Path| {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("fall|reminder"))
            .count()
    };

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && count_reminders(&log) < 2 {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        count_reminders(&log) >= 2,
        "expected repeated reminders, log was {:?}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );

    // Acknowledging stops them.
    assert_eq!(h.post("/alerts/fall/ack")["cleared"], true);
    std::thread::sleep(Duration::from_millis(500));
    let after_ack = count_reminders(&log);
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        count_reminders(&log),
        after_ack,
        "reminders continued after acknowledgement"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A notify command that hangs must not stall packet reception, or the monitor
/// manufactures the node-silence it was asked to report.
#[test]
fn a_hanging_notify_command_does_not_stall_reception() {
    let dir = std::env::temp_dir().join(format!("guardian-hang-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("hang.sh");
    std::fs::write(
        &script,
        "#!/bin/sh
sleep 30
",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let h = Harness::start(&[
        "--notify-command",
        script.to_str().unwrap(),
        "--notify-timeout-secs",
        "30",
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "4",
        "--repeat-alert-secs",
        "0",
    ]);

    // Trigger a fall, which starts a notify command that will hang for 30s.
    h.send(&vitals(1, true, false, 16.0, 72.0));
    h.send(&vitals(1, true, true, 16.0, 72.0));
    h.await_alerts("fall", Duration::from_secs(5), |a| a.contains("fall"));

    // Meanwhile keep the node reporting. If reception were stalled behind the
    // notifier, node 1 would be declared silent.
    h.stream(
        &[vitals(1, true, false, 16.0, 72.0)],
        Duration::from_secs(8),
    );

    let active = h.get("/alerts")["active"].to_string();
    assert!(
        !active.contains("node_silent"),
        "reception stalled behind the notify command: {active}"
    );
    assert_eq!(h.get("/status")["nodes"][0]["online"], true);

    std::fs::remove_dir_all(&dir).ok();
}

/// Build a 32-byte `edge_vitals_pkt_t` matching `edge_processing.h:140`.
fn vitals(node_id: u8, presence: bool, fall: bool, breathing_bpm: f64, hr_bpm: f64) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    let flags = u8::from(presence) | (u8::from(fall) << 1) | (1 << 2);
    b[0..4].copy_from_slice(&0xC511_0002u32.to_le_bytes());
    b[4] = node_id;
    b[5] = flags;
    b[6..8].copy_from_slice(&((breathing_bpm * 100.0) as u16).to_le_bytes());
    b[8..12].copy_from_slice(&((hr_bpm * 10_000.0) as u32).to_le_bytes());
    b[12] = (-55i8) as u8;
    b[13] = u8::from(presence);
    b[16..20].copy_from_slice(&0.25f32.to_le_bytes());
    b[20..24].copy_from_slice(&(if presence { 0.9f32 } else { 0.0 }).to_le_bytes());
    b[24..28].copy_from_slice(&123_456u32.to_le_bytes());
    b
}

#[test]
fn healthy_breathing_person_raises_nothing() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "2",
        "--node-silent-timeout-secs",
        "4",
    ]);
    h.stream(
        &[vitals(1, true, false, 16.0, 72.0)],
        Duration::from_secs(5),
    );

    let status = h.get("/status");
    assert_eq!(status["present"], true, "status was {status}");
    assert_eq!(status["active_alerts"].to_string(), "[]");
    assert_eq!(status["nodes"][0]["breathing_plausible"], true);
    assert_eq!(status["nodes"][0]["online"], true);
}

#[test]
fn fall_fires_latches_and_clears_only_on_acknowledgement() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "30",
    ]);
    h.send(&vitals(1, true, false, 16.0, 72.0));
    h.send(&vitals(1, true, true, 16.0, 72.0));
    h.await_alerts("fall", Duration::from_secs(5), |a| a.contains("fall"));

    // Flag drops on subsequent packets; the alert must survive.
    h.stream(
        &[vitals(1, true, false, 16.0, 72.0)],
        Duration::from_secs(2),
    );
    assert!(
        h.get("/alerts")["active"].to_string().contains("fall"),
        "fall must latch through the flag clearing"
    );

    assert_eq!(h.post("/alerts/fall/ack")["cleared"], true);
    assert!(!h.get("/alerts")["active"].to_string().contains("fall"));
    assert_eq!(
        h.post("/alerts/fall/ack")["cleared"],
        false,
        "ack is idempotent"
    );
}

#[test]
fn apnea_fires_while_present_and_clears_on_recovery() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "2",
        "--node-silent-timeout-secs",
        "30",
    ]);
    h.send(&vitals(1, true, false, 16.0, 72.0));

    // Present, but every reading is outside the 6-30 BPM band.
    h.stream(&[vitals(1, true, false, 0.0, 0.0)], Duration::from_secs(1));
    assert!(
        !h.get("/alerts")["active"]
            .to_string()
            .contains("no_breathing"),
        "must not fire before the timeout"
    );

    let flooded = std::thread::spawn({
        let addr = h.udp;
        move || {
            let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(6);
            while Instant::now() < deadline {
                let _ = s.send_to(&vitals(1, true, false, 0.0, 0.0), addr);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });
    h.await_alerts("apnea", Duration::from_secs(8), |a| {
        a.contains("no_breathing")
    });
    flooded.join().unwrap();

    h.stream(
        &[vitals(1, true, false, 16.0, 72.0)],
        Duration::from_secs(1),
    );
    assert!(!h.get("/alerts")["active"]
        .to_string()
        .contains("no_breathing"));
}

/// Leaving the room must never read as "stopped breathing". This is the false
/// alarm that would get the product unplugged.
#[test]
fn leaving_the_room_never_raises_apnea() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "1",
        "--node-silent-timeout-secs",
        "30",
    ]);
    h.send(&vitals(1, true, false, 16.0, 72.0));
    h.stream(&[vitals(1, false, false, 0.0, 0.0)], Duration::from_secs(6));

    let active = h.get("/alerts")["active"].to_string();
    assert!(
        !active.contains("no_breathing"),
        "apnea fired with nobody present: {active}"
    );
    assert_eq!(h.get("/status")["present"], false);
}

/// Regression, originally found end-to-end: node 2 reports healthy breathing
/// and then dies. Its stale reading must not go on satisfying the breathing
/// check, or a node failing at the wrong moment silently disables the alarm.
#[test]
fn a_dead_node_cannot_suppress_apnea_for_a_live_one() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "2",
        "--node-silent-timeout-secs",
        "3",
    ]);

    // Node 2 speaks once, healthily, then never again.
    h.send(&vitals(2, true, false, 15.5, 71.0));

    // Node 1 stays alive and present but stops breathing.
    let feeder = std::thread::spawn({
        let addr = h.udp;
        move || {
            let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(14);
            while Instant::now() < deadline {
                let _ = s.send_to(&vitals(1, true, false, 0.0, 0.0), addr);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });

    h.await_alerts(
        "apnea despite node 2's stale reading",
        Duration::from_secs(15),
        |a| a.contains("no_breathing"),
    );
    feeder.join().unwrap();

    // Node 2's death is also surfaced as equipment health.
    assert!(h.get("/alerts")["active"]
        .to_string()
        .contains("node_silent"));
}

/// Total equipment failure must report as equipment failure, never as apnea.
#[test]
fn total_node_failure_reports_equipment_not_apnea() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "2",
        "--node-silent-timeout-secs",
        "3",
    ]);
    h.send(&vitals(1, true, false, 16.0, 72.0));

    let active = h.await_alerts("node_silent", Duration::from_secs(10), |a| {
        a.contains("node_silent")
    });
    assert!(
        !active.contains("no_breathing"),
        "equipment failure presented as apnea: {active}"
    );

    // Still true after the apnea window has long passed.
    std::thread::sleep(Duration::from_secs(3));
    assert!(!h.get("/alerts")["active"]
        .to_string()
        .contains("no_breathing"));
    assert_eq!(
        h.get("/status")["present"],
        false,
        "stale presence must expire"
    );
}

/// An untrusted node is observed but cannot raise anything.
#[test]
fn untrusted_nodes_are_observed_but_cannot_alert() {
    let h = Harness::start(&[
        "--alert-nodes",
        "1",
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "30",
    ]);
    h.stream(&[vitals(3, true, true, 0.0, 0.0)], Duration::from_secs(2));

    assert_eq!(
        h.get("/alerts")["active"].to_string(),
        "[]",
        "node 3 must not alert"
    );

    let status = h.get("/status");
    assert_eq!(status["nodes"][0]["node_id"], 3, "but it is still observed");
    assert_eq!(status["nodes"][0]["trusted_for_alerts"], false);
    assert_eq!(
        status["present"], false,
        "untrusted presence does not count"
    );
}

/// Heart rate is carried for observability and never drives an alert.
#[test]
fn heartrate_is_surfaced_but_never_alerts() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "30",
    ]);
    h.stream(&[vitals(1, true, false, 16.0, 0.0)], Duration::from_secs(2));

    let status = h.get("/status");
    assert_eq!(status["active_alerts"].to_string(), "[]");
    assert_eq!(status["nodes"][0]["heartrate_bpm_unvalidated"], 0.0);
    assert!(status["heartrate"]
        .as_str()
        .unwrap()
        .contains("unvalidated"));
}

/// Malformed and foreign traffic must be ignored without disturbing state.
#[test]
fn junk_traffic_is_ignored() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "30",
    ]);
    h.send(&vitals(1, true, false, 16.0, 72.0));

    h.send(&[]);
    h.send(&[0xAA; 3]);
    h.send(&[0xFF; 64]);
    let mut wrong_magic = vitals(9, true, true, 0.0, 0.0);
    wrong_magic[0..4].copy_from_slice(&0xC511_0001u32.to_le_bytes()); // CSI frame
    h.send(&wrong_magic);
    let truncated = vitals(9, true, true, 0.0, 0.0)[..20].to_vec();
    h.send(&truncated);

    h.stream(
        &[vitals(1, true, false, 16.0, 72.0)],
        Duration::from_secs(1),
    );

    let status = h.get("/status");
    assert_eq!(status["active_alerts"].to_string(), "[]");
    let nodes = status["nodes"].as_array().unwrap();
    assert_eq!(
        nodes.len(),
        1,
        "junk must not create phantom nodes: {status}"
    );
    assert_eq!(nodes[0]["node_id"], 1);
}

/// The 48-byte ADR-063 fused packet parses on the same socket and surfaces its
/// mmWave fields.
#[test]
fn fused_mmwave_packets_are_accepted() {
    let h = Harness::start(&[
        "--apnea-timeout-secs",
        "30",
        "--node-silent-timeout-secs",
        "30",
    ]);

    let mut b = vec![0u8; 48];
    b[0..4].copy_from_slice(&0xC511_0004u32.to_le_bytes());
    b[4] = 7;
    b[5] = 0b0000_1001; // presence | mmwave_present
    b[6..8].copy_from_slice(&1_580u16.to_le_bytes()); // 15.80 BPM
    b[8..12].copy_from_slice(&715_000u32.to_le_bytes()); // 71.5 BPM
    b[12] = (-50i8) as u8;
    b[13] = 1;
    b[14] = 2; // mmwave_type
    b[15] = 88; // fusion_confidence
    b[20..24].copy_from_slice(&0.95f32.to_le_bytes());
    b[28..32].copy_from_slice(&71.5f32.to_le_bytes());
    b[32..36].copy_from_slice(&15.8f32.to_le_bytes());

    h.stream(&[b], Duration::from_secs(1));

    let status = h.get("/status");
    assert_eq!(status["present"], true, "status was {status}");
    assert_eq!(status["nodes"][0]["node_id"], 7);
    assert_eq!(status["nodes"][0]["breathing_rate_bpm"], 15.8);
    assert_eq!(status["active_alerts"].to_string(), "[]");
}
