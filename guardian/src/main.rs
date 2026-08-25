//! Guardian — a privacy-preserving elderly-care room monitor.
//!
//! Receives `edge_vitals_pkt_t` / `edge_fused_vitals_pkt_t` over UDP from
//! ESP32-S3 CSI nodes, tracks presence / respiration / fall conditions, and
//! raises alerts. No camera, no pose estimation, no raw CSI leaves the node.
//!
//! The design constraint that shapes this whole binary: the firmware's edge
//! processing is correct and the server must not re-derive its numbers. See
//! GUARDIAN.md for the measurements that established this.

use guardian::{alerts, capture, net, notify, vitals};

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use alerts::{AlertConfig, AlertEngine, AlertEvent, AlertKind, Transition};
use capture::Recorder;
use net::Allowlist;
use notify::Notifier;
use vitals::MAX_PACKET_LEN;

#[derive(Parser, Debug)]
#[command(
    name = "guardian",
    about = "Privacy-preserving elderly-care room monitor"
)]
struct Args {
    /// UDP port for ESP32 edge vitals packets.
    #[arg(long, default_value = "5005")]
    udp_port: u16,

    /// UDP bind address. Defaults to loopback; binding to a routable address
    /// is an explicit operator choice and requires `--udp-allow` or
    /// `--udp-insecure-lan`.
    #[arg(long, default_value = "127.0.0.1", env = "GUARDIAN_UDP_BIND")]
    udp_bind: IpAddr,

    /// Source IP/CIDR allowlist for inbound vitals (comma-separated,
    /// repeatable). Loopback is always allowed.
    #[arg(long = "udp-allow", value_name = "IP/CIDR", env = "GUARDIAN_UDP_ALLOW")]
    udp_allow: Vec<String>,

    /// Permit a routable bind with no allowlist. The vitals packets are
    /// unauthenticated, so anything on the LAN can then forge them.
    #[arg(long)]
    udp_insecure_lan: bool,

    /// Address for the read-only status/ack HTTP surface.
    #[arg(long, default_value = "127.0.0.1:8770")]
    http_bind: SocketAddr,

    /// Node IDs allowed to drive alerts (comma-separated). When unset, every
    /// node that reports can alert. Use this to observe a node whose placement
    /// or link quality is not yet trusted without letting it raise alarms.
    #[arg(long = "alert-nodes", value_delimiter = ',')]
    alert_nodes: Vec<u8>,

    /// Seconds a present person may go without a plausible breathing reading.
    #[arg(long, default_value = "60")]
    apnea_timeout_secs: u64,

    /// Seconds with nobody detected before flagging prolonged absence.
    #[arg(long, default_value = "43200")]
    absence_timeout_secs: u64,

    /// Seconds a node may go quiet before it is considered offline.
    #[arg(long, default_value = "60")]
    node_silent_timeout_secs: u64,

    /// Command to run on every alert transition. Receives GUARDIAN_ALERT_KIND,
    /// GUARDIAN_TRANSITION, GUARDIAN_SEVERITY, GUARDIAN_DETAIL and, for node
    /// health events, GUARDIAN_NODE_ID in its environment.
    ///
    /// Without this, alerts are only logged — which notifies nobody.
    #[arg(long, value_name = "PATH")]
    notify_command: Option<std::path::PathBuf>,

    /// Seconds a single notify attempt may take before it is killed.
    #[arg(long, default_value = "10")]
    notify_timeout_secs: u64,

    /// Attempts for a care alert before giving up. Node health is never
    /// retried.
    #[arg(long, default_value = "3")]
    notify_attempts: u32,

    /// Seconds between reminders for a care alert that is still active and
    /// unacknowledged. 0 disables reminders.
    #[arg(long, default_value = "300")]
    repeat_alert_secs: u64,

    /// Record every accepted packet to a capture file for later replay.
    ///
    /// A capture records when a specific person was present, moving, and
    /// breathing. Treat it as health data: keep it local and never commit it.
    #[arg(long, value_name = "PATH")]
    record: Option<std::path::PathBuf>,
}

struct AppState {
    engine: Mutex<AlertEngine>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "guardian=info".into()),
        )
        .init();

    let args = Args::parse();

    let allowlist = Allowlist::parse(&args.udp_allow).map_err(|e| format!("--udp-allow {e}"))?;

    // Least authority by default: a routable bind with no allowlist accepts
    // forged vitals from anything on the network, so it must be opted into.
    if !args.udp_bind.is_loopback() && allowlist.is_empty() && !args.udp_insecure_lan {
        return Err(format!(
            "refusing to bind {} without a source allowlist.\n\
             The vitals packets are unauthenticated, so any host on the network could \
             forge presence, breathing, or fall readings.\n\
             Pass --udp-allow <IP/CIDR> with your nodes' addresses, or --udp-insecure-lan \
             to accept that risk deliberately.",
            args.udp_bind
        )
        .into());
    }

    let trusted_nodes = if args.alert_nodes.is_empty() {
        warn!(
            "no --alert-nodes set: every reporting node can raise alerts. A node with \
             poor placement or an unstable link will produce false alarms; see GUARDIAN.md."
        );
        None
    } else {
        info!(nodes = ?args.alert_nodes, "alerts restricted to these nodes");
        Some(args.alert_nodes.clone())
    };

    let config = AlertConfig {
        apnea_timeout: Duration::from_secs(args.apnea_timeout_secs),
        absence_timeout: Duration::from_secs(args.absence_timeout_secs),
        node_silent_timeout: Duration::from_secs(args.node_silent_timeout_secs),
        repeat_care_alert: (args.repeat_alert_secs > 0)
            .then(|| Duration::from_secs(args.repeat_alert_secs)),
    };

    let state = Arc::new(AppState {
        engine: Mutex::new(AlertEngine::new(config, trusted_nodes, Instant::now())),
    });

    let notifier = match &args.notify_command {
        Some(path) => {
            // Checked at startup rather than at 03:00 on the night it matters.
            if !path.is_file() {
                return Err(format!("--notify-command {}: not a file", path.display()).into());
            }
            info!(command = %path.display(), "alerts will be delivered via notify command");
            Some(Notifier::new(
                path.clone(),
                Duration::from_secs(args.notify_timeout_secs),
                args.notify_attempts,
            ))
        }
        None => {
            warn!("no --notify-command set: alerts are written to the log only, which notifies nobody");
            None
        }
    };

    let recorder = match &args.record {
        Some(path) => {
            let r =
                Recorder::create(path).map_err(|e| format!("--record {}: {e}", path.display()))?;
            warn!(
                path = %path.display(),
                "recording vitals to disk; captures contain personal health data"
            );
            Some(r)
        }
        None => None,
    };

    let udp_addr = SocketAddr::new(args.udp_bind, args.udp_port);
    let socket = UdpSocket::bind(udp_addr).await?;
    info!(%udp_addr, "listening for ESP32 edge vitals");
    if !allowlist.is_empty() {
        info!("source allowlist active ({} entries)", args.udp_allow.len());
    } else if !args.udp_bind.is_loopback() {
        warn!("routable bind with no source allowlist (--udp-insecure-lan)");
    }

    let listener = tokio::net::TcpListener::bind(args.http_bind).await?;
    info!(http = %args.http_bind, "status surface on /status, /alerts, /healthz");

    let router = Router::new()
        .route("/status", get(status))
        .route("/alerts", get(active_alerts))
        .route("/alerts/fall/ack", post(ack_fall))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state.clone());

    tokio::select! {
        r = receive_loop(socket, allowlist, state.clone(), recorder, notifier.clone()) => r?,
        r = tick_loop(state.clone(), config, notifier.clone()) => r,
        r = axum::serve(listener, router) => r?,
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }

    Ok(())
}

async fn receive_loop(
    socket: UdpSocket,
    allowlist: Allowlist,
    state: Arc<AppState>,
    mut recorder: Option<Recorder>,
    notifier: Option<Notifier>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; MAX_PACKET_LEN];
    let mut dropped_unauthorised: u64 = 0;
    let capture_started = Instant::now();

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "UDP receive failed");
                continue;
            }
        };

        if !allowlist.permits(src.ip()) {
            dropped_unauthorised += 1;
            // Rate-limited: a misconfigured allowlist would otherwise flood the
            // log with one line per packet at ~15 Hz per node.
            if dropped_unauthorised.is_power_of_two() {
                warn!(%src, count = dropped_unauthorised, "dropped packet from disallowed source");
            }
            continue;
        }

        let Some(reading) = vitals::parse_vitals(&buf[..len]) else {
            continue;
        };

        // Recorded after parsing, so a capture holds only well-formed vitals
        // and replaying it exercises the same path the live nodes drive.
        if let Some(rec) = recorder.as_mut() {
            let offset_ms = capture_started.elapsed().as_millis() as u64;
            if let Err(e) = rec.record(offset_ms, &buf[..len]) {
                error!(error = %e, "capture write failed; continuing without recording");
                recorder = None;
            }
        }

        let now = Instant::now();
        let events = state.engine.lock().await.ingest(&reading, now);
        report(&events, notifier.as_ref());
    }
}

async fn tick_loop(state: Arc<AppState>, config: AlertConfig, notifier: Option<Notifier>) -> ! {
    let period = tick_period(&config);
    info!(?period, "evaluating time-based alert conditions");
    let mut ticker = tokio::time::interval(period);
    loop {
        ticker.tick().await;
        let events = state.engine.lock().await.tick(Instant::now());
        report(&events, notifier.as_ref());
    }
}

/// How often to re-evaluate time-based conditions.
///
/// Derived from the *shortest* configured threshold, not just one of them: a
/// period tied only to the node-silence window would let a shorter apnea
/// timeout or reminder interval fire late, or in the reminder's case never at
/// the requested cadence at all. The absence timeout is excluded because it is
/// measured in hours and would otherwise pin the period at the ceiling.
fn tick_period(config: &AlertConfig) -> Duration {
    let shortest = [
        Some(config.apnea_timeout),
        Some(config.node_silent_timeout),
        config.repeat_care_alert,
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(Duration::from_secs(4));

    // Four evaluations per window keeps a timeout from firing a full window
    // late, and the clamp keeps a pathological config from spinning or from
    // going effectively unresponsive.
    (shortest / 4).clamp(Duration::from_millis(200), Duration::from_secs(5))
}

/// Log alert transitions and hand them to the notify command.
///
/// Logging happens first and unconditionally, so a failing or absent notifier
/// still leaves a record of what the monitor saw.
///
/// Delivery is spawned rather than awaited: a notify command that hangs for its
/// full timeout, retried, would otherwise stall the UDP receive loop for tens
/// of seconds, dropping packets and manufacturing the very node-silence it was
/// being asked to report.
fn report(events: &[AlertEvent], notifier: Option<&Notifier>) {
    for event in events {
        match (event.transition, event.kind.is_care_alert()) {
            (Transition::Raised, true) => {
                error!(kind = ?event.kind, "ALERT: {}", event.detail)
            }
            (Transition::Reminder, _) => {
                error!(kind = ?event.kind, "STILL ACTIVE: {}", event.detail)
            }
            (Transition::Raised, false) => {
                warn!(kind = ?event.kind, "node health: {}", event.detail)
            }
            (Transition::Cleared, _) => {
                info!(kind = ?event.kind, "cleared: {}", event.detail)
            }
        }

        if let Some(n) = notifier {
            let (n, event) = (n.clone(), event.clone());
            tokio::spawn(async move { n.deliver(&event).await });
        }
    }
}

async fn status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(state.engine.lock().await.snapshot(Instant::now()))
}

async fn active_alerts(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "active": state.engine.lock().await.active_alerts() }))
}

async fn ack_fall(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let cleared = state.engine.lock().await.acknowledge(AlertKind::Fall);
    if cleared {
        info!("fall alert acknowledged");
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "cleared": cleared })),
    )
}

#[cfg(test)]
mod tick_period_tests {
    use super::*;

    fn config(apnea: u64, silent: u64, repeat: Option<u64>) -> AlertConfig {
        AlertConfig {
            apnea_timeout: Duration::from_secs(apnea),
            absence_timeout: Duration::from_secs(12 * 3600),
            node_silent_timeout: Duration::from_secs(silent),
            repeat_care_alert: repeat.map(Duration::from_secs),
        }
    }

    #[test]
    fn tracks_the_shortest_threshold_not_just_node_silence() {
        // A short reminder interval must not be starved by a long silence
        // window; this was a real bug caught end to end.
        let p = tick_period(&config(30, 30, Some(1)));
        assert!(p <= Duration::from_millis(250), "period was {p:?}");
    }

    #[test]
    fn a_short_apnea_timeout_shortens_the_period() {
        assert!(tick_period(&config(2, 60, Some(300))) <= Duration::from_millis(500));
    }

    #[test]
    fn the_long_absence_timeout_never_stretches_the_period() {
        assert!(tick_period(&config(60, 60, None)) <= Duration::from_secs(5));
    }

    #[test]
    fn stays_within_the_clamp() {
        // Pathologically small.
        assert_eq!(
            tick_period(&config(1, 1, Some(1))),
            Duration::from_millis(250)
        );
        // Pathologically large.
        assert_eq!(
            tick_period(&config(86_400, 86_400, None)),
            Duration::from_secs(5)
        );
    }
}
