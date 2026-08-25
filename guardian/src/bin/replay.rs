//! Replay a recorded vitals capture back at a running Guardian.
//!
//! The point is repeatability. A staged fall — a weighted cushion dropped on
//! the floor, a volunteer onto a mattress — is expensive and awkward to
//! reproduce, so capture it once and replay it against every subsequent change
//! to the alert rules.
//!
//! ```bash
//! guardian --record fall-proxy-01.jsonl        # capture, once
//! guardian-replay fall-proxy-01.jsonl --speed 4   # iterate, forever
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use guardian::capture::{read_capture, CapturedPacket};
use guardian::vitals;

#[derive(Parser, Debug)]
#[command(name = "guardian-replay", about = "Replay a recorded vitals capture")]
struct Args {
    /// Capture file written by `guardian --record`.
    capture: PathBuf,

    /// Where to send the replayed packets.
    #[arg(long, default_value = "127.0.0.1:5005")]
    target: SocketAddr,

    /// Playback speed multiplier. 0 sends everything as fast as possible,
    /// which is useful for exercising parsing but meaningless for any rule
    /// with a timeout.
    #[arg(long, default_value = "1.0")]
    speed: f64,

    /// Repeat the capture forever.
    #[arg(long)]
    repeat: bool,

    /// Describe the capture and exit without sending anything.
    #[arg(long)]
    inspect: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.speed < 0.0 {
        return Err("--speed cannot be negative".into());
    }

    let packets =
        read_capture(&args.capture).map_err(|e| format!("{}: {e}", args.capture.display()))?;
    if packets.is_empty() {
        return Err(format!("{}: no usable packets", args.capture.display()).into());
    }

    summarise(&packets);
    if args.inspect {
        return Ok(());
    }

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    println!("\nreplaying to {} at {}x", args.target, args.speed);

    // Offsets are relative to when the recorder started, not to the first
    // packet, so a capture usually opens with a gap of however long the
    // operator took to start the nodes. That gap is not part of the event.
    let base_ms = packets[0].offset_ms;

    loop {
        let started = Instant::now();
        for packet in &packets {
            if args.speed > 0.0 {
                let due = Duration::from_secs_f64(
                    (packet.offset_ms - base_ms) as f64 / 1000.0 / args.speed,
                );
                // Saturating: if we have fallen behind, send immediately rather
                // than trying to catch up in a burst.
                let elapsed = started.elapsed();
                if due > elapsed {
                    std::thread::sleep(due - elapsed);
                }
            }
            socket.send_to(&packet.data, args.target)?;
        }

        println!("sent {} packets", packets.len());
        if !args.repeat {
            return Ok(());
        }
    }
}

/// Print what a capture contains, so an operator can tell one staged event from
/// another without replaying it.
fn summarise(packets: &[CapturedPacket]) {
    let span_ms = packets.last().map_or(0, |p| p.offset_ms) - packets[0].offset_ms;
    println!(
        "{} packets over {:.1}s",
        packets.len(),
        span_ms as f64 / 1000.0
    );

    let mut nodes: std::collections::BTreeMap<u8, usize> = Default::default();
    let mut falls = 0usize;
    let mut presence = 0usize;
    let mut breathing: Vec<f64> = Vec::new();

    for p in packets {
        if let Some(v) = vitals::parse_vitals(&p.data) {
            *nodes.entry(v.node_id).or_default() += 1;
            falls += usize::from(v.fall_detected);
            presence += usize::from(v.presence);
            if v.breathing_is_plausible() {
                breathing.push(v.breathing_rate_bpm);
            }
        }
    }

    println!("nodes: {nodes:?}");
    println!(
        "presence in {:.0}% of packets, {} fall flag(s)",
        100.0 * presence as f64 / packets.len() as f64,
        falls
    );
    if breathing.is_empty() {
        println!("no plausible breathing readings in this capture");
    } else {
        let mean = breathing.iter().sum::<f64>() / breathing.len() as f64;
        println!(
            "breathing: {:.1} BPM mean over {} plausible readings ({:.0}% of packets)",
            mean,
            breathing.len(),
            100.0 * breathing.len() as f64 / packets.len() as f64
        );
    }
}
