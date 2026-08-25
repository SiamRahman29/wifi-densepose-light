//! Recording and replaying vitals traffic.
//!
//! This exists for the validation problem the project has not solved: the fall
//! heuristic cannot be tested on the person it is meant to protect. Validating
//! it needs a proxy — a weighted cushion dropped on the floor, or a younger
//! person falling onto a mattress — and you cannot re-stage that physical event
//! every time you change a threshold. Capture it once, replay it forever.
//!
//! It is also how a real deployment produces regression material: a night of
//! genuine traffic, replayable at any speed, is worth more than any synthetic
//! packet generator.
//!
//! ## Captures contain personal data
//!
//! A capture records when a specific person was present, moving, and breathing,
//! and at what rate. Treat it as health data: keep it local, do not commit it,
//! and get consent before recording anyone. `.gitignore` excludes `*.jsonl`
//! under this crate for that reason.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

/// One recorded packet: milliseconds since the capture began, plus the raw
/// bytes as they arrived on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPacket {
    pub offset_ms: u64,
    pub data: Vec<u8>,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl CapturedPacket {
    /// Serialise as one JSONL line.
    ///
    /// JSONL rather than a packed binary format because captures are small
    /// (three nodes at ~15 Hz is roughly 5 MB/hour) and being able to grep and
    /// eyeball a capture is worth more than the bytes.
    pub fn to_line(&self) -> String {
        format!(
            "{{\"offset_ms\":{},\"data\":\"{}\"}}",
            self.offset_ms,
            to_hex(&self.data)
        )
    }

    /// Parse one JSONL line. Returns `None` for anything malformed so a
    /// truncated capture — the normal result of killing the recorder — still
    /// replays up to the truncation point.
    pub fn from_line(line: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        Some(Self {
            offset_ms: value.get("offset_ms")?.as_u64()?,
            data: from_hex(value.get("data")?.as_str()?)?,
        })
    }
}

/// Appends packets to a capture file.
pub struct Recorder {
    writer: BufWriter<File>,
    packets: u64,
}

impl Recorder {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            writer: BufWriter::new(File::create(path)?),
            packets: 0,
        })
    }

    pub fn record(&mut self, offset_ms: u64, data: &[u8]) -> std::io::Result<()> {
        let packet = CapturedPacket {
            offset_ms,
            data: data.to_vec(),
        };
        writeln!(self.writer, "{}", packet.to_line())?;
        self.packets += 1;
        // Flushed every packet: a capture is usually ended by killing the
        // process, and a buffered tail would lose exactly the seconds around
        // the event being captured.
        self.writer.flush()?;
        Ok(())
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }
}

/// Read a whole capture, skipping malformed lines.
pub fn read_capture(path: &Path) -> std::io::Result<Vec<CapturedPacket>> {
    let reader = BufReader::new(File::open(path)?);
    Ok(reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| CapturedPacket::from_line(&l))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_packet() {
        let p = CapturedPacket {
            offset_ms: 1234,
            data: vec![0x00, 0xc5, 0x11, 0xff, 0x7f],
        };
        assert_eq!(CapturedPacket::from_line(&p.to_line()), Some(p));
    }

    #[test]
    fn round_trips_an_empty_payload() {
        let p = CapturedPacket {
            offset_ms: 0,
            data: vec![],
        };
        assert_eq!(CapturedPacket::from_line(&p.to_line()), Some(p));
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(CapturedPacket::from_line("").is_none());
        assert!(CapturedPacket::from_line("not json").is_none());
        assert!(CapturedPacket::from_line(r#"{"offset_ms":1}"#).is_none());
        assert!(CapturedPacket::from_line(r#"{"data":"00"}"#).is_none());
        // Odd-length and non-hex payloads.
        assert!(CapturedPacket::from_line(r#"{"offset_ms":1,"data":"abc"}"#).is_none());
        assert!(CapturedPacket::from_line(r#"{"offset_ms":1,"data":"zz"}"#).is_none());
    }

    /// Killing the recorder mid-write is the normal way a capture ends, so a
    /// half-written final line must not discard everything before it.
    #[test]
    fn a_truncated_capture_still_replays_up_to_the_truncation() {
        let dir = std::env::temp_dir().join(format!("guardian-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("truncated.jsonl");

        {
            let mut r = Recorder::create(&path).unwrap();
            r.record(0, &[1, 2, 3]).unwrap();
            r.record(100, &[4, 5, 6]).unwrap();
            assert_eq!(r.packets(), 2);
        }
        // Simulate a kill mid-line.
        let mut raw = std::fs::read_to_string(&path).unwrap();
        raw.push_str("{\"offset_ms\":200,\"da");
        std::fs::write(&path, raw).unwrap();

        let packets = read_capture(&path).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].data, vec![1, 2, 3]);
        assert_eq!(packets[1].offset_ms, 100);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn records_and_reads_back_in_order() {
        let dir = std::env::temp_dir().join(format!("guardian-cap-ord-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ordered.jsonl");

        {
            let mut r = Recorder::create(&path).unwrap();
            for i in 0..50u64 {
                r.record(i * 66, &[i as u8; 32]).unwrap();
            }
        }

        let packets = read_capture(&path).unwrap();
        assert_eq!(packets.len(), 50);
        assert!(packets.windows(2).all(|w| w[0].offset_ms < w[1].offset_ms));
        assert_eq!(packets[49].data.len(), 32);

        std::fs::remove_dir_all(&dir).ok();
    }
}
