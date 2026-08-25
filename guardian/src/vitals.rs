//! Wire-format parsers for the ESP32 edge vitals packets.
//!
//! These are lifted verbatim in behaviour from the sensing server's
//! `udp_receiver_task` path. The layouts are fixed by the firmware and are kept
//! in lockstep with `firmware/esp32-csi-node/main/edge_processing.h`, which
//! carries `_Static_assert`s on both sizes:
//!
//! - `edge_vitals_pkt_t`       — 32 bytes, magic `0xC511_0002` (ADR-039)
//! - `edge_fused_vitals_pkt_t` — 48 bytes, magic `0xC511_0004` (ADR-063)
//!
//! The firmware is the component that already does this correctly: it measures
//! the true inter-frame sample rate from timestamps and designs real *temporal*
//! biquad bandpass filters at 0.1-0.5 Hz (breathing) and 0.8-2.0 Hz (heart).
//! Guardian trusts these numbers rather than re-deriving them.

use serde::Serialize;

pub const EDGE_VITALS_MAGIC: u32 = 0xC511_0002;
pub const EDGE_FUSED_MAGIC: u32 = 0xC511_0004;

/// Largest packet we will ever parse; sizes the receive buffer.
pub const MAX_PACKET_LEN: usize = 64;

/// A decoded vitals reading from one node, normalised across both packet
/// variants so the alert layer never needs to care which one arrived.
#[derive(Debug, Clone, Serialize)]
pub struct VitalsReading {
    pub node_id: u8,
    pub presence: bool,
    pub fall_detected: bool,
    pub motion: bool,
    /// Breathing rate in BPM. See [`Self::breathing_is_plausible`] before use.
    pub breathing_rate_bpm: f64,
    /// Heart rate in BPM.
    ///
    /// UNVALIDATED on the CSI-only path. Heartbeat chest displacement is
    /// ~0.2-0.5 mm against ~5-12 mm for breathing, at 1-2 Hz where micro-motion
    /// dominates. Guardian carries this value for observability but never
    /// alerts on it. Whether it becomes trustworthy depends on the still-open
    /// mmWave-fusion decision; see GUARDIAN.md.
    pub heartrate_bpm: f64,
    pub rssi: i8,
    pub n_persons: u8,
    pub motion_energy: f32,
    pub presence_score: f32,
    /// Node-local milliseconds since boot. Not comparable across nodes, and it
    /// wraps roughly every 49 days — use it only for intra-node ordering.
    pub timestamp_ms: u32,
    /// Populated only by the 48-byte ADR-063 fused packet.
    pub mmwave: Option<MmWaveExtension>,
}

/// The 16-byte mmWave extension carried by `edge_fused_vitals_pkt_t`.
#[derive(Debug, Clone, Serialize)]
pub struct MmWaveExtension {
    pub present: bool,
    pub hr_bpm: f32,
    pub br_bpm: f32,
    pub distance_cm: f32,
    pub targets: u8,
    /// mmWave signal quality, 0-100.
    pub confidence: u8,
    /// 0-100 CSI/mmWave fusion quality score.
    pub fusion_confidence: u8,
    /// `mmwave_type_t` enum value from firmware.
    pub sensor_type: u8,
}

/// Respiration band the firmware's biquad actually passes: 0.1-0.5 Hz.
///
/// A reading outside this window did not come through the breathing filter as a
/// real cycle, so it is a filter artefact or an unlocked estimate, not a
/// measurement. Treating it as "no valid reading" rather than as a number is
/// what keeps the apnea rule honest.
pub const BREATHING_MIN_BPM: f64 = 6.0;
pub const BREATHING_MAX_BPM: f64 = 30.0;

impl VitalsReading {
    /// Whether `breathing_rate_bpm` is a usable measurement.
    pub fn breathing_is_plausible(&self) -> bool {
        self.breathing_rate_bpm >= BREATHING_MIN_BPM && self.breathing_rate_bpm <= BREATHING_MAX_BPM
    }
}

/// Read the 4-byte little-endian magic that prefixes every edge packet.
pub fn packet_magic(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Parse either supported vitals packet, dispatching on magic.
pub fn parse_vitals(buf: &[u8]) -> Option<VitalsReading> {
    match packet_magic(buf)? {
        EDGE_VITALS_MAGIC => parse_edge_vitals(buf),
        EDGE_FUSED_MAGIC => parse_edge_fused_vitals(buf),
        _ => None,
    }
}

/// Parse a 32-byte `edge_vitals_pkt_t` (ADR-039, magic `0xC511_0002`).
fn parse_edge_vitals(buf: &[u8]) -> Option<VitalsReading> {
    if buf.len() < 32 || packet_magic(buf)? != EDGE_VITALS_MAGIC {
        return None;
    }

    let flags = buf[5];
    let breathing_raw = u16::from_le_bytes([buf[6], buf[7]]);
    let heartrate_raw = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    // buf[14..16] are the firmware's `reserved[2]`.

    Some(VitalsReading {
        node_id: buf[4],
        presence: (flags & 0x01) != 0,
        fall_detected: (flags & 0x02) != 0,
        motion: (flags & 0x04) != 0,
        breathing_rate_bpm: breathing_raw as f64 / 100.0,
        heartrate_bpm: heartrate_raw as f64 / 10_000.0,
        rssi: buf[12] as i8,
        n_persons: buf[13],
        motion_energy: f32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        presence_score: f32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
        timestamp_ms: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        mmwave: None,
    })
}

/// Parse a 48-byte `edge_fused_vitals_pkt_t` (ADR-063, magic `0xC511_0004`).
///
/// Its first 32 bytes match `edge_vitals_pkt_t` except that the two reserved
/// bytes at offset 14 carry `mmwave_type` and `fusion_confidence`.
fn parse_edge_fused_vitals(buf: &[u8]) -> Option<VitalsReading> {
    if buf.len() < 48 || packet_magic(buf)? != EDGE_FUSED_MAGIC {
        return None;
    }

    let flags = buf[5];
    let breathing_raw = u16::from_le_bytes([buf[6], buf[7]]);
    let heartrate_raw = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    // buf[42..48] are the firmware's `reserved3` (u16) and `reserved4` (u32).

    Some(VitalsReading {
        node_id: buf[4],
        presence: (flags & 0x01) != 0,
        fall_detected: (flags & 0x02) != 0,
        motion: (flags & 0x04) != 0,
        breathing_rate_bpm: breathing_raw as f64 / 100.0,
        heartrate_bpm: heartrate_raw as f64 / 10_000.0,
        rssi: buf[12] as i8,
        n_persons: buf[13],
        motion_energy: f32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        presence_score: f32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
        timestamp_ms: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        mmwave: Some(MmWaveExtension {
            present: (flags & 0x08) != 0,
            hr_bpm: f32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
            br_bpm: f32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
            distance_cm: f32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
            targets: buf[40],
            confidence: buf[41],
            sensor_type: buf[14],
            fusion_confidence: buf[15],
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vitals_packet() -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&EDGE_VITALS_MAGIC.to_le_bytes());
        buf[4] = 1; // node_id
        buf[5] = 0b0000_0101; // presence | motion
        buf[6..8].copy_from_slice(&1_600u16.to_le_bytes()); // 16.00 BPM
        buf[8..12].copy_from_slice(&720_000u32.to_le_bytes()); // 72.0 BPM
        buf[12] = (-55i8) as u8;
        buf[13] = 1; // n_persons
        buf[16..20].copy_from_slice(&0.25f32.to_le_bytes());
        buf[20..24].copy_from_slice(&0.9f32.to_le_bytes());
        buf[24..28].copy_from_slice(&123_456u32.to_le_bytes());
        buf
    }

    fn fused_packet() -> Vec<u8> {
        let mut buf = vec![0u8; 48];
        buf[0..4].copy_from_slice(&EDGE_FUSED_MAGIC.to_le_bytes());
        buf[4] = 9;
        buf[5] = 0b0000_1001; // presence | mmwave_present
        buf[6..8].copy_from_slice(&1_600u16.to_le_bytes());
        buf[8..12].copy_from_slice(&720_000u32.to_le_bytes());
        buf[12] = (-55i8) as u8;
        buf[13] = 1;
        buf[14] = 2; // mmwave_type
        buf[15] = 88; // fusion_confidence
        buf[28..32].copy_from_slice(&71.5f32.to_le_bytes());
        buf[32..36].copy_from_slice(&15.8f32.to_le_bytes());
        buf[36..40].copy_from_slice(&120.0f32.to_le_bytes());
        buf[40] = 1;
        buf[41] = 92;
        buf
    }

    #[test]
    fn parses_32_byte_vitals() {
        let v = parse_vitals(&vitals_packet()).expect("must parse");
        assert_eq!(v.node_id, 1);
        assert!(v.presence);
        assert!(!v.fall_detected);
        assert!(v.motion);
        assert_eq!(v.breathing_rate_bpm, 16.0);
        assert_eq!(v.heartrate_bpm, 72.0);
        assert_eq!(v.rssi, -55);
        assert_eq!(v.timestamp_ms, 123_456);
        assert!(v.mmwave.is_none());
    }

    #[test]
    fn parses_48_byte_fused_vitals() {
        let v = parse_vitals(&fused_packet()).expect("must parse");
        assert_eq!(v.node_id, 9);
        let mm = v.mmwave.expect("fused packet carries the mmWave extension");
        assert!(mm.present);
        assert_eq!(mm.hr_bpm, 71.5);
        assert_eq!(mm.br_bpm, 15.8);
        assert_eq!(mm.distance_cm, 120.0);
        assert_eq!(mm.targets, 1);
        assert_eq!(mm.confidence, 92);
        assert_eq!(mm.fusion_confidence, 88);
        assert_eq!(mm.sensor_type, 2);
    }

    /// Issue #928: `0xC511_0004` collided with the WASM output magic and fused
    /// packets were silently eaten. Guardian does not parse WASM output at all,
    /// but the magics must still route distinctly.
    #[test]
    fn rejects_foreign_and_truncated_packets() {
        let mut wasm = vec![0u8; 48];
        wasm[0..4].copy_from_slice(&0xC511_0007u32.to_le_bytes());
        assert!(parse_vitals(&wasm).is_none());

        let mut csi = vec![0u8; 48];
        csi[0..4].copy_from_slice(&0xC511_0001u32.to_le_bytes());
        assert!(parse_vitals(&csi).is_none());

        assert!(parse_vitals(&[]).is_none());
        assert!(parse_vitals(&[0xAA]).is_none());
        // Right magic, short body: must not read past the end.
        assert!(parse_vitals(&vitals_packet()[..31]).is_none());
        assert!(parse_vitals(&fused_packet()[..47]).is_none());
    }

    /// A 32-byte payload carrying the fused magic must be rejected rather than
    /// parsed as a truncated fused packet.
    #[test]
    fn fused_magic_requires_full_48_bytes() {
        let mut buf = fused_packet();
        buf.truncate(32);
        assert!(parse_vitals(&buf).is_none());
    }

    #[test]
    fn breathing_plausibility_matches_the_firmware_biquad_band() {
        let mut v = parse_vitals(&vitals_packet()).unwrap();
        assert!(v.breathing_is_plausible());

        // Zero is what the firmware emits before the filter locks.
        v.breathing_rate_bpm = 0.0;
        assert!(!v.breathing_is_plausible());

        // Above 0.5 Hz is outside the band the biquad passes.
        v.breathing_rate_bpm = 45.0;
        assert!(!v.breathing_is_plausible());

        v.breathing_rate_bpm = BREATHING_MIN_BPM;
        assert!(v.breathing_is_plausible());
        v.breathing_rate_bpm = BREATHING_MAX_BPM;
        assert!(v.breathing_is_plausible());
    }
}
