//! The thin alert layer.
//!
//! Everything here is a state machine over the vitals stream. It deliberately
//! contains no signal processing: the firmware already measures the true sample
//! rate and runs temporal bandpass filters, and re-deriving those numbers on the
//! server is exactly the mistake this crate exists to stop repeating.
//!
//! [`AlertEngine`] is pure with respect to time — every entry point takes an
//! explicit `now: Instant` — so the timeout behaviour is testable without
//! sleeping.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::vitals::VitalsReading;

/// What kind of condition fired. Ordered most to least urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// A node raised the firmware fall flag.
    Fall,
    /// Someone is present but no plausible breathing reading has arrived.
    NoBreathing,
    /// Nobody has been detected anywhere for a long stretch.
    NoPresence,
    /// A node stopped reporting. Equipment health, not a care condition.
    NodeSilent { node_id: u8 },
}

impl AlertKind {
    /// Whether this condition is about the person rather than the equipment.
    pub fn is_care_alert(&self) -> bool {
        !matches!(self, AlertKind::NodeSilent { .. })
    }

    /// Whether the condition latches until a human acknowledges it.
    ///
    /// A fall is a discrete past event: the flag clears as soon as the person
    /// stops moving or the window rolls, so auto-clearing it would let a real
    /// fall vanish before anyone looked. Everything else reflects a condition
    /// that is either still true or not.
    pub fn latches(&self) -> bool {
        matches!(self, AlertKind::Fall)
    }
}

/// A transition worth telling someone about.
#[derive(Debug, Clone, Serialize)]
pub struct AlertEvent {
    pub kind: AlertKind,
    pub transition: Transition,
    /// Human-readable detail, including the evidence that drove the decision.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transition {
    Raised,
    Cleared,
    /// The condition is still active and has not been acknowledged. Emitted on
    /// a repeating interval so a single missed notification at 03:00 does not
    /// leave the condition unattended.
    Reminder,
}

/// Bookkeeping for one active condition.
#[derive(Debug, Clone, Copy)]
struct ActiveAlert {
    /// Used to report how long a condition has been unattended.
    raised_at: Instant,
    /// When this condition last produced an event, so reminders can be paced.
    last_signalled_at: Instant,
}

/// Tunable thresholds. Defaults are the ones named in the handoff keep-list.
#[derive(Debug, Clone, Copy)]
pub struct AlertConfig {
    /// How long a present person may go without a plausible breathing reading.
    pub apnea_timeout: Duration,
    /// How long with nobody detected before flagging it.
    pub absence_timeout: Duration,
    /// How long a node may go quiet before it is considered offline.
    pub node_silent_timeout: Duration,
    /// How often to re-emit a care alert that is still active. `None` emits
    /// once per raise.
    pub repeat_care_alert: Option<Duration>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            apnea_timeout: Duration::from_secs(60),
            absence_timeout: Duration::from_secs(12 * 60 * 60),
            node_silent_timeout: Duration::from_secs(60),
            repeat_care_alert: Some(Duration::from_secs(300)),
        }
    }
}

/// Last-known state for one node, for the status surface and health checks.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub node_id: u8,
    /// Whether this node's readings are allowed to drive care alerts.
    pub trusted_for_alerts: bool,
    pub presence: bool,
    pub breathing_rate_bpm: f64,
    pub breathing_plausible: bool,
    /// Carried for observability only; never drives an alert. See `vitals.rs`.
    pub heartrate_bpm_unvalidated: f64,
    pub rssi: i8,
    pub n_persons: u8,
    pub motion_energy: f32,
    pub presence_score: f32,
    pub packets_received: u64,
    pub seconds_since_last_packet: f64,
    pub online: bool,
    #[serde(skip)]
    last_packet_at: Instant,
}

/// Tracks alert conditions across all nodes.
pub struct AlertEngine {
    config: AlertConfig,
    /// Nodes allowed to drive care alerts. `None` trusts every node that
    /// reports. Set this once placement work has established which nodes are
    /// actually reliable.
    trusted_nodes: Option<Vec<u8>>,
    nodes: BTreeMap<u8, NodeStatus>,
    active: BTreeMap<AlertKind, ActiveAlert>,
    /// Last moment a trusted node reported presence.
    last_presence_at: Option<Instant>,
    /// Last moment a trusted node reported a plausible breathing rate while
    /// someone was present.
    last_plausible_breath_at: Option<Instant>,
    started_at: Instant,
}

impl AlertEngine {
    pub fn new(config: AlertConfig, trusted_nodes: Option<Vec<u8>>, now: Instant) -> Self {
        Self {
            config,
            trusted_nodes,
            nodes: BTreeMap::new(),
            active: BTreeMap::new(),
            last_presence_at: None,
            last_plausible_breath_at: None,
            started_at: now,
        }
    }

    fn trusts(&self, node_id: u8) -> bool {
        match &self.trusted_nodes {
            None => true,
            Some(ids) => ids.contains(&node_id),
        }
    }

    /// Fold one reading into the state, returning any transitions it caused.
    pub fn ingest(&mut self, reading: &VitalsReading, now: Instant) -> Vec<AlertEvent> {
        let trusted = self.trusts(reading.node_id);
        let plausible = reading.breathing_is_plausible();

        let entry = self.nodes.entry(reading.node_id).or_insert(NodeStatus {
            node_id: reading.node_id,
            trusted_for_alerts: trusted,
            presence: false,
            breathing_rate_bpm: 0.0,
            breathing_plausible: false,
            heartrate_bpm_unvalidated: 0.0,
            rssi: 0,
            n_persons: 0,
            motion_energy: 0.0,
            presence_score: 0.0,
            packets_received: 0,
            seconds_since_last_packet: 0.0,
            online: true,
            last_packet_at: now,
        });

        entry.trusted_for_alerts = trusted;
        entry.presence = reading.presence;
        entry.breathing_rate_bpm = reading.breathing_rate_bpm;
        entry.breathing_plausible = plausible;
        entry.heartrate_bpm_unvalidated = reading.heartrate_bpm;
        entry.rssi = reading.rssi;
        entry.n_persons = reading.n_persons;
        entry.motion_energy = reading.motion_energy;
        entry.presence_score = reading.presence_score;
        entry.packets_received = entry.packets_received.saturating_add(1);
        entry.last_packet_at = now;
        entry.online = true;

        let mut events = Vec::new();

        // An untrusted node is observed and shown, but never alerts. This is
        // how a node with known placement or link problems stays visible
        // without being able to raise a false alarm.
        if !trusted {
            events.extend(self.clear_if_active(
                AlertKind::NodeSilent {
                    node_id: reading.node_id,
                },
                now,
            ));
            return events;
        }

        events.extend(self.clear_if_active(
            AlertKind::NodeSilent {
                node_id: reading.node_id,
            },
            now,
        ));

        if reading.fall_detected {
            events.extend(self.raise(
                AlertKind::Fall,
                now,
                format!(
                    "node {} raised the fall flag (motion_energy {:.3}, presence_score {:.2})",
                    reading.node_id, reading.motion_energy, reading.presence_score
                ),
            ));
        }

        // Presence is an OR across trusted nodes: any node seeing the person is
        // enough, since a node with no line of sight legitimately sees nothing.
        let anyone_present = self.any_trusted_presence(now);

        if anyone_present {
            let first_presence = self.last_presence_at.is_none();
            self.last_presence_at = Some(now);
            events.extend(self.clear_if_active(AlertKind::NoPresence, now));

            // Seed the breathing clock when presence begins, so an apnea alert
            // cannot fire the instant someone walks into the room.
            if first_presence || self.last_plausible_breath_at.is_none() {
                self.last_plausible_breath_at = Some(now);
            }
        } else {
            // Nobody there: apnea is not a meaningful question. Clearing here
            // is what stops "no breathing detected" firing because the person
            // walked to the kitchen.
            self.last_plausible_breath_at = None;
            events.extend(self.clear_if_active(AlertKind::NoBreathing, now));
        }

        if anyone_present && self.any_trusted_plausible_breathing(now) {
            self.last_plausible_breath_at = Some(now);
            events.extend(self.clear_if_active(AlertKind::NoBreathing, now));
        }

        events
    }

    /// Re-evaluate time-based conditions. Call this on a timer; timeouts cannot
    /// fire from [`Self::ingest`] alone, because a silent node sends nothing.
    pub fn tick(&mut self, now: Instant) -> Vec<AlertEvent> {
        let mut events = Vec::new();

        let silent: Vec<u8> = self
            .nodes
            .values_mut()
            .filter_map(|n| {
                let quiet = now.duration_since(n.last_packet_at) > self.config.node_silent_timeout;
                n.online = !quiet;
                (quiet && n.trusted_for_alerts).then_some(n.node_id)
            })
            .collect();
        for node_id in silent {
            let last_seen = self.nodes[&node_id].last_packet_at;
            events.extend(self.raise(
                AlertKind::NodeSilent { node_id },
                now,
                format!(
                    "no packet from node {} in {:.0}s",
                    node_id,
                    now.duration_since(last_seen).as_secs_f64()
                ),
            ));
        }

        // Presence can go stale purely with time, with no packet to drive
        // `ingest`. If no fresh trusted node still sees the person, we do not
        // know whether they are breathing, so apnea is suspended and the
        // NodeSilent alert above is the honest signal instead. Raising
        // "no breathing" because the equipment failed would be a false alarm of
        // the worst possible kind.
        if !self.any_trusted_presence(now) {
            self.last_plausible_breath_at = None;
            events.extend(self.clear_if_active(AlertKind::NoBreathing, now));
        }

        if let Some(since) = self.last_plausible_breath_at {
            let elapsed = now.duration_since(since);
            if elapsed > self.config.apnea_timeout {
                events.extend(self.raise(
                    AlertKind::NoBreathing,
                    now,
                    format!(
                        "someone is present but no breathing rate in the {:.0}-{:.0} BPM band \
                         has arrived for {:.0}s",
                        crate::vitals::BREATHING_MIN_BPM,
                        crate::vitals::BREATHING_MAX_BPM,
                        elapsed.as_secs_f64()
                    ),
                ));
            }
        }

        // Absence is measured from startup when no presence has ever been seen,
        // so a monitor that never detects anyone still eventually says so.
        let absent_since = self.last_presence_at.unwrap_or(self.started_at);
        let absent_for = now.duration_since(absent_since);
        if absent_for > self.config.absence_timeout {
            events.extend(self.raise(
                AlertKind::NoPresence,
                now,
                format!(
                    "no presence detected by any trusted node for {:.1}h",
                    absent_for.as_secs_f64() / 3600.0
                ),
            ));
        }

        // Last, so a condition raised or cleared in this same tick is not also
        // reminded about in it.
        events.extend(self.reminders(now));

        events
    }

    /// Whether a node's last reading is recent enough to still mean anything.
    ///
    /// This is load-bearing for safety, not tidiness. A node holding
    /// `breathing_plausible: true` at the moment it dies would otherwise go on
    /// satisfying the breathing check forever, silently disabling the apnea
    /// alarm for as long as the node stayed offline. Stale evidence is absence
    /// of evidence.
    fn is_fresh(&self, node: &NodeStatus, now: Instant) -> bool {
        now.duration_since(node.last_packet_at) <= self.config.node_silent_timeout
    }

    fn any_trusted_presence(&self, now: Instant) -> bool {
        self.nodes
            .values()
            .any(|n| n.trusted_for_alerts && n.presence && self.is_fresh(n, now))
    }

    fn any_trusted_plausible_breathing(&self, now: Instant) -> bool {
        self.nodes
            .values()
            .any(|n| n.trusted_for_alerts && n.breathing_plausible && self.is_fresh(n, now))
    }

    /// Raise a condition, emitting an event only on the inactive -> active edge
    /// so a persistent condition does not re-notify on every packet.
    fn raise(&mut self, kind: AlertKind, now: Instant, detail: String) -> Vec<AlertEvent> {
        if self.active.contains_key(&kind) {
            return Vec::new();
        }
        self.active.insert(
            kind,
            ActiveAlert {
                raised_at: now,
                last_signalled_at: now,
            },
        );
        vec![AlertEvent {
            kind,
            transition: Transition::Raised,
            detail,
        }]
    }

    /// Re-emit care alerts that are still active and unacknowledged.
    fn reminders(&mut self, now: Instant) -> Vec<AlertEvent> {
        let Some(every) = self.config.repeat_care_alert else {
            return Vec::new();
        };

        let mut events = Vec::new();
        for (kind, state) in self.active.iter_mut() {
            if !kind.is_care_alert() || now.duration_since(state.last_signalled_at) < every {
                continue;
            }
            state.last_signalled_at = now;
            events.push(AlertEvent {
                kind: *kind,
                transition: Transition::Reminder,
                detail: format!(
                    "{kind:?} still active and unacknowledged after {:.0}s",
                    now.duration_since(state.raised_at).as_secs_f64()
                ),
            });
        }
        events
    }

    fn clear_if_active(&mut self, kind: AlertKind, _now: Instant) -> Vec<AlertEvent> {
        if kind.latches() || self.active.remove(&kind).is_none() {
            return Vec::new();
        }
        vec![AlertEvent {
            kind,
            transition: Transition::Cleared,
            detail: format!("{kind:?} condition no longer holds"),
        }]
    }

    /// Acknowledge a latched alert. Returns whether anything was cleared.
    pub fn acknowledge(&mut self, kind: AlertKind) -> bool {
        self.active.remove(&kind).is_some()
    }

    pub fn active_alerts(&self) -> Vec<AlertKind> {
        self.active.keys().copied().collect()
    }

    /// Snapshot for the status endpoint.
    pub fn snapshot(&self, now: Instant) -> serde_json::Value {
        let nodes: Vec<NodeStatus> = self
            .nodes
            .values()
            .map(|n| {
                let mut n = n.clone();
                n.seconds_since_last_packet = now.duration_since(n.last_packet_at).as_secs_f64();
                n.online =
                    n.seconds_since_last_packet <= self.config.node_silent_timeout.as_secs_f64();
                n
            })
            .collect();

        serde_json::json!({
            "uptime_seconds": now.duration_since(self.started_at).as_secs_f64(),
            "present": self.any_trusted_presence(now),
            "active_alerts": self.active_alerts(),
            "nodes": nodes,
            "heartrate": "unvalidated on the CSI-only path; carried but never alerted on",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vitals::MmWaveExtension;

    fn reading(node_id: u8, presence: bool, breathing: f64) -> VitalsReading {
        VitalsReading {
            node_id,
            presence,
            fall_detected: false,
            motion: false,
            breathing_rate_bpm: breathing,
            heartrate_bpm: 72.0,
            rssi: -55,
            n_persons: if presence { 1 } else { 0 },
            motion_energy: 0.1,
            presence_score: if presence { 0.9 } else { 0.0 },
            timestamp_ms: 0,
            mmwave: None,
        }
    }

    fn engine(now: Instant) -> AlertEngine {
        AlertEngine::new(AlertConfig::default(), None, now)
    }

    fn kinds(events: &[AlertEvent], t: Transition) -> Vec<AlertKind> {
        events
            .iter()
            .filter(|e| e.transition == t)
            .map(|e| e.kind)
            .collect()
    }

    #[test]
    fn breathing_person_raises_nothing() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        for i in 0..100 {
            let now = t0 + Duration::from_secs(i);
            assert!(e.ingest(&reading(1, true, 16.0), now).is_empty());
            assert!(e.tick(now).is_empty());
        }
        assert!(e.active_alerts().is_empty());
    }

    #[test]
    fn apnea_fires_only_after_the_timeout_and_clears_on_recovery() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);

        // Present, but every reading is outside the breathing band.
        for i in 1..=59 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, true, 0.0), now);
            assert!(e.tick(now).is_empty(), "must not fire before 60s (at {i}s)");
        }

        let fired = t0 + Duration::from_secs(61);
        e.ingest(&reading(1, true, 0.0), fired);
        assert_eq!(
            kinds(&e.tick(fired), Transition::Raised),
            vec![AlertKind::NoBreathing]
        );

        // Raising is edge-triggered: the next tick must stay quiet.
        let later = t0 + Duration::from_secs(70);
        e.ingest(&reading(1, true, 0.0), later);
        assert!(e.tick(later).is_empty());

        let recovered = t0 + Duration::from_secs(80);
        let events = e.ingest(&reading(1, true, 15.0), recovered);
        assert_eq!(
            kinds(&events, Transition::Cleared),
            vec![AlertKind::NoBreathing]
        );
        assert!(e.active_alerts().is_empty());
    }

    /// The false alarm that would destroy trust in the product: the person
    /// leaves the room, so breathing readings stop, and the monitor screams
    /// that they have stopped breathing.
    #[test]
    fn leaving_the_room_never_raises_apnea() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);

        for i in 1..=600 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, false, 0.0), now);
            let events = e.tick(now);
            assert!(
                !kinds(&events, Transition::Raised).contains(&AlertKind::NoBreathing),
                "apnea must not fire with nobody present (at {i}s)"
            );
        }
        assert!(!e.active_alerts().contains(&AlertKind::NoBreathing));
    }

    #[test]
    fn walking_back_in_does_not_instantly_trip_apnea() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);
        // Gone for an hour.
        let away = t0 + Duration::from_secs(3600);
        e.ingest(&reading(1, false, 0.0), away);
        e.tick(away);

        // Returns; the breathing filter has not locked yet.
        let back = away + Duration::from_secs(1);
        e.ingest(&reading(1, true, 0.0), back);
        assert!(e.tick(back).is_empty(), "clock must reseed on presence");

        // It still fires if breathing genuinely never arrives.
        let late = back + Duration::from_secs(61);
        e.ingest(&reading(1, true, 0.0), late);
        assert_eq!(
            kinds(&e.tick(late), Transition::Raised),
            vec![AlertKind::NoBreathing]
        );
    }

    #[test]
    fn fall_fires_immediately_and_latches_until_acknowledged() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        let mut r = reading(1, true, 16.0);
        r.fall_detected = true;
        assert_eq!(
            kinds(&e.ingest(&r, t0), Transition::Raised),
            vec![AlertKind::Fall]
        );

        // Flag drops on the next packet; the alert must survive.
        let later = t0 + Duration::from_secs(5);
        e.ingest(&reading(1, true, 16.0), later);
        e.tick(later);
        assert!(e.active_alerts().contains(&AlertKind::Fall));

        assert!(e.acknowledge(AlertKind::Fall));
        assert!(!e.active_alerts().contains(&AlertKind::Fall));
        assert!(!e.acknowledge(AlertKind::Fall), "second ack is a no-op");
    }

    #[test]
    fn absence_fires_after_twelve_hours_and_clears_on_return() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);

        let before = t0 + Duration::from_secs(11 * 3600);
        e.ingest(&reading(1, false, 0.0), before);
        assert!(!kinds(&e.tick(before), Transition::Raised).contains(&AlertKind::NoPresence));

        let after = t0 + Duration::from_secs(13 * 3600);
        e.ingest(&reading(1, false, 0.0), after);
        assert!(kinds(&e.tick(after), Transition::Raised).contains(&AlertKind::NoPresence));

        let returned = after + Duration::from_secs(60);
        let events = e.ingest(&reading(1, true, 16.0), returned);
        assert!(kinds(&events, Transition::Cleared).contains(&AlertKind::NoPresence));
    }

    #[test]
    fn absence_is_measured_from_startup_when_nobody_is_ever_seen() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        let after = t0 + Duration::from_secs(13 * 3600);
        e.ingest(&reading(1, false, 0.0), after);
        assert!(kinds(&e.tick(after), Transition::Raised).contains(&AlertKind::NoPresence));
    }

    #[test]
    fn silent_node_is_reported_then_cleared_on_return() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);

        let quiet = t0 + Duration::from_secs(90);
        assert!(kinds(&e.tick(quiet), Transition::Raised)
            .contains(&AlertKind::NodeSilent { node_id: 1 }));

        let back = quiet + Duration::from_secs(1);
        let events = e.ingest(&reading(1, true, 16.0), back);
        assert!(kinds(&events, Transition::Cleared).contains(&AlertKind::NodeSilent { node_id: 1 }));
    }

    /// Handoff evidence: node 3 disagrees with itself between two still phases
    /// (variance 3.87 vs 1.84) and node 2 shows 6.2-6.8 dB RSSI stdev in all
    /// phases. Both need placement work before they can be trusted, so an
    /// operator must be able to observe them without letting them alert.
    #[test]
    fn untrusted_nodes_are_observed_but_cannot_alert() {
        let t0 = Instant::now();
        let mut e = AlertEngine::new(AlertConfig::default(), Some(vec![1]), t0);

        let mut bad = reading(3, true, 0.0);
        bad.fall_detected = true;
        assert!(
            e.ingest(&bad, t0).is_empty(),
            "untrusted node must not raise a fall"
        );
        assert!(e.active_alerts().is_empty());

        // ...but it still shows up in the status surface.
        let snap = e.snapshot(t0);
        let nodes = snap["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["node_id"], 3);
        assert_eq!(nodes[0]["trusted_for_alerts"], false);

        // An untrusted node's presence must not satisfy the presence rule.
        let after = t0 + Duration::from_secs(13 * 3600);
        e.ingest(&bad, after);
        assert!(kinds(&e.tick(after), Transition::Raised).contains(&AlertKind::NoPresence));
    }

    /// A node with no line of sight legitimately reports nothing; one trusted
    /// node seeing the person is enough.
    #[test]
    fn presence_is_an_or_across_trusted_nodes() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, false, 0.0), t0);
        e.ingest(&reading(2, true, 16.0), t0);

        for i in 1..=200 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, false, 0.0), now);
            e.ingest(&reading(2, true, 16.0), now);
            assert!(e.tick(now).is_empty(), "at {i}s");
        }
    }

    /// Regression: found by the end-to-end smoke test, missed by the
    /// single-node unit tests. Node 2 reports healthy breathing and then dies.
    /// Its stale `breathing_plausible: true` must stop counting, or a node
    /// failing at the wrong instant silently disables the apnea alarm.
    #[test]
    fn a_dead_node_holding_a_good_reading_cannot_suppress_apnea() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);
        e.ingest(&reading(2, true, 15.5), t0); // node 2 is never heard from again

        // Node 1 stays alive and present, but stops breathing.
        let mut fired_at = None;
        for i in 1..=300 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, true, 0.0), now);
            if kinds(&e.tick(now), Transition::Raised).contains(&AlertKind::NoBreathing) {
                fired_at = Some(i);
                break;
            }
        }
        let fired_at = fired_at.expect("apnea must still fire despite node 2's stale reading");
        // Node 2 goes stale at 60s; apnea needs 60s of silence after that.
        assert!(
            (61..=125).contains(&fired_at),
            "apnea fired at {fired_at}s, outside the expected window"
        );
    }

    /// The complementary failure: every node dies while the person was present.
    /// We no longer know anything, so the honest alert is that the equipment is
    /// down — never that she stopped breathing.
    #[test]
    fn total_node_failure_reports_equipment_not_apnea() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);

        let mut raised = Vec::new();
        for i in 1..=600 {
            raised.extend(kinds(
                &e.tick(t0 + Duration::from_secs(i)),
                Transition::Raised,
            ));
        }

        assert!(raised.contains(&AlertKind::NodeSilent { node_id: 1 }));
        assert!(
            !raised.contains(&AlertKind::NoBreathing),
            "equipment failure must not present as apnea, got {raised:?}"
        );
        assert!(!e.active_alerts().contains(&AlertKind::NoBreathing));
    }

    /// Presence must also go stale: a node that dies mid-report should not keep
    /// the room marked occupied indefinitely.
    #[test]
    fn presence_goes_stale_when_the_reporting_node_dies() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        e.ingest(&reading(1, true, 16.0), t0);
        assert_eq!(e.snapshot(t0)["present"], true);

        let later = t0 + Duration::from_secs(120);
        e.tick(later);
        assert_eq!(e.snapshot(later)["present"], false);
    }

    /// An unacknowledged fall must keep telling someone. One notification at
    /// 03:00 into a notifier that happened to be down is the same as none.
    #[test]
    fn an_unacknowledged_care_alert_is_repeated() {
        let t0 = Instant::now();
        let config = AlertConfig {
            repeat_care_alert: Some(Duration::from_secs(300)),
            ..AlertConfig::default()
        };
        let mut e = AlertEngine::new(config, None, t0);

        let mut r = reading(1, true, 16.0);
        r.fall_detected = true;
        assert_eq!(
            kinds(&e.ingest(&r, t0), Transition::Raised),
            vec![AlertKind::Fall]
        );

        // Nothing before the interval elapses.
        let mut reminders = 0;
        for i in 1..=299 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, true, 16.0), now);
            reminders += kinds(&e.tick(now), Transition::Reminder).len();
        }
        assert_eq!(reminders, 0, "reminded before the interval elapsed");

        let due = t0 + Duration::from_secs(301);
        e.ingest(&reading(1, true, 16.0), due);
        assert_eq!(
            kinds(&e.tick(due), Transition::Reminder),
            vec![AlertKind::Fall]
        );

        // And again one interval later, not every tick in between.
        let mut reminders = 0;
        for i in 302..=602 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, true, 16.0), now);
            reminders += kinds(&e.tick(now), Transition::Reminder).len();
        }
        assert_eq!(reminders, 1, "expected exactly one further reminder");
    }

    #[test]
    fn acknowledging_stops_the_reminders() {
        let t0 = Instant::now();
        let config = AlertConfig {
            repeat_care_alert: Some(Duration::from_secs(60)),
            ..AlertConfig::default()
        };
        let mut e = AlertEngine::new(config, None, t0);

        let mut r = reading(1, true, 16.0);
        r.fall_detected = true;
        e.ingest(&r, t0);
        assert!(e.acknowledge(AlertKind::Fall));

        let mut reminders = 0;
        for i in 1..=600 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, true, 16.0), now);
            reminders += kinds(&e.tick(now), Transition::Reminder).len();
        }
        assert_eq!(reminders, 0);
    }

    /// Node health is informational; repeating it would just be noise from a
    /// node that is simply unplugged.
    #[test]
    fn node_health_events_are_never_repeated() {
        let t0 = Instant::now();
        let config = AlertConfig {
            repeat_care_alert: Some(Duration::from_secs(60)),
            ..AlertConfig::default()
        };
        let mut e = AlertEngine::new(config, None, t0);
        e.ingest(&reading(1, true, 16.0), t0);

        let mut reminders = Vec::new();
        for i in 1..=600 {
            reminders.extend(kinds(
                &e.tick(t0 + Duration::from_secs(i)),
                Transition::Reminder,
            ));
        }
        assert!(
            !reminders.contains(&AlertKind::NodeSilent { node_id: 1 }),
            "node health must not repeat, got {reminders:?}"
        );
    }

    #[test]
    fn reminders_can_be_disabled() {
        let t0 = Instant::now();
        let config = AlertConfig {
            repeat_care_alert: None,
            ..AlertConfig::default()
        };
        let mut e = AlertEngine::new(config, None, t0);

        let mut r = reading(1, true, 16.0);
        r.fall_detected = true;
        e.ingest(&r, t0);

        let mut reminders = 0;
        for i in 1..=5000 {
            let now = t0 + Duration::from_secs(i);
            e.ingest(&reading(1, true, 16.0), now);
            reminders += kinds(&e.tick(now), Transition::Reminder).len();
        }
        assert_eq!(reminders, 0);
    }

    #[test]
    fn heartrate_is_carried_but_never_alerts() {
        let t0 = Instant::now();
        let mut e = engine(t0);
        let mut r = reading(1, true, 16.0);
        r.heartrate_bpm = 0.0;
        r.mmwave = Some(MmWaveExtension {
            present: true,
            hr_bpm: 0.0,
            br_bpm: 16.0,
            distance_cm: 100.0,
            targets: 1,
            confidence: 90,
            fusion_confidence: 80,
            sensor_type: 2,
        });
        // Heart rate is absent (0.0) and mmWave reports none either, while
        // breathing is healthy. Nothing may fire on that basis alone.
        for i in 0..=120 {
            let now = t0 + Duration::from_secs(i);
            assert!(e.ingest(&r, now).is_empty(), "at {i}s");
            assert!(e.tick(now).is_empty(), "at {i}s");
        }
        assert!(e.active_alerts().is_empty());
        assert_eq!(e.snapshot(t0)["nodes"][0]["heartrate_bpm_unvalidated"], 0.0);
    }
}
