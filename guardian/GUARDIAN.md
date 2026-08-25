# Guardian

A privacy-preserving elderly-care room monitor. Presence, respiration, and fall
alerts from ESP32-S3 CSI nodes. No camera, no pose estimation, no raw CSI
leaving the node.

```bash
cd guardian
cargo run -- --udp-bind 0.0.0.0 --udp-allow 192.168.1.0/24 --alert-nodes 1
```

## Why this is a separate crate

Guardian is deliberately **not** a member of the `v2/` workspace. That workspace
pulls in nine git submodules and ~60 crates of pose machinery, none of which
this binary uses; at the time Guardian was written none of those submodules were
initialised, so `cargo check` could not even load the workspace manifest.

The keep-list for this product is three things:

| Keep | Why |
|---|---|
| `firmware/esp32-csi-node/` | the working sensor, untouched |
| the UDP vitals receive path | ~200 lines that parse the 32-byte packet |
| a thin alert layer | "no breathing 60 s", "fall flag", "no presence 12 h" |

Guardian is the second and third of those. It talks to the first over UDP and
depends on nothing else in the repository.

## The design constraint: trust the firmware

`firmware/esp32-csi-node/main/edge_processing.c` is correct in approach:

- it measures the **true** inter-frame sample rate from timestamps
  (EMA-smoothed, clamped 8-30 Hz) rather than assuming one;
- it designs real **temporal** biquad bandpass filters at 0.1-0.5 Hz (breathing)
  and 0.8-2.0 Hz (heart), re-tuning on >15% rate drift;
- it extracts and unwraps per-subcarrier phase.

It emits all of that as `edge_vitals_pkt_t` (`edge_processing.h:140`, 32 bytes).
**Guardian's job is to trust that packet, not to re-derive it.** There is no
signal processing in this crate, and adding any should be treated as a
regression.

### What re-deriving it cost last time

The previous server recomputed these features itself and got all of them wrong.
Measured 2026-08-26 with `evidence/motion-test.py` (3-phase A/B/C test, 30 s
each: still / moving / still, ~2030 frames per phase; raw output in
`evidence/motion-test-results.json`):

| Signal | Still A | Moving B | Still C | B : still |
|---|---|---|---|---|
| `motion_band_power` | 98.9 | 94.5 | 88.2 | 1.01 (blind) |
| `breathing_band_power` | 115.0 | 109.2 | 110.1 | 0.97 (blind) |
| `spectral_power` | 268.5 | 265.4 | 263.4 | 1.00 (blind) |
| raw CSI temporal variance, node 1 | 0.60 | 2.17 | 0.41 | 4.3x (works) |
| raw CSI temporal variance, node 2 | 0.27 | 1.22 | 0.28 | 4.4x (works) |
| raw CSI temporal variance, node 3 | 3.87 | 6.12 | 1.84 | 2.1x (unstable) |

Every named server feature was blind to a person walking and waving. The four
root causes, all in `v2/crates/wifi-densepose-sensing-server/src/main.rs`:

1. **Band powers used the wrong axis** (L2453-2473). `motion_band_power` and
   `breathing_band_power` split the *subcarrier array* in half and labelled the
   halves "motion" and "breathing" — that is spatial frequency across the
   channel, dominated by static multipath from walls and furniture. Breathing is
   0.1-0.5 Hz *in time*. These features could not detect what they were named
   after at any SNR.
2. **The working signal was masked** (L2447). `compute_subcarrier_variances()`
   computes correct temporal variance — the 4x signal above — and then
   `intra_variance.max(temporal_variance)` discarded it every frame, because
   intra is ~100 and temporal is ~0.5-6.
3. **Sample rate wrong by ~7x** (L6782). The server hardcoded `1000.0 / 500.0`
   = 2 Hz while the firmware measured 13-19 Hz. At an assumed 2 Hz, Nyquist is
   1 Hz, so heart rate (1.0-1.7 Hz) was above the sampling limit: the server was
   arithmetically incapable of producing a real heartbeat.
4. **Window too short** (`FRAME_HISTORY_CAPACITY = 100`, L1597). 100 frames at
   ~15 Hz is 6.7 s; resolving 0.1 Hz breathing needs one full 10 s cycle
   minimum, realistically 30-60 s.

Guardian does not fix these. It stops asking the question.

## Alert rules

All thresholds are flags; the defaults are shown.

| Alert | Condition | Default |
|---|---|---|
| `fall` | a trusted node raised the firmware fall flag | immediate |
| `no_breathing` | someone is present but no breathing rate in the 6-30 BPM band has arrived | 60 s |
| `no_presence` | no trusted node has seen anyone | 12 h |
| `node_silent` | a trusted node stopped reporting (equipment health, not a care alert) | 60 s |

Several rules exist specifically to avoid false alarms, which in a care product
are not a cosmetic problem — they are how the product gets unplugged:

- **Leaving the room is not apnea.** With nobody present, the breathing question
  is not asked at all. The clock also reseeds when presence begins, so walking
  back in cannot instantly trip the alarm before the firmware's filter locks.
- **Equipment failure is not apnea.** If no fresh trusted node still sees the
  person, `no_breathing` is suspended and `node_silent` fires instead. The
  honest signal is "the monitor is broken", never "she stopped breathing".
- **Stale readings do not count.** A node that dies while holding a healthy
  breathing reading would otherwise satisfy the breathing check forever and
  silently disable the apnea alarm. Readings older than the node-silence window
  are ignored. This bug was real and was caught by end-to-end testing after the
  unit tests missed it; see `a_dead_node_holding_a_good_reading_cannot_suppress_apnea`.
- **Falls latch.** The firmware flag clears as soon as the person stops moving,
  so an auto-clearing fall alert could vanish before anyone looked. It stays up
  until `POST /alerts/fall/ack`.
- **Breathing plausibility matches the filter.** 6-30 BPM is exactly the
  0.1-0.5 Hz band the firmware's biquad passes. A reading outside it did not
  come through that filter as a real cycle, so it is treated as *no reading*
  rather than as a number.

### Node trust

`--alert-nodes 1` restricts alerting to node 1. Other nodes are still received
and shown in `/status` but cannot raise anything.

This exists because node health is not uniform. In the 2026-08-26 measurement,
node 3 disagreed with **itself** between the two still phases (variance 3.87 vs
1.84) and node 2 showed RSSI stdev of 6.2-6.8 dB in *all* phases including
still — a bad link, unrelated to motion. Both need placement work before their
readings should be allowed to wake anyone up at 3 a.m. Guardian ships with no
node IDs hardcoded; this is a per-site setting.

## Security posture

The vitals packets are unauthenticated, so the source address is the only
boundary available. Following the same posture as ADR-296:

- the UDP receiver binds to loopback by default;
- a routable bind (`0.0.0.0`, a LAN IP) **refuses to start** without
  `--udp-allow <IP/CIDR>`, or an explicit `--udp-insecure-lan` opt-in;
- loopback is always permitted; disallowed sources are dropped and counted, with
  rate-limited logging so a misconfigured allowlist cannot flood the log at
  ~15 Hz per node.

The HTTP surface is read-only apart from the fall acknowledgement, and binds to
loopback by default.

## Heartbeat: deferred, deliberately

Heart rate is parsed and exposed in `/status` as
`heartrate_bpm_unvalidated`. **It never drives an alert.**

Heartbeat chest displacement is ~0.2-0.5 mm against ~5-12 mm for breathing —
roughly 30x smaller — at 1-2 Hz where micro-movement dominates. Published ESP32
CSI heart-rate results generally require a motionless subject about 1 m from the
antenna in a controlled room. Across a bedroom, with an elderly person shifting
in a chair, that will not hold. More ESP32s do not fix this; it is a
sensor-physics limit, not a node-count limit. (CLAIMED — from literature, not
measured here.)

The honest path if heart rate is wanted: `edge_fused_vitals_pkt_t`
(`edge_processing.h:174`, ADR-063) already defines a 60 GHz mmWave fusion path
with `mmwave_hr_bpm` / `mmwave_br_bpm`, and a ~$12 Seeed MR60BHA2 fuses into a
packet the firmware already speaks. Guardian parses that 48-byte packet today
and surfaces the mmWave fields, so adopting the sensor is a hardware decision,
not a code one.

**This decision is still open.** It only affects the alert layer, so it does not
block anything else.

## Fall detection: unsolved validation problem

Guardian currently forwards the firmware's fall flag; it does not implement its
own heuristic. The heuristic is buildable (large transient, then sustained
post-event stillness, no return to upright motion). *Validating* it is the hard
part: you cannot test on your grandmother. It needs a proxy — weighted cushion
drops, or a younger person falling onto a mattress — before any fall alert
should be trusted.

Until that validation exists, treat `fall` as an unverified signal.

## Alert delivery

`report()` in `src/main.rs` logs transitions and is the seam where a real
notifier (SMS, push, siren) is wired in. Logging is deliberately all it does
today: an untested notification path in a care product is worse than an
obvious absence of one.

## HTTP surface

| Route | Method | Purpose |
|---|---|---|
| `/status` | GET | full snapshot: per-node state, presence, active alerts |
| `/alerts` | GET | active alerts only |
| `/alerts/fall/ack` | POST | acknowledge a latched fall alert |
| `/healthz` | GET | liveness |

## Validation

```bash
cd guardian
cargo test              # 28 tests: parsers, allowlist, alert state machine
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The alert engine takes an explicit `now: Instant` at every entry point, so
timeout behaviour (including the 12-hour absence rule) is tested without
sleeping.

`evidence/` holds the measurement this design rests on: `motion-test.py` is the
A/B/C reproducer, `motion-test-results.json` its output, and
`2026-08-26-handoff.md` the original findings. `motion-test.py` measures the
*old* server's WebSocket feature stream; it is kept as the record of why
Guardian exists, and it needs that server running to execute.
