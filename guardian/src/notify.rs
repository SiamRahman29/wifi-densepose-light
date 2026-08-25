//! Alert delivery.
//!
//! Guardian shells out to an operator-supplied command rather than speaking any
//! particular notification service. That keeps the crate dependency-free and
//! unopinionated: a three-line script wrapping `curl` covers webhooks, ntfy,
//! Pushover or a home-automation endpoint, and `mpg123 siren.mp3` covers the
//! case where the person who needs telling is in the next room.
//!
//! The delivery rules are shaped by the failure that matters. A care alert that
//! is emitted once, at 03:00, into a notifier that happens to be down is
//! indistinguishable from no monitor at all. So delivery retries, and an
//! unacknowledged care alert is repeated until the condition clears.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tracing::{error, info, warn};

use crate::alerts::{AlertEvent, Transition};

/// How the notifier reports what happened, for logging and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Delivered,
    /// Every attempt failed; the detail is in the log.
    Failed,
}

/// Spawns an operator-supplied command per alert transition.
#[derive(Debug, Clone)]
pub struct Notifier {
    command: PathBuf,
    /// How long a single attempt may take before it is killed.
    timeout: Duration,
    /// Total attempts for a care alert. Node-health events are not retried:
    /// they are informational and a flapping node would amplify.
    care_attempts: u32,
}

impl Notifier {
    pub fn new(command: PathBuf, timeout: Duration, care_attempts: u32) -> Self {
        Self {
            command,
            timeout,
            care_attempts: care_attempts.max(1),
        }
    }

    /// Environment handed to the notify command.
    ///
    /// Passed as environment rather than argv so a detail string can never be
    /// mistaken for a flag by whatever the operator wrote.
    pub fn env_for(event: &AlertEvent) -> BTreeMap<String, String> {
        let (kind, node_id) = match event.kind {
            crate::alerts::AlertKind::NodeSilent { node_id } => {
                ("node_silent", Some(node_id.to_string()))
            }
            crate::alerts::AlertKind::Fall => ("fall", None),
            crate::alerts::AlertKind::NoBreathing => ("no_breathing", None),
            crate::alerts::AlertKind::NoPresence => ("no_presence", None),
        };

        let transition = match event.transition {
            Transition::Raised => "raised",
            Transition::Cleared => "cleared",
            Transition::Reminder => "reminder",
        };

        let mut env = BTreeMap::from([
            ("GUARDIAN_ALERT_KIND".to_string(), kind.to_string()),
            ("GUARDIAN_TRANSITION".to_string(), transition.to_string()),
            ("GUARDIAN_DETAIL".to_string(), event.detail.clone()),
            (
                "GUARDIAN_SEVERITY".to_string(),
                if event.kind.is_care_alert() {
                    "care"
                } else {
                    "health"
                }
                .to_string(),
            ),
        ]);
        if let Some(id) = node_id {
            env.insert("GUARDIAN_NODE_ID".to_string(), id);
        }
        env
    }

    /// Deliver one event, retrying care alerts. Never returns an error: a
    /// broken notifier must not take the monitor down with it.
    pub async fn deliver(&self, event: &AlertEvent) -> Delivery {
        let attempts = if event.kind.is_care_alert() {
            self.care_attempts
        } else {
            1
        };
        let env = Self::env_for(event);

        for attempt in 1..=attempts {
            match self.attempt(&env).await {
                Ok(()) => {
                    if attempt > 1 {
                        info!(attempt, "notify command succeeded on retry");
                    }
                    return Delivery::Delivered;
                }
                Err(e) => {
                    warn!(attempt, attempts, error = %e, "notify command failed");
                    if attempt < attempts {
                        // Brief linear backoff. Kept short because a care alert
                        // delayed by minutes has already lost most of its value.
                        tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
                    }
                }
            }
        }

        error!(
            command = %self.command.display(),
            kind = ?event.kind,
            "ALERT NOT DELIVERED after {attempts} attempt(s): {}",
            event.detail
        );
        Delivery::Failed
    }

    async fn attempt(&self, env: &BTreeMap<String, String>) -> Result<(), String> {
        let mut cmd = Command::new(&self.command);
        cmd.envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;

        match tokio::time::timeout(self.timeout, child.wait()).await {
            Err(_) => {
                let _ = child.kill().await;
                Err(format!("timed out after {:?}", self.timeout))
            }
            Ok(Err(e)) => Err(format!("wait: {e}")),
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(format!("exited with {status}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::AlertKind;

    fn event(kind: AlertKind, transition: Transition) -> AlertEvent {
        AlertEvent {
            kind,
            transition,
            detail: "a detail string with spaces and --flags".to_string(),
        }
    }

    /// Write a shell script that records its environment and exits with `code`.
    fn script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("guardian-notify-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn env_carries_the_alert_shape() {
        let env = Notifier::env_for(&event(AlertKind::Fall, Transition::Raised));
        assert_eq!(env["GUARDIAN_ALERT_KIND"], "fall");
        assert_eq!(env["GUARDIAN_TRANSITION"], "raised");
        assert_eq!(env["GUARDIAN_SEVERITY"], "care");
        assert!(env["GUARDIAN_DETAIL"].contains("--flags"));
        assert!(!env.contains_key("GUARDIAN_NODE_ID"));

        let env = Notifier::env_for(&event(
            AlertKind::NodeSilent { node_id: 3 },
            Transition::Cleared,
        ));
        assert_eq!(env["GUARDIAN_ALERT_KIND"], "node_silent");
        assert_eq!(env["GUARDIAN_TRANSITION"], "cleared");
        assert_eq!(env["GUARDIAN_SEVERITY"], "health");
        assert_eq!(env["GUARDIAN_NODE_ID"], "3");

        let env = Notifier::env_for(&event(AlertKind::NoBreathing, Transition::Reminder));
        assert_eq!(env["GUARDIAN_TRANSITION"], "reminder");
    }

    #[tokio::test]
    async fn delivers_and_passes_the_environment_through() {
        let dir = tmpdir("ok");
        let out = dir.join("received.txt");
        let cmd = script(
            &dir,
            "notify.sh",
            &format!(
                "printf '%s %s %s' \"$GUARDIAN_ALERT_KIND\" \"$GUARDIAN_TRANSITION\" \
                 \"$GUARDIAN_SEVERITY\" > {}",
                out.display()
            ),
        );

        let n = Notifier::new(cmd, Duration::from_secs(5), 3);
        assert_eq!(
            n.deliver(&event(AlertKind::Fall, Transition::Raised)).await,
            Delivery::Delivered
        );
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "fall raised care");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_failing_care_alert_is_retried() {
        let dir = tmpdir("retry");
        let counter = dir.join("count");
        let cmd = script(
            &dir,
            "fail.sh",
            &format!("echo x >> {}; exit 1", counter.display()),
        );

        let n = Notifier::new(cmd, Duration::from_secs(5), 3);
        assert_eq!(
            n.deliver(&event(AlertKind::Fall, Transition::Raised)).await,
            Delivery::Failed
        );
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().lines().count(),
            3
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Health events are informational; retrying a flapping node would amplify
    /// noise rather than protect anyone.
    #[tokio::test]
    async fn health_events_are_not_retried() {
        let dir = tmpdir("health");
        let counter = dir.join("count");
        let cmd = script(
            &dir,
            "fail.sh",
            &format!("echo x >> {}; exit 1", counter.display()),
        );

        let n = Notifier::new(cmd, Duration::from_secs(5), 3);
        assert_eq!(
            n.deliver(&event(
                AlertKind::NodeSilent { node_id: 1 },
                Transition::Raised
            ))
            .await,
            Delivery::Failed
        );
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().lines().count(),
            1
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A notifier that hangs must not wedge the monitor.
    #[tokio::test]
    async fn a_hanging_command_is_killed_and_reported() {
        let dir = tmpdir("hang");
        let cmd = script(&dir, "hang.sh", "sleep 60");

        let n = Notifier::new(cmd, Duration::from_millis(200), 1);
        let started = std::time::Instant::now();
        assert_eq!(
            n.deliver(&event(AlertKind::Fall, Transition::Raised)).await,
            Delivery::Failed
        );
        assert!(started.elapsed() < Duration::from_secs(5), "must not block");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A missing or non-executable notifier is an operator error, reported
    /// rather than fatal.
    #[tokio::test]
    async fn a_missing_command_fails_without_panicking() {
        let n = Notifier::new(
            PathBuf::from("/nonexistent/guardian-notify"),
            Duration::from_secs(1),
            2,
        );
        assert_eq!(
            n.deliver(&event(AlertKind::NoBreathing, Transition::Raised))
                .await,
            Delivery::Failed
        );
    }
}
