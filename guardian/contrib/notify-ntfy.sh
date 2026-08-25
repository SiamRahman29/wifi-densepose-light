#!/bin/sh
# Example Guardian notify command: forward alerts to an ntfy topic.
#
#   guardian --notify-command /path/to/notify-ntfy.sh
#
# Guardian sets these in the environment:
#   GUARDIAN_ALERT_KIND  fall | no_breathing | no_presence | node_silent
#   GUARDIAN_TRANSITION  raised | reminder | cleared
#   GUARDIAN_SEVERITY    care | health
#   GUARDIAN_DETAIL      human-readable explanation
#   GUARDIAN_NODE_ID     set only for node_silent
#
# Exit non-zero to tell Guardian delivery failed; care alerts are retried.
#
# Set NTFY_TOPIC to a long random string. An ntfy topic is a public URL: anyone
# who knows it can read every alert, which is to say every time the person is
# absent, asleep, or has fallen. Prefer a self-hosted server with auth.
set -eu

: "${NTFY_TOPIC:?set NTFY_TOPIC to your topic name}"
NTFY_SERVER="${NTFY_SERVER:-https://ntfy.sh}"

# Only escalate care conditions. Node health goes out quietly so a flapping
# node cannot train the household to ignore the alarm.
case "$GUARDIAN_SEVERITY" in
  care)
    case "$GUARDIAN_TRANSITION" in
      cleared) priority=low  ; tags=white_check_mark ;;
      *)       priority=urgent ; tags=rotating_light ;;
    esac
    ;;
  *) priority=low ; tags=warning ;;
esac

title="$GUARDIAN_ALERT_KIND ($GUARDIAN_TRANSITION)"
[ -n "${GUARDIAN_NODE_ID:-}" ] && title="$title node $GUARDIAN_NODE_ID"

exec curl --fail --silent --show-error --max-time 10 \
  -H "Title: $title" \
  -H "Priority: $priority" \
  -H "Tags: $tags" \
  -d "$GUARDIAN_DETAIL" \
  "$NTFY_SERVER/$NTFY_TOPIC"
