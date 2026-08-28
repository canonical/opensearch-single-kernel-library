#!/usr/bin/env bash
# ci-telemetry — stop collection, finalize the bundle.
# Must be safe to run under `if: always()`: never fails the job, even if start
# never ran or the collector died mid-run. Hence no `set -e`.
set -uo pipefail

CI_TELEMETRY_DIR="${CI_TELEMETRY_DIR:-${RUNNER_TEMP:-/tmp}/ci-telemetry}"
BUNDLE_PATH="${BUNDLE_PATH:-$(dirname "$CI_TELEMETRY_DIR")/ci-telemetry-bundle.tar.zst}"
PIDFILE="$CI_TELEMETRY_DIR/telegraf.pid"
LAUNCHER_PIDFILE="$CI_TELEMETRY_DIR/launcher.pid"

# Publish the path we actually wrote so the upload step never guesses. Set before
# any early exit so a missing bundle is a warning downstream, not a broken ref.
emit_output() {
  [ -n "${GITHUB_OUTPUT:-}" ] && echo "bundle-path=$1" >> "$GITHUB_OUTPUT"
  return 0
}

SUDO=()
if sudo -n true 2>/dev/null; then
  SUDO=(sudo -n)
fi

if [ ! -d "$CI_TELEMETRY_DIR" ]; then
  echo "ci-telemetry: nothing to stop ($CI_TELEMETRY_DIR does not exist)"
  emit_output ""
  exit 0
fi

# --- stop telegraf: SIGTERM triggers a final flush + clean shutdown -----------
# $PIDFILE is written by telegraf itself (--pidfile), so this is the collector's
# pid, not the pid of the sudo wrapper that launched it.
if [ -s "$PIDFILE" ]; then
  PID="$(cat "$PIDFILE")"
  if "${SUDO[@]}" kill -0 "$PID" 2>/dev/null; then
    echo "ci-telemetry: stopping telegraf (pid $PID)"
    "${SUDO[@]}" kill -TERM "$PID" 2>/dev/null || true
    for _ in $(seq 1 15); do
      "${SUDO[@]}" kill -0 "$PID" 2>/dev/null || break
      sleep 1
    done
    if "${SUDO[@]}" kill -0 "$PID" 2>/dev/null; then
      echo "ci-telemetry: SIGTERM timed out, sending SIGKILL (final flush lost)"
      "${SUDO[@]}" kill -KILL "$PID" 2>/dev/null || true
    fi
  fi
fi

# Wait for the launcher (sudo) to reap, so nothing is still writing into the
# directory while we archive it.
if [ -s "$LAUNCHER_PIDFILE" ]; then
  LAUNCHER_PID="$(cat "$LAUNCHER_PIDFILE")"
  for _ in $(seq 1 10); do
    kill -0 "$LAUNCHER_PID" 2>/dev/null || break
    sleep 1
  done
fi
rm -f "$PIDFILE" "$LAUNCHER_PIDFILE"

# telegraf may have run as root — hand files back so artifact upload can read them
if [ ${#SUDO[@]} -gt 0 ]; then
  "${SUDO[@]}" chown -R "$(id -u):$(id -g)" "$CI_TELEMETRY_DIR" 2>/dev/null || true
fi

# --- bundle --------------------------------------------------------------------
# Name the file after what it actually contains: the previous version wrote gzip
# into a .tar.zst path whenever zstd was missing.
if ! command -v zstd >/dev/null 2>&1; then
  BUNDLE_PATH="${BUNDLE_PATH%.tar.zst}.tar.gz"
  echo "ci-telemetry: zstd unavailable, falling back to gzip ($BUNDLE_PATH)"
  COMPRESS=(-z)
else
  COMPRESS=(--zstd)
fi

rm -f "$BUNDLE_PATH"
tar "${COMPRESS[@]}" -cf "$BUNDLE_PATH" -C "$CI_TELEMETRY_DIR" . || true

# tar creates the output file even when it fails part-way (a metric file still
# being written yields "file changed as we read it"), so existence proves
# nothing — read the archive back instead.
if tar -tf "$BUNDLE_PATH" >/dev/null 2>&1; then
  echo "ci-telemetry: bundle at $BUNDLE_PATH ($(du -h "$BUNDLE_PATH" | cut -f1))"
  emit_output "$BUNDLE_PATH"
else
  echo "ci-telemetry: WARNING: bundle is missing or unreadable, not uploading" >&2
  emit_output ""
fi
