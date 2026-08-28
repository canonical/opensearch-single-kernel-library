# ci-telemetry (vendored)

Host telemetry for CI runners: records what the machine was doing while the integration tests
ran, and uploads it as a workflow artifact — including, especially, when the job failed.

Integration failures on a runner normally leave only the test log, which cannot show that the
CPU was starved, memory ran out, inodes filled up, or I/O stalled past a `wait-for` timeout.
This action records that context so a failed or flaky run can be examined afterwards.

## Provenance

Vendored from the `ci-telemetry` PoC (`v0.1.0`, Telegraf 1.39.2 pinned by SHA256).

It is vendored rather than referenced as `uses: <org>/ci-telemetry@<ref>` because
`.github/zizmor.yaml` restricts `forbidden-uses` to `canonical/*`, `actions/*`,
`pypa/gh-action-pypi-publish` and `tiobe/tics-github-action`. Once the action is published under
`canonical/`, this directory should be deleted and the two steps in
`.github/workflows/integration_test.yaml` switched to a pinned `canonical/ci-telemetry@<ref>`.

To update: re-copy `action.yml`, `telegraf.conf` and `scripts/` from upstream. Nothing here is
modified for this repository — the OpenSearch-specific configuration lives outside the action,
in `.github/ci-telemetry-opensearch.conf`, passed via the `extra-config` input.

## Usage in this repository

See the `Start telemetry` / `Stop telemetry` steps in
`.github/workflows/integration_test.yaml`. Two properties matter there:

- `start` runs with `continue-on-error: true`. The script runs under `set -e` and would
  otherwise fail a 180-minute integration job over a telemetry problem.
- `stop` passes an explicit `artifact-name` including the matrix identity. `upload-artifact@v4`
  rejects duplicate artifact names, and the action's default is unique per run and job but not
  per matrix entry.

## What lands in the artifact

| File | Contents |
|---|---|
| `metrics.json` | Telegraf batches, one JSON object per line: `{"metrics": [...]}` |
| `telegraf.log` | Collector log |
| `telegraf.resolved.conf` | The exact config used, including the appended `extra-config` |

Collected: `cpu` (per-core, incl. `usage_steal`), `mem`, `swap`, `pressure` (PSI — cpu/mem/io
stall time), `disk` (bytes **and inodes**), `diskio`, `net`, `netstat`, `nstat`, `processes`,
`kernel`, `linux_sysctl_fs`, `conntrack`, and `procstat` for the Juju/OpenSearch process set.

Every metric is tagged with `run_id`, `run_attempt`, `repo`, `workflow`, `job`, `sha`, `ref`,
`runner_name`, `runner_os` and `image_os`, so a run can be pulled up whole or diffed against
another.

## Reading a bundle

```bash
gh run download <run-id> -n ci-telemetry-<name_in_artifact>
tar -xf ci-telemetry-bundle.tar.zst

# which processes were seen (is the OpenSearch JVM there?)
jq -r '.metrics[]|select(.name=="procstat").tags.process_name' metrics.json | sort -u

# stall time: the highest-signal metric for "the tests were randomly slow"
jq -r '.metrics[]|select(.name=="pressure")
       |"\(.timestamp) \(.tags.resource) \(.fields.some_avg10)"' metrics.json

# inodes remaining — a failure mode that looks like nothing else
jq -r '.metrics[]|select(.name=="disk")|"\(.tags.path) \(.fields.inodes_free)"' metrics.json

# collector cost, per input
jq -r '.metrics[]|select(.name=="internal_gather")|"\(.tags.input) \(.fields.gather_time_ns)"' metrics.json \
  | awk '{s[$1]+=$2;n[$1]++} END{for(i in s) printf "%-16s %6.1f ms\n", i, s[i]/n[i]/1e6}' | sort -k2 -rn
```

`metrics.json` holds one JSON document per line. When asserting over it, note that
`jq -e '<cond>' metrics.json` reflects only the **last** line; use `jq -ne 'all(inputs; <cond>)'`.

## Volume on this repository's jobs

The integration job allows up to 180 minutes, which is far longer than anything the action was
originally sized for. Measured on a 28-core host running this repo's OpenSearch workload:
~1.4 MB per 74 s, which extrapolates to **~200 MB of `metrics.json` over a full 180-minute job**,
packing down to a ~12 MB artifact. Expect less on the runners used in CI, which have fewer cores
and therefore fewer `cpu` series and fewer matched processes.

That file lives in `$RUNNER_TEMP`. This job already brackets itself with `df --human-readable`
steps, so if disk headroom turns out to be tight, the knob is the agent interval in
`telegraf.conf`:

```toml
[agent]
  interval = "2s"     # -> "5s" cuts volume ~2.5x, at the cost of PSI resolution
```

`extra-config` cannot change this — a second `[agent]` table is a TOML duplicate-key error — so
edit `telegraf.conf` in this directory directly, and note the change here so it is not lost on
the next re-vendor.

## Notes

- **Command lines are deliberately not recorded.** Telegraf's `procstat` captures each process's
  full `cmdline` by default; since the artifact is readable by anyone who can read the repo, that
  would publish any secret passed in `argv`. The config drops the field.
- **Overhead** is measured in-band — Telegraf watches its own process, so every bundle carries
  proof of its own cost. Reference measurement on a 28-core host: 2.5% of one core, 44 MB
  private memory, ~33 MB of metrics per 30 minutes.
- **Root.** Telegraf is launched under `sudo` when passwordless `sudo` is available, for a
  handful of root-only `/proc` reads. Without it everything still runs unprivileged.
- **Linux `x86_64`/`aarch64` only.**
