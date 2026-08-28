# Automation recipes

Technograph stays a one-shot scanner. Scheduling, retention, and notifications
belong to the environment that already owns those responsibilities rather than
an embedded daemon holding credentials.

v0.6 adds local immutable history to simplify that one-shot workflow:

```console
technograph watch --input domains.txt --store /absolute/path/history --output watch.json
technograph history stripe.com --store /absolute/path/history --limit 10
```

The first observation establishes a baseline. A changed scanner version or
fingerprint SHA-256 establishes a fresh baseline as well, so software upgrades
do not masquerade as website changes. History files use hashed domain
directories, atomic writes, and `0600` permissions.

## Cron

Run a watch scan every day and let cron notify on exit status 3:

```cron
15 7 * * * /opt/homebrew/bin/technograph watch --input /absolute/path/domains.txt --store /absolute/path/history --output /absolute/path/watch.json --fail-on-change
```

The explicit snapshot workflow remains supported when another system owns
durable storage:

```console
cp snapshots/current.json snapshots/previous.json
technograph scan --input domains.txt --output snapshots/current.json
technograph compare snapshots/previous.json snapshots/current.json --output snapshots/diff.json
```

Use absolute paths and let the surrounding job runner send notifications based
on `watch.json`, exit status 3, or `diff.json`. Both paths suppress removals
when a current scan is incomplete.

## GitHub Actions or another CI scheduler

A scheduled workflow should:

1. install the pinned Technograph release;
2. restore the last trusted snapshot from durable artifact storage;
3. run one `scan` command;
4. run `compare` against the prior snapshot;
5. upload the new snapshot and diff;
6. notify only when `changes` is non-empty or the scan itself fails.

Do not commit frequently changing snapshots back to the source branch with a
broad repository token. Prefer your CI system's artifacts, object storage, or a
dedicated data branch with tightly scoped credentials.

## Codex or another agent scheduler

Schedule a task that runs the same one-shot commands and asks the agent to
summarize only confirmed additions/removals plus `uncertain` observations. No
Technograph-specific skill is required: the CLI JSON contract and the local MCP
tools are sufficient. Keep notification credentials outside Technograph.

## Caching

Scanning remains fresh by default. History is not a result cache and never
avoids HTTP or DNS work. Every `watch` invocation performs a new scan, records
the observation timestamp, scanner identity, and fingerprint digest, then
compares only compatible observations.
