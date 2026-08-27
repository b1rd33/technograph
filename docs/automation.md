# Automation recipes

Technograph stays a one-shot scanner. Scheduling, retention, and notifications
belong to the environment that already owns those responsibilities rather than
an embedded daemon holding credentials.

## Cron

Create a timestamped snapshot every day:

```cron
15 7 * * * /opt/homebrew/bin/technograph scan --input /absolute/path/domains.txt --output /absolute/path/snapshots/current.json
```

Keep a previous snapshot before replacing it, then compare the two:

```console
cp snapshots/current.json snapshots/previous.json
technograph scan --input domains.txt --output snapshots/current.json
technograph compare snapshots/previous.json snapshots/current.json --output snapshots/diff.json
```

Use absolute paths and let the surrounding job runner send notifications based
on `diff.json`. The diff suppresses removals when a current scan is incomplete.

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

Scanning remains fresh by default. v0.2 does not persist a result cache because
stale cache data can hide real changes and complicate evidence timestamps.
Schedulers that need deduplication should compare versioned snapshots. A future
cache must include the fingerprint digest, scanner version, network settings,
and both observation and cache timestamps in its key and output.
