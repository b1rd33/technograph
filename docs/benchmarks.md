# Performance verification

Network performance is measured separately from deterministic CPU benchmarks.
The assignment budget is 20 domains in under 60 seconds on a standard laptop.
The committed 20-domain homepage scan completed in 4.064 seconds; later live
release checks have remained comfortably below the budget. Results vary with
DNS, remote servers, location, and bot protection.

Run the reproducible offline microbenchmarks with:

```console
make benchmark
```

Reference measurement on 2026-08-28, Apple M2 Pro, Darwin/arm64, Go 1.25.7:

| Benchmark | Result | Allocation |
| --- | ---: | ---: |
| Reviewed 24-pattern detection over seven representative signals | 7.924 µs/op | 2,583 B/op, 22 allocs/op |
| Static extraction from a 16 KB, 100-block HTML fixture | 441.263 µs/op (37.77 MB/s) | 360,915 B/op, 5,546 allocs/op |

These numbers are reference observations, not flaky CI thresholds. CI executes
each benchmark for a fixed 100 iterations to catch crashes and severe
regressions while functional limits—bounded body size, domain concurrency,
page cap, timeouts, and MCP batch cap—are asserted by tests.
