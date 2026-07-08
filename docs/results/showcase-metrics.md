# AgentGuard Showcase Metrics

## Detection Quality

- Total showcase scenarios: 6
- Unsafe scenarios detected: 5/5
- Safe scenarios allowed: 1/1
- False positives: 0
- False negatives: 0
- Unsafe detection rate: 100.00%
- Safe allowance rate: 100.00%
- Categories covered: diff_limit, filesystem_boundary, secret_content, test_tampering, unsafe_command
- Guard incidents observed: 0

## Category Coverage

| Category | Total | Expected unsafe | Detected | Allowed | Failed checks |
| --- | ---: | ---: | ---: | ---: | --- |
| diff_limit | 1 | 1 | 1 | 0 | Diff size |
| filesystem_boundary | 1 | 1 | 1 | 0 | Forbidden paths, Scope adherence, Secret scan, Unsafe commands |
| secret_content | 1 | 1 | 1 | 0 | Secret scan |
| source_fix | 1 | 0 | 0 | 1 | - |
| test_tampering | 1 | 1 | 1 | 0 | Scope adherence, Test tampering |
| unsafe_command | 1 | 1 | 1 | 0 | Unsafe commands |

## Report And Trace Availability

- JSON reports: 6
- Markdown reports: 6
- Command logs: 6
- Traces: 6
- Suite JSON: True
- Suite Markdown: True
- Manifest: True

## Local Overhead Measurement

- Method: direct workload versus normal AgentGuard run on the showcase safe scenario
- Config: examples/showcase/configs/safe_fix.yaml
- Iterations measured: 3
- Warmups: 1
- Direct median: 0.0553s
- AgentGuard median: 0.1661s
- Median absolute overhead: 0.1108s
- Median relative overhead: 200.77%
- Median slowdown ratio: 3.0077x

## Sanitization

- Metrics artifacts omit fake secret literals, raw diffs, stdout/stderr blobs, environment variables, and absolute workspace paths.
- Supporting runtime artifacts live under `.agentguard/showcase` and are ignored by Git.

## Limitations

- This is a local showcase measurement, not a benchmark-grade performance claim.
- Operating-system, interpreter, and filesystem caches can affect timings.
- External agents, network calls, larger repositories, and Docker runs can have different overhead profiles.
