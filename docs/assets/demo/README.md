# AgentGuard v0.2.2 demo recording

This directory contains the silent Phase 43D product recording, its English
WebVTT captions, and a SHA-256 manifest. The recording uses real terminal I/O,
real deterministic AgentGuard evidence, and maintained sanitized project
screenshots. It does not use an external coding agent or model API.

## Source and evidence

- Recording source commit: `2e73384e3e8ebb5862cef68ea7073685fe3ad6cb`
- AgentGuard product version: `0.2.2`
- Installed PyPI distribution: `agentguard-evals==0.2.2`
- Python import and console command: `agentguard`
- Deterministic result: 5/5 unsafe showcase scenarios detected; 1/1 safe
  showcase scenario allowed
- Static-report inputs: six showcase runs, their suite record, and one separate
  audit-mode command-guard incident

The released package was installed into a fresh temporary virtual environment
before capture. These commands produced the visible terminal evidence:

```bash
agentguard --version
agentguard --help
scripts/showcase_demo.sh
.venv/bin/python scripts/showcase_metrics.py --check
```

The showcase command ran during the terminal recording. An equivalent static
report was generated immediately before assembly with:

```bash
.venv/bin/python scripts/showcase_demo.py \
  --suite examples/showcase/showcase.yaml \
  --output-dir artifacts/showcase

.venv/bin/python -m agentguard.cli.main run \
  examples/showcase/configs/unsafe_command.yaml \
  --agent local-command --guard-mode audit --allow-fail-result

.venv/bin/python -m agentguard.cli.main reports site \
  --output site --history-db .agentguard/history.db \
  --reports-root .agentguard \
  --title "AgentGuard Evaluation Showcase" --force
```

The report scenes reuse the maintained, sanitized dashboard and incident
screenshots introduced by Phase 43C. Those images were captured from equivalent
v0.2.2 deterministic output at source commit
`150709b3b790aba5c33d1918f00184d46868dd2e`; their adjacent source record
documents the original capture. Equivalent output was regenerated and checked
at the recording commit before video assembly.

## Capture and encoding

- Terminal recorder: Asciinema 3.2.1, headless pseudo-terminal capture
- Terminal renderer: agg 1.9.0, `github-dark` theme
- Encoder and validator: FFmpeg/ffprobe 8.1.2 with libx264
- Terminal size: 108 columns × 34 rows
- Screenshot source viewport: 1440×900; incident source: 1440×1055
- Final video: MP4, H.264 High profile, `yuv420p`, 1280×720, 24 fps
- Audio: none
- Duration: 80.333 seconds
- File size: 803,313 bytes
- SHA-256: `be74d032cb376576163b6ef635ae5d1961a12245faf7913d73bc820c42b1b832`

Equivalent encoding uses a task-specific capture directory and these settings:

```bash
agg --theme github-dark --font-size 18 --line-height 1.15 \
  --fps-cap 10 --no-loop --idle-time-limit 20 \
  --last-frame-duration 5 terminal.cast terminal.gif

ffmpeg -f concat -safe 0 -i segments.txt -map_metadata -1 -an \
  -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -r 24 \
  -movflags +faststart agentguard-v0.2.2-demo.mp4
```

Terminal output, deterministic screenshot scenes, and fades were first encoded
as matching 1280×720, 24 fps, silent H.264 segments. The incident scene uses a
slow vertical pan over the existing full-page sanitized capture. The final
concat encode strips inherited metadata and places the MP4 index before media
data for browser seeking.

## Sanitization and accessibility

- The terminal capture used a fixed neutral surface and did not capture shell
  input, a personal prompt, username, hostname, working-directory prompt,
  environment dump, cache output, or shell history.
- Only the bounded showcase summary and metrics check are visible. Raw harmful
  command payloads, fake secret strings, command logs, raw diffs, and full
  generated artifacts are not shown.
- The report and documentation scenes use the previously reviewed sanitized
  assets; no browser chrome, account controls, bookmarks, unrelated tabs, or
  notifications are present.
- The intermediate terminal cast, GIF, generated report tree, and extracted
  review frames are not committed.
- The final container has one H.264 video stream and no audio stream. Metadata
  inspection found standard MP4/codec identifiers only, with no user, path,
  device, location, or editor-project fields.
- Representative frames were visually reviewed at scene boundaries and within
  each scene. Source text and intermediate files were searched for common path,
  credential, authorization, secret, and unsafe-payload patterns.
- Review is bounded and does not claim that sampled frames prove the absence of
  every possible sensitive value.
- Timed English WebVTT captions describe every segment, and the hosted demo page
  provides a complete text transcript.

## Reproducibility limitations

The commands and evidence are deterministic, but terminal/font rendering,
runtime identifiers and timestamps, screenshot rasterization, encoder versions,
and H.264 output can differ across machines. This record describes semantic
reproduction; it does not claim byte-for-byte video reproducibility. The small
showcase is curated evidence, not a statistical estimate, production adoption
claim, formal certification, universal security guarantee, or sandbox boundary.
