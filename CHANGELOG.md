# Changelog

## 0.1.0 — 2026-10-09 (prerelease)

- First public source release, extracted into independent service paths and configuration templates.
- Durable SQLite queue, source-signature checks, per-file checkpoints, retained deletions and history.
- Priority retries, bounded commands, daytime latching and nighttime retry policy.
- Restricted web controller with session authentication, CSRF, manual stop/start, error explanations, percentages and conditional ETA.
- Linux metadata/symlink restore helper.
- Pinned rclone backend patches and reproducible build, Python/HTTP fault tests and local integration.
- Russian operations/restore documentation and English overview.

Known limits: fixed Moscow day/night boundaries, Russian web UI, x86_64 build recipe, no atomic live-system snapshot, no database dump generation, no automatic history pruning, and no claim of completed full-server restore qualification.
