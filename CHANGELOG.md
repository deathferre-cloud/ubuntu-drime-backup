# Changelog

## 0.1.2 — 2026-10-09 (prerelease)

- Refresh panel status, progress, ETA and recent errors every 30 seconds without reloading the page.
- Added a filling countdown ring, loading indicator and last successful page-refresh time in Moscow.
- Failed reads retain previous data and retry; expired sessions stop polling. Status reads release the PHP session lock before querying the controller, so manual stop requests are not queued behind that lock.
- Inline JavaScript uses a per-response CSP nonce; refreshes are read-only authenticated GET requests.

## 0.1.1 — 2026-10-09 (prerelease)

- Recover an ambiguous Drime history move only after verifying the original object ID, exact destination parent/name, and absence of deleted or duplicate entries. Missing proof remains a failure; no history bypass.
- Correlate transfer errors and batch summaries with durable SQLite incident membership. A batch closes only after each of its files has a confirmed stable upload, including after process restarts. Later ordinary source changes do not reopen a resolved historical incident.
- Explain `No valid entries to move` in the panel and recognize exact paths in `Couldn't move` errors.
- Reject stale database rows when recording upload confirmations.
- Added real HTTP move fault injection and incident regressions. Day/night stop limits and file-retention behavior are unchanged.

## 0.1.0 — 2026-10-09 (prerelease)

- First public source release, extracted into independent service paths and configuration templates.
- Durable SQLite queue, source-signature checks, per-file checkpoints, retained deletions and history.
- Priority retries, bounded commands, daytime latching and nighttime retry policy.
- Restricted web controller with session authentication, CSRF, manual stop/start, error explanations, percentages and conditional ETA.
- Linux metadata/symlink restore helper.
- Pinned rclone backend patches and reproducible build, Python/HTTP fault tests and local integration.
- Russian operations/restore documentation and English overview.

Known limits: fixed Moscow day/night boundaries, Russian web UI, x86_64 build recipe, no atomic live-system snapshot, no database dump generation, no automatic history pruning, and no claim of completed full-server restore qualification.

- Added bounded observer API retries with daytime process pause/resume and transport timing diagnostics; exhausted requests still count toward the durable safety limit.
- Fixed a panel explanation that misread 510 unconfirmed files as zero; added coverage for nonzero counts.

- Documented and supplied an optional TCP DNS profile for environments with unreliable UDP resolution; the system resolver is unchanged.
