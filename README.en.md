# Ubuntu Drime Backup

Continuous, one-way Ubuntu file backup to **Drime**, preserving paths from `/`, with a durable SQLite journal, version history and an optional PHP control panel.

[Русская документация](README.md) · [Operations (Russian)](docs/OPERATIONS.ru.md) · [Restore (Russian)](docs/RESTORE.ru.md)

**v0.1.4 is a prerelease.** It was extracted from a working Ubuntu 22.04 deployment. The original deployment's initial full backup was still in progress at release preparation. Sample round trips and local integration tests do not establish that an entire server can already be restored. This is an independent project, not an official Drime product.

Features:

- Preserve source paths, including configuration, websites, home directories and cron.
- Detect changes using filesystem signatures; do not propagate deletions.
- Keep acknowledged files after partial failures; prioritize due retries.
- Save overwritten objects to a separate history tree and Linux metadata to manifests.
- Apply persistent manual stops and a day/night safety policy.
- Display percentages, an explicitly conditional completion estimate, and recent errors with evidence-based resolution states.
- Include reproducible patches for rclone v1.75.1: command-scoped absence caching and exact duplicate-folder conflict recovery.

This is not an atomic disk snapshot. Create database dumps separately. Symlinks are stored as target text and recreated by the metadata restore helper. Runtime sockets and device nodes are metadata-only.

## Quick start

Requirements: Ubuntu 22.04/24.04 x86_64, systemd, Python 3.10+, curl, CA certificates, GCC, OpenSSL and PHP CLI for tests. PHP-FPM/nginx/HTTPS are optional for the panel.

```bash
git clone https://github.com/deathferre-cloud/ubuntu-drime-backup.git
cd ubuntu-drime-backup
bash scripts/build-rclone.sh
bash scripts/check.sh
sudo bash scripts/install.sh --rclone ./dist/rclone-fast
sudo python3 scripts/configure.py
```

The installer does **not** start uploading. The configurator asks for a dedicated workspace ID, account email, hidden API token and source roots. Review the configuration and Drime alert-policy requirements in the Russian README, run its read-only preflight, then enable `ubuntu-drime-backup.service`.

The default clock is **Europe/Moscow**. From 07:00 to 19:00, five unresolved daytime errors latch a stop; critical failures stop immediately. At night, failures are logged and retried without a new automatic persistent latch. Manual stops and prior daytime latches persist. These fixed day boundaries are part of v0.1.4's documented behavior.

```bash
sudo systemctl status ubuntu-drime-backup
sudo journalctl -u ubuntu-drime-backup -f
sudo python3 /opt/ubuntu-drime-backup/control.py stop
```

The authenticated web panel is currently in Russian. It runs through a restricted Unix-socket controller rather than giving PHP arbitrary root command execution. Setup: `scripts/configure-panel.py` plus the nginx location example on an existing HTTPS site.

Use one writer per destination tree. Never treat an active process, a sample hash match, or a green historical error as proof that the entire first backup is complete. Check `initial_copy_complete`, the remaining queue and a restore into a separate directory. Versions are retained without automatic pruning.

MIT license; rclone attribution and its MIT license are included in `NOTICE` and `licenses/`.

Version 0.1.1 verifies an ambiguous history move by the original object ID in the exact destination before continuing. Durable incident membership links error summaries to actual upload confirmations, including across restarts; unrelated successful uploads never resolve another batch. See the operations guide for the migration and verification details.

### Stalled-command recovery (0.1.3)

Distinct `Making directory` events count as traversal progress, never as upload acknowledgements. Directory batches default to 16 entries. After 600 seconds without progress, the child is terminated and a durable 600-second maintenance pause begins, both day and night. After a read-only cloud preflight, retries use at most 16 entries and two transfers until a successful batch. Manual stops and existing safety latches are never cleared. Since 0.1.4, proven recovery of the matching operation releases its error-budget slot. Failed probes reschedule and actual errors retain the daytime budget. Process crashes, command-duration limits and security failures retain their prior policies. The panel shows the next attempt, and intentional pauses are excluded from ETA samples.

### Unresolved error budget (0.1.4)

The guard and panel now share the same resolution evidence. Confirmed recovery of a failed file/batch removes those errors from active day/night counts, preserving historical records. Unrelated successes do not clear failures, and security alerts require explicit review. Successful full observer reads and source scans resolve their respective outage events. The panel lists unresolved events even when they are older than the last ten journal lines. State upgrades to version 2; unavailable legacy evidence is kept unresolved, never silently discarded. Manual and already latched safety stops require operator action.
