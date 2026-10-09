#!/usr/bin/env bash
# Fresh install / stopped-service update. Never starts a backup automatically.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
[ "$#" -eq 2 ] && [ "$1" = '--rclone' ] || { echo 'Usage: sudo bash scripts/install.sh --rclone ./dist/rclone-fast' >&2; exit 1; }
project=$(cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(readlink -f -- "$2")
[ -x "$binary" ] || { echo 'Built rclone executable not found.' >&2; exit 1; }
"$binary" version | grep -F 'v1.75.1-ubuntu-drime.2' >/dev/null || { echo 'Build the pinned client with scripts/build-rclone.sh first.' >&2; exit 1; }
for unit in ubuntu-drime-backup ubuntu-drime-backup-control; do
  if systemctl is-active --quiet "$unit"; then
    echo "Stop $unit before updating its files." >&2; exit 1
  fi
done
umask 077
install -d -m 755 /opt/ubuntu-drime-backup
install -d -m 700 /etc/ubuntu-drime-backup /var/lib/ubuntu-drime-backup
for name in daemon.py safety.py control.py progress.py restore_metadata.py; do
  install -m 755 "$project/src/$name" "/opt/ubuntu-drime-backup/$name"
done
install -m 644 "$project/src/control.php" /opt/ubuntu-drime-backup/control.php
install -m 755 "$binary" /opt/ubuntu-drime-backup/rclone-fast
install -m 755 "$project/scripts/rclone-network" /opt/ubuntu-drime-backup/rclone-network
install -m 600 "$project/config/backup.example.json" /etc/ubuntu-drime-backup/backup.example.json
install -m 600 "$project/config/resolv-rclone.conf.example" /etc/ubuntu-drime-backup/resolv-rclone.conf.example
install -m 644 "$project/systemd/ubuntu-drime-backup.service" /etc/systemd/system/ubuntu-drime-backup.service
install -m 644 "$project/systemd/ubuntu-drime-backup-control.service" /etc/systemd/system/ubuntu-drime-backup-control.service
python3 -m py_compile /opt/ubuntu-drime-backup/*.py
systemd-analyze verify /etc/systemd/system/ubuntu-drime-backup.service /etc/systemd/system/ubuntu-drime-backup-control.service
systemctl daemon-reload
echo 'Installed. Next: sudo python3 scripts/configure.py. No service has been started.'
