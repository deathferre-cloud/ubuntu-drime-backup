#!/usr/bin/env bash
# Build an explicitly versioned rclone derivative. Does not install or start it.
set -euo pipefail
project=$(cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$project/dist"}
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/ubuntu-drime-build.XXXXXXXX")
cleanup() { case "$build" in /*/ubuntu-drime-build.*) rm -rf -- "$build";; *) exit 1;; esac; }
trap cleanup EXIT
curl -fL --retry 3 --connect-timeout 20 --max-time 600 \
  https://go.dev/dl/go1.27.2.linux-amd64.tar.gz -o "$build/go.tgz"
printf '%s  %s\n' ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5 "$build/go.tgz" | sha256sum -c -
curl -fL --retry 3 --connect-timeout 20 --max-time 600 \
  https://codeload.github.com/rclone/rclone/tar.gz/refs/tags/v1.75.1 -o "$build/rclone.tgz"
printf '%s  %s\n' fcc9351ab3976c73b4824cf7919f98f911f2442a606e2910fc2bd562111da220 "$build/rclone.tgz" | sha256sum -c -
tar -xzf "$build/go.tgz" -C "$build"
tar -xzf "$build/rclone.tgz" -C "$build"
python3 "$project/rclone-patches/apply-listing-cache.py" "$build/rclone-1.75.1"
export GOROOT="$build/go" GOPATH="$build/gopath" GOCACHE="$build/gocache"
export PATH="$GOROOT/bin:$PATH" GOMAXPROCS=2 GOMEMLIMIT=768MiB
cd "$build/rclone-1.75.1"
gofmt -w backend/drime/drime.go backend/drime/listing_cache*.go backend/drime/folder_conflict*.go
CGO_ENABLED=1 go test -race -p 2 -count=1 -run '^TestUbuntuDrime' ./backend/drime
CGO_ENABLED=0 go build -p 2 -trimpath \
  -ldflags '-s -w -X github.com/rclone/rclone/fs.Version=v1.75.1-ubuntu-drime.1' \
  -o "$output/rclone-fast" .
"$output/rclone-fast" version
sha256sum "$output/rclone-fast"
