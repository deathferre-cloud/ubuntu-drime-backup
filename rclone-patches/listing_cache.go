package drime

import (
    "path"
    "sync"
    "github.com/rclone/rclone/fs"
)

// A command-scoped, conservative absence cache for an exclusively managed tree.
// It never caches metadata and never bypasses an existing object's lookup.
type putListingCache struct {
    mu sync.Mutex
    complete map[string]bool
    present map[string]bool
}

func newPutListingCache() *putListingCache {
    return &putListingCache{complete: make(map[string]bool), present: make(map[string]bool)}
}

func (f *Fs) rememberCompleteListing(dir string, entries fs.DirEntries) {
    if !f.opt.FastListUpload { return }
    c := f.putCache
    c.mu.Lock()
    defer c.mu.Unlock()
    for _, entry := range entries { c.present[entry.Remote()] = true }
    // Never erase reservations: a repeated listing can be eventually consistent.
    c.complete[dir] = true
}

func (f *Fs) markUploadPossible(remote string) {
    if !f.opt.FastListUpload { return }
    c := f.putCache
    c.mu.Lock()
    c.present[remote] = true
    c.mu.Unlock()
}

func (f *Fs) reserveKnownAbsent(remote string) bool {
    if !f.opt.FastListUpload { return false }
    c := f.putCache
    parent := path.Dir(remote)
    if parent == "." { parent = "" }
    c.mu.Lock()
    defer c.mu.Unlock()
    absent := c.ensureDirectoryLocked(parent) && !c.present[remote]
    // Reserve BEFORE sending. Even a failed/ambiguous upload must subsequently
    // take the normal lookup path, never assume absence and create a duplicate.
    c.present[remote] = true
    return absent
}

// If a completed parent listing proves a whole branch absent, children of
// that branch are absent too. Keep all upload reservations made in this command.
func (c *putListingCache) ensureDirectoryLocked(dir string) bool {
    if c.complete[dir] { return true }
    if dir == "" { return false }
    parent := path.Dir(dir)
    if parent == "." { parent = "" }
    if !c.ensureDirectoryLocked(parent) || c.present[dir] { return false }
    c.complete[dir] = true
    c.present[dir] = true // reserve this directory against a conflicting file
    return true
}
