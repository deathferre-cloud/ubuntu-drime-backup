package drime

import (
    "sync"
    "sync/atomic"
    "testing"
    "time"
    "github.com/rclone/rclone/fs"
)

func TestUbuntuDrimeListingCache(t *testing.T) {
    f := &Fs{opt: Options{FastListUpload:true}, putCache:newPutListingCache()}
    if f.reserveKnownAbsent("unlisted/new") { t.Fatal("unlisted parent trusted") }
    f.rememberCompleteListing("d", fs.DirEntries{fs.NewDir("d/existing",time.Time{})})
    if f.reserveKnownAbsent("d/existing") { t.Fatal("existing entry treated as absent") }
    if !f.reserveKnownAbsent("d/new") { t.Fatal("known absence missed") }
    if f.reserveKnownAbsent("d/new") { t.Fatal("retry bypasses lookup after ambiguous upload") }
    f.rememberCompleteListing("d",nil)
    if f.reserveKnownAbsent("d/new") { t.Fatal("stale listing erased reservation") }
    f.markUploadPossible("d/direct")
    if f.reserveKnownAbsent("d/direct") { t.Fatal("direct upload was forgotten") }
    f.rememberCompleteListing("",nil)
    if !f.reserveKnownAbsent("root-new") { t.Fatal("root normalization failed") }
    if !f.reserveKnownAbsent("missing/deep/first") {t.Fatal("missing branch not inferred")}
    if !f.reserveKnownAbsent("missing/deep/second") {t.Fatal("new sibling not inferred")}
    if f.reserveKnownAbsent("missing/deep/first") {t.Fatal("branch inference lost reservation")}
    if f.reserveKnownAbsent("missing/deep") {t.Fatal("directory/file conflict not checked")}
    if f.reserveKnownAbsent("d/existing/unknown") {t.Fatal("contents of existing branch guessed")}
    f.rememberCompleteListing("bytes",fs.DirEntries{fs.NewDir("bytes/raw-\xff\nРусский",time.Time{})})
    if f.reserveKnownAbsent("bytes/raw-\xff\nРусский") { t.Fatal("byte name lost") }
    f.opt.FastListUpload=false
    if f.reserveKnownAbsent("d/disabled") { t.Fatal("disabled option ignored") }
}

func TestUbuntuDrimeListingCacheConcurrent(t *testing.T) {
    f:=&Fs{opt:Options{FastListUpload:true},putCache:newPutListingCache()}
    f.rememberCompleteListing("d",nil)
    var count atomic.Int32
    var wg sync.WaitGroup
    for i:=0;i<64;i++ { wg.Add(1);go func(){defer wg.Done();if f.reserveKnownAbsent("d/same"){count.Add(1)}}() }
    wg.Wait()
    if count.Load()!=1 {t.Fatalf("concurrent absence reservations = %d",count.Load())}
}
