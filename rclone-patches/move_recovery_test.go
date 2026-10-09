package drime

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "github.com/rclone/rclone/backend/drime/api"
    "github.com/rclone/rclone/fs"
    "github.com/rclone/rclone/lib/pacer"
    "github.com/rclone/rclone/lib/rest"
)

func TestUbuntuDrimeMoveRecoveryHTTP(t *testing.T) {
    for _, name := range []string{"committed_response_lost", "delayed_listing", "missing", "wrong_id", "wrong_parent", "wrong_name", "duplicate", "deleted", "list_failure", "forbidden", "other_error", "normal"} {
        t.Run(name, func(t *testing.T) {
            moves, lists := 0, 0
            server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                if r.URL.Query().Get("workspaceId") != "12345" { t.Error("lost workspace scope") }
                if r.Method == "POST" && r.URL.Path == "/file-entries/move" {
                    moves++
                    var request api.MoveRequest
                    if err := json.NewDecoder(r.Body).Decode(&request); err != nil { t.Error(err) }
                    if len(request.EntryIDs)!=1 || request.EntryIDs[0]!="42" || request.DestinationID!="7" { t.Error("wrong move identity", request) }
                    switch {
                    case name=="normal": fmt.Fprint(w,`{"status":"success"}`)
                    case name=="forbidden": w.WriteHeader(403);fmt.Fprint(w,`{"message":"Forbidden"}`)
                    case name=="other_error": w.WriteHeader(422);fmt.Fprint(w,`{"message":"Invalid destination"}`)
                    case name=="committed_response_lost" && moves==1:
                        // The server moved ID 42, but the first response fails.
                        w.WriteHeader(503);fmt.Fprint(w,`{"message":"Upstream response lost"}`)
                    default:w.WriteHeader(400);fmt.Fprint(w,`{"message":"No valid entries to move"}`)
                    }
                    return
                }
                if r.Method=="GET" && r.URL.Path=="/drive/file-entries" {
                    lists++
                    if r.URL.Query().Get("folderId")!="7" { t.Error("looked in wrong destination") }
                    if name=="list_failure" { w.WriteHeader(403);fmt.Fprint(w,`{"message":"Forbidden"}`);return }
                    item:=api.Item{ID:"42",ParentID:"7",Name:"metrics.gob",Type:"file"}
                    switch name {
                    case "wrong_id":item.ID="99"
                    case "wrong_parent":item.ParentID="8"
                    case "wrong_name":item.Name="other.gob"
                    case "deleted":item.IsDeleted=1
                    }
                    items:=[]api.Item{item}
                    if name=="missing" || (name=="delayed_listing" && lists==1) {items=nil}
                    if name=="duplicate" { other:=item;other.ID="99";items=append(items,other) }
                    _=json.NewEncoder(w).Encode(api.Listing{CurrentPage:1,LastPage:1,Data:items})
                    return
                }
                t.Errorf("unexpected operation: %s %s",r.Method,r.URL);w.WriteHeader(500)
            }))
            defer server.Close()
            ctx:=context.Background()
            f:=&Fs{opt:Options{ListChunk:100,WorkspaceID:"12345"},srv:rest.NewClient(server.Client()).SetRoot(server.URL),pacer:fs.NewPacer(ctx,pacer.NewDefault(pacer.MinSleep(time.Millisecond)))}
            f.srv.SetErrorHandler(errorHandler)
            err:=f.moveVerified(ctx,"42","7","metrics.gob")
            wantSuccess:=name=="normal" || name=="committed_response_lost" || name=="delayed_listing"
            if (err==nil)!=wantSuccess {t.Fatalf("wrong result: %v",err)}
            if name=="committed_response_lost" && (moves!=2 || lists!=1) {t.Fatal(moves,lists)}
            if name=="delayed_listing" && (moves!=1 || lists!=2) {t.Fatal(moves,lists)}
            if (name=="normal" || name=="forbidden" || name=="other_error") && lists!=0 {t.Fatal("unrelated response triggered recovery")}
            if !wantSuccess && name!="forbidden" && name!="other_error" && !strings.Contains(err.Error(),"No valid entries to move") {t.Fatal("original failure lost",err)}
            if lists>3 || moves>2 {t.Fatal("unbounded retry",moves,lists)}
        })
    }
}

func TestUbuntuDrimeMoveRecoveryCancellation(t *testing.T) {
    ctx,cancel:=context.WithCancel(context.Background())
    server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        if r.Method=="GET" {t.Error("listed after cancellation")}
        cancel();w.WriteHeader(400);fmt.Fprint(w,`{"message":"No valid entries to move"}`)
    }))
    defer server.Close()
    f:=&Fs{srv:rest.NewClient(server.Client()).SetRoot(server.URL),pacer:fs.NewPacer(ctx,pacer.NewDefault(pacer.MinSleep(time.Millisecond)))}
    f.srv.SetErrorHandler(errorHandler)
    if err:=f.moveVerified(ctx,"42","7","metrics.gob");err==nil {t.Fatal("cancelled operation acknowledged")}
}
