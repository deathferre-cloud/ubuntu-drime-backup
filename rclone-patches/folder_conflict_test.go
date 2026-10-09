package drime

import (
    "context"
    "encoding/json"
    "errors"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/rclone/rclone/backend/drime/api"
    "github.com/rclone/rclone/fs"
    "github.com/rclone/rclone/lib/pacer"
    "github.com/rclone/rclone/lib/rest"
)

func TestUbuntuDrimeFolderConflictClassification(t *testing.T) {
    e := errors.New("Folder with same name already exists.")
    if !isDuplicateFolderConflict(422,e) || isDuplicateFolderConflict(500,e) || isDuplicateFolderConflict(422,errors.New("invalid parent")) || isDuplicateFolderConflict(422,nil) { t.Fatal("over-broad conflict recognition") }
}

func TestUbuntuDrimeFolderConflictExactMatch(t *testing.T) {
    list := func(fn func(*api.Item) bool) error {
        for _, item := range []api.Item{
            {ID:"1", ParentID:"7", Name:"Nginx", Type:"folder"},
            {ID:"2", ParentID:"8", Name:"nginx", Type:"folder"},
            {ID:"3", ParentID:"7", Name:"nginx", Type:"file"},
            {ID:"4", ParentID:"7", Name:"nginx", Type:"folder"},
        } { fn(&item) }
        return nil
    }
    got,err:=resolveFolderConflict(context.Background(),"7","nginx",list)
    if err!=nil || got.ID!="4" { t.Fatalf("wrong folder: %v %v",got,err) }
}

func TestUbuntuDrimeFolderConflictAmbiguous(t *testing.T) {
    _,err:=resolveFolderConflict(context.Background(),"7","nginx",func(fn func(*api.Item) bool) error {
        for _,id:=range []string{"1","2"} { fn(&api.Item{ID:json.Number(id),ParentID:"7",Name:"nginx",Type:"folder"}) };return nil
    })
    if err==nil { t.Fatal("accepted ambiguous folder") }
}

func TestUbuntuDrimeFolderConflictRetryAndRoot(t *testing.T) {
    calls:=0
    got,err:=resolveFolderConflict(context.Background(),"","Русский\nкаталог",func(fn func(*api.Item) bool) error {
        calls++;if calls==2 { fn(&api.Item{ID:"8",ParentID:"",Name:"Русский\nкаталог",Type:"folder"}) };return nil
    })
    if err!=nil || got.ID!="8" || calls!=2 { t.Fatal(got,err,calls) }
}

func TestUbuntuDrimeFolderConflictErrors(t *testing.T) {
    expected:=errors.New("list failed")
    _,err:=resolveFolderConflict(context.Background(),"7","x",func(func(*api.Item) bool)error{return expected})
    if !errors.Is(err,expected) { t.Fatal(err) }
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    _,err=resolveFolderConflict(ctx,"7","x",func(func(*api.Item) bool)error{t.Fatal("listed after cancellation");return nil})
    if !errors.Is(err,context.Canceled) { t.Fatal(err) }
    _,err=resolveFolderConflict(context.Background(),"7","x",func(func(*api.Item) bool)error{return nil})
    if err==nil { t.Fatal("invented a folder") }
}

func TestUbuntuDrimeFolderConflictHTTP(t *testing.T) {
    for _, duplicate := range []bool{true,false} {
        t.Run(map[bool]string{true:"duplicate",false:"other422"}[duplicate],func(t *testing.T) {
            creates,lists:=0,0
            server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
                w.Header().Set("Content-Type","application/json")
                if r.URL.Query().Get("workspaceId")!="12345" { t.Error("workspace scope was lost") }
                if r.Method=="POST" && r.URL.Path=="/folders" {
                    creates++;w.WriteHeader(422)
                    if duplicate { _,_=w.Write([]byte(`{"message":"","errors":{"name":"Folder with same name already exists."}}`))
                    } else { _,_=w.Write([]byte(`{"message":"invalid name"}`)) };return
                }
                if r.Method=="GET" && r.URL.Path=="/drive/file-entries" {
                    lists++
                    if r.URL.Query().Get("folderId")!="7" { t.Error("wrong parent lookup") }
                    _=json.NewEncoder(w).Encode(api.Listing{CurrentPage:1,LastPage:1,Data:[]api.Item{{ID:"42",ParentID:"7",Name:"nginx",Type:"folder"}}});return
                }
                t.Errorf("unexpected call %s %s",r.Method,r.URL);w.WriteHeader(500)
            }))
            defer server.Close()
            ctx:=context.Background()
            f:=&Fs{opt:Options{ListChunk:100,WorkspaceID:"12345"},srv:rest.NewClient(server.Client()).SetRoot(server.URL),pacer:fs.NewPacer(ctx,pacer.NewDefault(pacer.MinSleep(time.Millisecond)))}
            f.srv.SetErrorHandler(errorHandler)
            item,err:=f.createDir(ctx,"7","nginx",time.Now())
            if duplicate {
                if err!=nil || item.ID!="42" || creates!=1 || lists!=1 { t.Fatalf("recovery failed: item=%v err=%v create=%d list=%d",item,err,creates,lists) }
            } else if err==nil || lists!=0 || creates!=1 { t.Fatalf("unrelated 422 was swallowed: %v",err) }
        })
    }
}
