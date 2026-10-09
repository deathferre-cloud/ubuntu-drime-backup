package drime

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/rclone/rclone/backend/drime/api"
)

func isDuplicateFolderConflict(status int, err error) bool {
    return status == 422 && err != nil && strings.Contains(strings.ToLower(err.Error()), "folder with same name already exists")
}

// Drime can acknowledge an earlier folder creation with a duplicate-name error.
// Reuse only one exact folder in the requested parent, never a case-folded match,
// file, different parent, or ambiguous duplicate. All other 422 errors stay errors.
func resolveFolderConflict(ctx context.Context, parentID, name string, list func(func(*api.Item) bool) error) (*api.Item, error) {
    for attempt := 0; attempt < 3; attempt++ {
        if err := ctx.Err(); err != nil { return nil, err }
        var match *api.Item
        ambiguous := false
        err := list(func(item *api.Item) bool {
            if item.Type != api.ItemTypeFolder || item.Name != name || item.ParentID.String() != parentID || item.ID.String() == "" { return false }
            if match != nil && match.ID != item.ID { ambiguous = true; return false }
            copy := *item
            match = &copy
            return false
        })
        if err != nil { return nil, err }
        if ambiguous { return nil, fmt.Errorf("multiple exact folders in parent %q for %q", parentID, name) }
        if match != nil { return match, nil }
        if attempt < 2 {
            timer := time.NewTimer(time.Duration(attempt+1)*200*time.Millisecond)
            select { case <-ctx.Done(): timer.Stop(); return nil, ctx.Err(); case <-timer.C: }
        }
    }
    return nil, fmt.Errorf("duplicate folder was not visible in parent %q for %q", parentID, name)
}
