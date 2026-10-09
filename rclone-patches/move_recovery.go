package drime

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/rclone/rclone/backend/drime/api"
    "github.com/rclone/rclone/fs"
)

// Drime can commit a move before a transient response fails. A low-level
// replay then reports "No valid entries to move". Never treat that message
// alone, or a matching name/size, as success: verify the original immutable ID
// in the exact destination, and reject deleted or ambiguous entries.
func (f *Fs) moveVerified(ctx context.Context, id, dstDirectoryID, leaf string) error {
    moveErr := f.move(ctx, id, dstDirectoryID)
    if moveErr == nil { return nil }
    var apiErr api.Error
    if !errors.As(moveErr, &apiErr) || apiErr.Message != "No valid entries to move" {
        return moveErr
    }
    if id == "" { return moveErr }
    for attempt := 0; attempt < 3; attempt++ {
        if err := ctx.Err(); err != nil { return fmt.Errorf("%w; move verification: %v", moveErr, err) }
        matches, exact := 0, false
        _, err := f.listAll(ctx, dstDirectoryID, false, false, leaf, func(item *api.Item) bool {
            if item.ParentID.String() == dstDirectoryID && item.Name == leaf {
                matches++
                exact = item.ID.String() == id && item.DeletedAt == nil && item.IsDeleted == 0
            }
            return false // inspect the whole listing to reject duplicate names
        })
        if err != nil { return fmt.Errorf("%w; move verification: %v", moveErr, err) }
        if matches == 1 && exact {
            fs.Infof(f, "Recovered completed move after ambiguous response: object ID verified in destination")
            return nil
        }
        if matches > 1 { return fmt.Errorf("%w; destination name is ambiguous", moveErr) }
        if attempt < 2 {
            timer := time.NewTimer(time.Duration(attempt+1)*200*time.Millisecond)
            select {
            case <-ctx.Done(): timer.Stop(); return fmt.Errorf("%w; move verification: %v", moveErr, ctx.Err())
            case <-timer.C:
            }
        }
    }
    return fmt.Errorf("%w; original object ID not verified at destination", moveErr)
}
