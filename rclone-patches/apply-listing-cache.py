#!/usr/bin/env python3
import pathlib,sys
root=pathlib.Path(sys.argv[1]);p=root/'backend/drime/drime.go'
s=p.read_text()
def replace(old,new):
    global s
    assert s.count(old)==1,repr(old)
    s=s.replace(old,new)
replace('\t\t\tName:     "hard_delete",','\t\t\tName: "fast_list_upload",\n\t\t\tHelp: "Reuse complete listings for new uploads. Use only with an exclusively managed destination; existing objects and ambiguous retries still use normal lookup.",\n\t\t\tDefault: false,\n\t\t\tAdvanced: true,\n\t\t}, {\n\t\t\tName:     "hard_delete",')
replace('type Options struct {','type Options struct {\n\tFastListUpload bool `config:"fast_list_upload"`')
replace('type Fs struct {','type Fs struct {\n\tputCache *putListingCache')
replace('\tf := &Fs{','\tf := &Fs{\n\t\tputCache: newPutListingCache(),')
replace('func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {\n\tdirectoryID, err := f.dirCache.FindDir(ctx, dir, false)\n\tif err != nil {\n\t\treturn nil, err','func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {\n\tdirectoryID, err := f.dirCache.FindDir(ctx, dir, false)\n\tif err != nil {\n\t\tif errors.Is(err, fs.ErrorDirNotFound) { f.rememberCompleteListing(dir, nil) }\n\t\treturn nil, err')
replace('\tif iErr != nil {\n\t\treturn nil, iErr\n\t}\n\treturn entries, nil','\tif iErr != nil {\n\t\treturn nil, iErr\n\t}\n\tf.rememberCompleteListing(dir, entries)\n\treturn entries, nil')
replace('func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {\n\texistingObj, err := f.NewObject(ctx, src.Remote())','func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {\n\tif f.reserveKnownAbsent(src.Remote()) {\n\t\treturn f.PutUnchecked(ctx, in, src, options...)\n\t}\n\texistingObj, err := f.NewObject(ctx, src.Remote())')
replace('func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {\n\tremote := src.Remote()','func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {\n\tremote := src.Remote()\n\tf.markUploadPossible(remote)')
replace('\t\treturn nil, fmt.Errorf("failed to create folder: %w", err)', '''        if resp != nil && isDuplicateFolderConflict(resp.StatusCode, err) {
            existing, lookupErr := resolveFolderConflict(ctx, pathID, leaf, func(fn func(*api.Item) bool) error {
                _, listErr := f.listAll(ctx, pathID, true, false, leaf, fn)
                return listErr
            })
            if lookupErr == nil {
                fs.Debugf(f, "Reused existing folder after 422: parent=%q name=%q id=%s", pathID, leaf, existing.ID.String())
                return existing, nil
            }
            return nil, fmt.Errorf("failed to create folder parent=%q name=%q: %w; recovery lookup: %v", pathID, leaf, err, lookupErr)
        }
        return nil, fmt.Errorf("failed to create folder parent=%q name=%q: %w", pathID, leaf, err)''')
p.write_text(s)
for name in ('listing_cache.go','listing_cache_test.go','folder_conflict.go','folder_conflict_test.go'):
    (root/'backend/drime'/name).write_bytes((pathlib.Path(__file__).parent/name).read_bytes())
print('LISTING_CACHE_PATCH_APPLIED')
