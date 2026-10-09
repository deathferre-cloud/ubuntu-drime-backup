#!/usr/bin/env python3
"""Restore Linux metadata and symlinks into a separately downloaded recovery tree.
Dry run unless --apply. Refuses the live / root and paths through symlinks.
"""
import argparse,base64,gzip,json,os,pathlib,stat

def records(filename):
    with gzip.open(filename,'rt',encoding='utf-8') as f:
        header=json.loads(next(f))
        if header.get('format')!='ubuntu-drime-filesystem-v1': raise ValueError('Unknown manifest format')
        for line in f:
            row=json.loads(line)
            if row['present']: yield row

def safe_path(root,relative):
    if not relative or os.path.isabs(relative) or any(x in (b'',b'.',b'..') for x in relative.split(b'/')):
        raise ValueError('Unsafe manifest path')
    current=root
    for component in relative.split(b'/')[:-1]:
        current=os.path.join(current,component)
        if os.path.islink(current): raise ValueError('Refusing path through a symbolic link: '+repr(current))
    return os.path.join(root,relative)

def permissions(path,meta):
    os.chown(path,meta['uid'],meta['gid'],follow_symlinks=False)
    if not os.path.islink(path):
        os.chmod(path,stat.S_IMODE(meta['mode']),follow_symlinks=False)
    for name,value in meta.get('xattrs',{}).items():
        os.setxattr(path,base64.b64decode(name),base64.b64decode(value),follow_symlinks=False)
    os.utime(path,ns=(meta['atime_ns'],meta['mtime_ns']),follow_symlinks=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',required=True);p.add_argument('--manifest',required=True)
    p.add_argument('--apply',action='store_true');args=p.parse_args()
    root=os.fsencode(os.path.abspath(args.root))
    if root==b'/' or os.path.islink(root): raise SystemExit('Use a separate recovery directory, never /')
    if not os.path.isdir(root): raise SystemExit('Recovery directory does not exist')
    counts={'dir':0,'file':0,'link':0,'special':0,'missing_data':0}
    directories=[]
    # Directories first, regular files second, links last to prevent traversal.
    for kind in ('dir','file','link','special'):
        for row in records(args.manifest):
            if row['kind']!=kind: continue
            path=safe_path(root,base64.b64decode(row['path_b64']));meta=row['metadata']
            counts[kind]+=1
            if kind=='dir':
                if os.path.islink(path): raise ValueError('Directory is a symbolic link: '+repr(path))
                if args.apply: os.makedirs(path,exist_ok=True)
                directories.append((path,meta))
            elif kind=='file':
                if not os.path.isfile(path) or os.path.islink(path):
                    counts['missing_data']+=1;continue
                if args.apply: permissions(path,meta)
            elif kind=='link':
                target=base64.b64decode(meta['link_target_b64'])
                if os.path.lexists(path):
                    if os.path.islink(path):
                        if os.readlink(path)!=target: raise ValueError('Different symbolic link already exists')
                    else:
                        with open(path,'rb') as f: descriptor=f.read(len(target)+1)
                        if descriptor!=target: raise ValueError('Refusing to replace non-descriptor file: '+repr(path))
                        if args.apply: os.unlink(path)
                if args.apply:
                    if not os.path.lexists(path):
                        os.makedirs(os.path.dirname(path),exist_ok=True);os.symlink(target,path)
                    permissions(path,meta)
            # Runtime sockets/device nodes have metadata only; they are not recreated.
    if args.apply:
        for path,meta in sorted(directories,key=lambda x:len(x[0]),reverse=True): permissions(path,meta)
    print(json.dumps({'applied':args.apply,**counts},indent=2))
    if counts['missing_data']: raise SystemExit(2)

if __name__=='__main__': main()
