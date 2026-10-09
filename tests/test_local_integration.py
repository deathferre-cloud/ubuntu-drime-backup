#!/usr/bin/env python3
"""Linux integration tests using the real rclone local backend, no production data."""
import importlib.util,json,os,pathlib,tempfile,time,shutil,stat,subprocess

import daemon as m

with tempfile.TemporaryDirectory(prefix='backup-tests-') as tmp:
    root=pathlib.Path(tmp);src=root/'source';src.mkdir()
    (src/'folder').mkdir();(src/'empty-folder').mkdir()
    file=src/'folder'/'same-size.txt';file.write_bytes(b'first')
    (src/'empty-file').touch();(src/'symlink').symlink_to('folder/same-size.txt')
    raw=os.fsencode(src)+b'/raw-\xff-name';open(raw,'wb').write(b'RAW')
    (src/'new\nline').write_bytes(b'NEWLINE')
    (src/'literal.rclonelink').write_bytes(b'NOT A LINK')
    config=dict(source=str(src),state_dir=str(root/'state'),destination=str(root/'cloud'),history=str(root/'cloud'/'.ubuntu-drime-backup'/'history'),metadata=str(root/'cloud'/'.ubuntu-drime-backup'/'metadata'),rclone=os.environ.get('DRIME_RCLONE','rclone'),rclone_config='/dev/null',scan_interval=300,settle_seconds=0,batch_files=512,batch_bytes=536870912,transfers=4,tpslimit=100,bwlimit='off',verify_sample_files=8)
    b=m.Backup(config);b.scan()
    while b.cycle(): pass
    assert (root/'cloud'/'folder'/'same-size.txt').read_bytes()==b'first'
    assert (root/'cloud'/'empty-folder').is_dir()
    assert (root/'cloud'/'empty-file').stat().st_size==0
    assert (root/'cloud'/'symlink').read_bytes()==b'folder/same-size.txt'
    assert (root/'cloud'/'literal.rclonelink').read_bytes()==b'NOT A LINK'
    assert open(os.fsencode(root/'cloud')+b'/raw-\xff-name','rb').read()==b'RAW'
    assert (root/'cloud'/'new\nline').read_bytes()==b'NEWLINE'
    assert b.counts['pending_files']==0 and b.counts['pending_directories']==0
    # Exercise the public manifest format and restore helper against downloaded files.
    b.manifest()
    recovery=root/'recovery'
    shutil.copytree(root/'cloud',recovery,ignore=shutil.ignore_patterns('.ubuntu-drime-backup'))
    recovered=recovery/'folder'/'same-size.txt'
    os.chmod(recovered,0o600);os.utime(recovered,ns=(1_000_000_000,1_000_000_000))
    helper=pathlib.Path(m.__file__).with_name('restore_metadata.py')
    command=['python3',str(helper),'--root',str(recovery),'--manifest',str(root/'state'/'filesystem.jsonl.gz')]
    subprocess.run(command,check=True,capture_output=True)
    assert not (recovery/'symlink').is_symlink(), 'Dry run must not change downloaded descriptors'
    subprocess.run(command+['--apply'],check=True,capture_output=True)
    assert (recovery/'symlink').is_symlink() and os.readlink(recovery/'symlink')=='folder/same-size.txt'
    assert recovered.read_bytes()==b'first'
    assert stat.S_IMODE(recovered.stat().st_mode)==stat.S_IMODE(file.stat().st_mode)
    assert recovered.stat().st_uid==file.stat().st_uid and recovered.stat().st_gid==file.stat().st_gid
    assert recovered.stat().st_mtime_ns==file.stat().st_mtime_ns
    refused=subprocess.run(['python3',str(helper),'--root','/','--manifest',str(root/'state'/'filesystem.jsonl.gz')],capture_output=True)
    assert refused.returncode != 0
    print('RESTORE_ROUNDTRIP_OK: dry run, mode, UID/GID, mtime, file bytes, symlink and live-root rejection',flush=True)
    old=os.stat(file);file.write_bytes(b'other');os.utime(file,ns=(old.st_atime_ns,old.st_mtime_ns))
    b.scan();batch=b.pending();assert len(batch)==1 and batch[0]['path']==b'folder/same-size.txt'
    b.transfer(batch)
    assert (root/'cloud'/'folder'/'same-size.txt').read_bytes()==b'other'
    versions=list((root/'cloud'/'.ubuntu-drime-backup'/'history').rglob('same-size.txt'))
    assert len(versions)==1 and versions[0].read_bytes()==b'first'
    file.unlink();b.scan()
    assert (root/'cloud'/'folder'/'same-size.txt').read_bytes()==b'other'
    assert b.db.execute('SELECT present FROM entries WHERE path=?',(b'folder/same-size.txt',)).fetchone()[0]==0
    retry=src/'retry.txt';retry.write_bytes(b'retry');b.scan()
    real_rc=b.rc
    b.rc=lambda *args,**kwargs: (_ for _ in ()).throw(RuntimeError('simulated network failure'))
    b.transfer(b.pending())
    row=b.db.execute('SELECT uploaded,last_error FROM entries WHERE path=?',(b'retry.txt',)).fetchone()
    assert row['uploaded']=='' and row['last_error']
    b.rc=real_rc;b.db.execute('UPDATE entries SET retry_at=0');b.db.commit();b.transfer(b.pending())
    assert (root/'cloud'/'retry.txt').read_bytes()==b'retry'
    b.db.close();b.lock.close()
    resumed=m.Backup(config);resumed.scan();assert not resumed.pending()
    resumed.db.close();resumed.lock.close()
    print('LOCAL_INTEGRATION_OK: same-size writes with restored mtime, history, retained deletions, retry checkpoint, restart, byte filenames, newline filenames, links, empty files and directories',flush=True)

with tempfile.TemporaryDirectory(prefix='scope-tests-') as tmp:
    root=pathlib.Path(tmp);(root/'included').mkdir();(root/'excluded').mkdir()
    (root/'included'/'yes').write_bytes(b'yes');(root/'excluded'/'no').write_bytes(b'no')
    config.update(source='/',include_roots=[str(root/'included')],required_roots=[str(root/'included')],state_dir=str(root/'state2'))
    b=m.Backup(config);b.scan()
    paths=[os.fsdecode(r[0]) for r in b.db.execute('SELECT path FROM entries')]
    assert len(paths)==2 and all('/included' in p for p in paths)
    b.db.close();b.lock.close()
    print('SOURCE_SCOPE_OK: only explicitly included roots are scanned',flush=True)
