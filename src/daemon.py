#!/usr/bin/env python3
"""One-way Drime file backup with a durable local change journal.

Never deletes from the source or destination. Rclone preserves overwritten
objects in a separate history tree; scans use size, mtime, ctime and inode,
so equal-size writes and restored mtimes are not silently skipped.
"""
import argparse
import base64
import datetime as dt
import fcntl
import gzip
import glob
import hashlib
import json
import logging
import os
import pathlib
import random
import selectors
import signal
import sqlite3
import stat
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from safety import SafetyGuard, SafetyStop, RecordedError, sanitize

LOG = logging.getLogger('ubuntu-drime-backup')


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def signature(s):
    return ':'.join(str(x) for x in (s.st_mode, s.st_size, s.st_mtime_ns,
                    s.st_ctime_ns, s.st_ino, s.st_dev, s.st_uid, s.st_gid))


def b64(value):
    return base64.b64encode(value).decode('ascii')


class Backup:
    def __init__(self, config):
        self.c = config
        self.source = os.fsencode(os.path.abspath(config['source']))
        self.state = pathlib.Path(config['state_dir'])
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = (self.state / 'daemon.lock').open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.guard = SafetyGuard(config)
        self.guard.check()
        if not os.path.isdir(self.source) or os.path.islink(self.source):
            raise RuntimeError('Source must be an existing real directory')
        self.db = sqlite3.connect(self.state / 'journal.sqlite3')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS entries (
            path BLOB PRIMARY KEY, kind TEXT, sig TEXT, size INTEGER,
            mtime_ns INTEGER, meta TEXT, uploaded TEXT DEFAULT '',
            seen INTEGER, present INTEGER DEFAULT 1,
            retry_at REAL DEFAULT 0, failures INTEGER DEFAULT 0,
            last_error TEXT, uploaded_at TEXT);
          CREATE INDEX IF NOT EXISTS pending ON entries(present,kind,retry_at);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
        ''')
        self.phase = 'starting'
        self.active = None
        self.last_scan = 0
        self.scan_errors = 0
        self.last_operation_error = None
        self.last_manifest_day = self.setting('manifest_day')
        self.last_verified_day = self.setting('verified_day')
        self.counts = {}
        self.file_batches = 0

    def setting(self, key, value=None):
        if value is None:
            row = self.db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
            return row[0] if row else None
        self.db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (key, value))
        self.db.commit()

    def command(self, *args):
        prefix=[self.c['network_wrapper']] if self.c.get('network_wrapper') else []
        tps=self.c['tpslimit']
        if not self.guard.daytime(): tps=self.c.get('night_tpslimit',tps)
        elif self.guard.data['count']: tps=max(2,tps//2)
        return prefix+[self.c['rclone'], *args, '--config', self.c['rclone_config'],
                '--contimeout', self.c.get('connect_timeout','20s'),
                '--timeout', self.c.get('io_timeout','120s'),
                '--retries', '2', '--retries-sleep', '10s',
                '--low-level-retries', str(self.c.get('low_level_retries',3)),
                '--disable-http2', '--disable-http-keep-alives', '--bind', '0.0.0.0',
                '--tpslimit', str(tps),
                '--tpslimit-burst', '4', '--buffer-size', '4Mi', '--bwlimit', self.c['bwlimit']]

    @staticmethod
    def kill_group(process):
        try: os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired: pass
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait()

    def rc(self, *args, capture=False, on_event=None):
        if capture and on_event: raise ValueError('Event capture cannot capture file data')
        self.guard.poll(force=True)
        command=self.command(*args)+['--use-json-log','--retries','1']
        command_id=str(uuid.uuid4()); seen_errors=set(); buffer=b''
        started=last_progress=time.monotonic(); progress=None
        def event_line(line):
            nonlocal last_progress,progress
            try: event=json.loads(line)
            except (ValueError,UnicodeDecodeError):
                LOG.warning('rclone: %s',sanitize(line.decode('utf-8',errors='replace')));return
            if on_event: on_event(event)
            msg=event.get('msg','');level=event.get('level','info')
            if 'stats' in event:
                stats=event['stats']; current=tuple(stats.get(k,0) for k in ('bytes','transfers','checks'))
                if current!=progress: last_progress=time.monotonic();progress=current
            elif msg.startswith(('Copied (','Made directory','Set directory modification time')):
                last_progress=time.monotonic()
            if level in ('error','fatal'):
                # The final Attempt summary repeats individual failures.
                if not (msg.startswith('Attempt ') and seen_errors):
                    key=event.get('object') or msg
                    if key not in seen_errors:
                        seen_errors.add(key)
                        self.guard.record('rclone_error',str(event.get('object',''))+': '+msg,command_id+':'+key)
            if level in ('error','fatal','warning'):
                LOG.warning('rclone %s %s: %s',level,event.get('object',''),sanitize(msg))
            elif 'stats' in event: LOG.info('rclone: %s',msg.strip())
        with tempfile.TemporaryFile() as output:
            with subprocess.Popen(command,stderr=subprocess.PIPE,stdout=output if capture else None,start_new_session=True) as p:
                with selectors.DefaultSelector() as selector:
                    selector.register(p.stderr,selectors.EVENT_READ)
                    try:
                        while selector.get_map() or p.poll() is None:
                            self.guard.poll()
                            if time.monotonic()-started>self.c.get('command_timeout_seconds',3600):
                                self.guard.trip('Rclone exceeded maximum command duration')
                            if time.monotonic()-last_progress>self.c.get('stall_timeout_seconds',600):
                                self.guard.trip('Rclone made no observable progress before stall deadline')
                            for key,_ in selector.select(timeout=0.5):
                                chunk=os.read(key.fileobj.fileno(),65536)
                                if not chunk:
                                    selector.unregister(key.fileobj)
                                    if buffer: event_line(buffer);buffer=b''
                                    continue
                                buffer+=chunk
                                while b'\n' in buffer:
                                    line,buffer=buffer.split(b'\n',1)
                                    if line: event_line(line)
                        p.wait()
                    except BaseException:
                        self.kill_group(p);raise
            if p.returncode<0: self.guard.trip('Rclone process crashed with signal '+str(-p.returncode))
            if p.returncode:
                if not seen_errors: self.guard.record('rclone_exit','rclone exit code '+str(p.returncode),command_id)
                raise RecordedError('rclone exit code '+str(p.returncode))
            if capture: output.seek(0);return output.read()

    def checkpoint(self,row):
        try: current=signature(os.lstat(os.path.join(self.source,row['path'])))
        except FileNotFoundError: current=None
        if current!=row['sig']:
            self.db.execute("UPDATE entries SET uploaded='' WHERE path=? AND sig=? AND uploaded=?",
                            (row['path'],row['sig'],row['sig']))
            return False
        self.db.execute('''UPDATE entries SET uploaded=?,uploaded_at=?,failures=0,
            retry_at=0,last_error=NULL WHERE path=? AND sig=?''',
            (row['sig'],utc(),row['path'],row['sig']))
        parent=os.path.dirname(row['path'])
        while parent and parent!=b'.':
            self.db.execute("UPDATE entries SET uploaded=sig,last_error=NULL WHERE path=? AND kind='dir'",(parent,))
            parent=os.path.dirname(parent)
        return True

    def transfer_event(self,event,rows):
        if 'stats' in event:
            self.status()
        if event.get('level') in ('error','fatal'):
            self.last_operation_error='rclone reported an error; see journal'
            raw=event.get('object','').encode('utf-8',errors='surrogatepass')
            row=rows.get(raw)
            if row is not None:
                self.db.execute('UPDATE entries SET last_error=? WHERE path=? AND sig=? AND uploaded!=sig',
                    (event.get('msg','rclone error')[:300],raw,row['sig']))
                self.db.commit()
            self.last_progress=time.monotonic();self.status()
            return
        # Only completed LOCAL-source writes qualify, never history moves/copies.
        # ASCII paths have an unambiguous JSON log representation. Unusual names
        # are checkpointed after whole-command success to avoid encoding aliases.
        if event.get('msg') not in ('Copied (new)','Copied (replaced existing)') or event.get('objectType')!='*local.Object':
            return
        path=event.get('object','').encode('utf-8',errors='surrogatepass')
        if not path or any(b<32 or b>126 for b in path): return
        row=rows.get(path)
        if row is None or row['kind']=='dir' or event.get('size',0)!=row['size']: return
        self.checkpoint(row);self.db.commit()
        if time.monotonic()-getattr(self,'last_progress',0)>30:
            self.last_progress=time.monotonic();self.status()

    def transfer_count(self,batch):
        files=[row for row in batch if row['kind']=='file']
        threshold=self.c.get('large_file_threshold',1048576)
        large=files and sum(row['size']>=threshold for row in files)*2>=len(files)
        if not self.guard.daytime():
            return self.c.get('night_large_file_transfers' if large else 'night_transfers',self.c['transfers'])
        count=self.c.get('large_file_transfers',self.c['transfers']) if large else self.c['transfers']
        return min(count,2) if self.guard.data['count'] else count

    def status(self):
        self.counts = dict(self.db.execute('''SELECT
          count(*) AS entries,
          sum(CASE WHEN kind='file' AND present=1 THEN 1 ELSE 0 END) AS source_files,
          sum(CASE WHEN kind='file' AND present=1 THEN size ELSE 0 END) AS source_bytes,
          sum(CASE WHEN kind IN ('file','link') AND present=1 AND uploaded=sig THEN 1 ELSE 0 END) AS current_files,
          sum(CASE WHEN kind='file' AND present=1 AND uploaded=sig THEN size ELSE 0 END) AS current_bytes,
          sum(CASE WHEN kind IN ('file','link') AND present=1 AND uploaded!=sig THEN 1 ELSE 0 END) AS pending_files,
          sum(CASE WHEN kind='dir' AND present=1 AND uploaded!=sig THEN 1 ELSE 0 END) AS pending_directories,
          sum(CASE WHEN last_error IS NOT NULL AND present=1 THEN 1 ELSE 0 END) AS error_files,
          sum(CASE WHEN present=0 THEN 1 ELSE 0 END) AS absent_retained_entries
          FROM entries''').fetchone())
        data = dict(updated_at=utc(), phase=self.phase, source=os.fsdecode(self.source),
                    include_roots=self.c.get('include_roots',[os.fsdecode(self.source)]),
                    destination=self.c['destination'], active=self.active,
                    scan_errors=self.scan_errors, last_operation_error=self.last_operation_error,
                    last_full_scan=self.setting('last_full_scan'),
                    initial_copy_complete=self.setting('initial_copy_complete'),
                    last_manifest=self.setting('last_manifest'),
                    last_sample_verification=self.setting('last_sample_verification'),
                    safety=self.guard.summary(),
                    **self.counts)
        tmp = self.state / 'status.json.tmp'
        tmp.write_text(json.dumps(data, ensure_ascii=True, indent=2)+'\n')
        os.replace(tmp, self.state / 'status.json')
        notify=os.environ.get('NOTIFY_SOCKET')
        if notify:
            try:
                address='\0'+notify[1:] if notify.startswith('@') else notify
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as channel:
                    channel.connect(address)
                    channel.send(('STATUS='+self.phase+'; copied='+str(self.counts['current_files'])+
                        '; pending='+str(self.counts['pending_files'])+' files, '+str(self.counts['pending_directories'])+
                        ' dirs; errors='+str(self.counts['error_files'])+'; scan_errors='+str(self.scan_errors)).encode())
            except OSError: pass
        return data

    def metadata(self, p, s, kind):
        attrs = {}
        for key in os.listxattr(p, follow_symlinks=False):
            attrs[b64(os.fsencode(key))] = b64(os.getxattr(p, key, follow_symlinks=False))
        return json.dumps(dict(mode=s.st_mode, uid=s.st_uid, gid=s.st_gid,
              size=s.st_size, mtime_ns=s.st_mtime_ns, atime_ns=s.st_atime_ns,
              inode=s.st_ino, device=s.st_dev, rdev=s.st_rdev,nlink=s.st_nlink, xattrs=attrs,
              link_target_b64=b64(os.readlink(p)) if kind=='link' else None),
              ensure_ascii=True, separators=(',',':'))

    def scan(self):
        self.phase = 'scanning'
        self.status()
        started = time.monotonic()
        generation = time.time_ns()
        errors = []
        root_stat = os.lstat(self.source)
        root_identity = f'{root_stat.st_dev}:{root_stat.st_ino}'
        previous_identity = self.setting('source_identity')
        if previous_identity and previous_identity != root_identity:
            raise RuntimeError('Source directory identity changed; review required')
        if not previous_identity:
            self.setting('source_identity', root_identity)
        for required in self.c.get('required_roots',[]):
            if not os.path.exists(required):
                raise RuntimeError('Required source path is missing: '+required)
        if 'include_roots' in self.c:
            roots = set()
            for pattern in self.c['include_roots']:
                roots.update(glob.glob(os.fsencode(pattern)))
            if not roots: raise RuntimeError('No source paths matched')
            stack = [(os.path.dirname(p),os.path.basename(p)) for p in roots]
        else:
            stack = [(self.source,None)]
        count = 0
        while stack:
            directory,only_name = stack.pop()
            try:
                with os.scandir(directory) as listing:
                    for entry in listing:
                        if only_name is not None and entry.name!=only_name: continue
                        p = entry.path
                        try:
                            s = entry.stat(follow_symlinks=False)
                            kind = 'file' if stat.S_ISREG(s.st_mode) else 'dir' if stat.S_ISDIR(s.st_mode) else 'link' if stat.S_ISLNK(s.st_mode) else 'special'
                            rel = os.path.relpath(p, self.source)
                            if kind == 'dir': stack.append((p,None))
                            sig = signature(s)
                            old = self.db.execute('SELECT sig,present,kind FROM entries WHERE path=?',(rel,)).fetchone()
                            if old and old['sig']==sig:
                                self.db.execute('UPDATE entries SET seen=?,present=1 WHERE path=?',(generation,rel))
                            else:
                                meta = self.metadata(p,s,kind)
                                self.db.execute('''INSERT INTO entries(path,kind,sig,size,mtime_ns,meta,seen)
                                  VALUES(?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET
                                  kind=excluded.kind,sig=excluded.sig,size=excluded.size,
                                  mtime_ns=excluded.mtime_ns,meta=excluded.meta,seen=excluded.seen,
                                  present=1,retry_at=0,failures=0,last_error=NULL''',
                                    (rel,kind,sig,s.st_size,min(max(s.st_mtime_ns,s.st_ctime_ns),time.time_ns()),meta,generation))
                                if kind=='dir' and old and old['kind']=='dir':
                                    self.db.execute("UPDATE entries SET uploaded=sig WHERE path=? AND uploaded!=''",(rel,))
                            count += 1
                            if count % 10000 == 0: self.db.commit()
                        except FileNotFoundError:
                            continue  # Renamed/deleted during scan; next scan reconciles it.
                        except Exception as e:
                            errors.append((b64(p),str(e)))
            except OSError as e:
                errors.append((b64(directory),str(e)))
        if not errors:
            self.db.execute('UPDATE entries SET present=0 WHERE seen!=?',(generation,))
        self.db.commit()
        self.scan_errors = len(errors)
        (self.state/'scan-errors.json').write_text(json.dumps(errors,ensure_ascii=True,indent=2)+'\n')
        self.setting('last_full_scan',utc())
        self.last_scan = time.monotonic()
        LOG.info('Scanned %d entries in %.1fs; errors=%d',count,self.last_scan-started,len(errors))
        self.status()
        for path,error in errors:
            self.guard.record('scan_error',path+': '+error)

    def pending(self, kind='file', failures_only=False):
        age_limit = time.time_ns()-int(self.c['settle_seconds']*1e9)
        candidates = self.db.execute('''SELECT * FROM entries WHERE present=1
          AND kind=? AND uploaded!=sig AND retry_at<=? AND mtime_ns<=?
          AND (?=0 OR last_error IS NOT NULL)
          ORDER BY CASE WHEN last_error IS NOT NULL THEN -1 WHEN uploaded!='' THEN 0 WHEN substr(path,1,18)=x'7661722f7777772f76686f7374732f62642f' THEN 1 ELSE 2 END,
          path LIMIT ?''',
          (kind,time.time(),age_limit,int(failures_only),
           min(16,self.c['batch_files']) if failures_only else self.c['batch_files'])).fetchall()
        batch=[]; size=0
        for row in candidates:
            if batch and size+row['size']>self.c['batch_bytes']: break
            batch.append(dict(row));size+=row['size']
        return batch

    def due_retries(self):
        # A failed link must not wait behind five potentially long file batches.
        # Backoff and settling still apply, and no acknowledged version is resent.
        age_limit=time.time_ns()-int(self.c['settle_seconds']*1e9)
        row=self.db.execute('''SELECT kind FROM entries WHERE present=1
          AND kind IN ('file','link','dir') AND uploaded!=sig
          AND last_error IS NOT NULL AND retry_at<=? AND mtime_ns<=?
          ORDER BY retry_at,path LIMIT 1''',(time.time(),age_limit)).fetchone()
        return self.pending(row['kind'],failures_only=True) if row else []

    def transfer(self, batch, depth=0):
        if not batch: return
        self.phase = 'copying'
        self.active = dict(files=len(batch),bytes=sum(r['size'] for r in batch),started_at=utc())
        self.status()
        batch_path = self.state / 'batch.files0'
        kind=batch[0]['kind']
        staging=self.state/'staging-tree'
        if staging.exists():
            if staging.is_symlink() or staging.resolve().parent!=self.state.resolve():
                raise RuntimeError('Unsafe staging directory')
            shutil.rmtree(staging)
        staging.mkdir(mode=0o700)
        upload_source=os.fsencode(staging)
        prepared=[]
        for row in batch:
            rel=row['path']
            if os.path.isabs(rel) or b'..' in rel.split(b'/'): raise RuntimeError('Invalid relative path')
            original=os.path.join(self.source,rel)
            try:
                if signature(os.lstat(original))!=row['sig']: continue
                target=os.path.join(upload_source,rel)
                if kind=='dir':
                    os.makedirs(target,exist_ok=True)
                elif kind=='link':
                    os.makedirs(os.path.dirname(target),exist_ok=True)
                    with open(target,'wb') as f: f.write(os.readlink(original))
                else:
                    os.makedirs(os.path.dirname(target),exist_ok=True)
                    # Rclone's private DNS namespace overlays /etc/resolv.conf.
                    # Materialize that one original host file BEFORE entering it.
                    # All metadata/signature checks still use the host namespace.
                    if self.c.get('network_wrapper') and original==b'/etc/resolv.conf':
                        shutil.copyfile(original,target)
                    else:
                        os.symlink(original,target)
                prepared.append(row)
            except FileNotFoundError:
                continue
        batch=prepared
        if not batch:
            self.last_scan=0
            self.active=None
            return
        transfers=self.transfer_count(batch)
        self.active.update(files=len(batch),bytes=sum(row['size'] for row in batch),transfers=transfers)
        self.status()
        with batch_path.open('wb') as stream:
            for row in batch:
                stream.write(row['path']+b'\0')
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
        rows={row['path']:row for row in batch}
        try:
            self.rc('copy',os.fsdecode(upload_source),self.c['destination'],
                '--copy-links','--ignore-times','--create-empty-src-dirs',
                '--exclude','/.ubuntu-drime-backup/**',
                '--backup-dir',self.c['history']+'/'+stamp+os.fsdecode(self.source),
                '--transfers',str(transfers),'--checkers',str(transfers),
                '--log-level','INFO','--stats','60s','--stats-log-level','NOTICE','--stats-one-line',
                on_event=lambda event:self.transfer_event(event,rows))
        except SafetyStop:
            raise
        except Exception as e:
            self.last_operation_error=str(e)
            if not isinstance(e,RecordedError): self.guard.record('transfer_error',str(e))
            # Keep durable acknowledgements for individually completed writes;
            # only remaining files enter retry/backoff after a partial failure.
            batch=[row for row in batch if self.db.execute('SELECT uploaded FROM entries WHERE path=?',(row['path'],)).fetchone()[0]!=row['sig']]
            for row in batch:
                failures=row['failures']+1
                self.db.execute('UPDATE entries SET failures=?,retry_at=?,last_error=COALESCE(last_error,?) WHERE path=?',
                    (failures,time.time()+min(3600,60*2**min(failures,6))+random.uniform(0,15),sanitize(e),row['path']))
            if batch:
                LOG.error('Operation failed; %d unconfirmed files retained for retry: %s',len(batch),sanitize(e))
            else:
                LOG.error('Operation failed after all batch files were individually confirmed; no file re-upload scheduled: %s',sanitize(e))
            self.db.commit()
        else:
            for row in batch:
                self.checkpoint(row)
            self.db.commit()
            self.last_operation_error=None
            LOG.info('Completed batch: %d files, %d bytes',len(batch),sum(r['size'] for r in batch))
        self.active=None
        self.status()

    def manifest(self):
        self.phase='saving_metadata';self.status()
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        output=self.state/'filesystem.jsonl.gz'
        with gzip.open(output,'wt',encoding='utf-8',compresslevel=5) as stream:
            root_stat=os.lstat(self.source)
            header={'format':'ubuntu-drime-filesystem-v1','created_at':utc(),
                    'source_b64':b64(self.source),'root':json.loads(self.metadata(self.source,root_stat,'dir')),
                    'include_roots':self.c.get('include_roots',[os.fsdecode(self.source)]),
                    'description':'Observed filesystem metadata; uploaded_at and content_current describe copied file data. Directories and symlinks can be restored from this manifest.'}
            stream.write(json.dumps(header,ensure_ascii=True)+'\n')
            for row in self.db.execute('SELECT * FROM entries ORDER BY path'):
                record=dict(path_b64=b64(row['path']),path=os.fsdecode(row['path']),
                            kind=row['kind'],present=bool(row['present']),
                            content_current=row['uploaded']==row['sig'],uploaded_at=row['uploaded_at'],
                            metadata=json.loads(row['meta']))
                stream.write(json.dumps(record,ensure_ascii=True,separators=(',',':'))+'\n')
        self.rc('copyto',str(output),self.c['metadata']+'/'+stamp+'/filesystem.jsonl.gz','--immutable')
        self.last_manifest_day=dt.datetime.now(dt.timezone.utc).date().isoformat()
        self.setting('manifest_day',self.last_manifest_day)
        self.setting('last_manifest',utc())
        LOG.info('Filesystem metadata saved: %s',stamp)

    def verify_sample(self):
        self.phase='verifying_sample';self.status()
        rows=self.db.execute('''SELECT path,sig FROM entries WHERE present=1 AND kind='file'
            AND uploaded=sig AND size<=16777216 ORDER BY RANDOM() LIMIT ?''',(self.c.get('verify_sample_files',8),)).fetchall()
        if not rows: return
        checked=0
        for row in rows:
            # CLI object paths use rclone's standard control-character encoding.
            # These uncommon names are tested by full-tree round trips instead.
            decoded=os.fsdecode(row['path'])
            if any(ord(ch)<32 or ord(ch)==127 or 0xD800<=ord(ch)<=0xDFFF or 0x2400<=ord(ch)<=0x2426 or ch=='\u201b' for ch in decoded):
                continue
            local=os.path.join(self.source,row['path'])
            before=os.lstat(local)
            if signature(before)!=row['sig']: continue
            with open(local,'rb') as f: expected=hashlib.file_digest(f,'sha256').digest() if hasattr(hashlib,'file_digest') else hashlib.sha256(f.read()).digest()
            # cat writes to a private file to bound memory and hashes the downloaded bytes.
            check_path=self.state/'verify.download'
            try:
                check_path.write_bytes(self.rc('cat',self.c['destination']+'/'+os.fsdecode(row['path']),capture=True))
            except SafetyStop: raise
            except Exception:
                self.db.execute("UPDATE entries SET uploaded='',last_error='Sample download failed' WHERE path=?",(row['path'],))
                self.db.commit()
                raise RecordedError('Sample download failed; file queued for repair')
            actual=hashlib.sha256(check_path.read_bytes()).digest()
            check_path.unlink()
            if signature(os.lstat(local))!=row['sig']: continue
            if actual!=expected:
                self.db.execute("UPDATE entries SET uploaded='',last_error='SHA256 verification mismatch' WHERE path=?",(row['path'],))
                self.db.commit()
                self.guard.trip('SHA256 sample mismatch for path_b64='+b64(row['path']))
            checked+=1
        if checked:
            self.last_verified_day=dt.datetime.now(dt.timezone.utc).date().isoformat()
            self.setting('verified_day',self.last_verified_day)
            self.setting('last_sample_verification',json.dumps({'at':utc(),'files':checked,'result':'sha256_match'}))
            LOG.info('Verified downloaded SHA256 for %d sample files',checked)

    def cycle(self):
        self.guard.poll(force=True)
        if time.monotonic()-self.last_scan>=self.c['scan_interval']:
            self.scan()
        today=dt.datetime.now(dt.timezone.utc).date().isoformat()
        if self.last_manifest_day!=today: self.manifest()
        batch=self.due_retries()
        if batch: LOG.info('Retrying %d previously unconfirmed %s entries',len(batch),batch[0]['kind'])
        if not batch and self.file_batches and self.file_batches%10==0:
            batch=self.pending('dir')
            self.file_batches+=1
        if not batch and self.file_batches and self.file_batches%5==0:
            batch=self.pending('link')
            self.file_batches+=1
        if not batch: batch=self.pending('file')
        if not batch: batch=self.pending('link')
        if not batch: batch=self.pending('dir')
        if batch:
            self.transfer(batch)
            if batch[0]['kind']=='file': self.file_batches+=1
        else:
            self.phase='waiting';self.status()
            if not self.counts['pending_files'] and not self.counts['pending_directories'] and not self.scan_errors:
                if not self.setting('initial_copy_complete'):
                    self.manifest()
                    self.setting('initial_copy_complete',utc())
                    LOG.info('Initial full file copy completed')
                if self.last_verified_day!=today: self.verify_sample()
            self.status()
        return bool(batch)


class StopRequested(BaseException):
    pass


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    config=json.loads(pathlib.Path(args.config).read_text())
    backup=Backup(config)
    def stopping(signum,frame): raise StopRequested()
    signal.signal(signal.SIGTERM,stopping)
    signal.signal(signal.SIGINT,stopping)
    try:
        backup.guard.begin_run()
        while True:
            try:
                work=backup.cycle()
            except SafetyStop: raise
            except Exception as e:
                if not isinstance(e,RecordedError): backup.guard.record('cycle_error',str(e))
                backup.phase='retrying';backup.last_operation_error=sanitize(e);backup.status()
                LOG.exception('Cycle paused after error; durable budget %s/%s',backup.guard.data['count'],backup.guard.limit)
                if args.once: raise
                time.sleep(60)
                continue
            if args.once:
                if work: continue
                if backup.counts['pending_files'] or backup.counts['pending_directories'] or backup.scan_errors: raise SystemExit(2)
                break
            if not work: time.sleep(5)
    except StopRequested:
        LOG.info('Stopped by operator')
    except SafetyStop as error:
        backup.phase='safety_stopped';backup.last_operation_error=sanitize(error)
        LOG.critical('SAFETY STOP: %s',sanitize(error))
        raise SystemExit(78)
    finally:
        backup.guard.end_run()
        backup.active=None
        if backup.phase!='safety_stopped': backup.phase='stopped'
        backup.status()
        backup.db.close();backup.lock.close()


if __name__=='__main__':
    main()
