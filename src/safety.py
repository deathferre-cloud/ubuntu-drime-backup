#!/usr/bin/env python3
"""Persistent, manually reset backup safety latch and Drime alert observer."""
import argparse
import configparser
import datetime as dt
import fcntl
import json
import logging
import os
import pathlib
import re
import subprocess
import time
import uuid
from zoneinfo import ZoneInfo


class SafetyStop(RuntimeError):
    pass


class RecordedError(RuntimeError):
    """An operation failure already charged to the durable error budget."""
    pass


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sanitize(value):
    value = re.sub(r'(https?://[^\s"?]+)\?[^\s"]+', r'\1?[redacted]', str(value))
    value = re.sub(r'(?i)(bearer\s+|access_token[=:]\s*)[^\s,;]+', r'\1[redacted]', value)
    return value[:1200]


def atomic_json(path, value):
    tmp = path.with_name(path.name+'.tmp')
    with tmp.open('w') as stream:
        os.chmod(tmp, 0o600)
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


class SafetyGuard:
    def __init__(self, config):
        self.c = config
        self.root = pathlib.Path(config['state_dir'])
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.root/'safety-state.json'
        self.latch = self.root/'SAFETY_STOP.json'
        self.manual = self.root/'MANUAL_STOP.json'
        self.running = self.root/'RUNNING.json'
        self.limit = int(config.get('safety_error_limit', 5))
        if not 1 <= self.limit <= 10: raise ValueError('Safety limit must be between 1 and 10')
        self.data = dict(version=1, count=0, events=[], status='armed', activity_cursor=None, epoch=str(uuid.uuid4()))
        self.next_poll = 0
        self.next_policy_check = 0
        self.policies = ('ransomware_suspected', 'malware_shared_by_team_member')
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
                assert self.data['version'] == 1 and isinstance(self.data['count'], int)
                assert isinstance(self.data['events'], list) and self.data['status'] in ('armed', 'stopped')
            except (ValueError, KeyError, AssertionError, TypeError):
                self.trip('Safety state is unreadable; inspection required')

    def daytime(self):
        """07:00 inclusive to 19:00 exclusive in Moscow, independent of host TZ."""
        return 7 <= dt.datetime.now(ZoneInfo('Europe/Moscow')).hour < 19

    def save(self):
        self.data['limit'] = self.limit
        self.data['updated_at'] = now()
        atomic_json(self.path, self.data)

    def check(self):
        if self.manual.exists():
            raise SafetyStop('Persistent manual stop: '+str(self.manual))
        if self.latch.exists() or self.data['status'] == 'stopped':
            raise SafetyStop('Persistent safety stop: '+str(self.latch))
        if self.daytime() and self.data['count'] >= self.limit:
            self.trip('Persistent error budget exhausted')

    def trip(self, reason):
        if not self.daytime():
            # Abort the bad operation, but never latch or acknowledge bad data.
            self.record('night_operation_abort', reason)
            raise RecordedError(sanitize(reason))
        self.data.update(status='stopped', reason=sanitize(reason), stopped_at=now())
        self.save()
        atomic_json(self.latch, self.data)
        raise SafetyStop(sanitize(reason))

    def record(self, kind, detail, event_id=None):
        self.check()
        event_id = event_id or str(uuid.uuid4())
        if any(e['id'] == event_id for e in self.data['events']): return
        day = self.daytime()
        if day: self.data['count'] += 1
        else: self.data['night_errors'] = self.data.get('night_errors', 0)+1
        self.data['events'].append(dict(id=event_id, kind=kind, detail=sanitize(detail), at=now(), period='day' if day else 'night'))
        self.data['events'] = self.data['events'][-100:]
        self.save()
        logging.getLogger('ubuntu-drime-backup').warning('%s error: %s: %s', 'DAY' if day else 'NIGHT', kind, sanitize(detail))
        if day and self.data['count'] >= self.limit:
            self.trip(f"Error limit reached ({self.data['count']}/{self.limit}); last event: {kind}: {sanitize(detail)}")

    def summary(self):
        result = {k:self.data.get(k) for k in ('status','count','reason','stopped_at','activity_cursor','night_errors')}
        result.update(limit=self.limit,period='day' if self.daytime() else 'night',auto_stop_enabled=self.daytime(),
                      manual_stop=self.manual.exists(),latched=self.latch.exists() or self.data['status']=='stopped')
        return result

    def api(self, path):
        config = configparser.ConfigParser()
        config.read(self.c['rclone_config'])
        remote = self.c['destination'].split(':',1)[0]
        token = config[remote]['access_token']
        workspace = int(self.c['cloud_guard_workspace'])
        if int(config[remote]['workspace_id']) != workspace:
            self.trip('Cloud guard workspace does not match upload workspace')
        prefix = [self.c['network_wrapper']] if self.c.get('network_wrapper') else []
        command = prefix+['curl','-4','--http1.1','--silent','--show-error','--compressed',
            '--connect-timeout','3','--max-time','7','--config','-',
            '--write-out','\nSTATUS:%{http_code}',f'https://app.drime.cloud/api/v1/workspace/{workspace}/'+path]
        result = subprocess.run(command, input='header = "Authorization: Bearer '+token+'"\nheader = "Accept: application/json"\n',
                                text=True, capture_output=True, timeout=10)
        body, _, status = result.stdout.rpartition('\nSTATUS:')
        if result.returncode or status != '200':
            raise RuntimeError('Drime safety API unavailable: HTTP '+status+' curl='+str(result.returncode))
        return json.loads(body)

    def validate_policies(self):
        data = self.api('alert-policies')
        rows = {p['policy']:p for p in data['policies']}
        for name in self.policies:
            policy = rows[name]
            ordinary=set(self.c.get('cloud_guard_ordinary_extensions',['js']))
            configured={str(x).lower().lstrip('.') for x in policy['settings']['extensions']}
            if not policy['enabled'] or not policy['notify_email'] or ordinary & configured:
                self.trip('Expected alert policy changed (enabled, email on, ordinary program extensions excluded): '+name)
        self.next_policy_check = time.monotonic()+300

    def ordinary_extension_notice(self, row):
        """Only the observed informational extension rule for this backup actor."""
        meta=row.get('metadata')
        if not isinstance(meta,dict): return False
        if set(meta)-{'name','extension','actor','severity','policy'}: return False
        extension=meta.get('extension')
        name=row.get('target_name')
        actor=self.c.get('cloud_guard_actor_email')
        return bool(actor and row.get('workspace_id')==self.c.get('cloud_guard_workspace')
            and row.get('action')=='alert_malware_shared_by_member' and row.get('target_type')=='file'
            and meta.get('policy')=='malware_shared_by_team_member' and meta.get('severity')=='informational'
            and isinstance(meta.get('actor'),str) and meta['actor'].casefold()==actor.casefold()
            and isinstance(extension,str) and extension.lower() in self.c.get('cloud_guard_ordinary_extensions',[])
            and isinstance(name,str) and name==meta.get('name') and name.lower().endswith('.'+extension.lower()))

    def activity_since_cursor(self):
        """Follow pages to the saved cursor; a fast upload is not a journal gap."""
        cursor=self.data.get('activity_cursor');rows={};previous=None
        for page in range(1,int(self.c.get('cloud_guard_max_pages',20))+1):
            batch=self.api('activity?perPage=100&page='+str(page))['pagination']['data']
            if not isinstance(batch,list): raise ValueError('Invalid activity page')
            ids=tuple(int(row['id']) for row in batch)
            if ids and ids==previous: raise RuntimeError('Drime returned a repeated activity page')
            previous=ids
            rows.update((int(row['id']),row) for row in batch)
            if cursor is None or len(batch)<100 or min(ids)<=cursor: break
        return list(rows.values())

    def ingest_activity(self, rows, baseline=False):
        self.check()
        if not isinstance(rows,list): raise ValueError('Invalid activity page')
        ids = [int(row['id']) for row in rows]
        cursor = self.data['activity_cursor']
        if cursor is None or baseline:
            self.data['activity_cursor'] = max(ids, default=0)
            self.save(); return
        if len(rows) >= 100 and min(ids) > cursor:
            if self.daytime(): self.trip('Cloud activity exceeded one observation page; refusing to miss alerts')
            self.record('cloud_observation_gap', 'Activity page overflow at night; continuing at latest visible events')
        for row in sorted(rows,key=lambda r:int(r['id'])):
            event_id = int(row['id'])
            if event_id <= cursor: continue
            self.data['activity_cursor'] = event_id
            action = str(row.get('action',''))
            if action.startswith('alert_') and action != 'alert_policy_updated':
                details = row.get('details') or row.get('target_name') or action
                if self.ordinary_extension_notice(row):
                    self.data['ordinary_extension_notices']=self.data.get('ordinary_extension_notices',0)+1
                    logging.getLogger('ubuntu-drime-backup').info('Drime extension-only notice (not a transfer failure): %s',sanitize(details))
                else:
                    self.record('cloud_alert', action+': '+str(details), 'drime:'+str(event_id))
        self.data['activity_cursor'] = max([cursor]+ids)
        self.save()

    def poll(self, force=False):
        self.check()
        if not self.c.get('cloud_guard_workspace'): return
        if not force and time.monotonic() < self.next_poll: return
        self.next_poll = time.monotonic()+float(self.c.get('cloud_guard_poll_seconds',5))
        try:
            if time.monotonic() >= self.next_policy_check: self.validate_policies()
            self.ingest_activity(self.activity_since_cursor())
        except SafetyStop: raise
        except RecordedError:
            if self.daytime(): raise
        except Exception as error:
            self.record('guard_api_error',str(error))
            if self.daytime():
                raise RecordedError('Cloud alert observer unavailable; uploads paused') from error

    def begin_run(self):
        self.check()
        self.check_unclean()
        atomic_json(self.running,dict(pid=os.getpid(),started_at=now()))

    def check_unclean(self):
        if self.running.exists():
            if self.daytime(): self.trip('Previous process did not exit cleanly; inspection required')
            self.record('unclean_night_restart', 'Previous process did not exit cleanly; restarting at night')
            self.end_run()

    def end_run(self):
        self.running.unlink(missing_ok=True)

    def reset(self, reason):
        if not reason.strip(): raise ValueError('A review reason is required')
        if self.running.exists(): raise RuntimeError('Running marker present; stop/check the service first')
        cursor = self.data.get('activity_cursor')
        if self.c.get('cloud_guard_workspace'):
            self.validate_policies()
            rows = self.api('activity?perPage=100&page=1')['pagination']['data']
            cursor = max((int(r['id']) for r in rows),default=0)
        atomic_json(self.root/('safety-review-'+str(time.time_ns())+'.json'),dict(reason=reason,at=now(),previous=self.data))
        self.data = dict(version=1,count=0,events=[],status='armed',activity_cursor=cursor,epoch=str(uuid.uuid4()),review_reason=reason)
        self.save()
        self.latch.unlink(missing_ok=True)
        self.manual.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('check','show','reset','service-stop'))
    parser.add_argument('--config',required=True)
    parser.add_argument('--reason',default='')
    args = parser.parse_args()
    config=json.loads(pathlib.Path(args.config).read_text())
    guard=SafetyGuard(config)
    if args.action=='show': print(json.dumps(guard.summary(),indent=2));return
    if args.action=='service-stop':
        result=os.environ.get('SERVICE_RESULT','unknown')
        if result!='success' and not guard.latch.exists() and guard.data['status']!='stopped':
            try: guard.trip('Service terminated: '+result+'; '+os.environ.get('EXIT_CODE','')+' '+os.environ.get('EXIT_STATUS',''))
            except (SafetyStop, RecordedError): pass
        guard.end_run()
        status_path=guard.root/'status.json'
        if status_path.exists():
            try:
                status=json.loads(status_path.read_text())
                stopped=guard.latch.exists() or guard.manual.exists() or guard.data['status']=='stopped'
                status.update(updated_at=now(),active=None,phase='safety_stopped' if stopped else 'stopped',safety=guard.summary())
                if stopped:status['last_operation_error']=guard.data.get('reason')
                atomic_json(status_path,status)
            except (ValueError,OSError):pass
        return
    if args.action=='reset':
        if subprocess.run(['systemctl','is-active','--quiet','ubuntu-drime-backup']).returncode==0:
            raise RuntimeError('Stop the backup service before acknowledging an incident')
        with (guard.root/'daemon.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            guard.reset(args.reason)
        print('Safety stop acknowledged; service was NOT started');return
    guard.check()
    guard.check_unclean()


if __name__=='__main__':
    try: main()
    except SafetyStop as error:
        print(str(error));raise SystemExit(78)
