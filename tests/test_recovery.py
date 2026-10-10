#!/usr/bin/env python3
"""Fault-injection checks for durable stall recovery, with no cloud writes."""
import datetime as dt
import json
import pathlib
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

import control
import progress
from daemon import Backup, ScheduledRetry
from safety import SafetyGuard, SafetyStop, RecordedError

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.src=self.root/'source';self.src.mkdir()
        self.cfg=dict(source=str(self.src),state_dir=str(self.root/'state'),destination=str(self.root/'dest'),
            history=str(self.root/'history'),metadata=str(self.root/'metadata'),rclone='/bin/true',rclone_config='/dev/null',
            transfers=4,night_transfers=7,tpslimit=8,bwlimit='off',scan_interval=300,settle_seconds=0,
            batch_files=512,batch_bytes=536870912,stall_recovery_seconds=600,stall_timeout_seconds=.35)
        p=patch.object(SafetyGuard,'daytime',return_value=True);p.start();self.addCleanup(p.stop)
        self.b=Backup(self.cfg);self.addCleanup(self.b.lock.close);self.addCleanup(self.b.db.close)
        p=patch.object(control,'ROOT',self.b.state);p.start();self.addCleanup(p.stop)

    def script(self,body):
        path=self.root/'fake-rclone';path.write_text('#!/usr/bin/python3\n'+body);path.chmod(0o700)
        self.b.c['rclone']=str(path)

    def rows(self,*names):
        for name in names:(self.src/name).write_text('content')
        self.b.scan();return self.b.pending()

    def test_distinct_directory_events_keep_traversal_alive_without_acknowledging(self):
        rows=self.rows('untouched')
        self.script('''import json,sys,time
for i in range(10):
 print(json.dumps({'msg':'Making directory','object':'folder'+str(i),'level':'info'}),file=sys.stderr,flush=True)
 print(json.dumps({'msg':'0 B transferred','stats':{'bytes':0,'transfers':0,'checks':0}}),file=sys.stderr,flush=True)
 time.sleep(.1)
''')
        start=time.monotonic();self.b.rc('copy',on_event=lambda e:self.b.transfer_event(e,{r['path']:r for r in rows}))
        self.assertGreater(time.monotonic()-start,.8)
        self.assertEqual(len(self.b.pending()),1);self.assertEqual(self.b.guard.data['count'],0)

    def test_repeated_directory_and_zero_stats_do_not_mask_hang(self):
        self.script('''import json,sys,time
for i in range(100):
 print(json.dumps({'msg':'Making directory','object':'same','level':'info'}),file=sys.stderr,flush=True)
 print(json.dumps({'msg':'0 B transferred','stats':{'bytes':0,'transfers':0,'checks':0}}),file=sys.stderr,flush=True)
 time.sleep(.1)
''')
        start=time.monotonic()
        with self.assertRaisesRegex(ScheduledRetry,'distinct directory operations=1'):self.b.rc('copy')
        self.assertLess(time.monotonic()-start,3);self.assertFalse(self.b.guard.latch.exists())

    def test_pause_survives_restart_and_starts_nothing_before_deadline(self):
        with patch('daemon.time.time',return_value=1000):self.b.schedule_repair('injected stall')
        self.assertEqual(self.b.repair_state()['retry_at'],1600)
        self.b.db.close();self.b.lock.close();self.b=Backup(self.cfg)
        self.addCleanup(self.b.lock.close);self.addCleanup(self.b.db.close)
        with patch('daemon.time.time',return_value=1599),patch.object(self.b,'rc') as rc:
            self.assertFalse(self.b.cycle());rc.assert_not_called()
        self.assertEqual(self.b.phase,'repair_wait')

    def test_probe_small_retry_and_success_restore_profile_without_resetting_budget(self):
        rows=self.rows('a','b');self.b.guard.record('existing','review pending')
        with patch('daemon.time.time',return_value=1000):self.b.schedule_repair('stall')
        with patch('daemon.time.time',return_value=1600),patch.object(self.b,'rc') as rc:
            self.assertFalse(self.b.repair_gate());rc.assert_called_once_with('lsf',self.cfg['destination'],'--dirs-only','--max-depth','1',capture=True)
        self.assertEqual(self.b.repair_state()['state'],'retrying');self.assertEqual(self.b.batch_limit('file'),16)
        with patch.object(SafetyGuard,'daytime',return_value=False):self.assertEqual(self.b.transfer_count(rows),2)
        with patch.object(self.b,'rc'):self.b.transfer(rows)
        self.assertIsNone(self.b.repair_state());self.assertEqual(self.b.guard.data['count'],1)
        self.assertEqual(self.b.batch_limit('file'),512)
        with patch.object(SafetyGuard,'daytime',return_value=False):self.assertEqual(self.b.transfer_count(rows),7)

    def test_probe_failure_reschedules_and_retains_error_budget(self):
        with patch('daemon.time.time',return_value=1000):self.b.schedule_repair('stall')
        with patch('daemon.time.time',return_value=1600),patch.object(self.b,'rc',side_effect=OSError('cloud offline')):
            self.assertTrue(self.b.repair_gate())
        self.assertEqual(self.b.repair_state()['retry_at'],2200);self.assertEqual(self.b.repair_state()['attempts'],2)
        self.assertEqual(self.b.guard.data['count'],1)

    def test_manual_stop_is_never_cleared_by_timer(self):
        with patch('daemon.time.time',return_value=1000):self.b.schedule_repair('stall')
        self.b.guard.manual.write_text('{}')
        with patch('daemon.time.time',return_value=2000),patch.object(self.b,'rc') as rc:
            with self.assertRaises(SafetyStop):self.b.repair_gate()
            rc.assert_not_called()
        self.assertTrue(self.b.guard.manual.exists());self.assertEqual(self.b.repair_state()['state'],'waiting')

    def test_safety_alerts_during_probe_latch_and_are_not_rescheduled(self):
        with patch('daemon.time.time',return_value=1000):self.b.schedule_repair('stall')
        for n in range(4):self.b.guard.record('real_error',str(n))
        def fifth(*a,**kw):self.b.guard.record('security','fifth real error')
        with patch('daemon.time.time',return_value=1600),patch.object(self.b,'rc',side_effect=fifth):
            with self.assertRaises(SafetyStop):self.b.repair_gate()
        self.assertTrue(self.b.guard.latch.exists());self.assertEqual(self.b.guard.data['count'],5)
        self.assertEqual(self.b.repair_state()['attempts'],1)

    def test_directory_batch_cap_applies_to_pending_and_direct_transfer(self):
        for i in range(40):(self.src/('dir%03d'%i)).mkdir()
        self.b.scan();all_rows=[dict(r) for r in self.b.db.execute("SELECT * FROM entries WHERE kind='dir'")]
        self.assertEqual(len(self.b.pending('dir')),16)
        with patch.object(self.b,'rc') as rc:self.b.transfer(all_rows)
        self.assertEqual(rc.call_count,1)
        count=self.b.db.execute("SELECT COUNT(*) FROM entries WHERE kind='dir' AND uploaded=sig").fetchone()[0]
        self.assertEqual(count,16);self.assertEqual(self.b.batch_limit('file'),512)

    def test_partial_ack_and_stalled_queue_are_preserved_for_ten_minute_retry(self):
        rows=self.rows('a','b');self.b.c['stall_timeout_seconds']=600
        def stalled(*args,**kw):
            self.b.checkpoint(rows[0]);self.b.db.commit();raise ScheduledRetry('injected stall')
        with patch('daemon.time.time',return_value=1000),patch.object(self.b,'rc',side_effect=stalled):self.b.transfer(rows)
        records=[dict(r) for r in self.b.db.execute('SELECT * FROM entries ORDER BY path')]
        self.assertEqual(records[0]['uploaded'],records[0]['sig']);self.assertNotEqual(records[1]['uploaded'],records[1]['sig'])
        self.assertEqual(records[1]['retry_at'],1600);self.assertEqual(self.b.guard.data['count'],0)
        state=self.b.repair_state();self.assertTrue(state['incident_id'])
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM incident_files WHERE resolved_at IS NULL').fetchone()[0],1)
        with patch('daemon.time.time',return_value=1600),patch.object(self.b,'rc'):
            self.assertFalse(self.b.repair_gate());retry=self.b.due_retries();self.assertEqual(len(retry),1);self.b.transfer(retry)
        self.assertIsNone(self.b.repair_state())
        self.assertTrue(self.b.db.execute('SELECT resolved_at FROM transfer_incidents WHERE id=?',(state['incident_id'],)).fetchone()[0])

    def test_legacy_log_alias_requires_real_incident_completion(self):
        rows=self.rows('a');incident=self.b.begin_incident(rows);self.b.finish_incident(incident,'stall')
        stamp=int(time.time()*1000000);message='CRITICAL legacy stall';key=control.error_identity(stamp,message)
        path=self.b.state/'error-resolutions.json';path.write_text(json.dumps({key:{'incident_id':incident}}))
        def lookup(text=message):
            reader=control.ErrorResolutions()
            try:return reader.lookup(stamp,text)['resolved']
            finally:reader.close()
        self.assertFalse(lookup());self.b.checkpoint(rows[0]);self.b.db.commit();self.assertTrue(lookup())
        self.assertFalse(lookup('different error'))
        path.write_text(json.dumps({key:{'incident_id':'invalid'}}));self.assertFalse(lookup())

    def test_paused_recovery_does_not_distort_eta_or_override_stopped_ui(self):
        now=dt.datetime.now(dt.timezone.utc);state=dict(updated_at=now.isoformat(),phase='repair_wait',
            repair=dict(state='waiting',retry_at=now.timestamp()+600,reason='stall'),current_files=0,current_bytes=0,pending_files=1)
        self.assertIsNone(progress.sample(state,{},dict(pid=12,started_at=now.isoformat()),now.timestamp()))
        (self.b.state/'status.json').write_text(json.dumps(state))
        with patch.object(control,'systemctl',return_value=Mock(stdout='ActiveState=active\n')),patch.object(control,'recent_errors',return_value={}):
            result=control.status();self.assertEqual(result['eta']['state'],'repair');self.assertIn('МСК',result['repair']['label'])
            self.b.guard.manual.write_text('{}');result=control.status()
            self.assertEqual(result['eta']['state'],'paused');self.assertIn('приостановлен',result['repair']['label'])

if __name__=='__main__':unittest.main(verbosity=2)
