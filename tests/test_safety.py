#!/usr/bin/env python3
"""Fault-injection tests. All data and fake commands stay in temporary trees."""
import json
import os
import pathlib
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import datetime as dt

from safety import SafetyGuard, SafetyStop, RecordedError
from daemon import Backup


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.day=patch.object(SafetyGuard,'daytime',return_value=True)
        self.day.start();self.addCleanup(self.day.stop)
        self.tmp=tempfile.TemporaryDirectory(prefix='ubuntu-drime-safety-test-')
        self.root=pathlib.Path(self.tmp.name)
        (self.root/'source').mkdir()
        self.config=dict(source=str(self.root/'source'),state_dir=str(self.root/'state'),
            destination=str(self.root/'dest'),history=str(self.root/'history'),metadata=str(self.root/'metadata'),
            rclone_config='/dev/null',rclone='/bin/true',transfers=4,tpslimit=8,bwlimit='off',
            safety_error_limit=5,scan_interval=300,settle_seconds=0,batch_files=512,batch_bytes=536870912)
        self.backups=[]

    def tearDown(self):
        for b in self.backups: b.db.close();b.lock.close()
        self.tmp.cleanup()

    def backup(self):
        b=Backup(self.config);self.backups.append(b);return b

    def script(self,body):
        p=self.root/'fake-rclone';p.write_text('#!/usr/bin/python3\n'+body);p.chmod(0o700)
        self.config['rclone']=str(p);return p

    def test_persistent_budget_duplicate_and_manual_reset(self):
        g=SafetyGuard(self.config)
        g.record('io','first','same');g.record('io','first','same')
        g=SafetyGuard(self.config);self.assertEqual(g.data['count'],1)
        for i in range(3):g.record('io','failure '+str(i))
        with self.assertRaises(SafetyStop):g.record('io','fifth')
        self.assertTrue(g.latch.exists());self.assertEqual(g.data['count'],5)
        # Deleting only the latch cannot bypass persistent state.
        g.latch.unlink()
        with self.assertRaises(SafetyStop):SafetyGuard(self.config).check()
        g.reset('Reviewed injected failures, explicit manual reset')
        SafetyGuard(self.config).check();self.assertEqual(g.data['count'],0)

    def test_cloud_alerts_dedup_and_threshold(self):
        g=SafetyGuard(self.config);g.ingest_activity([{'id':100,'action':'alert_malware_shared_by_member'}])
        self.assertEqual(g.data['count'],0)
        g.ingest_activity([{'id':101,'action':'file_uploaded'},{'id':100,'action':'alert_malware_shared_by_member'}])
        rows=[{'id':i,'action':'alert_malware_shared_by_member'} for i in range(102,107)]
        with self.assertRaises(SafetyStop):g.ingest_activity(rows)
        self.assertEqual(g.data['count'],5)
        self.assertEqual(g.data['activity_cursor'],106)

    def test_cloud_cursor_gap_stops(self):
        g=SafetyGuard(self.config);g.ingest_activity([{'id':1}])
        with self.assertRaises(SafetyStop):g.ingest_activity([{'id':i,'action':'file_uploaded'} for i in range(2,102)])

    def test_observer_failure_prevents_starting_transfer(self):
        marker=self.root/'started'
        self.script('import pathlib\npathlib.Path('+repr(str(marker))+').touch()\n')
        b=self.backup();b.c['cloud_guard_workspace']=12345
        b.guard.api=lambda path: (_ for _ in ()).throw(OSError('offline'))
        for _ in range(4):
            with self.assertRaises(RecordedError):b.rc('copy')
        with self.assertRaises(SafetyStop):b.rc('copy')
        self.assertFalse(marker.exists());self.assertEqual(b.guard.data['count'],5)

    def test_policy_change_stops_without_waiting_for_email(self):
        g=SafetyGuard(self.config)
        g.api=lambda path:{'policies':[{'policy':p,'enabled':True,'notify_email':True,'settings':{'extensions':['js']}} for p in g.policies]}
        with self.assertRaises(SafetyStop):g.validate_policies()

    def test_unclean_exit_and_corrupt_state(self):
        g=SafetyGuard(self.config);g.begin_run()
        with self.assertRaises(SafetyStop):SafetyGuard(self.config).begin_run()
        g.end_run();g.reset('Reviewed unclean-exit test')
        g.path.write_text('{bad json')
        with self.assertRaises(SafetyStop):SafetyGuard(self.config)

    def test_fifth_error_kills_process_tree_and_preserves_success(self):
        data=self.root/'source/ok';data.write_bytes(b'OK')
        childpid=self.root/'child.pid'
        self.script('''import json,os,pathlib,subprocess,sys,time
child=subprocess.Popen(['/bin/sleep','90'])
pathlib.Path(%r).write_text(str(child.pid))
print(json.dumps({'level':'info','msg':'Copied (new)','objectType':'*local.Object','object':'ok','size':2}),file=sys.stderr,flush=True)
for i in range(20):
 print(json.dumps({'level':'error','msg':'injected network error','object':'file-'+str(i)}),file=sys.stderr,flush=True)
 time.sleep(.05)
time.sleep(90)
''' % str(childpid))
        b=self.backup();b.scan();batch=b.pending();start=time.monotonic()
        with self.assertRaises(SafetyStop):b.transfer(batch)
        self.assertLess(time.monotonic()-start,5)
        self.assertEqual(b.guard.data['count'],5)
        self.assertTrue(b.db.execute('SELECT uploaded=sig FROM entries WHERE path=?',(b'ok',)).fetchone()[0])
        pid=int(childpid.read_text())
        for _ in range(30):
            proc=pathlib.Path('/proc')/str(pid)/'stat'
            if not proc.exists() or proc.read_text().split()[2]=='Z':break
            time.sleep(.05)
        else:self.fail('Descendant survived safety stop')

    def test_summary_does_not_double_count_and_success_does_not_reset(self):
        self.script('''import json,sys
for event in [{'level':'error','object':'one','msg':'failed upload'}, {'level':'error','msg':'Attempt 1/1 failed with 1 errors'}]:
 print(json.dumps(event),file=sys.stderr)
sys.exit(5)
''')
        b=self.backup()
        with self.assertRaises(RecordedError):b.rc('copy')
        self.assertEqual(b.guard.data['count'],1)
        self.script('pass\n');b.rc('copy')
        self.assertEqual(b.guard.data['count'],1)
        self.assertEqual(b.transfer_count([{'kind':'file','size':1}]),2)

    def test_silent_hang_stops_without_waiting_for_a_log_line(self):
        self.script('import time\ntime.sleep(90)\n')
        self.config['stall_timeout_seconds']=.3
        b=self.backup();start=time.monotonic()
        with self.assertRaises(SafetyStop):b.rc('copy')
        self.assertLess(time.monotonic()-start,4)

    def test_process_crash_stops_immediately(self):
        self.script('import os,signal\nos.kill(os.getpid(),signal.SIGKILL)\n')
        b=self.backup()
        with self.assertRaises(SafetyStop):b.rc('copy')
        self.assertTrue(b.guard.latch.exists())

    def test_cloud_alerts_stop_an_already_running_silent_process(self):
        self.script('import time\ntime.sleep(90)\n')
        b=self.backup();b.c['cloud_guard_workspace']=12345;b.c['cloud_guard_poll_seconds']=.1
        b.guard.next_policy_check=time.monotonic()+60
        calls=[]
        def api(path):
            calls.append(path)
            rows=[{'id':100,'action':'file_uploaded'}]
            if len(calls)>1:rows += [{'id':i,'action':'alert_malware_shared_by_member'} for i in range(101,106)]
            return {'pagination':{'data':rows}}
        b.guard.api=api
        start=time.monotonic()
        with self.assertRaises(SafetyStop):b.rc('copy')
        self.assertLess(time.monotonic()-start,4)
        self.assertEqual(b.guard.data['count'],5)

    def test_moscow_boundaries(self):
        self.day.stop()
        for hour,minute,expected in [(6,59,False),(7,0,True),(18,59,True),(19,0,False),(23,59,False),(0,0,False)]:
            instant=dt.datetime(2026,10,9,hour,minute)
            with patch('safety.dt.datetime') as clock:
                clock.now.return_value=instant
                self.assertEqual(SafetyGuard.daytime(None),expected)
                self.assertEqual(str(clock.now.call_args.args[0]),'Europe/Moscow')

    def test_night_errors_do_not_consume_day_budget(self):
        g=SafetyGuard(self.config);g.record('day','one')
        with patch.object(SafetyGuard,'daytime',return_value=False):
            for i in range(30):g.record('night','error '+str(i))
            self.assertEqual(g.data['count'],1);self.assertEqual(g.data['night_errors'],30)
            self.assertFalse(g.latch.exists());g.check()
            with self.assertRaises(RecordedError):g.trip('Night child crash')
            self.assertFalse(g.latch.exists())
        g.check();self.assertEqual(g.data['count'],1)

    def test_day_latch_and_manual_latch_survive_night(self):
        g=SafetyGuard(self.config)
        with self.assertRaises(SafetyStop):g.trip('Day crash')
        with patch.object(SafetyGuard,'daytime',return_value=False):
            with self.assertRaises(SafetyStop):SafetyGuard(self.config).check()
            g.reset('User confirmed incident');g.manual.write_text('{}')
            with self.assertRaises(SafetyStop):g.check()
            g.reset('User explicitly starts');g.check()

    def test_night_hang_aborts_command_without_latching(self):
        self.script('import time\ntime.sleep(90)\n');self.config['stall_timeout_seconds']=.3
        b=self.backup()
        with patch.object(SafetyGuard,'daytime',return_value=False):
            with self.assertRaises(RecordedError):b.rc('copy')
            self.assertFalse(b.guard.latch.exists());self.assertEqual(b.guard.data['count'],0)
            self.script('pass\n');b.rc('copy')

    def test_night_crash_observer_outage_and_unclean_restart(self):
        self.script('import os,signal\nos.kill(os.getpid(),signal.SIGKILL)\n');b=self.backup()
        with patch.object(SafetyGuard,'daytime',return_value=False):
            with self.assertRaises(RecordedError):b.rc('copy')
            b.guard.begin_run();b.guard.begin_run();b.guard.end_run()
            self.script('pass\n');b.c['cloud_guard_workspace']=12345
            b.guard.api=lambda path: (_ for _ in ()).throw(OSError('offline'))
            b.rc('copy')
            self.assertFalse(b.guard.latch.exists());self.assertEqual(b.guard.data['count'],0)

    def test_night_activity_overflow_continues_and_email_enabled_is_expected(self):
        g=SafetyGuard(self.config)
        g.api=lambda path:{'policies':[{'policy':p,'enabled':True,'notify_email':True,'settings':{'extensions':['exe']}} for p in g.policies]}
        g.validate_policies()
        with patch.object(SafetyGuard,'daytime',return_value=False):
            g.ingest_activity([{'id':1}])
            g.ingest_activity([{'id':i,'action':'alert_security'} for i in range(2,102)])
            self.assertEqual(g.data['activity_cursor'],101);self.assertFalse(g.latch.exists())

    def test_day_night_concurrency_and_api_limits(self):
        self.config.update(night_transfers=7,night_large_file_transfers=6,night_tpslimit=24)
        b=self.backup();small=[{'kind':'file','size':20}];large=[{'kind':'file','size':2**21}]
        def tps():
            cmd=b.command('copy');return cmd[cmd.index('--tpslimit')+1]
        self.assertEqual(b.transfer_count(small),4);self.assertEqual(tps(),'8')
        b.guard.record('day','injected');self.assertEqual(b.transfer_count(small),2);self.assertEqual(tps(),'4')
        with patch.object(SafetyGuard,'daytime',return_value=False):
            self.assertEqual(b.transfer_count(small),7);self.assertEqual(b.transfer_count(large),6);self.assertEqual(tps(),'24')

    def extension_notice(self, event_id=2, extension='exe'):
        return dict(id=event_id,workspace_id=12345,action='alert_malware_shared_by_member',target_type='file',
            target_name='program.'+extension,metadata=dict(name='program.'+extension,extension=extension,
                actor='backup@example.test',severity='informational',policy='malware_shared_by_team_member'))

    def test_ordinary_program_notices_do_not_stop_all_file_backup(self):
        self.config.update(cloud_guard_workspace=12345,cloud_guard_actor_email='backup@example.test',
                           cloud_guard_ordinary_extensions=['exe','dll','js'])
        g=SafetyGuard(self.config);g.ingest_activity([{'id':1}])
        rows=[self.extension_notice(i,('exe','dll','js')[i%3]) for i in range(2,17)]
        g.ingest_activity(rows);g.ingest_activity(rows)
        self.assertEqual(g.data['count'],0);self.assertEqual(g.data['ordinary_extension_notices'],15)
        self.assertEqual(g.data['activity_cursor'],16);self.assertFalse(g.latch.exists())
        # An actual unknown security event still consumes the daytime budget.
        with self.assertRaises(SafetyStop):g.ingest_activity([dict(id=i,action='alert_content_malware') for i in range(17,22)])

    def test_extension_exception_never_covers_unrecognized_security_events(self):
        self.config.update(cloud_guard_workspace=12345,cloud_guard_actor_email='backup@example.test',cloud_guard_ordinary_extensions=['exe'])
        g=SafetyGuard(self.config);self.assertTrue(g.ordinary_extension_notice(self.extension_notice()))
        for change in ({'action':'alert_ransomware_suspected'},{'workspace_id':999},{'target_type':'folder'},{'target_name':'different.exe'}):
            row=self.extension_notice();row.update(change);self.assertFalse(g.ordinary_extension_notice(row))
        for change in ({'actor':'other@example.test'},{'severity':'high'},{'policy':'content_scan'},{'verdict':'malicious'},{'extension':'encrypted'}):
            row=self.extension_notice();row['metadata'].update(change);self.assertFalse(g.ordinary_extension_notice(row))

    def test_program_extensions_are_excluded_from_both_alert_rules(self):
        self.config['cloud_guard_ordinary_extensions']=['js','exe','dll']
        g=SafetyGuard(self.config)
        rows=[{'policy':p,'enabled':True,'notify_email':True,'settings':{'extensions':['locked','encrypted']}} for p in g.policies]
        g.api=lambda path:{'policies':rows};g.validate_policies()
        rows[1]['settings']['extensions'].append('dll')
        with self.assertRaises(SafetyStop):g.validate_policies()

    def test_activity_pagination_prevents_false_stop_and_deduplicates_overlap(self):
        g=SafetyGuard(self.config);g.ingest_activity([{'id':1}])
        pages=[range(201,101,-1),range(105,5,-1),range(8,0,-1)];calls=[]
        def api(path):
            calls.append(path);page=int(path.rsplit('=',1)[1]);return {'pagination':{'data':[dict(id=i,action='file_uploaded') for i in pages[page-1]]}}
        g.api=api;rows=g.activity_since_cursor();self.assertEqual(len(rows),201)
        g.ingest_activity(rows);self.assertEqual(g.data['activity_cursor'],201);self.assertFalse(g.latch.exists())
        self.assertEqual(len(calls),3)

    def test_repeated_activity_page_is_not_silently_accepted(self):
        g=SafetyGuard(self.config);g.ingest_activity([{'id':1}])
        g.api=lambda path:{'pagination':{'data':[dict(id=i,action='file_uploaded') for i in range(2,102)]}}
        with self.assertRaises(RuntimeError):g.activity_since_cursor()


if __name__=='__main__':unittest.main(verbosity=2)
