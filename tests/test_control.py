#!/usr/bin/env python3
import hashlib
import base64
import datetime as dt
import json
import pathlib
import tempfile
import subprocess
import sqlite3
import unittest
from unittest.mock import patch
import control

class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ubuntu-drime-control-test-')
        self.addCleanup(self.tmp.cleanup)
        patcher=patch.object(control,'ROOT',pathlib.Path(self.tmp.name))
        patcher.start();self.addCleanup(patcher.stop)

    def test_auth_and_fixed_actions(self):
        with tempfile.TemporaryDirectory() as root:
            auth=pathlib.Path(root)/'auth.json';key='c'*64
            auth.write_text(json.dumps({'key_sha256':hashlib.sha256(key.encode()).hexdigest()}))
            with patch.object(control,'AUTH',auth),patch.object(control,'systemctl') as command,patch.object(control,'status',return_value={'test':True}):
                for request in [{},{'key':'x'*64,'action':'stop'},{'key':['bad'],'action':'stop'}]:
                    self.assertFalse(control.dispatch(request)['ok'])
                self.assertFalse(control.dispatch({'key':key,'action':'stop; touch /tmp/pwned'})['ok'])
                self.assertTrue(control.dispatch({'key':key,'action':'status'})['ok'])
                command.assert_not_called()

    def test_web_start_keeps_short_read_only_preflight_budget(self):
        key='d'*64;auth=control.ROOT/'auth.json';config=control.ROOT/'config.json'
        auth.write_text(json.dumps({'key_sha256':hashlib.sha256(key.encode()).hexdigest()}))
        config.write_text(json.dumps({'cloud_guard_attempts':3,'cloud_guard_timeout':20}))
        with patch.object(control,'AUTH',auth),patch.object(control,'CONFIG',config),patch.object(control,'SafetyGuard') as guard, \
             patch.object(control,'status',return_value={'service':{'ActiveState':'inactive'}}), \
             patch.object(control,'systemctl',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertTrue(control.dispatch({'key':key,'action':'start'})['ok'])
            settings=guard.call_args.args[0]
            self.assertEqual(settings['cloud_guard_attempts'],1);self.assertEqual(settings['cloud_guard_timeout'],10)
            guard.return_value.reset.assert_called_once()
        self.assertEqual(json.loads(config.read_text())['cloud_guard_attempts'],3)

    def test_stop_latches_before_systemctl_and_keeps_latch_on_failure(self):
        with tempfile.TemporaryDirectory() as root:
            root=pathlib.Path(root);key='a'*64;auth=root/'auth.json'
            auth.write_text(json.dumps({'key_sha256':hashlib.sha256(key.encode()).hexdigest()}))
            def stop(*args):
                self.assertEqual(args,('stop',));self.assertTrue((root/'MANUAL_STOP.json').exists())
                raise RuntimeError('injected systemctl failure')
            with patch.object(control,'ROOT',root),patch.object(control,'AUTH',auth),patch.object(control,'systemctl',side_effect=stop):
                with self.assertRaises(RuntimeError):control.dispatch({'key':key,'action':'stop'})
                self.assertTrue((root/'MANUAL_STOP.json').exists())

    def test_error_log_merges_sorts_limits_and_formats_moscow(self):
        instant=dt.datetime(2026,10,9,4,45,4,tzinfo=dt.timezone.utc)
        stamp=int(instant.timestamp()*1_000_000)
        def records(start,end):
            return '\n'.join(json.dumps({'__CURSOR':str(i),'__REALTIME_TIMESTAMP':str(stamp+i*1_000_000),
                'MESSAGE':'2026-10-09 07:45:04,123 ERROR item '+str(i)}) for i in range(start,end))
        responses=[subprocess.CompletedProcess([],0,records(0,8),''),subprocess.CompletedProcess([],0,records(4,12),'')]
        with patch.object(control.subprocess,'run',side_effect=responses) as command:
            result=control.recent_errors()
        self.assertTrue(result['available']);self.assertEqual(len(result['entries']),10)
        self.assertEqual(result['entries'][0]['time'],'2026.10.09 — 07:45:15')
        self.assertEqual(result['entries'][0]['text'],'ERROR item 11')
        self.assertEqual(result['entries'][-1]['text'],'ERROR item 2')
        for call in command.call_args_list:
            self.assertIn(control.UNIT,call.args[0]);self.assertEqual(call.kwargs['timeout'],5)

    def test_error_log_redacts_secrets_and_handles_no_matches_or_failure(self):
        message='ERROR https://example.test/file?key=PRIVATE Bearer PRIVATE'
        row=json.dumps({'__REALTIME_TIMESTAMP':'1791521104000000','MESSAGE':message})
        with patch.object(control.subprocess,'run',side_effect=[subprocess.CompletedProcess([],0,row,''),subprocess.CompletedProcess([],0,'','')]):
            self.assertNotIn('PRIVATE',json.dumps(control.recent_errors()))
        with patch.object(control.subprocess,'run',side_effect=[subprocess.CompletedProcess([],1,'',''),subprocess.CompletedProcess([],0,'','')]):
            self.assertEqual(control.recent_errors(),{'available':True,'entries':[]})
        with patch.object(control.subprocess,'run',side_effect=subprocess.TimeoutExpired('journalctl',5)):
            self.assertEqual(control.recent_errors(),{'available':False,'entries':[]})

    def test_explanations_use_evidence_not_bare_numbers_in_file_names(self):
        self.assertIn('Сеть или Drime',control.explain_error('read tcp4: i/o timeout'))
        self.assertIn('папка с таким именем',control.explain_error('422: Folder with same name already exists.'))
        self.assertIn('Drime не принял',control.explain_error('HTTP 401'))
        self.assertIn('запретил запрос',control.explain_error('403 Forbidden'))
        self.assertIn('итог неудачной',control.explain_error('Copy failed path_b64=abcd403xyz: rclone exit code 5'))
        self.assertIn('нет надёжного автоматического',control.explain_error('New unfamiliar failure'))

    def test_error_filter_ignores_successful_files_with_error_in_name(self):
        import re
        for text in ('2026-10-09 07:45:04,123 ERROR failed','2026-10-09 07:45:04,123 WARNING rclone error : timeout','2026-10-09 07:45:04,123 WARNING DAY error: failure'):
            self.assertRegex(text,control.ERROR_PATTERN)
        for text in ('2026-10-09 07:45:04,123 INFO Copied ERROR.md','2026-10-09 07:45:04,123 INFO errors=0','2026-10-09 07:45:04,123 INFO Copied error.js'):
            self.assertIsNone(re.search(control.ERROR_PATTERN,text))

    def test_listing_timeout_and_confirmed_batch_are_not_reported_as_lost_files(self):
        self.assertIn('списка файлов',control.explain_error("couldn't list files: timeout awaiting response headers"))
        self.assertIn('результат может быть неопределённым',control.explain_error('failed to upload file: timeout awaiting response headers'))
        for text in ('Operation failed; 0 unconfirmed files retained for retry: rclone exit code 5',
                     'Operation failed after all batch files were individually confirmed; no file re-upload scheduled: rclone exit code 5'):
            self.assertIn('Повторная загрузка этих файлов не требуется',control.explain_error(text))

    def test_nonzero_batch_counts_never_claim_all_files_confirmed(self):
        for count in (1,10,100,510,1000):
            text=control.explain_error('ERROR Operation failed; '+str(count)+' unconfirmed files retained for retry: Cloud alert observer unavailable; uploads paused')
            self.assertIn(str(count)+' файлов пока не получили подтверждения',text)
            self.assertNotIn('Повторная загрузка этих файлов не требуется',text)
            self.assertIn('чтение предупреждений Drime',text)
        self.assertIn('уже учтённой',control.explain_error('ERROR Cycle paused after error; durable budget 3/5'))

    def test_resolved_file_requires_later_success_and_no_pending_or_error(self):
        path=b'home/user/file.txt';stamp=control.iso_microseconds('2026-10-09T00:00:00+00:00')
        message='ERROR Copy failed path_b64='+base64.b64encode(path).decode()+': rclone exit code 5'
        with sqlite3.connect(control.ROOT/'journal.sqlite3') as db:
            db.execute('CREATE TABLE entries(path BLOB,kind TEXT,present INTEGER,sig TEXT,uploaded TEXT,uploaded_at TEXT,last_error TEXT)')
            db.execute('INSERT INTO entries VALUES (?,?,?,?,?,?,?)',(path,'file',1,'new','new','2026-10-09T00:01:00+00:00',None));db.commit()
            reader=control.ErrorResolutions()
            try:
                result=reader.lookup(stamp,message)
                self.assertTrue(result['resolved']);self.assertIn('03:01:00',result['detail'])
                for assignments,values in [
                    ('uploaded_at=?',('2026-10-08T23:59:00+00:00',)),
                    ('uploaded_at=?,uploaded=?',('2026-10-09T00:01:00+00:00','old')),
                    ('uploaded=?,last_error=?',('new','new timeout')),
                    ('last_error=NULL,present=?',(0,)),
                ]:
                    db.execute('UPDATE entries SET '+assignments,values);db.commit()
                    self.assertFalse(reader.lookup(stamp,message)['resolved'])
            finally:reader.close()

    def test_review_closes_only_exact_incident_and_must_be_later(self):
        stamp=control.iso_microseconds('2026-10-09T00:00:00+00:00');message='ERROR Folder with same name already exists.'
        key=control.error_identity(stamp,message)
        def review(at):
            (control.ROOT/'error-resolutions.json').write_text(json.dumps({key:{'at':at,'reason':'Exact folder-conflict fix installed and tested'}}))
        review('2026-10-09T01:00:00+00:00')
        reader=control.ErrorResolutions()
        try:
            self.assertTrue(reader.lookup(stamp,message)['resolved'])
            self.assertFalse(reader.lookup(stamp+1_000_000,message)['resolved'])
            self.assertFalse(reader.lookup(stamp,message+' New failure')['resolved'])
        finally:reader.close()
        review('2026-10-08T23:59:00+00:00');reader=control.ErrorResolutions()
        try:self.assertFalse(reader.lookup(stamp,message)['resolved'])
        finally:reader.close()

    def test_unknown_or_missing_evidence_stays_open(self):
        reader=control.ErrorResolutions()
        try:
            self.assertFalse(reader.lookup(1,'ERROR mystery')['resolved'])
            self.assertFalse(reader.lookup(1,'WARNING rclone error home/file: Failed to copy: i/o timeout')['resolved'])
            self.assertFalse((control.ROOT/'journal.sqlite3').exists())
        finally:reader.close()

    def test_file_identification_is_exact_and_rejects_ambiguous_paths(self):
        path='home/user/файл.txt'.encode()
        self.assertEqual(control.error_file('ERROR path_b64='+base64.b64encode(path).decode()+': failure'),path)
        self.assertEqual(control.error_file('WARNING rclone error home/user/file.txt: Failed to copy: timeout'),b'home/user/file.txt')
        self.assertEqual(control.error_file('WARNING DAY error: rclone_error: home/file: Failed to copy: timeout'),b'home/file')
        for message in ('WARNING rclone error : Attempt 1/1 failed with 1 errors',
                        'WARNING rclone error home/a: b: Failed to copy: timeout','ERROR path_b64=Li4vZXRjL3Bhc3N3ZA==: failure'):
            self.assertIsNone(control.error_file(message))

if __name__=='__main__':unittest.main(verbosity=2)
