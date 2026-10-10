#!/usr/bin/env python3
"""Only unresolved evidence-backed failures occupy the persistent safety budget."""
import datetime as dt
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import control
from daemon import Backup
from error_state import ErrorResolutions, event_key, refresh_error_state, iso_microseconds
from safety import SafetyGuard, SafetyStop, now

class ActiveErrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.src=self.root/'source';self.src.mkdir()
        cfg=dict(source=str(self.src),state_dir=str(self.root/'state'),destination=str(self.root/'dest'),history=str(self.root/'history'),
            metadata=str(self.root/'metadata'),rclone='/bin/true',rclone_config='/dev/null',transfers=4,tpslimit=8,bwlimit='off',
            scan_interval=300,settle_seconds=0,batch_files=512,batch_bytes=536870912,safety_error_limit=5)
        p=patch.object(SafetyGuard,'daytime',return_value=True);p.start();self.addCleanup(p.stop)
        self.b=Backup(cfg);self.g=self.b.guard;self.addCleanup(self.b.lock.close);self.addCleanup(self.b.db.close)
        p=patch.object(control,'ROOT',self.b.state);p.start();self.addCleanup(p.stop)

    def rows(self,*names):
        for name in names:(self.src/name).write_text('content')
        self.b.scan();return self.b.pending()

    def failure(self,rows,kind='rclone_error',event_id=None):
        incident=self.b.begin_incident(rows)
        self.g.record(kind,'size mismatch [incident_id='+incident+']',event_id)
        self.b.finish_incident(incident,'size mismatch')
        return incident

    def test_four_resolved_failures_free_budget_and_next_failure_is_one(self):
        rows=self.rows('growing.log');incidents=[self.failure(rows) for _ in range(4)]
        self.assertEqual(self.g.data['count'],4)
        self.b.checkpoint(rows[0]);self.b.db.commit();self.g.check()
        self.assertEqual(self.g.data['count'],0);self.assertEqual(self.g.data['day_total'],4)
        self.assertEqual(len([e for e in self.g.data['events'] if e.get('resolved_at')]),4)
        self.g.record('unrelated_failure','still needs inspection')
        self.assertEqual(self.g.data['count'],1);self.assertFalse(self.g.latch.exists())
        reloaded=SafetyGuard(self.b.c);reloaded.check();self.assertEqual(reloaded.data['count'],1)

    def test_partial_or_unrelated_success_does_not_clear_counter(self):
        rows=self.rows('a','b','other');self.failure(rows[:2])
        self.b.checkpoint(rows[2]);self.b.checkpoint(rows[0]);self.b.db.commit();self.g.check()
        self.assertEqual(self.g.data['count'],1)
        self.b.checkpoint(rows[1]);self.b.db.commit();self.g.check();self.assertEqual(self.g.data['count'],0)

    def test_five_unresolved_failures_latch_and_resolution_does_not_unlatch(self):
        rows=self.rows('pending')
        for _ in range(4):self.failure(rows)
        incident=self.b.begin_incident(rows)
        with self.assertRaises(SafetyStop):self.g.record('rclone_error','failed [incident_id='+incident+']')
        self.b.finish_incident(incident,'failure');self.assertEqual(self.g.data['count'],5)
        self.b.checkpoint(rows[0]);self.b.db.commit()
        with self.assertRaises(SafetyStop):self.g.check()
        self.assertEqual(self.g.data['count'],0);self.assertTrue(self.g.latch.exists())

    def test_manual_stop_is_preserved_when_all_failures_resolve(self):
        rows=self.rows('a');self.failure(rows);self.g.manual.write_text('{}')
        self.b.checkpoint(rows[0]);self.b.db.commit()
        with self.assertRaises(SafetyStop):self.g.check()
        self.assertEqual(self.g.data['count'],0);self.assertTrue(self.g.manual.exists())

    def test_night_resolution_is_separate_and_old_closed_events_stay_closed(self):
        rows=self.rows('a')
        with patch.object(SafetyGuard,'daytime',return_value=False):self.failure(rows)
        self.assertEqual(self.g.data['night_errors'],1);self.assertEqual(self.g.data['count'],0)
        self.b.checkpoint(rows[0]);self.b.db.commit();self.g.check()
        self.assertEqual(self.g.data['night_errors'],0);self.assertEqual(self.g.data['night_total'],1)
        (self.src/'a').write_text('new contents');self.b.scan();self.g.check()
        self.assertEqual(self.g.data['night_errors'],0)

    def test_cloud_alert_cannot_borrow_a_transfer_confirmation(self):
        rows=self.rows('a');incident=self.b.begin_incident(rows);self.b.finish_incident(incident,'failure')
        self.b.checkpoint(rows[0]);self.b.db.commit()
        self.g.record('cloud_alert','suspicious [incident_id='+incident+']',event_id='drime:42')
        self.g.check();self.assertEqual(self.g.data['count'],1)
        proof={'event:'+event_key('drime:42'):{'at':now(),'reason':'Reviewed this exact security alert'}}
        (self.b.state/'error-resolutions.json').write_text(json.dumps(proof));self.g.check()
        self.assertEqual(self.g.data['count'],0)
        reader=ErrorResolutions(self.b.state)
        try:
            forged='WARNING NIGHT error: cloud_alert: unrelated security event [error_id='+event_key('drime:42')+']'
            self.assertFalse(reader.lookup(iso_microseconds(now()),forged)['resolved'])
        finally:reader.close()

    def test_full_observer_recovery_clears_only_observer_errors(self):
        self.g.record('guard_api_error','observer unreachable');self.g.record('cloud_alert','security notice')
        self.g.c['cloud_guard_workspace']=1
        self.g.api=lambda path: {'policies':[dict(policy=p,enabled=True,notify_email=True,settings={'extensions':['exe']}) for p in self.g.policies]} if path=='alert-policies' else {'pagination':{'data':[]}}
        self.g.poll(force=True);self.assertEqual(self.g.data['count'],1)
        opened=[e for e in self.g.data['events'] if not e.get('resolved_at')];self.assertEqual(opened[0]['kind'],'cloud_alert')

    def test_successful_scan_clears_scan_errors_only(self):
        self.g.record('scan_error','file unreadable');self.g.record('unknown','needs review');self.b.scan()
        self.assertEqual(self.g.data['count'],1)

    def test_unresolved_night_events_are_never_truncated_at_one_hundred(self):
        with patch.object(SafetyGuard,'daytime',return_value=False):
            for i in range(105):self.g.record('unknown','night failure',str(i))
        self.assertEqual(self.g.data['night_errors'],105)
        self.assertEqual(len(self.g.data['events']),105)
        self.g.check();self.assertEqual(self.g.data['count'],0)

    def test_legacy_unrepresented_counts_remain_visible_and_manual_alias_is_verified(self):
        rows=self.rows('a');incident=self.b.begin_incident(rows);self.b.finish_incident(incident,'failure')
        old=dict(version=1,count=4,night_errors=1,status='armed',events=[dict(id='legacy-night',kind='night_operation_abort',detail='stall',at=now(),period='night')])
        ledger={'event:'+event_key('legacy-night'):{'incident_id':incident}}
        (self.b.state/'error-resolutions.json').write_text(json.dumps(ledger))
        migrated=refresh_error_state(old,self.b.state)
        self.assertEqual(migrated['count'],4);self.assertEqual(migrated['night_errors'],1)
        self.assertEqual(migrated['version'],2)
        self.b.checkpoint(rows[0]);self.b.db.commit();migrated=refresh_error_state(migrated,self.b.state)
        self.assertEqual(migrated['count'],4);self.assertEqual(migrated['night_errors'],0)
        self.assertEqual(refresh_error_state(migrated,self.b.state),migrated)

    def test_panel_counts_and_error_badge_use_same_proof_without_writing_state(self):
        rows=self.rows('a');self.failure(rows,event_id='same-event');self.b.checkpoint(rows[0]);self.b.db.commit()
        before=self.g.path.read_bytes()
        with patch.object(control,'systemctl',return_value=subprocess.CompletedProcess([],0,'ActiveState=active\n','')),patch.object(control,'recent_errors',return_value={}):
            s=control.status()
        self.assertEqual(s['day_errors'],0);self.assertEqual(s['pending_errors']['total'],0);self.assertEqual(s['resolved_day_errors'],1)
        self.assertEqual(before,self.g.path.read_bytes())
        reader=ErrorResolutions(self.b.state)
        try:self.assertTrue(reader.lookup(iso_microseconds(now()),'WARNING transport failure [error_id='+event_key('same-event')+'] [incident_id='+self.g.data['events'][0]['detail'].split('incident_id=')[1])['resolved'])
        finally:reader.close()

    def test_pending_errors_outside_recent_ten_are_visible(self):
        with patch.object(SafetyGuard,'daytime',return_value=False):
            for i in range(12):self.g.record('unknown','still pending '+str(i))
        with patch.object(control,'systemctl',return_value=subprocess.CompletedProcess([],0,'ActiveState=active\n','')),patch.object(control,'recent_errors',return_value={'entries':[]}):s=control.status()
        self.assertEqual(s['pending_errors']['total'],12);self.assertEqual(len(s['pending_errors']['entries']),12)

if __name__=='__main__':unittest.main(verbosity=2)
