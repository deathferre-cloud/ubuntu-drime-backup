#!/usr/bin/env python3
"""Durable incident correlation: never infer recovery from another batch."""
import datetime as dt
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import control
from daemon import Backup
from safety import RecordedError

class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.src=self.root/'source';self.src.mkdir()
        self.cfg=dict(source=str(self.src),state_dir=str(self.root/'state'),destination=str(self.root/'dest'),
            history=str(self.root/'history'),metadata=str(self.root/'metadata'),rclone='unused',rclone_config='/dev/null',
            transfers=4,tpslimit=8,bwlimit='off',scan_interval=300,settle_seconds=0,batch_files=512,batch_bytes=536870912)
        self.b=Backup(self.cfg);self.addCleanup(self.b.lock.close);self.addCleanup(self.b.db.close)
        p=patch.object(control,'ROOT',self.b.state);p.start();self.addCleanup(p.stop)
        self.stamp=control.iso_microseconds(dt.datetime.now(dt.timezone.utc).isoformat())

    def rows(self,*names):
        for name in names:(self.src/name).write_text('old')
        self.b.scan();return self.b.pending()

    def lookup(self,incident):
        reader=control.ErrorResolutions()
        try:return reader.lookup(self.stamp,'ERROR Operation failed [incident_id='+incident+']')
        finally:reader.close()

    def test_partial_retry_and_unrelated_batch_do_not_close_incident(self):
        rows=self.rows('a','b','unrelated');incident=self.b.begin_incident(rows[:2])
        self.b.finish_incident(incident,'injected move failure')
        self.b.checkpoint(rows[2]);self.b.checkpoint(rows[0]);self.b.db.commit()
        self.assertFalse(self.lookup(incident)['resolved'])
        self.assertIn('1.',self.lookup(incident)['detail'])
        self.b.checkpoint(rows[1]);self.b.db.commit()
        self.assertTrue(self.lookup(incident)['resolved'])

    def test_changed_source_is_not_confirmed_but_later_stable_version_is(self):
        rows=self.rows('hot');incident=self.b.begin_incident(rows);self.b.finish_incident(incident,'failure')
        (self.src/'hot').write_text('changed')
        self.assertFalse(self.b.checkpoint(rows[0]));self.b.db.commit()
        self.assertFalse(self.lookup(incident)['resolved'])
        self.b.scan();self.assertTrue(self.b.checkpoint(self.b.pending()[0]));self.b.db.commit()
        self.assertTrue(self.lookup(incident)['resolved'])
        (self.src/'hot').write_text('next normal change');self.b.scan()
        self.assertTrue(self.lookup(incident)['resolved'], 'historical recovery must not flicker when new data arrives')

    def test_missing_file_stays_open_and_wrong_kind_does_not_close(self):
        rows=self.rows('a');incident=self.b.begin_incident(rows);self.b.finish_incident(incident,'failure')
        (self.src/'a').unlink();self.assertFalse(self.b.checkpoint(rows[0]));self.b.scan()
        self.assertFalse(self.lookup(incident)['resolved'])
        (self.src/'a').symlink_to('elsewhere');self.b.scan();row=dict(self.b.db.execute('SELECT * FROM entries WHERE path=?',(b'a',)).fetchone())
        self.b.checkpoint(row);self.b.db.commit()
        self.assertFalse(self.lookup(incident)['resolved'])

    def test_restart_preserves_resolution_evidence(self):
        rows=self.rows('a');incident=self.b.begin_incident(rows);self.b.finish_incident(incident,'failure')
        self.b.db.close();self.b.lock.close();self.b=Backup(self.cfg)
        self.addCleanup(self.b.lock.close);self.addCleanup(self.b.db.close)
        self.assertFalse(self.lookup(incident)['resolved'])
        self.b.checkpoint(rows[0]);self.b.db.commit();self.assertTrue(self.lookup(incident)['resolved'])

    def test_no_evidence_and_empty_incident_stay_open(self):
        self.assertFalse(self.lookup('a'*32)['resolved'])
        incident=self.b.begin_incident([]);self.b.finish_incident(incident,'failure')
        self.assertFalse(self.lookup(incident)['resolved'])

    def test_successful_batch_does_not_accumulate_incident_rows(self):
        rows=self.rows('a');self.b.rc=lambda *a,**kw:None;self.b.transfer(rows)
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM transfer_incidents').fetchone()[0],0)
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM incident_files').fetchone()[0],0)

    def test_failed_transfer_correlates_summary_and_closes_on_checkpoint(self):
        rows=self.rows('a','b');ids=[]
        def failed(*args,**kw):
            ids.append(kw['incident_id'])
            self.b.checkpoint(rows[0]);self.b.db.commit()
            raise RecordedError('injected move failure')
        self.b.rc=failed
        with self.assertLogs('ubuntu-drime-backup',level='ERROR') as logged:self.b.transfer(rows)
        self.assertIn('[incident_id='+ids[0]+']',logged.output[-1])
        self.assertFalse(self.lookup(ids[0])['resolved'])
        self.b.checkpoint(rows[1]);self.b.db.commit()
        self.assertTrue(self.lookup(ids[0])['resolved'])

    def test_final_summary_journal_timestamp_can_follow_confirmation(self):
        rows=self.rows('a');incident=self.b.begin_incident(rows)
        self.b.checkpoint(rows[0]);self.b.finish_incident(incident,'summary after completed writes')
        self.stamp+=1_000_000
        self.assertTrue(self.lookup(incident)['resolved'])

    def test_stale_database_row_cannot_resolve_incident(self):
        rows=self.rows('a');incident=self.b.begin_incident(rows);self.b.finish_incident(incident,'failure')
        self.b.db.execute('UPDATE entries SET sig=?',('different signature',));self.b.db.commit()
        self.assertFalse(self.b.checkpoint(rows[0]));self.b.db.commit()
        self.assertFalse(self.lookup(incident)['resolved'])

    def test_confirmed_child_also_confirms_parent_directory_incident(self):
        (self.src/'parent').mkdir();rows=self.rows('parent/child')
        parent=dict(self.b.db.execute('SELECT * FROM entries WHERE path=?',(b'parent',)).fetchone())
        incident=self.b.begin_incident([parent]);self.b.finish_incident(incident,'directory failure')
        self.b.checkpoint(rows[0]);self.b.db.commit()
        self.assertTrue(self.lookup(incident)['resolved'])

    def test_move_error_path_and_explanation(self):
        for prefix in ('WARNING rclone error ', 'WARNING DAY error: rclone_error: '):
            self.assertEqual(control.error_file(prefix+"etc/service/metrics.gob: Couldn't move: failed to move item"),b'etc/service/metrics.gob')
        text=control.explain_error('failed to move item: Error "No valid entries to move"')
        self.assertIn('исходный ID',text);self.assertIn('без проверки нельзя',text)
        for text in ("WARNING rclone error a: b: Couldn't move: error", "WARNING rclone error : Couldn't move: error"):
            self.assertIsNone(control.error_file(text))

if __name__=='__main__':unittest.main(verbosity=2)
