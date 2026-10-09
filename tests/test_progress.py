#!/usr/bin/env python3
import copy
import datetime as dt
import unittest
import progress


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.now=dt.datetime(2026,10,9,7,tzinfo=dt.timezone.utc).timestamp()
        self.state=dict(updated_at=dt.datetime.fromtimestamp(self.now,dt.timezone.utc).isoformat(),
            phase='copying',current_files=100,current_bytes=1000,pending_files=1000,pending_directories=500,source_bytes=100000)
        self.run={'pid':12,'started_at':'2026-10-09T06:30:00+00:00'}
        self.first=progress.sample(self.state,{},self.run,self.now)
        self.last=dict(self.first,at=self.now+120,current_files=220,current_bytes=13000,pending_files=880,pending_directories=440)

    def forecast(self,last=None,**kwargs):
        return progress.estimate({'samples':[self.first]},last or self.last,
            kwargs.get('running',True),kwargs.get('blocked',False),self.now+120,kwargs.get('scan_errors',0))

    def test_estimate_uses_slower_of_object_and_byte_forecasts(self):
        result=self.forecast()
        # 180 file/directory acknowledgements / 120 s: 1320 / 1.5 = 880 s.
        # Bytes: 87000 / 100 = 870 s. Conservative rounded duration: 900 s.
        self.assertEqual(result['remaining_seconds'],900)
        self.assertEqual(result['objects_per_minute'],90)
        self.assertEqual(result['bytes_per_second'],100)
        self.assertEqual(result['finish_msk'],'2026.10.09 — 10:17 МСК')
        slower=dict(self.last,source_bytes=200000)
        self.assertEqual(self.forecast(slower)['remaining_seconds'],2100)

    def test_stopped_and_blocked_never_show_a_live_finish_time(self):
        for args in ({'running':False},{'blocked':True}):
            result=self.forecast(**args);self.assertEqual(result['state'],'paused');self.assertIsNone(result['finish_msk'])

    def test_insufficient_window_and_zero_progress_have_no_date(self):
        self.assertEqual(self.forecast(dict(self.last,at=self.now+60))['state'],'collecting')
        self.assertEqual(self.forecast(dict(self.first,at=self.now+120))['state'],'no_progress')
        self.assertEqual(self.forecast(dict(self.last,current_bytes=1000))['method'],'objects_only')

    def test_tiny_file_sample_is_not_extrapolated_into_years_of_bulk_data(self):
        result=self.forecast(dict(self.last,source_bytes=600000000000))
        self.assertEqual(result['method'],'objects_only')
        self.assertEqual(result['remaining_seconds'],900)
        self.assertIn('общий срок требует замеров',result['detail'])

    def test_directory_only_queue_can_be_estimated(self):
        result=self.forecast(dict(self.last,pending_files=0,source_bytes=13000))
        self.assertEqual(result['state'],'estimated')

    def test_empty_queue_is_not_full_backup_verification(self):
        end=dict(self.last,pending_files=0,pending_directories=0)
        self.assertEqual(self.forecast(end)['state'],'empty')
        self.assertEqual(self.forecast(end,scan_errors=2)['state'],'scan_errors')

    def test_stale_future_and_stopped_samples_are_rejected(self):
        self.assertIsNone(progress.sample(self.state,{},self.run,self.now+181))
        self.assertIsNone(progress.sample(self.state,{},self.run,self.now-1))
        self.assertIsNone(progress.sample(dict(self.state,phase='stopped'),{},self.run,self.now))
        self.assertIsNone(progress.sample(self.state,{},dict(self.run,pid=0),self.now))

    def test_restart_day_night_and_reduced_rate_start_new_window(self):
        history={'samples':[self.first]}
        for run,guard,stamp in [(dict(self.run,pid=13),{},self.now),
                                (self.run,{'count':1},self.now),
                                (self.run,{},self.now+9*3600)]:
            state=dict(self.state,updated_at=dt.datetime.fromtimestamp(stamp,dt.timezone.utc).isoformat())
            current=progress.sample(state,guard,run,stamp)
            self.assertNotEqual(current['condition'],self.first['condition'])
            self.assertEqual(len(progress.record(history,current)['samples']),1)

    def test_sampling_is_bounded_and_does_not_duplicate_a_status(self):
        history={}
        for i in range(250):history=progress.record(history,dict(self.first,at=self.now+i*30))
        rows=history['samples'];self.assertLessEqual(len(rows),61)
        self.assertEqual(progress.record(history,rows[-1]),history)
        self.assertEqual(progress.record(history,None)['samples'],[])

    def test_counter_regression_and_unusable_history_do_not_invent_progress(self):
        self.assertEqual(self.forecast(dict(self.last,current_files=50,current_bytes=50,pending_directories=600))['state'],'no_progress')
        self.assertEqual(progress.estimate({'samples':[{}]},self.last,True,False,self.now+120)['state'],'collecting')
        malformed=copy.deepcopy(self.first);malformed['current_bytes']='bad'
        result=progress.estimate({'samples':[malformed]},self.last,True,False,self.now+120)
        self.assertEqual(result['state'],'collecting')


if __name__=='__main__':unittest.main(verbosity=2)
