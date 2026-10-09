#!/usr/bin/env python3
"""Observer fault injection; fake credentials and child processes, no cloud access."""
import json,os,pathlib,signal,subprocess,tempfile,time,unittest,http.server,threading
from unittest.mock import patch
from safety import SafetyGuard,SafetyStop,RecordedError
from daemon import Backup

class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='observer-tests-');self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);(self.root/'source').mkdir()
        self.cfg=dict(source=str(self.root/'source'),state_dir=str(self.root/'state'),destination='drime:',
            history='drime:.history',metadata='drime:.metadata',rclone='/bin/true',rclone_config=str(self.root/'rclone.conf'),
            transfers=4,tpslimit=8,bwlimit='off',safety_error_limit=5,scan_interval=300,settle_seconds=0,batch_files=512,batch_bytes=536870912,
            cloud_guard_workspace=12345,cloud_guard_retry_delay=0)
        (self.root/'rclone.conf').write_text('[drime]\ntype=drime\nworkspace_id=12345\naccess_token=FAKE-TEST-TOKEN\n')
        self.day=patch.object(SafetyGuard,'daytime',return_value=True);self.day.start();self.addCleanup(self.day.stop)
    def result(self,status='200',code=0,payload=None):
        body=json.dumps(payload if payload is not None else {'pagination':{'data':[]}})
        return subprocess.CompletedProcess([],code,body+'\nSTATUS:'+status+'\nTIMING:0.01,0.02,0.04,0.2,0.21','')
    def guard(self):
        g=SafetyGuard(self.cfg);g.next_policy_check=time.monotonic()+3600;return g
    def test_timeout_recovers_without_consuming_budget_and_keeps_token_off_argv(self):
        g=self.guard();events=[];g.on_api_retry=lambda:events.append('pause')
        with patch('safety.subprocess.run',side_effect=[self.result('000',28),self.result()]) as run:
            g.poll(force=True)
        self.assertEqual(g.data['count'],0);self.assertEqual(events,['pause'])
        for call,limit in zip(run.call_args_list,(20,45)):
            cmd=call.args[0];self.assertEqual(float(cmd[cmd.index('--max-time')+1]),limit)
            self.assertEqual(call.kwargs['timeout'],limit+5);self.assertNotIn('FAKE-TEST-TOKEN',' '.join(cmd))
    def test_curl_timeout_arguments_are_locale_independent_integers(self):
        self.cfg.update(cloud_guard_connect_timeout=4.2,cloud_guard_timeout=6.1)
        g=self.guard()
        with patch('safety.subprocess.run',return_value=self.result()) as run:g.api('activity')
        command=run.call_args.args[0]
        self.assertEqual(command[command.index('--connect-timeout')+1],'5')
        self.assertEqual(command[command.index('--max-time')+1],'7')
    def test_real_curl_round_trip_parses_response_and_uses_private_stdin_header(self):
        requests=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.headers.get('Authorization'))
                body=b'{"pagination":{"data":[]}}'
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        original=subprocess.run
        def local(command,**kwargs):
            self.assertTrue(command[-1].startswith('https://app.drime.cloud/api/v1/workspace/12345/'))
            command=list(command);command[-1]='http://127.0.0.1:'+str(server.server_port)+'/activity'
            return original(command,**kwargs)
        try:
            with patch('safety.subprocess.run',side_effect=local):self.assertEqual(self.guard().api('activity'),{'pagination':{'data':[]}})
            self.assertEqual(requests,['Bearer FAKE-TEST-TOKEN'])
        finally:server.shutdown();server.server_close();worker.join(timeout=2)
    def test_three_exhausted_attempts_count_once_and_keep_day_stop(self):
        g=self.guard();events=[];g.on_api_retry=lambda:events.append(1)
        with patch('safety.subprocess.run',return_value=self.result('000',28)) as run:
            with self.assertRaises(RecordedError):g.poll(force=True)
        self.assertEqual(run.call_count,3);self.assertEqual(len(events),2);self.assertEqual(g.data['count'],1)
        self.assertIn('attempt=3/3',g.data['events'][-1]['detail']);self.assertIn('dns_connect_tls',g.data['events'][-1]['detail'])
        with patch('safety.subprocess.run',return_value=self.result('000',28)):
            for _ in range(3):
                with self.assertRaises(RecordedError):g.poll(force=True)
            with self.assertRaises(SafetyStop):g.poll(force=True)
        self.assertTrue(g.latch.exists());self.assertEqual(g.data['count'],5)
    def test_auth_permissions_and_certificate_failures_are_not_retried(self):
        for status,code in [('401',0),('403',0),('404',0),('000',60)]:
            with self.subTest(status=status,code=code):
                g=self.guard()
                with patch('safety.subprocess.run',return_value=self.result(status,code)) as run:
                    with self.assertRaises(RuntimeError):g.api('activity')
                self.assertEqual(run.call_count,1)
    def test_temporary_http_failures_recover(self):
        for status in ('408','429','500','502','503','504'):
            with self.subTest(status=status):
                g=self.guard()
                with patch('safety.subprocess.run',side_effect=[self.result(status),self.result()]) as run:g.api('activity')
                self.assertEqual(run.call_count,2)
    def test_subprocess_timeout_is_bounded_and_retried(self):
        g=self.guard()
        with patch('safety.subprocess.run',side_effect=[subprocess.TimeoutExpired('curl',25),self.result()]) as run:g.api('activity')
        self.assertEqual(run.call_count,2)
    def test_invalid_json_does_not_silently_pass_or_retry(self):
        g=self.guard();result=subprocess.CompletedProcess([],0,'not-json\nSTATUS:200\nTIMING:0,0,0,0,0','')
        with patch('safety.subprocess.run',return_value=result) as run:
            with self.assertRaises(RecordedError):g.poll(force=True)
        self.assertEqual(run.call_count,1);self.assertEqual(g.data['count'],1)
    def test_next_poll_is_measured_after_slow_request_completion(self):
        g=self.guard();clock=[100.];calls=[];g.next_policy_check=1000
        def api(path):calls.append(path);clock[0]+=8;return {'pagination':{'data':[]}}
        g.api=api
        with patch('safety.time.monotonic',side_effect=lambda:clock[0]):
            g.poll();self.assertEqual(g.next_poll,113)
            clock[0]=110;g.poll();self.assertEqual(len(calls),1)
            clock[0]=114;g.poll();self.assertEqual(len(calls),2)
    def test_exhausted_requests_at_night_do_not_latch(self):
        g=self.guard()
        with patch.object(SafetyGuard,'daytime',return_value=False),patch('safety.subprocess.run',return_value=self.result('000',28)):
            for _ in range(8):g.poll(force=True)
        self.assertEqual(g.data['count'],0);self.assertEqual(g.data['night_errors'],8);self.assertFalse(g.latch.exists())
    def backup(self):
        b=Backup(self.cfg);self.addCleanup(b.lock.close);self.addCleanup(b.db.close);return b
    def script(self):
        path=self.root/'fake-rclone';heartbeat=self.root/'heartbeat';pid=self.root/'pid';done=self.root/'done'
        path.write_text('#!/usr/bin/python3\n'+
            'import json,os,pathlib,sys,time\n'+
            'pathlib.Path('+repr(str(pid))+').write_text(str(os.getpid()))\n'+
            'for i in range(25):\n'+
            ' with open('+repr(str(heartbeat))+',"ab") as f:f.write(b"x")\n'+
            ' print(json.dumps({"stats":{"bytes":i+1,"transfers":0,"checks":0}}),file=sys.stderr,flush=True)\n'+
            ' time.sleep(.03)\n'+
            'pathlib.Path('+repr(str(done))+').touch()\n')
        path.chmod(0o700);self.cfg['rclone']=str(path)
        return heartbeat,pid,done
    def test_day_process_is_paused_and_same_process_resumes_without_false_stall(self):
        heartbeat,pid,done=self.script();self.cfg['stall_timeout_seconds']=.8;b=self.backup();events=[]
        def poll(force=False):
            if force or events or not heartbeat.exists():return
            b.guard.on_api_retry();time.sleep(.05);before=heartbeat.stat().st_size
            events.append(int(pid.read_text()));time.sleep(1)
            self.assertEqual(heartbeat.stat().st_size,before)
        b.guard.poll=poll;b.rc('copy')
        self.assertTrue(done.exists());self.assertEqual(len(events),1);self.assertEqual(int(pid.read_text()),events[0])
        self.assertIsNone(b.guard.on_api_retry);self.assertEqual(b.guard.data['count'],0)
        self.assertNotEqual(b.phase,'waiting_cloud_observer')
    def test_failed_recovery_kills_paused_process_and_preserves_budget(self):
        heartbeat,pid,done=self.script();b=self.backup();paused=[]
        def poll(force=False):
            if force or not heartbeat.exists():return
            b.guard.on_api_retry();paused.append(int(pid.read_text()))
            b.guard.record('guard_api_error','injected exhausted request')
            raise RecordedError('Cloud alert observer unavailable; uploads paused')
        b.guard.poll=poll
        with self.assertRaises(RecordedError):b.rc('copy')
        self.assertTrue(paused);self.assertFalse(done.exists());self.assertEqual(b.guard.data['count'],1)
        self.assertFalse(pathlib.Path('/proc/'+str(paused[0])).exists());self.assertIsNone(b.guard.on_api_retry)
    def test_actual_alerts_during_recovery_still_latch_and_kill(self):
        heartbeat,pid,done=self.script();b=self.backup();b.guard.ingest_activity([{'id':1}])
        def poll(force=False):
            if force or not heartbeat.exists():return
            b.guard.on_api_retry()
            b.guard.ingest_activity([{'id':i,'action':'alert_security'} for i in range(2,7)])
        b.guard.poll=poll
        with self.assertRaises(SafetyStop):b.rc('copy')
        self.assertTrue(b.guard.latch.exists());self.assertFalse(done.exists());self.assertEqual(b.guard.data['count'],5)
    def test_night_retry_does_not_suspend_upload(self):
        heartbeat,pid,done=self.script();b=self.backup();events=[]
        def poll(force=False):
            if force or events or not heartbeat.exists():return
            before=heartbeat.stat().st_size;b.guard.on_api_retry();time.sleep(.15)
            self.assertGreater(heartbeat.stat().st_size,before);events.append(1)
        b.guard.poll=poll
        with patch.object(SafetyGuard,'daytime',return_value=False):b.rc('copy')
        self.assertTrue(done.exists());self.assertEqual(events,[1]);self.assertFalse(b.guard.latch.exists())

if __name__=='__main__':unittest.main(verbosity=2)
