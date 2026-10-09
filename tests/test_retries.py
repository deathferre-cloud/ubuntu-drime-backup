#!/usr/bin/env python3
"""Queue regressions and real rclone HTTP fault injection; no cloud writes."""
import datetime as dt
import http.server
import json
import pathlib
import os
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from daemon import Backup
from safety import SafetyGuard, RecordedError


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ubuntu-drime-retry-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.src=self.root/'source';self.src.mkdir()
        self.cfg=dict(source=str(self.src),state_dir=str(self.root/'state'),
            destination=str(self.root/'dest'),history=str(self.root/'history'),metadata=str(self.root/'metadata'),
            rclone=os.environ.get('DRIME_RCLONE','rclone'),rclone_config='/dev/null',
            transfers=4,tpslimit=8,bwlimit='off',scan_interval=300,settle_seconds=0,
            batch_files=512,batch_bytes=536870912,safety_error_limit=5)
        self.b=Backup(self.cfg)
        self.addCleanup(self.b.lock.close);self.addCleanup(self.b.db.close)
        self.b.last_manifest_day=dt.datetime.now(dt.timezone.utc).date().isoformat()

    def mark_failed(self,path,delay=0):
        self.b.db.execute('UPDATE entries SET last_error=?,failures=1,retry_at=? WHERE path=?',
            ('timeout awaiting response headers',time.time()+delay,path))
        self.b.db.commit()

    def test_failed_link_precedes_regular_file_batches(self):
        (self.src/'a.txt').write_text('first');(self.src/'z-link').symlink_to('a.txt')
        self.b.scan();self.mark_failed(b'z-link');sent=[]
        self.b.transfer=lambda rows:sent.extend(rows)
        self.b.cycle()
        self.assertEqual([r['path'] for r in sent],[b'z-link'])

    def test_retry_respects_backoff_settle_presence_and_acknowledgement(self):
        for name in ('future','settling','absent','ack','due'):(self.src/name).write_text(name)
        self.b.scan()
        for name in ('future','settling','absent','ack','due'):self.mark_failed(name.encode())
        self.b.db.execute('UPDATE entries SET retry_at=? WHERE path=?',(time.time()+3600,b'future'))
        self.b.db.execute('UPDATE entries SET mtime_ns=? WHERE path=?',(time.time_ns()+int(1e12),b'settling'))
        self.b.db.execute('UPDATE entries SET present=0 WHERE path=?',(b'absent',))
        self.b.db.execute('UPDATE entries SET uploaded=sig WHERE path=?',(b'ack',));self.b.db.commit()
        self.assertEqual([r['path'] for r in self.b.due_retries()],[b'due'])

    def test_failed_files_not_starved_by_alphabetical_limit(self):
        (self.src/'aaa').write_text('first');(self.src/'zzz').write_text('failed')
        self.b.scan();self.mark_failed(b'zzz');self.cfg['batch_files']=1
        self.assertEqual(self.b.pending()[0]['path'],b'zzz')

    def test_retry_batch_is_bounded_and_source_change_is_not_acknowledged(self):
        for i in range(18):(self.src/str(i)).write_text('old')
        self.b.scan()
        for i in range(18):self.mark_failed(str(i).encode())
        rows=self.b.due_retries();self.assertEqual(len(rows),16)
        (self.src/rows[0]['path'].decode()).write_text('new bytes')
        self.b.rc=lambda *a,**k:None
        self.b.transfer([rows[0]])
        row=self.b.db.execute('SELECT uploaded,sig FROM entries WHERE path=?',(rows[0]['path'],)).fetchone()
        self.assertNotEqual(row['uploaded'],row['sig'])

    def test_failed_retry_keeps_specific_cause_and_backoff(self):
        (self.src/'failed').write_text('x');self.b.scan()
        def failure(*a,**k):
            k['on_event']({'level':'error','object':'failed','msg':'specific timeout awaiting response headers'})
            raise RecordedError('rclone exit code 5')
        self.b.rc=failure;self.b.transfer(self.b.pending())
        row=self.b.db.execute('SELECT * FROM entries WHERE path=?',(b'failed',)).fetchone()
        self.assertIn('specific timeout',row['last_error']);self.assertGreater(row['retry_at'],time.time())
        self.assertEqual(self.b.due_retries(),[])

    def test_failed_command_keeps_successful_checkpoint_without_reupload(self):
        (self.src/'ok').write_text('OK');self.b.scan()
        def failure(*a,**k):
            k['on_event']({'level':'info','object':'ok','objectType':'*local.Object','msg':'Copied (new)','size':2})
            raise RecordedError('rclone exit code 5')
        self.b.rc=failure
        with self.assertLogs('ubuntu-drime-backup',level='ERROR') as logs:self.b.transfer(self.b.pending())
        self.assertIn('all batch files were individually confirmed',logs.output[0])
        self.assertEqual(self.b.pending(),[]);self.assertEqual(self.b.due_retries(),[])

    def test_transport_limits_and_day_night_safety_unchanged(self):
        cmd=self.b.command('copy');self.assertEqual(cmd[cmd.index('--timeout')+1],'120s')
        self.assertEqual(cmd[cmd.index('--contimeout')+1],'20s')
        self.assertEqual(cmd[cmd.index('--low-level-retries')+1],'3')
        with patch.object(SafetyGuard,'daytime',return_value=True):
            self.b.guard.record('test','failed request')
            self.assertEqual(self.b.guard.data['count'],1)
        with patch.object(SafetyGuard,'daytime',return_value=False):
            for _ in range(6):self.b.guard.record('test','night request')
            self.assertFalse(self.b.guard.latch.exists());self.assertEqual(self.b.guard.data['count'],1)


class TransportTests(unittest.TestCase):
    def test_real_client_accepts_31_second_response_after_timeout_change(self):
        counts={};lock=threading.Lock()
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_HEAD(self):
                self.send_response(200);self.send_header('Content-Length','2')
                self.send_header('Content-Type','text/plain');self.end_headers()
            def do_GET(self):
                with lock:
                    counts[self.path]=counts.get(self.path,0)+1;n=counts[self.path]
                if self.path.startswith('/slow'):time.sleep(31)
                self.send_response(200);self.send_header('Content-Length','2');self.end_headers()
                try:self.wfile.write(b'OK')
                except (BrokenPipeError,ConnectionResetError):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            base=[os.environ.get('DRIME_RCLONE','rclone'),'cat','--config','/dev/null',
                '--http-url','http://127.0.0.1:'+str(server.server_port),
                '--disable-http2','--disable-http-keep-alives','--bind','0.0.0.0',
                '--contimeout','20s','--retries','1']
            old=subprocess.Popen(base+[':http:slow-old.txt','--timeout','30s','--low-level-retries','1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            new=subprocess.Popen(base+[':http:slow-new.txt','--timeout','120s','--low-level-retries','3'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                old_out,old_err=old.communicate(timeout=40);new_out,new_err=new.communicate(timeout=40)
            finally:
                for p in (old,new):
                    if p.poll() is None:p.kill();p.wait()
            self.assertNotEqual(old.returncode,0,old_err.decode());self.assertIn(b'timeout',old_err)
            self.assertEqual(new.returncode,0,new_err.decode());self.assertEqual(new_out,b'OK')
        finally:server.shutdown();server.server_close()

    def test_real_drime_listing_retries_are_bounded_and_auth_errors_are_not_retried(self):
        # A loopback-only CONNECT fixture terminates its own test TLS session.
        # Fake token/config and a dedicated CA; no request can reach the Internet.
        with tempfile.TemporaryDirectory(prefix='ubuntu-drime-http-fixture-') as tmp:
            root=pathlib.Path(tmp);cert=root/'cert.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=app.drime.cloud',
                '-addext','subjectAltName=DNS:app.drime.cloud'],check=True,capture_output=True)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            config=root/'rclone.conf';config.write_text('[fixture]\ntype = drime\naccess_token = FAKE-TEST-TOKEN\nworkspace_id = 12345\n')
            state={'mode':'recover','calls':0};lock=threading.Lock()
            class Proxy(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def finish(self):
                    try:super().finish()
                    finally:self.connection.close()
                def do_CONNECT(self):
                    if self.path!='app.drime.cloud:443':self.send_error(502);return
                    self.send_response(200);self.end_headers();self.wfile.flush()
                    self.rfile.close();self.wfile.close()
                    self.connection=context.wrap_socket(self.connection,server_side=True)
                    self.rfile=self.connection.makefile('rb');self.wfile=self.connection.makefile('wb')
                    self.close_connection=True;self.handle_one_request()
                def do_GET(self):
                    if not self.path.startswith('/api/v1/drive/file-entries?') or self.headers.get('Authorization')!='Bearer FAKE-TEST-TOKEN':
                        self.send_error(400);return
                    with lock:state['calls']+=1;n=state['calls'];mode=state['mode']
                    code=401 if mode=='auth' else 503 if mode=='exhaust' or mode=='recover' and n<3 else 200
                    if mode=='timeout' and n==1:time.sleep(.4)
                    body=json.dumps({'data':[],'current_page':1,'last_page':1} if code==200 else {'message':'injected test failure'}).encode()
                    try:
                        self.send_response(code);self.send_header('Content-Type','application/json')
                        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);self.wfile.flush()
                    except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            try:
                for mode,expected_calls,success in [('recover',3,True),('exhaust',3,False),('auth',1,False),('timeout',2,True)]:
                    with self.subTest(mode=mode):
                        state.update(mode=mode,calls=0)
                        command=[os.environ.get('DRIME_RCLONE','rclone'),'lsjson','fixture:',
                            '--config',str(config),'--http-proxy','http://127.0.0.1:'+str(server.server_port),
                            '--ca-cert',str(cert),'--timeout','.2s' if mode=='timeout' else '120s',
                            '--contimeout','20s','--low-level-retries','3','--retries','1',
                            '--disable-http2','--disable-http-keep-alives']
                        result=subprocess.run(command,capture_output=True,timeout=30)
                        self.assertEqual(result.returncode==0,success,result.stderr.decode())
                        self.assertEqual(state['calls'],expected_calls,result.stderr.decode())
                        if success:self.assertEqual(json.loads(result.stdout),[])
            finally:server.shutdown();server.server_close()


if __name__=='__main__':unittest.main()
