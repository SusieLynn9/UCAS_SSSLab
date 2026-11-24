import hashlib,json,os,socket,tempfile,threading,time,unittest
from pathlib import Path
from scripts.init_demo import initialize
from harbor.server import Server
from harbor.client import Client,ClientError
from harbor.limits import Bandwidth

def sha(b):return hashlib.sha256(b).hexdigest()

class TransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.paths=initialize(Path(cls.temp.name)/'runtime')
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.case=tempfile.TemporaryDirectory();self.work=Path(self.case.name)
        config=json.loads(Path(self.paths['server_config']).read_text());base=Path(self.paths['server_config']).parent
        for key in ('certfile','keyfile','cafile'):config[key]=str(base/config[key])
        config['root']=str(self.work/'state')
        for u in config['users']:u['rate_bps']=16*1024*1024
        path=self.work/'server.json';path.write_text(json.dumps(config));self.server=Server(path,port=0);self.server.start()
        self.clients=[]
    def tearDown(self):
        for c in self.clients:c.close()
        self.server.stop();self.case.cleanup()
    def client(self,name='alice',**changes):
        original=Path(self.paths[name+'_config']);cfg=json.loads(original.read_text())
        for key in ('certfile','keyfile','cafile'):cfg[key]=str(original.parent/cfg[key])
        cfg.update(port=self.server.port,**changes);path=self.work/(name+str(len(self.clients))+'.json');path.write_text(json.dumps(cfg))
        c=Client(path);self.clients.append(c);c.connect();return c
    def test_same_tls_connection_reused_for_multiple_requests(self):
        c=self.client();ident=c.info['connection_id'];self.assertEqual(c.list_files(),[]);self.assertEqual(c.ping()['connection_id'],ident)
        self.assertEqual(self.server.metrics()['accepted'],1)
    def test_roundtrip_hash_and_other_user_isolation(self):
        c=self.client();path=self.work/'原始文件.bin';data=os.urandom(190000);path.write_bytes(data)
        r=c.upload(path);self.assertEqual(r['status'],'complete');self.assertEqual(r['sha256'],sha(data))
        target=self.work/'out.bin';c.download(path.name,target);self.assertEqual(target.read_bytes(),data)
        self.assertEqual(self.client('bob').list_files(),[])
        with self.assertRaises(ClientError):self.clients[-1].download(path.name,self.work/'bad')
    def test_upload_and_download_resume(self):
        c=self.client();path=self.work/'large.bin';data=os.urandom(250000);path.write_bytes(data);pause=threading.Event()
        def first(done,total):
            if done>=65536:pause.set()
        result=c.upload(path,progress=first,pause_event=pause);self.assertEqual(result['status'],'paused');self.assertEqual(c.list_files(),[])
        c.close();c=self.client();result=c.upload(path);self.assertGreater(result['resumed_from'],0)
        target=self.work/'download.bin';pause.clear();r=c.download(path.name,target,progress=first,pause_event=pause);self.assertEqual(r['status'],'paused');self.assertFalse(target.exists())
        pause.clear();r=c.download(path.name,target,pause_event=pause);self.assertGreater(r['resumed_from'],0);self.assertEqual(target.read_bytes(),data)
    def test_parallel_upload_and_download(self):
        c=self.client();seed=self.work/'seed';seed.write_bytes(os.urandom(170000));c.upload(seed)
        a=self.client();b=self.client();other=self.work/'other';other.write_bytes(os.urandom(180000));errors=[]
        def run(fn):
            try:fn()
            except Exception as e:errors.append(e)
        threads=[threading.Thread(target=run,args=(lambda:a.upload(other),)),threading.Thread(target=run,args=(lambda:b.download('seed',self.work/'copy'),))]
        for t in threads:t.start()
        for t in threads:t.join(10)
        self.assertFalse(any(t.is_alive() for t in threads));self.assertEqual(errors,[]);self.assertEqual((self.work/'copy').read_bytes(),seed.read_bytes())
    def test_wrong_hostname_refused(self):
        with self.assertRaises(ClientError):self.client(server_hostname='wrong.example')
    def test_sql_like_filename_is_literal_and_paths_rejected(self):
        c=self.client();path=self.work/"x' OR 1=1 --.txt";path.write_bytes(b'literal');c.upload(path)
        self.assertEqual(c.list_files()[0]['name'],path.name)
        with self.assertRaises(ClientError):c.download('../server.json',self.work/'escape')
    def test_cancel_cleans_upload_reservation(self):
        c=self.client();p=self.work/'cancel';p.write_bytes(b'x'*150000);cancel=threading.Event()
        def progress(done,total):cancel.set()
        r=c.upload(p,progress=progress,cancel_event=cancel);self.assertEqual(r['status'],'cancelled')
        r=c.upload(p);self.assertEqual(r['resumed_from'],0)
    def test_local_download_symlink_is_rejected(self):
        c=self.client();p=self.work/'source';p.write_bytes(b'abc');c.upload(p);outside=self.work/'outside';outside.write_bytes(b'secret')
        os.symlink(outside,self.work/'target.part')
        with self.assertRaises(ClientError):c.download('source',self.work/'target')
        self.assertEqual(outside.read_bytes(),b'secret')

    def test_cancel_paused_upload_after_local_source_deleted(self):
        c=self.client();p=self.work/'removed';p.write_bytes(b'x'*150000);pause=threading.Event()
        def progress(done,total):
            if done:pause.set()
        result=c.upload(p,progress=progress,pause_event=pause);p.unlink()
        self.assertEqual(result['status'],'paused')
        c.cancel_upload(result['upload_ticket'])
        self.assertEqual(list((self.work/'state'/'alice'/'.partial').iterdir()),[])

    def test_cancel_download_without_server_or_remote_file(self):
        c=self.client();p=self.work/'remove-remote';p.write_bytes(b'x'*150000);c.upload(p);pause=threading.Event();target=self.work/'partial-target'
        def progress(done,total):
            if done:pause.set()
        c.download(p.name,target,progress=progress,pause_event=pause)
        c.close();self.server.stop()
        result=c.cancel_download(target)
        self.assertEqual(result['status'],'cancelled');self.assertFalse(Path(str(target)+'.part').exists());self.assertFalse(Path(str(target)+'.part.json').exists())

    def test_download_publication_rejects_replaced_partial_path(self):
        c=self.client();p=self.work/'verified';p.write_bytes(b'verified bytes');c.upload(p);target=self.work/'out';replaced=False
        def change_path(done,total):
            nonlocal replaced
            if done==total and not replaced:
                partial=Path(str(target)+'.part');partial.rename(self.work/'original-partial');partial.write_bytes(b'UNVERIFIED');replaced=True
        with self.assertRaises(ClientError):c.download(p.name,target,progress=change_path)
        self.assertFalse(target.exists())


    def test_gui_pool_uses_real_persistent_tls_workers(self):
        from harbor.gui import TransferPool
        c=self.client();cfg=c.config_path;c.close();baseline=self.server.metrics()['accepted'];pool=TransferPool(cfg,workers=2)
        def wait(predicate):
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if predicate():return
                time.sleep(.01)
            self.fail('GUI worker integration timed out')
        try:
            pool.start();one=self.work/'pool-one';two=self.work/'pool-two';one.write_bytes(os.urandom(100000));two.write_bytes(os.urandom(110000))
            a=pool.submit('upload',str(one),one.name);b=pool.submit('upload',str(two),two.name)
            wait(lambda:all(pool.snapshot(j)['state'] in ('complete','error') for j in (a,b)))
            self.assertEqual(pool.snapshot(a)['state'],'complete');self.assertEqual(pool.snapshot(b)['state'],'complete')
            d=pool.submit('download',one.name,str(self.work/'pool-copy'))
            wait(lambda:pool.snapshot(d)['state'] in ('complete','error'))
            self.assertEqual(pool.snapshot(d)['state'],'complete');self.assertEqual((self.work/'pool-copy').read_bytes(),one.read_bytes())
            self.assertEqual(self.server.metrics()['accepted'],baseline+3)
        finally:pool.close()

    def test_permission_denial_preserves_session_and_isolation(self):
        c=self.client();p=self.work/'denied';p.write_bytes(b'x')
        self.server.store.users['alice']['can_upload']=False
        with self.assertRaises(ClientError):c.upload(p)
        self.assertEqual(c.ping()['connection_id'],c.info['connection_id'])

    def test_unknown_certificate_fingerprint_refused(self):
        self.server.users.clear()
        with self.assertRaises(ClientError):self.client()

    def test_untrusted_client_certificate_refused(self):
        foreign=initialize(self.work/'foreign')
        cfg=json.loads(Path(foreign['alice_config']).read_text());base=Path(foreign['alice_config']).parent
        with self.assertRaises(ClientError):self.client(certfile=str(base/cfg['certfile']),keyfile=str(base/cfg['keyfile']))

    def test_handshake_admission_is_bounded_before_authentication(self):
        self.server.max_per_ip=2;sockets=[]
        try:
            for _ in range(5):sockets.append(socket.create_connection(('127.0.0.1',self.server.port),timeout=2))
            deadline=time.monotonic()+2
            while self.server.metrics().get('rejected',0)<3 and time.monotonic()<deadline:time.sleep(.01)
            self.assertLessEqual(self.server.metrics()['active'],2);self.assertGreaterEqual(self.server.metrics().get('rejected',0),3)
        finally:
            for sock in sockets:sock.close()


    def test_retry_after_completed_upload_does_not_overwrite(self):
        c=self.client();p=self.work/'retry';p.write_bytes(b'finished bytes');first=c.upload(p);second=c.upload(p)
        self.assertEqual(second['status'],'complete');self.assertEqual(second['resumed_from'],p.stat().st_size);self.assertEqual(first['sha256'],second['sha256'])


    def test_download_retry_after_initial_info_denied(self):
        c=self.client();p=self.work/'retry-info';p.write_bytes(b'hello');c.upload(p);target=self.work/'retry-target'
        self.server.store.users['alice']['can_download']=False
        with self.assertRaises(ClientError):c.download(p.name,target)
        self.server.store.users['alice']['can_download']=True
        result=c.download(p.name,target);self.assertEqual(result['status'],'complete');self.assertEqual(target.read_bytes(),p.read_bytes())

    def test_download_recovers_completed_local_publication(self):
        c=self.client();p=self.work/'recover-name';p.write_bytes(b'completed');c.upload(p);target=self.work/'recovered';part=Path(str(target)+'.part');manifest=Path(str(target)+'.part.json')
        part.write_bytes(p.read_bytes());manifest.write_text(json.dumps({'name':p.name,'size':p.stat().st_size,'sha256':sha(p.read_bytes())}));os.link(part,target)
        result=c.download(p.name,target);self.assertEqual(result['status'],'complete');self.assertFalse(part.exists());self.assertFalse(manifest.exists());self.assertEqual(target.stat().st_nlink,1)


    def test_low_rate_client_uses_small_blocks(self):
        self.server.store.users['alice']['rate_bps']=1024;self.server.budgets['alice']=Bandwidth(1024)
        c=self.client();self.assertEqual(c.info['chunk_size'],256)
        p=self.work/'small-rate';p.write_bytes(b'x'*2048);steps=[]
        c.upload(p,progress=lambda done,total:steps.append(done))
        self.assertLessEqual(max(b-a for a,b in zip(steps,steps[1:])),256)


class LimitTests(unittest.TestCase):
    def test_user_bandwidth_is_shared_across_threads(self):
        bucket=Bandwidth(65536);bucket.consume(65536);start=time.monotonic()
        ts=[threading.Thread(target=bucket.consume,args=(32768,)) for _ in range(2)]
        for t in ts:t.start()
        for t in ts:t.join()
        self.assertGreaterEqual(time.monotonic()-start,.80)
