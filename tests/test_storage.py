import hashlib,os,tempfile,unittest
from pathlib import Path
from harbor.storage import Storage,StorageError

def sha(b):return hashlib.sha256(b).hexdigest()

class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'state'
        self.users=[dict(name='alice',quota_bytes=1024*1024,can_upload=True,can_download=True),dict(name='bob',quota_bytes=1024,can_upload=True,can_download=True)]
        self.s=Storage(self.root,self.users)
    def tearDown(self):self.s.close();self.temp.cleanup()
    def test_upload_resume_actual_offset_commit_and_user_isolation(self):
        data=b'hello world';a=self.s.begin('alice','hello.txt',len(data),sha(data),'one')
        self.s.write('alice',a['transfer_id'],0,data[:5],'one');self.s.release_owner('one')
        self.s.close();self.s=Storage(self.root,self.users)
        b=self.s.begin('alice','hello.txt',len(data),sha(data),'two')
        self.assertEqual(b['offset'],5);self.assertEqual(b['prefix_sha256'],sha(b'hello'))
        self.s.write('alice',b['transfer_id'],5,data[5:],'two');self.s.commit('alice',b['transfer_id'],'two')
        self.assertEqual([r['name'] for r in self.s.list_files('alice')],['hello.txt']);self.assertEqual(self.s.list_files('bob'),[])
        self.assertEqual((self.root/'alice'/'hello.txt').read_bytes(),data)
    def test_conflicting_writer_offset_and_final_hash_rejected(self):
        a=self.s.begin('alice','x',3,sha(b'abc'),'one');tid=a['transfer_id']
        with self.assertRaises(StorageError):self.s.begin('alice','x',3,sha(b'abc'),'two')
        with self.assertRaises(StorageError):self.s.write('alice',tid,1,b'a','one')
        self.s.write('alice',tid,0,b'xyz','one')
        with self.assertRaises(StorageError):self.s.commit('alice',tid,'one')
        self.assertFalse((self.root/'alice'/'x').exists())
    def test_quota_accounts_for_reservations(self):
        self.s.begin('bob','one',900,sha(b'a'*900),'one')
        with self.assertRaises(StorageError):self.s.begin('bob','two',900,sha(b'b'*900),'two')
    def test_paths_symlinks_and_cross_user_access_rejected(self):
        for name in ('../secret','/etc/passwd','a/b','a\\b','.partial','..','CON','x\x00'):
            with self.subTest(name=name):
                with self.assertRaises(StorageError):self.s.begin('alice',name,0,sha(b''),'one')
        outside=Path(self.temp.name)/'outside';outside.write_bytes(b'secret')
        os.symlink(outside,self.root/'alice'/'link')
        with self.assertRaises(StorageError):self.s.open_download('alice','link')
    def test_cancel_deletes_partial_and_releases_reservation(self):
        a=self.s.begin('bob','x',900,sha(b'a'*900),'one');self.s.cancel('bob',a['transfer_id'],'one',discard=True)
        b=self.s.begin('bob','y',900,sha(b'a'*900),'two');self.assertEqual(b['offset'],0)
    def test_download_handle_stays_bound_to_open_file(self):
        data=b'abc';a=self.s.begin('alice','x',3,sha(data),'one');self.s.write('alice',a['transfer_id'],0,data,'one');self.s.commit('alice',a['transfer_id'],'one')
        d=self.s.open_download('alice','x',offset=2)
        try:self.assertEqual(d.info['prefix_sha256'],sha(b'ab'));self.assertEqual(d.read(2,100),b'c')
        finally:d.close()
    def test_published_name_cannot_be_overwritten(self):
        a=self.s.begin('alice','x',0,sha(b''),'one');self.s.commit('alice',a['transfer_id'],'one')
        with self.assertRaises(StorageError):self.s.begin('alice','x',1,sha(b'x'),'two')

    def test_inactive_upload_can_be_cancelled_by_its_user(self):
        t=self.s.begin('alice','cancel-after-restart',20,sha(b'x'*20),'old')
        self.s.release_owner('old');self.s.cancel('alice',t['transfer_id'],'new',discard=True)
        self.assertFalse(list((self.root/'alice'/'.partial').iterdir()))

    def test_repeated_completed_upload_is_idempotent_only_for_same_content(self):
        data=b'finished';t=self.s.begin('alice','repeat',len(data),sha(data),'one');self.s.write('alice',t['transfer_id'],0,data,'one');self.s.commit('alice',t['transfer_id'],'one')
        again=self.s.begin('alice','repeat',len(data),sha(data),'retry')
        self.assertTrue(again['complete']);self.assertEqual(again['sha256'],sha(data))
        with self.assertRaises(StorageError):self.s.begin('alice','repeat',3,sha(b'new'),'retry')

    def test_restart_recovers_interrupted_publication(self):
        data=b'completed';t=self.s.begin('alice','published',len(data),sha(data),'one');self.s.write('alice',t['transfer_id'],0,data,'one')
        partial=self.root/'alice'/'.partial'/(t['transfer_id']+'.part');target=self.root/'alice'/'published';os.link(partial,target)
        self.s.close();self.s=Storage(self.root,self.users)
        self.assertEqual(self.s.list_files('alice')[0]['name'],'published');self.assertEqual(target.stat().st_nlink,1)
        self.assertEqual(list(partial.parent.iterdir()),[])
