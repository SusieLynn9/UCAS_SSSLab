import json,os,select,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from scripts.init_demo import initialize
from scripts.sandbox_profile import profile
from harbor.config import load
from harbor.client import Client

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('sandbox-exec'),'macOS sandbox-exec required')
class SandboxTests(unittest.TestCase):
    def test_launcher_uses_custom_config_for_sandbox_and_server(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=initialize(root/'custom runtime');config=Path(paths['server_config'])
            project=Path(__file__).resolve().parents[1]
            for options in (['--config',str(config)],['--config='+str(config)]):
                with self.subTest(options=options):
                    proc=subprocess.Popen([str(project/'launch_server.command'),*options,'--port','0'],cwd=project,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
                    client=None
                    try:
                        port=None
                        for _ in range(3):
                            self.assertTrue(select.select([proc.stdout],[],[],8)[0],'Launcher did not start')
                            line=proc.stdout.readline().decode()
                            if not line:self.fail('Launcher exited: '+proc.stderr.read().decode())
                            if 'listening at' in line:port=int(line.rsplit(':',1)[1]);break
                        self.assertIsNotNone(port)
                        cfg=load(paths['alice_config']);cfg['port']=port
                        clientconfig=root/'client.json';clientconfig.write_text(json.dumps(cfg));client=Client(clientconfig)
                        self.assertEqual(client.connect()['username'],'alice');self.assertIn('connection_id',client.ping())
                    finally:
                        if client:client.close()
                        if proc.poll() is None:proc.terminate()
                        proc.wait(timeout=8);proc.stdout.close();proc.stderr.close()

    def test_real_server_transfer_and_outside_access_denial(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=initialize(root/'runtime');config=Path(paths['server_config']);sb=root/'server.sb';sb.write_text(profile(config));outside=root/'outside.txt';outside.write_bytes(b'outside marker')
            code='''import json,sys
from pathlib import Path
from harbor.server import Server
s=Server(sys.argv[1],port=0);s.start();outside=Path(sys.argv[2]);result={"port":s.port}
for op in ("read","write"):
    try:
        outside.read_bytes() if op=="read" else outside.write_bytes(b"changed")
        result[op+"_denied"]=False
    except PermissionError:result[op+"_denied"]=True
print(json.dumps(result),flush=True)
try:sys.stdin.buffer.read(1)
finally:s.stop()
'''
            # The real interpreter bypasses the system xcrun shim, which writes a
            # compiler cache before Python starts and is unnecessary in this sandbox.
            actual=subprocess.check_output(['/usr/bin/python3','-c','import sys;print(sys.executable)'],text=True).strip()
            proc=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(sb),actual,'-B','-u','-c',code,str(config),str(outside)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=Path(__file__).resolve().parents[1])
            client=None
            try:
                self.assertTrue(select.select([proc.stdout],[],[],8)[0],'Sandbox server did not start')
                line=proc.stdout.readline()
                if not line:self.fail('Sandbox server exited: '+proc.stderr.read(4096).decode(errors='replace'))
                info=json.loads(line);self.assertTrue(info['read_denied']);self.assertTrue(info['write_denied'])
                cfg=load(paths['alice_config']);cfg['port']=info['port'];clientconfig=root/'client.json';clientconfig.write_text(json.dumps(cfg));client=Client(clientconfig)
                source=root/'probe.bin';source.write_bytes(os.urandom(100000));self.assertEqual(client.upload(source)['status'],'complete')
                target=root/'download.bin';self.assertEqual(client.download(source.name,target)['status'],'complete');self.assertEqual(target.read_bytes(),source.read_bytes());client.close();client=None
                proc.stdin.close();self.assertEqual(proc.wait(timeout=6),0)
            finally:
                if client:client.close()
                if not proc.stdin.closed:proc.stdin.close()
                if proc.poll() is None:proc.terminate();proc.wait(timeout=6)
                proc.stdout.close();proc.stderr.close()
