import tempfile,unittest,zipfile
from pathlib import Path
from scripts.package_submission import package

class PackagingTests(unittest.TestCase):
    def test_exact_layout_and_no_runtime_or_private_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);report=root/'report.pdf';video=root/'video.mp4';report.write_bytes(b'%PDF-1.4\nfixture');video.write_bytes(b'\x00\x00\x00\x18ftypmp42'+bytes(20))
            path=package('测试同学','20260001','https://github.com/student/repo',report,video,root)
            with zipfile.ZipFile(path) as z:
                names=z.namelist();base='测试同学_20260001_EX1B/测试同学_20260001_ex1B'
                self.assertIn(base+'_report.pdf',names);self.assertIn(base+'_play.mp4',names);self.assertIn(base+'_src/harbor/server.py',names)
                self.assertFalse(any('/runtime/' in n or '/docs/' in n or n.endswith(('.key','.pem')) for n in names))
    def test_missing_video_and_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with self.assertRaises(ValueError):package('../bad','20260001','https://github.com/student/repo',root/'a',root/'b',root)
            with self.assertRaises(FileNotFoundError):package('测试同学','20260001','https://github.com/student/repo',root/'a.pdf',root/'b.mp4',root)
