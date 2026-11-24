import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

class PackagingTests(unittest.TestCase):
    def test_requires_real_report_video_and_identity(self):
        from scripts.package_submission import package
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=root/'report.pdf';video=root/'play.mp4'
            report.write_bytes(b'%PDF-1.4\nreport');video.write_bytes(b'\x00\x00\x00\x18ftypmp42'+bytes(20))
            with self.assertRaises(ValueError):package('../bad','20260001','https://github.com/student/software_and_system_security_lab',report,video,root)
            with self.assertRaises(ValueError):package('张三','20260001','TODO',report,video,root)
            with self.assertRaises(FileNotFoundError):package('张三','20260001','https://github.com/student/software_and_system_security_lab',report,root/'missing.mp4',root)
    def test_zip_has_exact_course_layout_and_sources(self):
        from scripts.package_submission import package
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=root/'report.pdf';video=root/'play.mp4';report.write_bytes(b'%PDF-1.4\nreport');video.write_bytes(b'\x00\x00\x00\x18ftypmp42'+bytes(20))
            result=package('测试同学','20260001','https://github.com/student/software_and_system_security_lab',report,video,root)
            with zipfile.ZipFile(result) as z:
                names=z.namelist();base='测试同学_20260001_EX1A/'
                self.assertIn(base+'测试同学_20260001_ex1A_play.mp4',names)
                self.assertIn(base+'测试同学_20260001_ex1A_report.pdf',names)
                self.assertIn(base+'测试同学_20260001_ex1A_src/sniffer/pcap.py',names)
                self.assertIn(base+'测试同学_20260001_ex1A_src/README.md',names)
                self.assertFalse(any(Path(n).name in ('.gitignore','.gitattributes','submission-metadata.json') for n in names))
                self.assertFalse(any('/.git/' in n or '/output/' in n or '/runtime/' in n or '/__pycache__/' in n for n in names))
                self.assertNotIn(base+'测试同学_20260001_ex1A_src/实验 1 讲解 2026.pdf',names)
                self.assertFalse(any('/docs/' in n for n in names))
                self.assertFalse(any(n.endswith('git-history.txt') for n in names))
