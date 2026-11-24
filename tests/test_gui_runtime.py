import json,subprocess,sys,unittest
from pathlib import Path

class GuiRuntimeTests(unittest.TestCase):
    def test_runtime_probe_rejects_unsupported_tk_without_opening_window(self):
        root=Path(__file__).resolve().parents[1]
        probe=subprocess.run([sys.executable,'-c','import tkinter; print(tkinter.TkVersion)'],capture_output=True,text=True)
        actual=subprocess.run([sys.executable,str(root/'run_client.py'),'--check-runtime'],capture_output=True,text=True,timeout=10)
        if probe.returncode:
            self.assertNotEqual(actual.returncode,0);self.assertIn('Tkinter',actual.stderr)
        elif float(probe.stdout)<8.6:
            self.assertNotEqual(actual.returncode,0);self.assertIn('Tk 8.5',actual.stderr)
        else:
            self.assertEqual(actual.returncode,0,actual.stderr);self.assertIn('Tk:',actual.stdout)
