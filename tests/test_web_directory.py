"""Exercise operator UI behavior through the existing Python CI entrypoint."""
from pathlib import Path
import shutil
import subprocess
import unittest


class OperatorDirectoryUITests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node is required for operator UI contract tests')
    def test_duplicate_names_and_canonical_selections(self):
        result = subprocess.run([shutil.which('node'), '--test',
            str(Path(__file__).with_name('web_directory.test.mjs'))],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
