"""The batch must retain every independent failure and never hide a timeout."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('reliability', Path(__file__).resolve().parents[1] / 'reliability-suite.py')
suite = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(suite)


@unittest.skipUnless(os.name == 'posix', 'POSIX validation worker')
class BatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'input').write_text('original')
        subprocess.run(['git', 'add', 'input'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'], cwd=self.root, check=True)

    def case(self, name, code, **extra):
        return dict(id=name, command=[sys.executable, '-c', code], timeout_seconds=5,
                    requirements=['R03'], **extra)

    def run_cases(self, *cases):
        return suite.run_suite({'cases': list(cases)}, self.root, self.base / 'evidence')

    def test_continues_independent_failures_and_blocks_only_dependencies(self):
        result = self.run_cases(self.case('red', 'raise SystemExit(7)'),
                                self.case('dependent', 'raise SystemExit(99)', requires=['red']),
                                self.case('second-red', 'raise SystemExit(8)'),
                                self.case('green', 'print("actual execution")'))
        self.assertFalse(result['passed'])
        self.assertTrue(result['source_unchanged'])
        self.assertEqual([v['status'] for v in result['cases'].values()],
                         ['failed', 'blocked', 'failed', 'passed'])
        self.assertEqual(result['cases']['second-red']['exit_code'], 8)
        self.assertEqual((self.base / 'evidence/green/command.log').read_text(), 'actual execution\n')
        self.assertFalse((self.base / 'evidence/dependent').exists())

    def test_timeout_runs_cleanup_and_does_not_become_late_success(self):
        slow = self.case('slow', 'import time; time.sleep(10)')
        slow['timeout_seconds'] = 0.1
        slow['cleanup'] = [sys.executable, '-c', 'print("cleaned")']
        result = self.run_cases(slow, self.case('next', 'pass'))
        self.assertEqual(result['cases']['slow']['status'], 'timeout')
        self.assertEqual(result['cases']['slow']['cleanup']['status'], 'passed')
        self.assertEqual(result['cases']['next']['status'], 'passed')
        self.assertFalse(result['passed'])

    def test_cleanup_failure_and_changed_source_fail_even_after_zero_exit(self):
        case = self.case('mutator', 'from pathlib import Path; Path("input").write_text("changed")',
                         cleanup=[sys.executable, '-c', 'raise SystemExit(9)'])
        result = self.run_cases(case)
        self.assertFalse(result['passed'])
        self.assertFalse(result['source_unchanged'])
        self.assertEqual(result['cases']['mutator']['status'], 'cleanup_failed')
        self.assertEqual(result['cases']['mutator']['command_status'], 'passed')
        retained = json.loads((self.base / 'evidence/summary.json').read_text())
        self.assertEqual(retained, result)

    def test_interrupted_case_runs_cleanup_and_does_not_start_next_case(self):
        original = suite.subprocess.Popen.wait
        calls = 0
        def interrupted_once(child, *args, **kwargs):
            nonlocal calls
            if child.args[0] == sys.executable:
                calls += 1
                if calls == 1:
                    raise KeyboardInterrupt
            return original(child, *args, **kwargs)
        case = self.case('interrupted', 'import time; time.sleep(10)',
                         cleanup=[sys.executable, '-c', 'print("cleaned")'])
        with mock.patch.object(suite.subprocess.Popen, 'wait', interrupted_once):
            result = self.run_cases(case, self.case('not-started', 'pass'))
        self.assertFalse(result['passed'])
        self.assertEqual(result['cases']['interrupted']['status'], 'interrupted')
        self.assertEqual(result['cases']['interrupted']['cleanup']['status'], 'passed')
        self.assertNotIn('not-started', result['cases'])

    def test_cannot_overwrite_receipt_or_accept_invalid_manifest(self):
        green = self.case('green', 'pass')
        self.assertTrue(self.run_cases(green)['passed'])
        with self.assertRaises(FileExistsError):
            self.run_cases(green)
        for cases in ([], [green, green], [dict(green, id='../escape')],
                      [dict(green, requires=['later'])], [dict(green, timeout_seconds=float('nan'))],
                      [dict(green, command='echo bad')]):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                suite.validate({'cases': cases})


if __name__ == '__main__':
    unittest.main()
