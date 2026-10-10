"""A diagnostic failure must never become release or deployment authority."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    'relay_recovery', Path(__file__).resolve().parents[1] / 'qualify-relay-recovery.py')
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


class RelayRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.gcoms, self.gchat = self.root / 'gcoms', self.root / 'gchat'
        self.output, self.work = self.root / 'evidence', self.root / 'work'
        self.sources = {self.gcoms: {'commit': 'a' * 40, 'tree': 'c' * 40},
                        self.gchat: {'commit': 'b' * 40, 'tree': 'd' * 40}}
        self.origin = recovery.provider({'GITHUB_REPOSITORY': 'IggyGG/gcoms',
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40})
        helpers = ModuleType('relay_load_run')
        helpers.execute = Mock(side_effect=self.execute)
        helpers.retain_journey = Mock(side_effect=self.retain)
        evidence = ModuleType('release_evidence')
        evidence.source_identity = Mock(side_effect=lambda p: self.sources[p])
        evidence.digest = lambda p: recovery.hashlib.sha256(p.read_bytes()).hexdigest()
        verifier = ModuleType('release_relay_load')
        verifier.verify = Mock(side_effect=self.verify)
        self.helpers, self.evidence, self.verifier = helpers, evidence, verifier
        for patcher in (patch.dict(sys.modules, {'relay_load_run': helpers,
                         'release_evidence': evidence, 'release_relay_load': verifier}),
                        patch.object(recovery, 'ROOT', self.gcoms),
                        patch.object(sys, 'path', list(sys.path))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def execute(self, command, workspace, log, timeout):
        log.write_text('original execution log')
        if '--mode' not in command:
            (self.work / 'build').mkdir()
            (self.work / 'build/build.json').write_text('{"passed": true}')

    def retain(self, source, destination):
        destination.mkdir()
        (destination / 'worker.json').write_text('{"original": true}')

    def verify(self, output, manifest, provider):
        self.assertTrue(self.report()['passed'], 'source drift must fail the strict verifier')

    def report(self):
        return json.loads((self.output / 'summary.json').read_text())

    def run_gate(self):
        recovery.run(self.gchat, self.output, self.work, self.root / 'target', self.origin)

    def test_diagnostic_success_never_authorizes_a_release(self):
        self.run_gate()
        value = self.report()
        self.assertTrue(value['passed'])
        self.assertTrue(value['strict_verifier_passed'])
        self.assertFalse(value['release_qualified'])
        self.assertEqual(value['provider'], self.origin)
        commands = [call.args[0] for call in self.helpers.execute.call_args_list]
        self.assertEqual(commands[-1][-6:], ['--load-seconds', '1800',
                         '--load-relay-circuits', '2048', '--load-relay-connections', '4096'])

    def test_failed_campaign_retains_original_evidence_and_failed_summary(self):
        def execute(*args):
            self.execute(*args)
            if 'relay-load' in args[0]:
                raise subprocess.CalledProcessError(1, args[0])
        self.helpers.execute.side_effect = execute
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_gate()
        self.assertFalse(self.report()['passed'])
        self.assertIn('load/worker.json', self.report()['evidence'])
        self.verifier.verify.assert_not_called()

    def test_changed_source_cannot_pass_after_successful_commands(self):
        self.evidence.source_identity.side_effect = [self.sources[self.gcoms],
            self.sources[self.gchat], {**self.sources[self.gcoms], 'commit': 'e' * 40}]
        with self.assertRaisesRegex(AssertionError, 'source drift'):
            self.run_gate()
        self.assertFalse(self.report()['passed'])
        self.assertFalse(self.report()['source_unchanged'])

    def test_verifier_failure_or_interruption_preserves_failed_verdict(self):
        for error in (ValueError('original gate failure'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory(dir=self.root) as directory:
                self.output, self.work = Path(directory) / 'out', Path(directory) / 'work'
                self.verifier.verify.side_effect = error
                with self.assertRaises(type(error)):
                    self.run_gate()
                self.assertFalse(self.report()['passed'])
                self.assertFalse(self.report()['strict_verifier_passed'])

    def test_workflow_commit_mismatch_refuses_before_building(self):
        self.origin['workflow_commit'] = 'e' * 40
        with self.assertRaisesRegex(ValueError, 'same commit'):
            self.run_gate()
        self.helpers.execute.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_outputs_inside_source_are_refused(self):
        self.output = self.gchat / 'evidence'
        with self.assertRaisesRegex(ValueError, 'outside both source'):
            self.run_gate()
        self.helpers.execute.assert_not_called()

    def test_missing_provider_identity_is_refused(self):
        with self.assertRaises(ValueError):
            recovery.provider({})


if __name__ == '__main__':
    unittest.main()
