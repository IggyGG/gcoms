import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_limits


class NativeLimitsTest(unittest.TestCase):
    def resource(self, values):
        return Mock(RLIMIT_NOFILE=7, RLIM_INFINITY=-1,
                    getrlimit=Mock(side_effect=values))

    def run_prepare(self, resource, platform='darwin'):
        with patch.object(native_limits.sys, 'platform', platform), patch.dict(sys.modules, resource=resource):
            native_limits.prepare()

    def test_preserves_hard_limit_and_raises_only_low_soft_limit(self):
        r = self.resource([(256, -1), (8192, -1)])
        self.run_prepare(r)
        r.setrlimit.assert_called_once_with(7, (8192, -1))

    def test_does_not_lower_existing_limits(self):
        for soft in (8192, 16384, -1):
            r = self.resource([(soft, -1)])
            self.run_prepare(r)
            r.setrlimit.assert_not_called()

    def test_insufficient_hard_limit_fails_before_tests(self):
        r = self.resource([(256, 4096)])
        with self.assertRaisesRegex(RuntimeError, 'hard limit'):
            self.run_prepare(r)
        r.setrlimit.assert_not_called()

    def test_verifies_effective_limit(self):
        r = self.resource([(256, -1), (256, -1)])
        with self.assertRaisesRegex(RuntimeError, 'not applied'):
            self.run_prepare(r)

    def test_other_platforms_are_unchanged(self):
        for platform in ('linux', 'win32'):
            r = self.resource([])
            self.run_prepare(r, platform)
            r.getrlimit.assert_not_called()


class DisposableMacPortsTest(unittest.TestCase):
    def environment(self, platform='darwin', github='true'):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(native_limits.sys, 'platform', platform))
        stack.enter_context(patch.dict(native_limits.os.environ, GITHUB_ACTIONS=github))
        return stack

    def test_restores_original_ports_after_success_and_child_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), self.environment(), \
                 patch.object(native_limits.subprocess, 'check_output', side_effect=['49152', '10240', '49152']), \
                 patch.object(native_limits.subprocess, 'run') as run:
                try:
                    with native_limits.disposable_mac_ports():
                        self.assertEqual(run.call_count, 1)
                        if fail:
                            raise ValueError('child test failed')
                except ValueError as error:
                    self.assertTrue(fail)
                    self.assertEqual(str(error), 'child test failed')
                self.assertEqual([call.args[0][-1] for call in run.call_args_list],
                                 ['net.inet.ip.portrange.first=10240', 'net.inet.ip.portrange.first=49152'])

    def test_failed_reservation_still_restores_before_refusing_test(self):
        with self.environment(), \
             patch.object(native_limits.subprocess, 'check_output', side_effect=['49152', '49152', '49152']), \
             patch.object(native_limits.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'not applied'):
                with native_limits.disposable_mac_ports():
                    self.fail('test ran without its required resources')
            self.assertEqual(run.call_count, 2)

    def test_failed_restore_is_not_a_pass(self):
        with self.environment(), \
             patch.object(native_limits.subprocess, 'check_output', side_effect=['49152', '10240', '10240']), \
             patch.object(native_limits.subprocess, 'run'):
            with self.assertRaisesRegex(RuntimeError, 'not restored'):
                with native_limits.disposable_mac_ports():
                    pass

    def test_sufficient_existing_range_is_not_narrowed(self):
        with self.environment(), patch.object(native_limits.subprocess, 'check_output', return_value='8192'), \
             patch.object(native_limits.subprocess, 'run') as run:
            with native_limits.disposable_mac_ports():
                pass
            run.assert_not_called()

    def test_personal_macs_and_non_macs_never_change_host_ports(self):
        for platform, github in [('darwin', ''), ('linux', 'true'), ('win32', 'true')]:
            with self.subTest(platform=platform, github=github), self.environment(platform, github), \
                 patch.object(native_limits.subprocess, 'check_output') as read, \
                 patch.object(native_limits.subprocess, 'run') as run:
                with native_limits.disposable_mac_ports():
                    pass
                read.assert_not_called()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
