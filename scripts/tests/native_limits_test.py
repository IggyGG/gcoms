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


if __name__ == '__main__':
    unittest.main()
