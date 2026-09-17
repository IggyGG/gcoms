import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "gchat_source_check", Path(__file__).resolve().parents[1] / "check-gchat.py"
)
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class SourceCheckTest(unittest.TestCase):
    def repository(self, directory):
        root = Path(directory).resolve()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / "Cargo.toml").write_text('[workspace]\nmembers=[]\n')
        (root / "Cargo.lock").write_text('# retained registry lock\n')
        (root / ".gitignore").write_text('target/\n')
        subprocess.run(["git", "add", "Cargo.toml", "Cargo.lock", ".gitignore"],
                       cwd=root, check=True)
        return root

    def test_snapshot_includes_current_work_preserves_original_and_excludes_builds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.repository(Path(temp) / "source")
            (root / "Cargo.toml").write_text('[workspace]\nmembers=["crates/chat-api"]\n')
            (root / "new.rs").write_text('// compatible pending work\n')
            (root / "target").mkdir()
            (root / "target/private-output").write_text('must not copy\n')
            out = Path(temp) / "snapshot"
            hashes = check.snapshot(root, out)
            (out / "Cargo.lock").write_text('# Cargo can rewrite this copy\n')
            self.assertEqual((root / "Cargo.lock").read_text(), '# retained registry lock\n')
            self.assertEqual((out / "new.rs").read_text(), '// compatible pending work\n')
            self.assertEqual((out / "Cargo.toml").read_bytes(), (root / "Cargo.toml").read_bytes())
            self.assertEqual(sorted(hashes), ['.gitignore', 'Cargo.lock', 'Cargo.toml', 'new.rs'])
            self.assertFalse((out / "target").exists())

    def test_deleted_tracked_file_is_not_resurrected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.repository(temp)
            (root / "removed.rs").write_text('old\n')
            subprocess.run(["git", "add", "removed.rs"], cwd=root, check=True)
            (root / "removed.rs").unlink()
            self.assertNotIn('removed.rs', check.source_files(root))

    @unittest.skipIf(os.name == 'nt', 'unprivileged Windows symlinks are not assumed')
    def test_external_symlink_cannot_read_another_repository(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.repository(Path(temp) / "source")
            (Path(temp) / "external").write_text('not part of the authorized source\n')
            (root / "escape").symlink_to(Path(temp) / "external")
            with self.assertRaisesRegex(ValueError, 'escapes repository'):
                check.source_files(root)

    def test_concurrent_edits_and_added_files_invalidate_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.repository(Path(temp) / "source")
            hashes = check.snapshot(root, Path(temp) / "snapshot")
            self.assertTrue(check.unchanged(root, hashes))
            (root / "new.rs").write_text('// new work\n')
            self.assertFalse(check.unchanged(root, hashes))
            (root / "new.rs").unlink()
            self.assertTrue(check.unchanged(root, hashes))
            (root / "Cargo.toml").write_text('[workspace]\nmembers=["changed"]\n')
            self.assertFalse(check.unchanged(root, hashes))

    def test_patch_covers_only_protocol_packages_inside_the_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            members = ['crates/node', 'crates/sdk', 'crates/rpc', 'examples/client']
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=' + repr(members).replace("'", '"') + '\n')
            for member, name in zip(members, ['gcoms-node', 'gcoms-sdk', 'gcoms-rpc', 'example-client']):
                directory = root / member
                directory.mkdir(parents=True)
                (directory / 'Cargo.toml').write_text(f'[package]\nname="{name}"\n')
            encoded, names = check.patches(root)
            parsed = check.tomllib.loads(encoded)['patch']['crates-io']
            self.assertEqual(names, ['gcoms-node', 'gcoms-rpc', 'gcoms-sdk'])
            self.assertEqual(sorted(parsed), names)
            self.assertTrue(all(Path(item['path']).is_relative_to(root) for item in parsed.values()))

    def test_later_success_retains_the_previous_failure_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            failure = check.write_report(root, 'test', 'first', {'exit_code': 1})
            success = check.write_report(root, 'test', 'second', {'exit_code': 0})
            self.assertEqual(check.json.loads(failure.read_text()), {'exit_code': 1})
            self.assertEqual((root / 'test-summary.json').read_bytes(), success.read_bytes())
            with self.assertRaises(FileExistsError):
                check.write_report(root, 'test', 'first', {'exit_code': 0})

    @unittest.skipUnless(shutil.which('cargo'), 'Rust toolchain is unavailable')
    def test_clippy_resolves_an_unpublished_package_without_touching_originals(self):
        # Exercise the external Cargo subcommand, not just its assembled argv.
        if subprocess.run(['cargo', 'clippy', '--version'], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode:
            self.skipTest('Clippy is unavailable')
        with tempfile.TemporaryDirectory() as temp:
            protocol = self.repository(Path(temp) / 'gcoms')
            chat = self.repository(Path(temp) / 'gchat')
            (protocol / 'Cargo.toml').write_text(
                '[workspace]\nresolver="2"\nmembers=["crates/*"]\n')
            for name in ['node', 'sdk', 'rpc']:
                directory = protocol / 'crates' / name
                (directory / 'src').mkdir(parents=True)
                (directory / 'Cargo.toml').write_text(
                    f'[package]\nname="gcoms-{name}"\nversion="0.0.0-source-check"\nedition="2021"\n')
                (directory / 'src/lib.rs').write_text('pub fn value() -> u32 { 42 }\n')
            (chat / 'Cargo.toml').write_text(
                '[workspace]\nresolver="2"\nmembers=["crates/chat-api"]\n')
            api = chat / 'crates/chat-api'
            (api / 'src').mkdir(parents=True)
            (api / 'Cargo.toml').write_text(
                '[package]\nname="gchat-api"\nversion="0.0.0"\nedition="2021"\n'
                '[dependencies]\ngcoms-rpc="=0.0.0-source-check"\n')
            (api / 'src/lib.rs').write_text('pub fn value() -> u32 { gcoms_rpc::value() }\n')
            # Uncommitted fixture repos need no user identity or commit hooks.
            original_output = subprocess.check_output
            def output(args, **kwargs):
                if args == ['git', 'rev-parse', 'HEAD']:
                    return 'fixture-revision\n'
                return original_output(args, **kwargs)
            target = Path(temp) / 'results'
            argv = ['check-gchat.py', '--gchat', str(chat), '--action', 'clippy',
                    '--offline', '--target-dir', str(target)]
            with patch.object(check, 'ROOT', protocol), patch('sys.argv', argv), \
                    patch.object(check.subprocess, 'check_output', side_effect=output), \
                    self.assertRaises(SystemExit) as result:
                check.main()
            self.assertEqual(result.exception.code, 0)
            report = check.json.loads((target / 'clippy-summary.json').read_text())
            self.assertTrue(report['passed'])
            self.assertTrue(all(item['unchanged_during_check'] for item in report['sources'].values()))
            for root in [protocol, chat]:
                self.assertEqual((root / 'Cargo.lock').read_text(), '# retained registry lock\n')


if __name__ == '__main__':
    unittest.main()
