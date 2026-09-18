"""Exercise unpublished npm archives in a real isolated workspace."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
SPEC = importlib.util.spec_from_file_location(
    "package_consumers", Path(__file__).resolve().parents[1] / "check-consumers.py")
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


@unittest.skipUnless(shutil.which("npm") and shutil.which("node"), "Node/npm unavailable")
class PackageConsumersTest(unittest.TestCase):
    def test_local_archives_replace_registry_checksums_only_in_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = []
            names = ["@gcoms-fixture/rpc", "@gcoms-fixture/codegen"]
            for name in names:
                archive = root / (name.split("/")[1] + ".tgz")
                files = {
                    "package.json": json.dumps({"name": name, "version": "0.1.0",
                                                "type": "module", "exports": "./index.js"}),
                    "index.js": "export const fixture = 42;\n",
                }
                with tarfile.open(archive, "w:gz") as tar:
                    for filename, contents in files.items():
                        data = contents.encode()
                        entry = tarfile.TarInfo("package/" + filename)
                        entry.size = len(data)
                        tar.addfile(entry, io.BytesIO(data))
                archives.append(archive)
            source = root / "original"
            (source / "ui").mkdir(parents=True)
            (source / "package.json").write_text(json.dumps(
                {"name": "fixture-chat", "private": True, "workspaces": ["ui"]}))
            ui = {"name": "fixture-ui", "private": True,
                  "dependencies": {name: "0.1.0" for name in names}}
            (source / "ui/package.json").write_text(json.dumps(ui))
            packages = {"": {"name": "fixture-chat", "workspaces": ["ui"]},
                        "ui": ui, "node_modules/fixture-ui": {"resolved": "ui", "link": True}}
            for name in names:
                packages["node_modules/" + name] = {
                    "version": "0.1.0", "resolved": "https://registry.npmjs.org/" + name + "/fixture.tgz",
                    "integrity": "sha512-" + base64.b64encode(bytes(64)).decode()}
            (source / "package-lock.json").write_text(json.dumps(
                {"name": "fixture-chat", "lockfileVersion": 3, "packages": packages}))
            original = {str(p.relative_to(source)): p.read_bytes()
                        for p in source.rglob("*") if p.is_file()}
            snapshot = root / "snapshot"
            shutil.copytree(source, snapshot)

            def run(command, cwd):
                subprocess.run(list(map(str, command)), cwd=cwd, check=True,
                               capture_output=True, text=True, timeout=60)
            check.install_snapshot_npm(snapshot, archives, True, run)
            run(["node", "--input-type=module", "-e",
                 "import {fixture} from '@gcoms-fixture/rpc';"
                 "import {fixture as other} from '@gcoms-fixture/codegen';"
                 "if(fixture!==42||other!==42)throw Error('wrong archive');"], snapshot / "ui")
            lock = json.loads((snapshot / "package-lock.json").read_text())
            for name, archive in zip(names, archives):
                package = lock["packages"]["node_modules/" + name]
                self.assertTrue(package["resolved"].startswith("file:"))
                self.assertEqual(package["integrity"], "sha512-" +
                                 base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode())
            self.assertEqual(original, {str(p.relative_to(source)): p.read_bytes()
                                        for p in source.rglob("*") if p.is_file()})
            self.assertEqual((snapshot / "ui/package.json").read_bytes(), original["ui/package.json"])


if __name__ == "__main__":
    unittest.main()
