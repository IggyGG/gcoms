"""Install only the pinned Android build packages inside the cluster image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import urlopen
import zipfile


def install(only=None):
    packages = json.loads(Path('/opt/gcoms/android-packages.json').read_text())
    receipt_path = Path('/opt/android/packages.lock.json')
    receipts = json.loads(receipt_path.read_text()) if only else []
    if only:
        packages = [p for p in packages if p['package'] == only]
        if len(packages) != 1 or any(p['package'] == only for p in receipts):
            raise ValueError('toolchain extension requires one new pinned package')
    for package in packages:
        destination = Path('/opt/android').joinpath(*package['package'].split(';'))
        if destination.exists():
            raise ValueError('preserve existing Android toolchain package')
        with tempfile.TemporaryDirectory(prefix='android-toolchain-', dir='/var/tmp') as scratch:
            archive = Path(scratch) / 'package.zip'
            count = 0
            with urlopen(package['url'], timeout=120) as source, archive.open('wb') as output:
                while chunk := source.read(1024 * 1024):
                    count += len(chunk)
                    if count > package['size']:
                        raise ValueError('Android vendor archive exceeds pinned size')
                    output.write(chunk)
            with archive.open('rb') as stream:
                checksum = hashlib.file_digest(stream, 'sha1').hexdigest()
            if count != package['size'] or checksum != package['sha1']:
                raise ValueError('Android vendor archive does not match its pinned receipt')
            with archive.open('rb') as stream:
                sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            with zipfile.ZipFile(archive) as contents:
                if any(Path(i.filename).is_absolute() or '..' in Path(i.filename).parts for i in contents.infolist()):
                    raise ValueError('Android archive path escapes its package')
            expanded = Path(scratch) / 'expanded'
            subprocess.run(['unzip', '-q', str(archive), '-d', str(expanded)], check=True)
            children = list(expanded.iterdir())
            source_root = expanded if (expanded / 'source.properties').is_file() else (
                children[0] if len(children) == 1 and children[0].is_dir() else None)
            if source_root is None or not (source_root / 'source.properties').is_file():
                raise ValueError('Android archive has an unexpected package layout')
            for path in source_root.rglob('*'):
                if path.is_symlink() and not path.resolve().is_relative_to(source_root.resolve()):
                    raise ValueError('Android package symlink escapes its verified package')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(source_root, destination)
            # The CMake vendor ZIP marks this public SDK metadata owner-only.
            # Gradle and our toolchain probe run as the unprivileged builder.
            (destination / 'source.properties').chmod(0o644)
            receipts.append(dict(package, sha256=sha))
    receipt_path.write_text(json.dumps(receipts, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--only', help='Append one missing package to the pinned base receipt')
    install(parser.parse_args().only)
