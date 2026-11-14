import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
import runpy
from pathlib import Path, PurePosixPath


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def inventory(root):
    records = []
    for path in root.rglob('*'):
        if path.is_symlink() or path.stat().st_file_attributes & 0x400:
            raise ValueError('Reparse point in dependency tree')
        if path.is_file() and path.name not in ('.nativebox-lock.json', '.nativebox-files.sha256'):
            relative = path.relative_to(root).as_posix()
            records.append((relative, sha(path)))
    text = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(records))
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve()
    lock = json.loads((source / 'dependencies.lock.json').read_text(encoding='utf-8-sig'))
    qt = lock['dependencies']['qt']
    cache = args.cache.resolve() if args.cache else source / '.deps/.downloads'
    cache.mkdir(parents=True, exist_ok=True)
    runtime_tools = runpy.run_path(str(source / 'scripts/prepare-runtime.py'))
    runtime_tools['prepare'](source, cache, args.offline, args.verify_only)
    target = source / qt['target']
    if not target.resolve().is_relative_to(source / '.deps'):
        raise ValueError('Dependency target escapes project .deps')
    if target.exists():
        if inventory(target) != qt['inventorySha256']:
            raise ValueError('Installed Qt differs from the pinned inventory; existing bytes were preserved')
        print(json.dumps({'dependency': 'qt', 'status': 'VERIFIED', 'inventorySha256': qt['inventorySha256']}))
        return
    if args.verify_only:
        raise FileNotFoundError('Pinned Qt is missing')

    def pinned(url, name, expected):
        path = cache / name
        if path.is_file() and sha(path) == expected:
            return path
        if args.offline:
            raise FileNotFoundError('Offline dependency cache missing or modified: ' + name)
        partial = cache / (name + '.partial')
        with urllib.request.urlopen(url, timeout=40) as response, partial.open('wb') as stream:
            for block in iter(lambda: response.read(1024 * 1024), b''):
                stream.write(block)
        if sha(partial) != expected:
            raise ValueError('Official archive differs from its pinned SHA-256: ' + name)
        os.replace(partial, path)
        return path

    seven = lock['tools']['sevenZip']
    tool = pinned(seven['url'], '7zr.exe', seven['sha256'])
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='qt-staging-', dir=target.parent))
    for entry in qt['archives']:
        name = qt['prefix'] + entry['name']
        archive = pinned(qt['base'] + '/' + name, name, entry['sha256'])
        listing = subprocess.run([str(tool), 'l', '-slt', str(archive)], capture_output=True, check=True).stdout.decode('utf-8', errors='strict')
        paths = [line[7:] for line in listing.splitlines() if line.startswith('Path = ')][1:]
        for name in paths:
            relative = PurePosixPath(name.replace('\\', '/'))
            if relative.is_absolute() or '..' in relative.parts or ':' in name:
                raise ValueError('Unsafe dependency archive entry')
        subprocess.run([str(tool), 'x', '-y', '-o' + str(staging), str(archive)], capture_output=True, check=True)
    if inventory(staging) != qt['inventorySha256']:
        raise ValueError('Restored Qt inventory differs; staging is retained for diagnosis')
    os.replace(staging, target)
    print(json.dumps({'dependency': 'qt', 'status': 'RESTORED_AND_VERIFIED', 'inventorySha256': qt['inventorySha256']}))


if __name__ == '__main__':
    main()
