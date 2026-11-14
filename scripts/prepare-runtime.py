import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*'))
            if p.is_file() and p.name != '.nativebox-source.json'}


def prepare(source, cache, offline=False, verify_only=False):
    lock = json.loads((source / 'dependencies.lock.json').read_text(encoding='utf-8-sig'))
    pin = lock['dependencies']['detours']
    target = source / pin['target']
    if not target.resolve().is_relative_to(source / '.deps'):
        raise ValueError('Runtime dependency target escapes project .deps')
    if target.exists():
        receipt = json.loads((target / '.nativebox-source.json').read_text(encoding='utf-8'))
        if receipt['archiveSha256'] != pin['archiveSha256'] or receipt['files'] != inventory(target):
            raise ValueError('Detours source differs from its pinned inventory; existing data retained')
    else:
        if verify_only:
            raise FileNotFoundError('Pinned Detours source is missing')
        archive = cache / pin['archive']
        if not archive.is_file():
            if offline:
                raise FileNotFoundError('Offline official Detours archive is missing: ' + str(archive))
            partial = archive.with_suffix('.partial')
            with urllib.request.urlopen(pin['url'], timeout=40) as response, partial.open('wb') as stream:
                shutil.copyfileobj(response, stream)
            if sha(partial) != pin['archiveSha256']:
                raise ValueError('Downloaded official Detours archive differs from the reviewed pin')
            os.replace(partial, archive)
        if sha(archive) != pin['archiveSha256']:
            raise ValueError('Detours source archive differs from its reviewed pin')
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix='detours-', dir=target.parent))
        with zipfile.ZipFile(archive) as z:
            if z.testzip() is not None or z.comment.decode('ascii') != pin['commit']:
                raise ValueError('Detours archive CRC or pinned commit identity mismatch')
            total = 0
            for item in z.infolist():
                path = PurePosixPath(item.filename)
                total += item.file_size
                if path.is_absolute() or '..' in path.parts or ':' in item.filename or '\\' in item.filename or total > 16777216:
                    raise ValueError('Unsafe Detours archive path or size')
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError('Detours archive contains a link')
            z.extractall(staging)
        roots = list(staging.iterdir())
        if len(roots) != 1 or not (roots[0] / 'src/detours.h').is_file():
            raise ValueError('Unexpected pinned Detours source layout')
        root = roots[0]
        receipt = {'version': pin['version'], 'commit': pin['commit'], 'archiveSha256': pin['archiveSha256'],
                   'repository': pin['repository'], 'files': inventory(root)}
        (root / '.nativebox-source.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        os.replace(root, target)
    offline_pin = lock['dependencies']['offregUserMode']
    bundled = source / 'third_party/offreg/x64/offreg.dll'
    if bundled.exists() and (bundled.is_symlink() or bundled.stat().st_file_attributes & 0x400 or sha(bundled) != offline_pin['sha256']):
        raise ValueError('Bundled Microsoft user-mode redistributable differs from its pin')
    offline_target = source / offline_pin['target']
    if not offline_target.exists():
        if verify_only:
            raise FileNotFoundError('Pinned Offline Registry redistributable is missing')
        cached = bundled if bundled.is_file() else cache / 'offreg-10.0.26100.6584-x64.dll'
        if not cached.is_file() or sha(cached) != offline_pin['sha256']:
            raise FileNotFoundError('Verified Microsoft user-mode Offline Registry DLL is missing from the dependency cache')
        offline_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cached, offline_target)
    if sha(offline_target) != offline_pin['sha256']:
        raise ValueError('Offline Registry redistributable differs from the Microsoft pin')
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve()
    cache = args.cache.resolve() if args.cache else source / '.deps/.downloads'
    cache.mkdir(parents=True, exist_ok=True)
    target = prepare(source, cache, args.offline, args.verify_only)
    print(json.dumps({'dependency': 'Detours 4.0.1 and user-mode Offline Registry', 'status': 'PINNED_INPUTS_VERIFIED', 'source': str(target)}))


if __name__ == '__main__':
    main()
