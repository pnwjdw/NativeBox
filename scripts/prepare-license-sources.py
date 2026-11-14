import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import urllib.request
import uuid


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def regular(path):
    if path.is_symlink() or path.is_junction() or path.stat().st_file_attributes & 0x400:
        raise RuntimeError(f'Reparse point in source distribution input: {path}')
    if not path.is_file():
        raise RuntimeError(f'Not a regular source distribution input: {path}')


def stage(source, output):
    source = source.resolve(strict=True)
    output = output.resolve()
    if output == source or output.name != 'corresponding-source' or output.parent.name != 'licenses':
        raise RuntimeError('Output must be a package licenses/corresponding-source directory')
    spec = json.loads((source / 'licenses/source-archives.json').read_text(encoding='utf-8'))
    if spec['schema'] != 1:
        raise RuntimeError('Unsupported source distribution catalog schema')
    cache = source / '.deps/.downloads'
    cache.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    records = []
    for entry in spec['archives']:
        name, expected, url = entry['archive'], entry['sha256'], entry['url']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise RuntimeError('Invalid source archive name or digest')
        if not url.startswith('https://'):
            raise RuntimeError('Source downloads require HTTPS')
        archive = cache / name
        if not archive.exists():
            partial = cache / (name + '.partial-' + uuid.uuid4().hex)
            request = urllib.request.Request(url, headers={'User-Agent': 'NativeBox-source-distribution'})
            with urllib.request.urlopen(request, timeout=60) as response, partial.open('xb') as stream:
                size = 0
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > 200 * 1024 * 1024:
                        raise RuntimeError('Source archive exceeds the permitted size')
                    stream.write(block)
            if digest(partial) != expected:
                raise RuntimeError(f'Source archive digest mismatch; retained {partial}')
            partial.replace(archive)
        regular(archive)
        if digest(archive) != expected:
            raise RuntimeError(f'Cached source archive digest mismatch: {archive}')
        target = output / name
        if target.exists():
            regular(target)
            if digest(target) != expected:
                raise RuntimeError(f'Existing staged source differs: {target}')
        else:
            shutil.copyfile(archive, target)
        if digest(target) != expected:
            raise RuntimeError('Staged source copy differs')
        records.append({**entry, 'path': name, 'bytes': target.stat().st_size})
    for relative in spec['buildRecipes']:
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts:
            raise RuntimeError('Invalid library build recipe path')
        original = source / path
        regular(original)
        target = output / 'build-recipes' / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            regular(target)
        shutil.copyfile(original, target)
        if digest(original) != digest(target):
            raise RuntimeError('Library recipe copy differs')
        records.append({'path': target.relative_to(output).as_posix(), 'sha256': digest(target),
                        'bytes': target.stat().st_size, 'kind': 'library-modification-build-input'})
    own_license = source / 'licenses/NativeBox-MIT.txt'
    application_license = None
    if own_license.exists():
        regular(own_license)
        application_license = {'spdx': 'MIT', 'path': '../NativeBox-MIT.txt',
                               'sha256': digest(own_license)}
    manifest = {'schema': 1, 'scope': 'Complete upstream archives plus NativeBox library modification recipes',
                'ownApplicationLicenseAssigned': application_license is not None,
                'applicationLicense': application_license, 'files': records}
    (output / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'archives': len(spec['archives']), 'files': len(records), 'output': str(output)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    stage(args.source, args.output)
