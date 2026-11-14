import argparse
import hashlib
import json
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    spec = json.loads((args.source / 'dependencies.lock.json').read_text(encoding='utf-8'))['dependencies']['sqlitePlugin']
    args.cache.mkdir(parents=True, exist_ok=True)
    archives = {}
    for name in ('qtSource', 'sqliteSource'):
        entry = spec[name]
        path = args.cache / entry['archive']
        if not path.is_file() or sha(path) != entry['sha256']:
            partial = path.with_suffix(path.suffix + '.partial')
            with urllib.request.urlopen(entry['url'], timeout=120) as response, partial.open('wb') as stream:
                while block := response.read(1024 * 1024):
                    stream.write(block)
            if sha(partial) != entry['sha256']:
                raise ValueError('Source archive digest differs from the pinned published provenance')
            partial.replace(path)
        if 'sha3_256' in entry and hashlib.sha3_256(path.read_bytes()).hexdigest() != entry['sha3_256']:
            raise ValueError('Upstream SHA3-256 differs')
        archives[name] = path
    identity = hashlib.sha256(json.dumps(spec, sort_keys=True).encode() + Path(__file__).read_bytes()).hexdigest()
    root = args.output / ('s-' + identity[:12])
    receipt = args.output / ('s-' + identity[:12] + '.json')
    if root.exists():
        prepared = json.loads(receipt.read_text(encoding='utf-8'))
        if prepared['inputsSha256'] != identity:
            raise ValueError('Prepared source identity prefix collision')
        records = prepared['files']
        actual = {p.relative_to(root).as_posix(): sha(p) for p in root.rglob('*') if p.is_file()}
        if actual != {item['path']: item['sha256'] for item in records} or any(p.is_symlink() for p in root.rglob('*')):
            raise ValueError('Prepared SQLite source tree changed')
    else:
        root.mkdir(parents=True)
        seen = set()
        with tarfile.open(archives['qtSource']) as archive:
            for member in archive:
                relative = PurePosixPath(*PurePosixPath(member.name).parts[1:])
                selected = relative.parts[:3] in [('src', 'plugins', 'sqldrivers'), ('src', '3rdparty', 'sqlite')] or relative.parts[:1] == ('LICENSES',)
                if not selected or member.isdir():
                    continue
                if not member.isfile() or member.size > 32 * 1024 * 1024 or relative.is_absolute() or '..' in relative.parts or ':' in str(relative) or '\\' in str(relative):
                    raise ValueError('Unsafe Qt source member')
                key = str(relative).casefold()
                if key in seen:
                    raise ValueError('Duplicate Qt source member')
                seen.add(key)
                target = root / str(relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        with zipfile.ZipFile(archives['sqliteSource']) as archive:
            for name in ('sqlite3.c', 'sqlite3.h', 'sqlite3ext.h'):
                matches = [item for item in archive.infolist() if item.filename.split('/')[-1] == name]
                if len(matches) != 1 or matches[0].file_size > 16 * 1024 * 1024:
                    raise ValueError('Unexpected SQLite amalgamation member')
                data = archive.read(matches[0])
                if name == 'sqlite3.c' and hashlib.sha3_256(data).hexdigest() != spec['sqliteSource']['cSha3_256']:
                    raise ValueError('SQLite C file differs from the published release digest')
                (root / 'src/3rdparty/sqlite' / name).write_bytes(data)
        cmake = root / 'src/plugins/sqldrivers/sqlite/CMakeLists.txt'
        text = cmake.read_text(encoding='utf-8')
        anchor = '        SQLITE_ENABLE_COLUMN_METADATA\n'
        if text.count(anchor) != 1:
            raise ValueError('SQLite compile policy anchor changed')
        cmake.write_text(text.replace(anchor, anchor + '        SQLITE_DEFAULT_DEFENSIVE=1\n        SQLITE_TRUSTED_SCHEMA=0\n'), encoding='utf-8')
        records = [{'path': p.relative_to(root).as_posix(), 'sha256': sha(p)} for p in sorted(root.rglob('*')) if p.is_file()]
        receipt.write_text(json.dumps({'inputsSha256': identity, 'files': records, 'defaultDefensive': True}, indent=2), encoding='utf-8')
    print(json.dumps({'source': str(root), 'receipt': str(receipt), 'inputsSha256': identity}))


if __name__ == '__main__':
    main()
