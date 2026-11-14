import argparse
import hashlib
import stat
import zipfile
from pathlib import Path, PurePosixPath


def verify(package, expected, installed, prefix):
    if hashlib.sha256(package.read_bytes()).hexdigest() != expected:
        raise ValueError('NuGet archive digest mismatch')
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist()
        if len(entries) > 100000 or sum(entry.file_size for entry in entries) > 4 * 1024**3:
            raise ValueError('NuGet archive resource budget exceeded')
        names = set()
        payload = {}
        for entry in entries:
            name = entry.filename
            path = PurePosixPath(name)
            if (path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name
                    or any(part.endswith((' ', '.')) for part in path.parts)
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError('Unsafe NuGet archive member: ' + name)
            normalized = path.as_posix()
            if normalized.casefold() in names:
                raise ValueError('Duplicate NuGet archive member: ' + name)
            names.add(normalized.casefold())
            if not entry.is_dir() and normalized.startswith(prefix):
                payload[normalized[len(prefix):]] = hashlib.sha256(archive.read(entry)).hexdigest()
        if installed:
            for parent in (installed, *installed.parents):
                if parent.exists() and getattr(parent.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError('Link in installed NuGet path')
            for relative, digest in payload.items():
                path = installed / relative
                if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError('Installed NuGet payload mismatch: ' + relative)
            actual = set()
            for path in installed.rglob('*'):
                if getattr(path.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError('Link in installed NuGet payload')
                if path.is_file():
                    actual.add(path.relative_to(installed).as_posix())
            if actual != set(payload):
                raise ValueError('Unexpected installed NuGet files: ' + str(sorted(actual - set(payload))))
    print('NuGet archive and payload verified: ' + package.name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--installed', type=Path)
    parser.add_argument('--prefix', default='')
    args = parser.parse_args()
    verify(args.package, args.sha256, args.installed, args.prefix)
