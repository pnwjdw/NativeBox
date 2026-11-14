import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def source_inventory(source):
    exact = ['CMakeLists.txt', 'CMakePresets.json', 'dependencies.lock.json', 'ui/Main.qml',
             'third_party/offreg/x64/offreg.dll',
             'apps/desktop/controller.cpp', 'apps/desktop/controller.h',
             'apps/desktop/accessible_scrollbar.cpp', 'apps/desktop/accessible_scrollbar.h']
    files = {source / name for name in exact}
    files.update(path for path in (source / 'driverless').rglob('*') if path.suffix in ('.h', '.cpp', '.def', '.in') or path.name == 'CMakeLists.txt')
    files.update(source / 'scripts' / name for name in ('build-driverless.py', 'build-manifest.py', 'restore-driverless.py',
                                                        'prepare-sqlite.py', 'msvc-dependencies.cmake', 'build-runtime.py', 'prepare-runtime.py',
                                                        'deploy-driverless.py', 'package-driverless.py', 'verify-nuget.py', 'prepare-license-sources.py'))
    files.update(path for path in (source / 'packaging/driverless').rglob('*') if path.is_file())
    files.update(path for path in (source / 'licenses').rglob('*') if path.is_file() and 'dokany' not in path.parts)
    return {path.relative_to(source).as_posix(): sha(path) for path in sorted(files)}


def create_build_manifest(source, build, expected_sources, commands):
    if source_inventory(source) != expected_sources:
        raise ValueError('Source changed during build; output is INVALIDATED and no manifest is created')
    cache = (build / 'CMakeCache.txt').read_text(encoding='utf-8')
    expected = 'CMAKE_HOME_DIRECTORY:INTERNAL=' + source.as_posix()
    if expected not in cache.replace('\\', '/') or not (build / 'compile_commands.json').is_file():
        raise ValueError('Build output does not belong to the explicit CMake source root')
    debug = 'CMAKE_BUILD_TYPE:STRING=Debug' in cache
    relative_files = ['nativebox.exe', 'nativebox_cli.exe', 'nativebox_broker.exe', 'nativebox_audit.exe',
                      'sqldrivers/qsqlited.dll' if debug else 'sqldrivers/qsqlite.dll']
    relative_files += ['nativebox_runtime64.dll', 'nativebox_runtime32.dll', 'offreg.dll', 'runtime-artifacts.json']
    artifacts = {name: sha(build / name) for name in relative_files}
    source_digest = hashlib.sha256(''.join(value + '  ' + name + '\n' for name, value in sorted(expected_sources.items())).encode()).hexdigest()
    record = {'schema': 1, 'contract': 'nativebox.application-build/1', 'sourceRoot': str(source), 'buildRoot': str(build),
              'sourceDigest': source_digest, 'sources': expected_sources, 'artifacts': artifacts, 'commands': commands,
              'scope': 'Application outputs only; does not certify runtime instrumentation, dependencies or release acceptance',
              'configuration': 'Debug' if debug else 'Release',
              'runtimeQualified': False, 'releaseReady': False}
    path = build / 'nativebox-build-manifest.json'
    path.write_text(json.dumps(record, indent=2), encoding='utf-8')
    return path


def validate_staging(manifest_path, staging):
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or manifest.get('contract') != 'nativebox.application-build/1':
        raise ValueError('Unknown application build manifest contract')
    if not manifest.get('artifacts'):
        raise ValueError('Build manifest contains no approved artifacts')
    for name, expected in manifest['artifacts'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or ':' in name or '\\' in name:
            raise ValueError('Unsafe artifact path in build manifest')
        path = staging / relative
        for component in [staging, *path.parents]:
            if component == staging.parent:
                break
            if component.exists() and (component.is_symlink() or component.stat().st_file_attributes & 0x400):
                raise ValueError('Staging must not traverse reparse points')
        if not path.is_file() or path.is_symlink() or path.stat().st_file_attributes & 0x400 or sha(path) != expected:
            raise ValueError('Stale or missing staged artifact: ' + name)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--staging', type=Path, required=True)
    args = parser.parse_args()
    record = validate_staging(args.manifest.resolve(), args.staging.resolve())
    print(json.dumps({'status': 'STAGED_APPLICATION_BYTES_MATCH_APPROVED_BUILD', 'sourceDigest': record['sourceDigest'],
                      'artifacts': len(record['artifacts']), 'releaseReady': False}))


if __name__ == '__main__':
    main()
