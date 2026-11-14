import argparse
import datetime
import json
import msvcrt
import os
import runpy
import shutil
import subprocess
from pathlib import Path


def deploy(source, build, destination, corresponding=True):
    helpers = runpy.run_path(str(source / 'scripts/build-manifest.py'))
    manifest_path = build / 'nativebox-build-manifest.json'
    manifest = helpers['validate_staging'](manifest_path, build)
    if manifest['configuration'] != 'Release' or helpers['source_inventory'](source) != manifest['sources']:
        raise ValueError('Deployment requires an unchanged explicit Release build')
    destination = destination.resolve()
    if not destination.is_relative_to(source / 'out') or destination.exists():
        raise ValueError('Deployment requires a new directory inside project out')
    if shutil.disk_usage(source).free < 2 * 1024 ** 3:
        raise OSError('At least 2 GiB of free space is required before deployment')
    destination.mkdir(parents=True)
    env, cmake = runpy.run_path(str(source / 'scripts/build-runtime.py'))['compiler_environment']('x64')
    commands = [[str(cmake), '--install', str(build), '--prefix', str(destination)]]
    qt = source / '.deps/qt-6.8.3'
    commands.append([str(qt / 'bin/windeployqt.exe'), '--release', '--qmldir', str(source / 'ui'),
                     '--no-opengl-sw', '--no-system-d3d-compiler', '--no-compiler-runtime',
                     '--no-system-dxc-compiler', '--skip-plugin-types', 'qmltooling,generic,networkinformation',
                     '--verbose', '1', *[str(destination / name) for name in ('nativebox.exe', 'nativebox_cli.exe', 'nativebox_broker.exe', 'nativebox_audit.exe')]])
    records = []
    for index, command in enumerate(commands):
        process = subprocess.run(command, cwd=source, env=env, capture_output=True, timeout=120)
        log = destination.parent / (destination.name + '-deploy-' + str(index) + '.log')
        log.write_bytes(process.stdout + process.stderr)
        records.append({'command': command, 'exitCode': process.returncode, 'log': str(log)})
        if process.returncode:
            raise RuntimeError('Deployment failed; inspect ' + str(log))
    shutil.copy2(build / 'sqldrivers/qsqlite.dll', destination / 'sqldrivers/qsqlite.dll')
    shutil.copytree(source / 'licenses', destination / 'licenses', dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('dokany'))
    (destination / 'qt.conf').write_text('[Paths]\nPrefix=.\nPlugins=.\nQmlImports=qml\nTranslations=translations\n', encoding='utf-8')
    if corresponding:
        runpy.run_path(str(source / 'scripts/prepare-license-sources.py'))['stage'](source, destination / 'licenses/corresponding-source')
    for path in destination.rglob('*'):
        if path.is_symlink() or path.stat().st_file_attributes & 0x400:
            raise ValueError('Deployment contains a reparse point')
        if path.suffix.lower() in ('.sys', '.inf', '.cat', '.pdb', '.obj', '.lib', '.exp', '.ilk'):
            raise ValueError('Unexpected build or driver artifact: ' + str(path))
        if path.name.lower() in ('nativebox_service.exe', 'dokan2.dll', 'nativebox_engine_setup.exe'):
            raise ValueError('Legacy backend is forbidden in driverless deployment')
    helpers['validate_staging'](manifest_path, destination)
    inventory = {path.relative_to(destination).as_posix(): helpers['sha'](path)
                 for path in sorted(destination.rglob('*')) if path.is_file()}
    receipt = {'contract': 'nativebox.deployment/1', 'sourceDigest': manifest['sourceDigest'],
               'buildManifest': str(manifest_path), 'buildManifestSha256': helpers['sha'](manifest_path),
               'staging': str(destination), 'files': inventory, 'commands': records,
               'correspondingSourceIncluded': corresponding, 'releaseReady': False}
    output = destination.parent / (destination.name + '-deployment.json')
    output.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps({'deployment': str(output), 'staging': str(destination), 'files': len(inventory)}))
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    with (source / '.nativebox-acceptance.lock').open('a+b') as lease:
        msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
        deploy(source, args.build.resolve(), args.destination.resolve())


if __name__ == '__main__':
    main()
