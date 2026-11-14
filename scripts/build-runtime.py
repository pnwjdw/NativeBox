import argparse
import datetime
import hashlib
import json
import msvcrt
import os
import runpy
import shutil
import subprocess
from pathlib import Path


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def compiler_environment(architecture):
    vswhere = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    root = Path(subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
                                      'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property',
                                      'installationPath'], text=True).strip())
    script = root / 'VC/Auxiliary/Build' / ('vcvars64.bat' if architecture == 'x64' else 'vcvars32.bat')
    if any(value in str(script) for value in '"%\r\n&|<>^!'):
        raise ValueError('Unsupported compiler installation path')
    base = {key.upper(): value for key, value in os.environ.items()
            if not key.upper().startswith(('VSCMD_', '__VSCMD_', 'VSINSTALL', 'VCINSTALL', 'VCTOOLS', 'WINDOWSSDK', 'UNIVERSALCRT'))
            and key.upper() not in ('INCLUDE', 'LIB', 'LIBPATH', 'PLATFORM')}
    base['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32') + os.pathsep + os.environ['SystemRoot']
    block = subprocess.check_output('cmd.exe /d /u /s /c ""' + str(script) + '" >nul && set"', env=base).decode('utf-16-le')
    env = dict(base)
    for line in block.splitlines():
        if '=' in line and not line.startswith('='):
            key, value = line.split('=', 1)
            env[key.upper()] = value
    tools = root / 'Common7/IDE/CommonExtensions/Microsoft/CMake'
    env['PATH'] = str(tools / 'CMake/bin') + os.pathsep + str(tools / 'Ninja') + os.pathsep + env['PATH']
    return env, tools / 'CMake/bin/cmake.exe'


def run(command, directory, env, log):
    if log.exists():
        history = log.parent / 'history'
        history.mkdir(exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        shutil.copy2(log, history / (stamp + '-' + log.name))
    with log.open('wb') as stream:
        process = subprocess.run(command, cwd=directory, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=240)
    if process.returncode:
        raise RuntimeError('Runtime build step failed (' + str(process.returncode) + '); log: ' + str(log))


def build(source, destination, configuration):
    lock = json.loads((source / 'dependencies.lock.json').read_text(encoding='utf-8-sig'))
    detours = source / lock['dependencies']['detours']['target']
    receipt = json.loads((detours / '.nativebox-source.json').read_text(encoding='utf-8'))
    if receipt['archiveSha256'] != lock['dependencies']['detours']['archiveSha256']:
        raise ValueError('Detours source provenance differs from the pinned dependency')
    manifest_tools = runpy.run_path(str(source / 'scripts/build-manifest.py'))
    inputs = manifest_tools['source_inventory'](source)
    commands, products = [], {}
    for architecture, bits in (('x64', '64'), ('x86', '32')):
        directory = destination / 'runtime-build' / architecture
        directory.mkdir(parents=True, exist_ok=True)
        env, cmake = compiler_environment(architecture)
        compiler = shutil.which('cl.exe', path=env['PATH'])
        configure = [str(cmake), '-S', str(source / 'driverless/runtime'), '-B', str(directory), '-G', 'Ninja',
                     '-DCMAKE_BUILD_TYPE=' + configuration, '-DCMAKE_CXX_COMPILER=' + compiler,
                     '-DNATIVEBOX_DETOURS_ROOT=' + str(detours)]
        compile_command = [str(cmake), '--build', str(directory), '--parallel', '3', '--verbose', '--', '-d', 'keeprsp']
        commands += [configure, compile_command]
        run(configure, source, env, directory / 'configure.log')
        run(compile_command, source, env, directory / 'build.log')
        product = directory / ('nativebox_runtime' + bits + '.dll')
        if not product.is_file():
            raise FileNotFoundError('Linked runtime output is missing: ' + str(product))
        dumpbin = shutil.which('dumpbin.exe', path=env['PATH'])
        for option in ('/headers', '/exports', '/imports', '/dependents'):
            command = [dumpbin, option, str(product)]
            commands.append(command)
            run(command, source, env, directory / (option[1:] + '.log'))
        (directory / 'inputs.json').write_text(json.dumps({'configuration': configuration, 'architecture': architecture,
            'compiler': compiler, 'commands': [configure, compile_command], 'productSha256': sha(product),
            'responseFiles': {str(p.relative_to(directory)): sha(p) for p in directory.rglob('*.rsp')}}, indent=2), encoding='utf-8')
        products[product.name] = product
    if manifest_tools['source_inventory'](source) != inputs:
        raise ValueError('Runtime inputs changed during build; result INVALIDATED')
    offline_pin = lock['dependencies']['offregUserMode']
    offline = source / offline_pin['target']
    if sha(offline) != offline_pin['sha256']:
        raise ValueError('Offline Registry DLL differs from the Microsoft pin')
    for name, product in products.items():
        shutil.copy2(product, destination / name)
    shutil.copy2(offline, destination / 'offreg.dll')
    legal = destination / 'licenses/detours'
    legal.mkdir(parents=True, exist_ok=True)
    shutil.copy2(detours / 'LICENSE.md', legal / 'Detours-4.0.1-MIT.txt')
    source_digest = hashlib.sha256(''.join(value + '  ' + name + '\n' for name, value in sorted(inputs.items())).encode()).hexdigest()
    result = {'contract': 'nativebox.runtime/1', 'productVersion': '0.4.1', 'configuration': configuration,
              'sourceDigest': source_digest, 'provenance': {'detoursVersion': '4.0.1',
              'archiveSha256': receipt['archiveSha256'], 'commit': receipt['commit'],
              'repository': lock['dependencies']['detours']['repository']},
              'artifacts': {name: sha(destination / name) for name in [*products, 'offreg.dll']},
              'commands': commands, 'qualification': 'LINKED_NOT_FUNCTIONALLY_QUALIFIED', 'releaseReady': False}
    temporary = destination / 'runtime-artifacts.pending'
    temporary.write_text(json.dumps(result, indent=2), encoding='utf-8')
    os.replace(temporary, destination / 'runtime-artifacts.json')
    print(json.dumps({'configuration': configuration, 'runtimeManifest': str(destination / 'runtime-artifacts.json'),
                      'artifacts': result['artifacts'], 'releaseReady': False}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--application-build', type=Path, required=True)
    parser.add_argument('--configuration', choices=('Debug', 'Release'), default='Release')
    parser.add_argument('--cmake-child', action='store_true')
    args = parser.parse_args()
    source, destination = args.source.resolve(), args.application_build.resolve()
    if not destination.is_relative_to(source / 'out'):
        raise ValueError('Runtime build destination must remain inside project out')
    destination.mkdir(parents=True, exist_ok=True)
    if args.cmake_child:
        build(source, destination, args.configuration)
    else:
        with (source / '.nativebox-acceptance.lock').open('a+b') as lease:
            msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
            build(source, destination, args.configuration)


if __name__ == '__main__':
    main()
