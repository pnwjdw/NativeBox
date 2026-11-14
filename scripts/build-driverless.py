import argparse
import json
import msvcrt
import os
import runpy
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--configuration', choices=('Debug', 'Release'), default='Release')
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--analyze', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve()
    with (source / '.nativebox-acceptance.lock').open('a+b') as lease:
        msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
        manifest_tools = runpy.run_path(str(source / 'scripts/build-manifest.py'))
        source_before = manifest_tools['source_inventory'](source)
        restore = [sys.executable, '-I', '-B', str(source / 'scripts/restore-driverless.py'), '--source', str(source)]
        if args.cache:
            restore += ['--cache', str(args.cache.resolve())]
        if args.offline:
            restore += ['--offline']
        subprocess.run(restore, check=True)
        vswhere = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        root = Path(subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip())
        vcvars = root / 'VC/Auxiliary/Build/vcvars64.bat'
        if not vcvars.is_file():
            raise FileNotFoundError('Installed MSVC x64/x86 toolchain was not found')
        if any(character in str(vcvars) for character in '\"%\r\n&|<>^!'):
            raise ValueError('Unsupported compiler installation path')
        command = 'cmd.exe /d /u /s /c ""' + str(vcvars) + '" >nul && set"'
        block = subprocess.check_output(command).decode('utf-16-le')
        env = dict(os.environ)
        for line in block.splitlines():
            if '=' in line and not line.startswith('='):
                key, value = line.split('=', 1)
                env[key.upper()] = value
        tools = root / 'Common7/IDE/CommonExtensions/Microsoft/CMake'
        env['PATH'] = str(tools / 'CMake/bin') + os.pathsep + str(tools / 'Ninja') + os.pathsep + env['PATH']
        build = source / 'out' / (('analyze-' if args.analyze else '') + args.configuration.lower())
        cmake = str(tools / 'CMake/bin/cmake.exe')
        configure = [cmake, '-S', str(source), '-B', str(build), '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=' + args.configuration,
                     '-DCMAKE_PREFIX_PATH=' + str(source / '.deps/qt-6.8.3')]
        if args.cache:
            configure += ['-DNATIVEBOX_DOWNLOAD_CACHE=' + str(args.cache.resolve())]
        if args.analyze:
            configure += ['-DCMAKE_CXX_FLAGS=/analyze']
        subprocess.run(configure, env=env, check=True)
        command = [cmake, '--build', str(build), '--parallel', '3']
        subprocess.run(command, env=env, check=True)
        manifest = manifest_tools['create_build_manifest'](source, build, source_before, [configure, command])
        print(json.dumps({'status': 'BUILD_VERIFIED', 'configuration': args.configuration, 'build': str(build),
                          'manifest': str(manifest), 'releaseReady': False}))


if __name__ == '__main__':
    main()
