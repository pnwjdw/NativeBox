import argparse
import json
import msvcrt
import os
import runpy
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path


def package(source, deployment_path, output, verifications, offline, build_only=False):
    helpers = runpy.run_path(str(source / 'scripts/build-manifest.py'))
    sha = helpers['sha']
    deployment = json.loads(deployment_path.read_text(encoding='utf-8'))
    stage = Path(deployment['staging'])
    build_manifest = Path(deployment['buildManifest'])
    if sha(build_manifest) != deployment['buildManifestSha256']:
        raise ValueError('Deployment build manifest changed')
    manifest = helpers['validate_staging'](build_manifest, stage)
    if helpers['source_inventory'](source) != manifest['sources']:
        raise ValueError('Packaging inputs differ from the explicit build')
    inventory = {path.relative_to(stage).as_posix(): sha(path) for path in stage.rglob('*') if path.is_file()}
    if inventory != deployment['files'] or not deployment['correspondingSourceIncluded']:
        raise ValueError('Unapproved staging bytes or incomplete corresponding source')
    receipts = []
    for path in verifications:
        record = json.loads(path.read_text(encoding='utf-8'))
        if not record.get('passed') or record.get('sourceDigest') != manifest['sourceDigest']:
            raise ValueError('Verification receipt does not qualify the current source identity')
        for name, value in inventory.items():
            if record.get('binariesBefore', {}).get(name) != value or record.get('binariesAfter', {}).get(name) != value:
                raise ValueError('Verification did not test exact deployed bytes: ' + name)
        receipts.append({'path': str(path), 'sha256': sha(path), 'scope': record['scope']})
    if len(receipts) < 2 and not build_only:
        raise ValueError('At least redirected and managed runtime receipts for exact staging are required')
    output = output.resolve()
    if not output.is_relative_to(source / 'out') or output.exists():
        raise ValueError('Installer output must be a new directory inside project out')
    output.mkdir(parents=True)
    lock = json.loads((source / 'dependencies.lock.json').read_text(encoding='utf-8-sig'))
    tool = lock['tools']['wix']
    verify = runpy.run_path(str(source / 'scripts/verify-nuget.py'))['verify']
    cache = source / '.deps/.downloads'
    tool_root = source / '.deps' / ('wix-driverless-' + tool['version'])
    extensions = {}
    for entry in tool['packages']:
        name = entry['id'] + '.' + tool['version'] + '.nupkg'
        archive = cache / name
        if not archive.is_file():
            if offline:
                raise FileNotFoundError('Pinned packaging cache is missing ' + name)
            url = 'https://api.nuget.org/v3-flatcontainer/' + entry['id'] + '/' + tool['version'] + '/' + name
            with urllib.request.urlopen(url, timeout=40) as response, archive.with_suffix('.partial').open('xb') as stream:
                count = 0
                while block := response.read(1024 * 1024):
                    count += len(block)
                    if count > 64 * 1024 * 1024:
                        raise ValueError('Packaging dependency exceeds its download budget')
                    stream.write(block)
            if sha(archive.with_suffix('.partial')) != entry['sha256']:
                raise ValueError('Packaging archive digest mismatch')
            archive.with_suffix('.partial').replace(archive)
        verify(archive, entry['sha256'], None, '')
        installed = tool_root / entry['id']
        if not installed.exists():
            with zipfile.ZipFile(archive) as compressed:
                compressed.extractall(installed)
        verify(archive, entry['sha256'], installed, '')
        if entry['id'] == 'wix':
            wix = installed / 'tools/net6.0/any/wix.dll'
        else:
            extensions[entry['id']] = installed / entry['dll']
    compiler_env, _ = runpy.run_path(str(source / 'scripts/build-runtime.py'))['compiler_environment']('x64')
    vsroot = Path(compiler_env['VSINSTALLDIR'])
    redist = vsroot / lock['tools']['vcRuntime']['visualStudioRelativePath']
    if sha(redist) != lock['tools']['vcRuntime']['sha256']:
        raise ValueError('VC++ runtime differs from its approved pin')
    escaped = str(redist).replace("'", "''")
    powershell = shutil.which('pwsh.exe') or shutil.which('powershell.exe')
    signature = subprocess.run([powershell, '-NoProfile', '-Command',
                                "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped +
                                "'; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation'){exit 1}; $s.Status.ToString()"],
                               capture_output=True, timeout=30)
    (output / 'vc-redist-signature.log').write_bytes(signature.stdout + signature.stderr)
    if signature.returncode:
        raise ValueError('VC++ runtime Microsoft signature verification failed')
    dotnet = shutil.which('dotnet.exe')
    if not dotnet:
        raise FileNotFoundError('The .NET SDK is required for the pinned WiX build tools')
    msi, bundle = output / 'NativeBox.msi', output / '1.exe'
    version = '0.4.1'
    wxs = source / 'packaging/driverless'
    commands = [[dotnet, str(wix), 'build', '-arch', 'x64', '-nologo', '-d', 'ProductVersion=' + version,
                 '-d', 'PackageDir=' + str(stage), '-bindpath', str(stage), '-intermediatefolder', str(output / 'obj-msi'),
                 '-o', str(msi), str(wxs / 'NativeBox.wxs')]]
    runtime = lock['tools']['vcRuntime']['version'].split('.')
    commands.append([dotnet, str(wix), 'build', '-arch', 'x64', '-nologo',
                     '-ext', str(extensions['wixtoolset.bal.wixext']), '-ext', str(extensions['wixtoolset.util.wixext']),
                     '-d', 'ProductVersion=' + version, '-d', 'WixDir=' + str(wxs), '-d', 'MsiPath=' + str(msi),
                     '-d', 'VcRedist=' + str(redist), *[item for name, value in zip(('Major', 'Minor', 'Build', 'Revision'), runtime)
                                                       for item in ('-d', 'VcRuntime' + name + '=' + value)],
                     '-intermediatefolder', str(output / 'obj-bundle'), '-o', str(bundle), str(wxs / 'Bundle.wxs')])
    records = []
    for index, command in enumerate(commands):
        process = subprocess.run(command, cwd=source, capture_output=True, timeout=240)
        log = output / ('build-' + str(index) + '.log')
        log.write_bytes(process.stdout + process.stderr)
        records.append({'command': command, 'exitCode': process.returncode, 'log': str(log)})
        if process.returncode:
            raise RuntimeError('Packaging failed; inspect ' + str(log))
    if inventory != {path.relative_to(stage).as_posix(): sha(path) for path in stage.rglob('*') if path.is_file()}:
        raise ValueError('Staging changed while packaging; candidate is INVALIDATED')
    report = {'contract': 'nativebox.driverless-candidate/1', 'sourceDigest': manifest['sourceDigest'],
              'qualification': 'BUILD_ONLY_NOT_FUNCTIONALLY_QUALIFIED' if build_only else 'EXACT_DEPLOYED_RUNTIME_RECEIPTS_VERIFIED',
              'deployment': str(deployment_path), 'deploymentSha256': sha(deployment_path),
              'verification': receipts, 'commands': records, 'payloadFiles': inventory,
              'artifacts': {path.name: {'sha256': sha(path), 'bytes': path.stat().st_size} for path in (msi, bundle)},
              'scope': 'Exact tested staging packaged; installer lifecycle, visible GUI, authenticated route and final scan require separate qualification',
              'releaseReady': False}
    (output / 'candidate.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'candidate': str(bundle), 'manifest': str(output / 'candidate.json'), 'artifacts': report['artifacts']}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verification', type=Path, nargs='+', default=[])
    parser.add_argument('--build-only', action='store_true', help='Build an explicitly unqualified engineering candidate; all source/build/staging integrity checks remain mandatory')
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve()
    with (source / '.nativebox-acceptance.lock').open('a+b') as lease:
        msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
        package(source, args.deployment.resolve(), args.output.resolve(), [path.resolve() for path in args.verification], args.offline, args.build_only)


if __name__ == '__main__':
    main()
