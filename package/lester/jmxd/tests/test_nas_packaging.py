#!/usr/bin/env python3
"""Execute package install recipes into /tmp; never install on a running router."""
import argparse
import gzip
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / 'dreamingwrt-web'

def definitions(path):
    text = path.read_text()
    return dict(re.findall(r'^define ([^\n]+)\n(.*?)^endef\s*$', text, re.M | re.S))

def stage(package_dir, package, output, binary_dir):
    definitions_ = definitions(package_dir / 'Makefile')
    recipe = definitions_[f'Package/{package}/install']
    # Use the real package recipe and make expansion, independent of the full
    # OpenWrt build graph. Source files are read from their original tree.
    makefile = output.parent / (package + '.mk')
    makefile.write_text('INSTALL_DIR=install -d -m0755\nINSTALL_BIN=install -m0755\n'
                        'INSTALL_CONF=install -m0600\nINSTALL_DATA=install -m0644\n'
                        'CP=cp -fpR\nRM=rm -f\nTAR=tar\n'
                        f'PKG_BUILD_DIR={binary_dir}\n'
                        'define stage\n' + recipe + '\nendef\n'
                        'all:\n\t$(call stage,' + str(output) + ')\n')
    subprocess.run(['make', '--no-print-directory', '-f', str(makefile)], cwd=package_dir,
                   check=True, stdout=subprocess.DEVNULL)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binaries', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='nas-packaging-') as tmp:
        output = args.output or Path(tmp)
        output.mkdir(parents=True, exist_ok=True)
        packages = ['dreamingos-nas-extra', 'dreamingos-nas-archive', 'dreamingos-nas-web', 'dreamingwrt-web', 'dreamingos-nas-nvr', 'dreamingos-nvr-web']
        ownership = {}
        for package in packages:
            target = output / package
            stage(WEB if package.endswith('-web') else ROOT, package, target, args.binaries)
            paths = set()
            for p in target.rglob('*'):
                if not p.is_file(): continue
                relative = str(p.relative_to(target))
                assert relative not in ownership, (relative, ownership.get(relative), package)
                ownership[relative] = package
                paths.add(relative)
                if p.suffix == '.gz' and p.with_suffix('').is_file() and (
                    '/desktop/nas/' in relative or '/desktop/nvr/' in relative or '/desktop/file-tools/' in relative or
                    any(relative.endswith('/'+app+'.html.gz') for app in ['photos','music','cinema','archive-manager','downloads','image-viewer','media-player','text-editor','nvr'])
                ):
                    assert gzip.decompress(p.read_bytes()) == p.with_suffix('').read_bytes(), p
            (output / (package + '.files.json')).write_text(json.dumps(sorted(paths), indent=2))
        for app in ['photos', 'music', 'cinema', 'archive-manager', 'downloads']:
            assert ownership[f'www/dreamingwrt/app/{app}.html'] == 'dreamingos-nas-web'
        assert ownership['www/dreamingwrt/app/nvr.html'] == 'dreamingos-nvr-web'
        assert ownership['usr/sbin/dreamingos-nvrd'] == 'dreamingos-nas-nvr'
        assert 'nas-extra' not in definitions(ROOT/'Makefile')['Package/dreamingos-nas-nvr']
        for app in ['image-viewer', 'text-editor', 'media-player']:
            assert ownership[f'www/dreamingwrt/app/{app}.html'] == 'dreamingwrt-web'
        assert json.loads((output/'dreamingos-nas-extra/etc/dreamingwrt/nas.json').read_text()) == {}
        for package in ['dreamingwrt-core', 'dreamingwrt-webd', 'jmxd']:
            definition = definitions(ROOT/'Makefile')[f'Package/{package}']
            assert 'nas-extra' not in definition and 'ffmpeg' not in definition and 'libarchive' not in definition
        source_make = (ROOT/'src/Makefile').read_text()
        for line in source_make.splitlines():
            if line.startswith(('all:', 'OBJS ', 'WEBD_OBJS ')):
                assert 'nas/' not in line and 'NAS_' not in line
        service = ROOT/'files/dreamingos-nas.init'
        subprocess.run(['sh', '-n', str(service)], check=True)
        assert '/usr/sbin/dreamingos-nasd' in service.read_text()
        assert not any(s in service.read_text() for s in ['killall', 'rm ', '/etc/init.d/aria2', '/etc/init.d/qbittorrent'])
        print(f'PASS: six real package install recipes; {len(ownership)} non-overlapping files; basic/NAS split, gzip pairs, empty initial config, isolated dependencies and service')
        if args.output: print('staged package roots:', output)

if __name__ == '__main__': main()
