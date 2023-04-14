#!/usr/bin/env python3

from pathlib import Path
from glob import glob
import os
import yaml

try:
    G_PREFIX = os.getenv('G_PREFIX')
except:
    G_PREFIX = ""


programms = [Path(i) for i in glob('embench-src/*/*.c')]
with open('config.yml') as f:
    archs = yaml.safe_load(f)
for arch, (compiler, cflags, objcopy, strip, libdir, run_fixup) in archs.items():
    if libdir is not None:
        libdir = libdir.format(G_PREFIX)
    for programm in programms:
        Path(f'{arch}/elf/').mkdir(parents=True, exist_ok=True)
        if libdir:
            print(f'build {arch}/elf/lib{programm.name}-{arch}.elf: compile {programm}')
        else:
            print(f'build {arch}/elf/lib{programm.name}-{arch}.elf: compile-native {programm}')
        print(f'  cc={compiler}')
        if libdir:
            print(f'  libdir={libdir}')
        if objcopy:
            print(f'  objcopy={objcopy}')
        if strip:
            print(f'  strip={strip}')
        if cflags:
            print(f'  cflags={cflags}')
        if run_fixup:
            print(f'build {arch}/output-{arch}-{programm.name}/: run-fixup {arch}/elf/lib{programm.name}-{arch}.elf')
        else:
            print(f'build {arch}/output-{arch}-{programm.name}/: run {arch}/elf/lib{programm.name}-{arch}.elf')
