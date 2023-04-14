# Dataflow Analyzer for Redundant Number Systems

This tool is designed to analyze dataflow in binaries for architectures with a datapath utilizing redundant number systems.
The main command is calculate-dataflow, which does dataflow analysis on binary file and outputs the result as HTML.
Internally it is based on ![Radare2](https://github.com/radareorg/radare2/).
A installation of Radare2 is required for this tool to work.

## Result Examples

TODO

## Building

Note: This tool has only been tested on Linux based platforms and with a limited number of Versions of Radare2.

## Usage

OpenRNSAnalyzer requires an `--input` and `--output` argument, as well as a subcommand, specifying the requested operation.
This should in most cases be `calculate-dataflow`, as the other subcommands are for debugging purposes.

```sh
open-rns-analyzer --input example.elf --output-dir output calculate-dataflow
```

### Examples in `./examples`

In `./examples` are a few simple examples with according Makefile for ease of use.

## Known Bugs and Limitations

### Limitations on ESIL

- Only instructions annotated by Radare2 with ESIL ("Evaluable Strings Intermediate Language") can be analyzed.
- Some rarely used features of ESIL are not supported, e.g. `SKIP`
- Flags are not supported (e.g. `$o`)
- If conditional (`?{ [...] }`) are used, items that were consumed from the stack by operations in the conditional are not considered to be consumed.

### Symbols and Relocations

- Currently the Symbols in the binary are considered, if these are Relocations / PLT entries / dynamic, they are included in the output even if they are not useful to the end user

### Bugs in Radare2

We have experienced some bugs in various versions of Radare2, some of which we implemented workarounds for:

- Some register profiles are incomplete
  - WORKAROUND: We have provided a workaround by patching these into our data structures:
    - RISC-V :: `fflags`, `frm`, `fcsr`, `cycle{,h}`, `time{,h}`, `instret{,h}`)
    - ARM/AArch64 :: `nzcv`, `ffr`
    - PPC :: `f{0-31}`
    - MIPS :: `f{0-31}`
- Broken relocation handling in PowerPC:
  - Relocations can't be avoided when using modern versions of GCC
  - Functions cannot be found in this case
  - WORKAROUND: Addresses can be patched via `--fixup-file`
    - see `test-data/fixup.sh` on how to create these
- On PowerPC some instructions are not properly decoded and invalid ESIL is produced
  - WORKAROUND: Our ESIL processing ignores some forms of broken ESIL strings
- Some versions of Radare2 crash with RISC-V binaries
