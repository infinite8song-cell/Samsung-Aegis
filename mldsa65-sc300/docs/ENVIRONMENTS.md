# Environments

`impl_sc300` supports two clearly separated host environments.

## Mac mini — development / iteration

**Role.** Day-to-day code iteration driven by Claude Code.
QEMU test cycle on the ARMv7-M MPS2-AN385 emulation is the primary
feedback loop.

**Installed tools.**

| Tool                  | Path (default)                                                      |
|-----------------------|---------------------------------------------------------------------|
| arm-none-eabi-gcc 13.3 | `/tmp/arm-gnu-toolchain-13.3.rel1-darwin-arm64-arm-none-eabi`        |
| qemu-system-arm        | `/opt/homebrew/bin/qemu-system-arm`                                  |
| armclang               | *not installed* (library delivery is done on Ubuntu)                |

**Typical workflow.**

```bash
cd impl_sc300
tools/tui.sh          # interactive menu, or:
make -f Makefile.gcc s8
make -f Makefile.gcc qemu_s8
```

Three gates expected: `S1-GATE PASS`, `INT-GATE PASS`, `KAT-GATE PASS`.

## Ubuntu — library delivery / integration

**Role.** Produce the shipped static library with ARM Compiler 6
(`armclang` + `armar`), and exercise/integration-test the library.

**Installed tools.**

| Tool                  | Path (default)                                              |
|-----------------------|-------------------------------------------------------------|
| arm-none-eabi-gcc 13.3 | `/tmp/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi`       |
| qemu-system-arm        | `/usr/bin/qemu-system-arm`                                    |
| armclang               | `/opt/armclang/bin/armclang` (ARM Compiler 6.x, licensed)    |
| armar                  | `/opt/armclang/bin/armar`                                     |

**Typical workflow.**

```bash
cd impl_sc300
tools/tui.sh          # interactive menu, or:
make -f Makefile.armclang.lib                       # LE + long enum
make -f Makefile.armclang.lib BE=1 ENUM=short       # BE + short enum
```

The TUI automatically presents the delivery-oriented menu (library
archive production, matrix validation, armclang QEMU run) on Ubuntu.

## Path auto-detection

`tools/env.sh` detects the host and populates `GNU_TC`, `QEMU`,
`ARMCLANG`, `ARMAR` with sensible defaults per host.  Every path is
override-friendly via the usual `?=` pattern:

```bash
# Override from the shell:
GNU_TC=/my/toolchain make -f Makefile.gcc s8
QEMU=/opt/custom/qemu-system-arm tools/tui.sh
ARMCLANG=/usr/local/armclang/bin/armclang make -f Makefile.armclang.lib
```

## Environment matrix (summary)

| Capability                       | macOS (dev)           | Ubuntu (delivery)    |
|----------------------------------|-----------------------|----------------------|
| Claude-driven edit + QEMU loop   | ✅ primary             | Possible but not the focus |
| QEMU mps2-an385 runs             | ✅                     | ✅                     |
| armclang static library archive  | ✗ (no armclang)       | ✅ primary             |
| Library consumer integration     | (not typical)         | ✅                     |

## When to use which Makefile

| Makefile                   | Purpose                            | Output              |
|----------------------------|------------------------------------|---------------------|
| `Makefile.gcc`             | QEMU test (gcc)                    | `mldsa65_s8.elf`    |
| `Makefile.armclang`        | QEMU test (armclang)               | `mldsa65_s8_ac.elf` |
| `Makefile.gcc.lib`         | Library sanity (gcc)               | `libmldsa65_sc300_gcc_*.a` |
| `Makefile.armclang.lib`    | Library delivery (armclang)        | `libmldsa65_sc300_*.a` |

See `tools/tui.sh` for a guided flow that picks the right Makefile
based on the host and the task.
