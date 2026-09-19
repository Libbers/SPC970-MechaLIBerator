# SPC970-MechaLIBerator

PS2SDK application for dumping the 256 KiB pre-Dragon SPC970 MechaCon ROM
window at `FC0000-FFFFFF` to USB storage.

> [!CAUTION]
> **THIS TOOL CAN DAMAGE YOUR PLAYSTATION 2.** It intentionally performs
> low-level MechaCon and NVRAM writes. Using it on unsupported hardware,
> resetting or losing power while it runs, removing the USB drive, or hitting
> an unexpected software or storage failure could corrupt console data, leave
> the PS2 unable to operate normally, or require hardware-level repair. Use it
> entirely at your own risk.

> **Back up every file written under `SPC970/` before deleting, renaming, or
> separating anything.** Session and recovery files may be needed to resume a
> dump or restore NVRAM.

## Build

Install PS2SDK, set its environment variables, and put the EE, IOP, and DVP
tools on `PATH`:

```sh
export PS2DEV=/path/to/ps2dev
export PS2SDK="$PS2DEV/ps2sdk"
export PATH="$PS2DEV/ee/bin:$PS2DEV/iop/bin:$PS2DEV/dvp/bin:$PATH"
make clean
make
```

The output is `SPC970-MechaLIBerator.elf`.

## Use

1. Remove any disc, close the tray, and let the drive stop.
2. Launch the ELF with a writable USB drive attached.
3. Wait for the initial capture to finish.
4. Press **X** to start or resume, **Square** to restore an available NVRAM
   backup, or **Circle** to exit.
5. Hold **X** continuously for five seconds to fill the confirmation bar before
   any MechaCon write. Releasing X resets the bar; Circle cancels.
6. Wait for the final screen before resetting, then back up the complete
   `SPC970/` directory.

The disc is not used. An open, moving, or occupied drive can delay MechaCon
commands and change the live configuration data used for layout detection, so
the dumper asks you to confirm that the drive is empty and stopped before it
continues.

The initial capture reads the console without modifying it and saves:

- `NVRAMnn.BIN`: the complete 1,024-byte NVRAM image;
- `PROBEnn.BIN`: the raw SCMD `0x41` configuration window;
- `NVRAMnn.TXT`: capture details and CRC32 values.

Numbered captures are create-only and never replace an older capture. The
dumper reports a specific error if all 100 slots are occupied.

## How the exploit works

The MechaCon is the PS2's drive and security controller. The dumper uses these
secure commands (SCMDs):

| SCMD | Arguments | Use |
| --- | --- | --- |
| `0x03` | `00` | Read the raw MechaCon version. |
| `0x0A` | `address_hi address_lo` | Read one 16-bit NVRAM word. |
| `0x0B` | `address_hi address_lo value_hi value_lo` | Restore one NVRAM word. |
| `0x40` | `00 02 10` | Open region 2 for a normal 16-block configuration read. |
| `0x41` | none | Read the next 16-byte configuration block. |
| `0x40` | `01 02 00` | Open region 2 for the wrapped configuration-write path. |
| `0x42` | one 16-byte block | Stage or trigger the internal copy worker. |
| `0x43` | none | Close the configuration session and report when the worker is done. |

First, `0x40`, sixteen `0x41` calls, and `0x43` capture the live configuration
window. Stable bytes identify a supported worker layout. The dumper also reads
all NVRAM with `0x0A`, then saves and verifies that original image on USB before
it attempts the exploit.

The key is SCMD `0x40` with arguments `01 02 00`. Its zero block count lets
successive `0x42` writes wrap into the nearby worker fields. Each `0x42` block
has 15 data bytes followed by their 8-bit checksum. Layout-specific fields are
set to the SPC970 ROM source address, a zero source offset, the word count, and
a destination in one of four NVRAM banks. A final `0x42` sets the worker's
trigger flags, and `0x43` is polled until the copy finishes.

The copied words are read from NVRAM with `0x0A`, placed in SPC970 address order,
and written to USB as one 256-byte ROM chunk. The dumper rotates through the
four NVRAM banks to reduce wear. When validation or dumping stops, the original
words are restored with `0x0B` and read back with `0x0A` until the complete
NVRAM baseline matches.

## Supported layouts

The layout is detected from stable bytes in the live SCMD `0x41` window. Model
and version strings are recorded but do not select a layout.

| Report name | Known hardware |
| --- | --- |
| `standard-fields` | SCPH-18000 and CXP102064-era consoles |
| `fields-2-bytes-earlier` | CXP103049 marker `00` |
| `shifted-marker-01-pointer-at-6` | CXP103049 marker `01`, including SCPH-39001 |

Unknown layouts are captured and stopped before any MechaCon write. A new
session must pass a small ROM-copy test and complete NVRAM restoration before
the full dump can begin. Shifted layouts are checked through all four NVRAM
banks.

Validated hardware includes:

- SCPH-18000, raw version `00 02 02 00`, ROM revision 1.19;
- DTL-H30101, CXP102064-705R, raw version `81 02 0D 00`, ROM revision 1.36;
- SCPH-39001, raw version `01 03 06 00`, CXP103049-401GG layout.

See the [public SPC970 compatibility table](https://github.com/spc970-dumper-union/spc970-dumps-public)
for the broader community status.

The early SCPH-10000/CXP101064-605R worker layout is intentionally unsupported
at this time.

## Dump and resume

New dumps use the lowest free session number from `000` through `099`. Each
resumable session consists of four files with the same number:

- `SPC970_ROM_000.BIN`: the raw 262,144-byte ROM image;
- `SPC970_ROM_000.MAP`: session metadata, chunk CRC32 values, and progress;
- `SPC970_ROM_000.NVRAM`: the checked NVRAM restoration baseline;
- `SPC970_ROM_000.TXT`: current state, progress, and final CRC32.

The validation files use the same number, such as
`SPC970_VALIDATION_000.TXT`. Keep matching file numbers together. Session IDs
also bind each ROM, map, and NVRAM set, and every completed ROM chunk is checked
before resume.

The dumper scans every session when the USB moves to another PS2. It resumes or
offers recovery only for one safely matching session. When no matching session
exists and the occupied sessions are safely identified as belonging elsewhere,
it leaves them untouched and starts in a new create-only slot. Ambiguous,
damaged, incompatible, or unsafe incomplete files disable starting until they
receive attention. A verified baseline left by interrupted setup can continue
after NVRAM is restored. A specific error is shown when all 100 dump slots are
occupied.

Existing unnumbered `SPC970_ROM.*` sessions remain readable for resume and
recovery, but new sessions are always numbered and never overwrite them.

A new session saves and verifies its original NVRAM baseline before the first
MechaCon write. Each ROM chunk, its CRC, and its completion marker are written
and verified in crash-safe order. NVRAM is restored and verified after a
controlled stop or completed dump.

## NVRAM recovery

If validation, dumping, or restoration is interrupted, the next run offers the
saved session baseline when the console identity can be established safely.
Press **Square**, then hold **L1+R1** and press **X**. Only differing words are
written, and the complete restored NVRAM is verified.

To request an older numbered backup, rename only `NVRAMnn.BIN` to
`NVRAMnn_RESTORE.BIN` and leave its matching `NVRAMnn.TXT` beside it. Only one
restore marker may exist. The backup and report must match the live console and
pass their version, model, filename, and CRC checks.

The current resume and recovery paths have passed host-side fault injection.
Power loss during validation or NVRAM restoration, interrupted USB writes, and
USB capacity failures still require confirmation on real hardware.

## License

The dumper source and documentation are available under the [MIT License](LICENSE).
PS2SDK, embedded IRX modules, and other toolchain components retain their upstream
licenses.
