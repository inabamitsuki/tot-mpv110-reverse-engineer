# TOT MPV110 / Marvell Berlin BG2CT — kernel RAM dump analysis

Date: 2026-10-21

## Dump

- File: `546/ram_kernel_10m.bin`
- Size: `10,485,760` bytes (10 MiB)
- MD5: `4e972c8262c40df76fde8e90733f5ade`
- Physical range: `0x01008000` – `0x01A08000`
- Virtual range: `0x80008000` – `0x80A08000` (physical offset `0x7F000000`)
- First word: `0xE321F0D3` = `msr cpsr_c, #0xd3` (kernel entry, matches `devmem 0x01008000 32`)

This is the **live, decrypted kernel in RAM**, not the encrypted `zImage` container.
The dump also contains runtime `.bss` data and some stale/free-memory content
(including Android userspace log strings), so treat the file as sensitive.

## Kernel identity

- Linux `3.4.60` `#2 SMP PREEMPT`
- Built `Mon Jun 23 14:08:35 CST 2014` by `root@appteam2-desktop`
- GCC `4.6.x-google 20120106 (prerelease)`
- Architecture: ARMv7, 32-bit little-endian
- Extracted with `vmlinux-to-elf` from the raw dump

Output:

- `546/vmlinux.elf`
- Size: `11,858,044` bytes
- SHA-256: `0d7ce3fd6fe1b5098e3f93c1cd266c02fc99c3c311eee600125cd24226b8572b`
- ELF32 ARM, base `0x80008000`, `36,936` symbols
- `_stext` = `0x80008000`
- `_etext` = `0x806a1000`
- `_einittext` = `0x806c7424`
- `start_kernel` = `0x806a1584`
- Entry point in the ELF: `0x806a1584` (`start_kernel`)

The ELF can be opened directly in Ghidra/IDA. Load it as ELF32 ARM little-endian at
base `0x80008000`; symbols are already present.

Note: `vmlinux-to-elf` also created a synthetic `NOBITS .bss` at `0x80a08000`.
That section is **not** the real kernel `.bss`; it is an artifact of the 10 MiB
dump size. The real `.data`/`.bss` are inside the `.kernel` section.

## Real kernel layout

From `s1.txt` (`Virtual kernel memory layout`) and `/proc/iomem`:

```
.text : 0x80008000 - 0x806a1000   (6756 kB)
.init : 0x806a1000 - 0x806d3bc0   ( 203 kB)
.data : 0x806d4000 - 0x80715440   ( 262 kB)
.bss  : 0x80715464 - 0x80848658   (1229 kB)
```

Kernel end: virtual `0x80848658` = physical `0x01848658`.

`/proc/iomem`:

```
01000000-25ffffff : System RAM
  01008000-016a0fff : Kernel code
  016d4000-01848657 : Kernel data
```

The 10 MiB dump ends at physical `0x01A08000`, i.e. **beyond** kernel `_end`
(`0x01848658`). The whole kernel, including `.data` and `.bss`, is present.
An earlier note that the kernel extended to `0x80e48658` was incorrect; that
address belongs to a different layout, not this boot.

## Security-relevant findings

- No OTP, eFuse, secure-boot key, or customer-key symbols are present in the
  kernel symbol table.
- `sys_tee` (`0x800eee04`) is the standard Linux pipe `tee(2)` syscall; it calls
  `fget_light` and `get_pipe_info`. It is **not** a TrustZone/TEE interface.
- `trustee_thread` (`0x80520b20`) sits among CPU hotplug/timer code; it is not a
  secure-world TEE.
- `mrvlsecure=1` is a bootloader-supplied command-line token. The kernel image
  does not contain that string in its static data; the key/decrypt/verify logic
  is in the loader, not the kernel.
- The loader container in `mmcblk0boot0` (`0x10400`, payload `0x51298`) remains
  encrypted/signed. Its key is external (OTP/key ladder), not in boot0 metadata
  and not in the kernel.

## Why `dd` failed but `devmem` worked

Disassembly of the `/dev/mem` path:

- `read_mem` (`0x8027d0b8`) calls `valid_phys_addr_range` (`0x800196c8`).
  - `valid_phys_addr_range` rejects any physical address below `0x01000000`.
  - This is why `dd if=/dev/mem` cannot read low memory (and can fail on
    `/dev/mem` reads that cross invalid ranges).
- `mmap_mem` (`0x8027d210`) calls `valid_mmap_phys_addr_range` (`0x80019708`).
  - It only checks `pfn + size <= 0x100000` pages (4 GiB).
  - Low physical memory is therefore mappable through `mmap(/dev/mem)`.
- `busybox devmem` uses `mmap`, which is why `devmem 0x01008000 32` returned
  `0xE321F0D3` while `dd` failed.

Consequence: the reserved low 16 MiB (`0x00000000`–`0x00FFFFFF`) can be dumped
with a small mmap dumper. That region is where a decrypted loader/stage-1 and/or
the injected DTB may still reside.

## Prepared next dumps

Three variants were created by patching the original static ARM dumper:

- `546/memdump_low16`
  - maps physical `0x00000000`, length `0x01000000` (16 MiB)
  - captures low reserved memory: possible decrypted stage-1/loader at `0x0`,
    and any DTB below `0x01000000`
  - SHA-256: `cf52e4febbf71e91c6a9a14d91f319d7af377bfb63029e4a11451acb68429589`
- `546/memdump_dtb64k`
  - maps physical `0x01000000`, length `0x00010000` (64 KiB)
  - captures the injected DTB expected at `0x01000000` (FDT magic
    `0xD00DFEED`), plus the first 56 KiB of the kernel
  - SHA-256: `0142763a37ccebc9cfcdd40c32af196d2f94e22773cf12faa537e41447bdd7d9`
- `546/memdump_kernel16`
  - maps physical `0x01008000`, length `0x01000000` (16 MiB)
  - optional; **not needed** because the existing 10 MiB dump already covers
    kernel `_end` at `0x01848658`

Suggested device commands (run as root, same environment where the first
`memdump` worked):

```sh
# quick sanity checks
busybox devmem 0x0 32
busybox devmem 0x01000000 32

# low reserved memory (possible decrypted loader / stage-1 / DTB)
/data/local/tmp/memdump_low16 > /data/local/tmp/ram_low_16m.bin

# DTB at 0x01000000
/data/local/tmp/memdump_dtb64k > /data/local/tmp/dtb_64k.bin
```

Then pull:

```sh
adb pull /data/local/tmp/ram_low_16m.bin 546/
adb pull /data/local/tmp/dtb_64k.bin 546/
```

Expected:

- `devmem 0x01000000 32` → `0xEDFE0DD0` if the DTB starts there.
- `devmem 0x0 32` → an ARM instruction (loader/stage-1) or `0x00000010`
  (still-encrypted stage-1 header), or `0x00000000` if the loader cleared it.
- If `mmap` at `0x0` fails or SIGBUSes, retry from `0x1000` (a fallback variant
  can be generated).

## What to do with the low dump

If the decrypted loader survived at `0x0` (or elsewhere in low memory), search
the 16 MiB dump for:

- ASCII `RDKDMP`
- `Kernel image decrypt`
- `verify Kernel image`
- `bootloader_en`
- `UD3"`
- AES/SHA constants and key-loading code

If found, carve the loader and disassemble it with the same workflow. That is
the component that implements secure boot and holds the customer-key logic.
If the low dump is all zeros or random, the loader was cleared/overwritten and
the remaining option is static analysis of the encrypted boot0 container plus
hardware behavior.

The DTB dump will give the actual bootargs/partition nodes and confirm whether
`mrvlsecure=1` is only a bootloader token or is consumed by a kernel driver.

## Update 2026-10-21: loader recovered, DTB and boot-header corrections

- The final DTB is at **`0x01000100`**, not `0x01000000`; its totalsize is
  `0x2227` (8,743).  `dtb_64k.bin` contains it at offset `0x100`.
- The decrypted loader is in low RAM at **`0x00692820`** (second copy at
  `0x00797280`); exact plaintext size `0x51218`, entry `0x006C53BC`.
  Extracted as `loader.bin` / `loader.elf`.
- The loader's kernel decrypt is a hardware secure-engine operation at
  `0xF7CC0000` (`0xF7CC0004 <- 0xFFFF0001`); no software key/IV is loaded.
  The key is in OTP/the engine.  See `loader_analysis.md`.
- The live boot-image header is at **`0x006E6D88`** and is a standard Android
  header: kernel `0x01008000`, ramdisk `0x02000000`, size `0x2DE92`, tags
  `0x01000100`, page `0x800`.  This matches `parts/bootimg.cfg`.
- The top-level workspace `boot.img` header does **not** match: its fields are
  shifted/missing the kernel address.  Do not use it as a repack template;
  use `boot_header_live.bin` / `boot_header_live.txt` and `parts/bootimg.cfg`.
- The SM firmware at `0x00684364` is the power/IR/CEC/temp/watchdog RTOS, not
  the secure-boot component.  The kernel-side interface is the `berlin_sm`
  driver (`bsm_msg_send/recv`).
