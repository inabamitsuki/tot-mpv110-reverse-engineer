# MPV110 / BG2CT loader and secure-boot analysis

Recovered from the 16 MiB low-memory dump (`ram_low_16m.bin`) pulled from the live
box.  The loader is **not** overwritten by the boot logo: a decrypted copy is
resident at `0x00692820`, and an almost identical second copy is at `0x00797280`.
The SM-CPU firmware and two DTB copies are also in this dump.

## 1. What was recovered

| Artifact | Address / source | Size | Notes |
|---|---|---|---|
| SM-CPU firmware | `0x00684364` | 50,076 (`0xC39C`) | reset vector at `0x006843C4`; RTOS for power/IR/CEC/temp/watchdog |
| DTB template #1 | `0x00690708` | 8,443 (`0x20FB`) | `d00dfeed`; only `bootargs = "console=ttyS0,115200"` |
| **loader copy #1** | **`0x00692820`** | **332,312 (`0x51218`)** | active/primary copy, entry `0x006C53BC` |
| chip dispatch table | `0x006E63D4` | 4 x 12 bytes | id `0x3C -> 0x6C7EF0`, id `0x20 -> 0x6BBDF0` |
| DTB template #2 | `0x00795168` | 8,443 | byte-identical to template #1 |
| loader copy #2 | `0x00797280` | 332,312 | first `0x421C0` bytes identical; later data differs (runtime state) |
| final kernel DTB | `0x01000100` (`dtb_64k.bin` + `0x100`) | 8,743 (`0x2227`) | bootargs + initrd patched by loader |
| decompressed kernel | `0x01008000` | `0x840658` | 10 MiB RAM dump; symbolized as `vmlinux.elf` |

Files written in this directory:

- `loader.bin` / `loader.elf` – exact plaintext loader, base `0x00692820`,
  entry `0x006C53BC` (raw ELF for Ghidra/IDA).
- `loader_a.bin` – original 0x51298-byte extraction (0x80 bytes of adjacent
  memory included).
- `sm_firmware.bin` / `sm_firmware.elf` – SM-CPU firmware, base `0x00684364`,
  entry `0x006843C4`.
- `dtb_loader.bin` / `dtb_loader.dts` – DTB template.
- `dtb_kernel.bin` / `dtb_kernel.dts` – final DTB passed to Linux.
- `boot_header_live.bin` / `boot_header_live.txt` – the live boot-image header
  copied from `0x006E6D88`; authoritative fields and SHA1 id.
- `loader_decomp/` – Ghidra headless decompilation and string-xref dumps.

Hashes:

```
loader.bin        MD5 842588655a9979a58bce52129a744552
                  SHA256 7793c0326b7f6f63dca250d9f54ce247717ded9b44e7890a3227926c649dadcd
sm_firmware.bin   MD5 de564800f30ae8ff7548fd28daed350a
dtb_loader.bin    MD5 8697f10951910d52f62ab0b0443aa3e4
dtb_kernel.bin    MD5 425750215da69605a6dad9dfdd26c529
```

## 2. Loader image layout

The boot0 container at `mmcblk0boot0 + 0x10400` is a 0x80-byte secure container
header followed by the encrypted loader.  After the secure engine decrypts it,
the plaintext loader lives at `0x00692820`.

The first words at the load address are a small entry header:

```
00692820: 3f 50 bd e8   E8BD503F   (ldm sp!, {r0-r5,ip,lr} as data)
00692824: 04 f0 5e e2   E25EF004
00692828: bc 53 6c 00   006C53BC   <- entry point
```

The first-stage jumps to `0x006C53BC`.  That function is a chip-revision
dispatcher:

```
uVar1 = *(u32 *)0xF7AD010C;
for (i = 0; i < 4; i++)
    if (*(u32 *)(0x6E63D4 + i*12) == (uVar1 & 0x3ff))
        (*(void (**)(void))(0x6E63D8 + i*12))();
*(u32 *)0xF7AD0110 = uVar1;
```

The table contains ids `0x3C` and `0x20`; the `0x3C` entry
(`0x006C7EF0`) is the likely match for this BG2CT/B0.  The second entry
(`0x20 -> 0x006BBDF0`) is the alternate chip revision.

The two loader copies are at `0x00692820` and `0x00797280`.  Their first
`0x421C0` bytes (code/rodata/string pool) are byte-identical; they diverge in
the data area, consistent with two boot instances (normal/recovery) using the
same code with different runtime state.  The second copy still contains the
*first* copy's entry pointer (`0x006C53BC`), so the second copy is a backup /
data image rather than a separately linked binary.

## 3. Boot flow (from loader decompilation)

Key functions (names assigned during analysis):

| Address | Description |
|---|---|
| `0x006C53BC` | `entry` – chip-revision dispatch described above |
| `0x006BF7DC` | `main` – banner, `bootloader_en`, flash_ts, bootlogo, then boot |
| `0x006BF184` | `boot_images` – normal/recovery selection and boot decision |
| `0x006BD458` | `load_boot_image` – read boot image, decrypt kernel, copy ramdisk |
| `0x006BD124` | `kernel_is_encrypted` – always returns 1 in this build |
| `0x006BD1A0` | `verify_bootimg_sha1` – boot-image SHA1 (integrity only) |
| `0x006BDAA4` | `copy_dtb_template` – copies DTB from `0x690708` to `0x01000100` |
| `0x006BDB28` | `setup_bootargs_dtb` – bootargs, `mrvlsecure`, initrd, DTB patch |
| `0x006BE340` | `send_bootmode_to_sm` – mailbox message to SM CPU |
| `0x006BE3E4` | `read_otp_temperature` – "OTP Temperature: %d celsius degree" |
| `0x006BEB68` | `verify_system_signature` – production-only SHA1 sampling |
| `0x006BF104` | `append_mrvlsecure` – appends ` mrvlsecure=%x` |
| `0x006BF6D0` | `check_bootloader_en` – searches partitions 1..8 for `bootloader_en` |
| `0x006C1A38` / `0x6C1B3C` / `0x6C1AE0` | SHA1 init / update / final |
| `0x006BD148` | SHA1 word byte-swap |
| `0x00694218` | secure-engine decrypt/verify command |
| `0x00694414` | `image_decrypt` wrapper around `0x00694218` |
| `0x0069418C` / `0x006941C8` | container size helpers |
| `0x00692B84` | `memcpy` |
| `0x00695250` | `strcpy` |
| `0x00695848` | `memset` |
| `0x00694A24` | loader `printf` / log |
| `0x00684234` | L2 cache clean/invalidate helper (outside loader) |

`main` prints the banner:

```
RDKDMP BG2CT [Jul  1 2014 13:22:28]
```

then checks `bootloader_en`, initializes FTS/flash and the boot logo
(framebuffer at `0x00B00000`, default 1280x720), and calls `boot_images`.

`boot_images`:

1. Determine boot mode (`normal`, `recovery`, `recovery_backup`) from
   `0xF7FCD02C` and related registers/flags.
2. Call `load_boot_image(mode)`.
3. On failure:
   - if the chip reports production (`*0xF7CC08C8 == 0xDF`): print
     `FATAL ERROR! Bootloader Verify Failed in production chip!` and stop;
   - otherwise: fall back to recovery (`Invalid normal boot image! Boot recovery image...`).
4. On success: `verify_system_signature()` (skipped unless production),
   read OTP temperature, build bootargs/DTB, send boot mode to the SM CPU.

## 4. Kernel container and the hardware secure engine

`load_boot_image` reads the `boot` partition into `0x01000000`, checks the
Android/Image3 magic, and then **always** calls `image_decrypt`:

```
kernel_is_encrypted()  -> 1
image_decrypt(0x01000800, kernel_size, 0x01000800)
```

No software key material for the container is loaded by the loader.
`image_decrypt` calls the secure engine wrapper `0x00694218`, which programs
the engine at `0xF7CC0000`:

```
0xF7CC0004 <- 0xFFFF0001      command / key-select word
0xF7CC0008 <- 0
0xF7CC000C <- size
0xF7CC0010 <- source address
0xF7CC0014 <- destination address
0xF7CC0000 <- 1               start
poll 0xF7CC0000 bit 0
check 0xF7CC0018 & 0xff == 1
check 0xF7CC0020 == 0
```

Before programming it polls `0xF7CCD848 & 3` until the engine reports ready.
If `0xF7CC0000` bit 0 is already set it returns `-4`; otherwise it calls the L2
cache clean/invalidate helper at `0x00684234`, writes the registers above, and
polls bit 0 until the engine clears it.  It then verifies
`0xF7CC0018 & 0xff == 1` and `0xF7CC0020 == 0`, calls the cache helper again,
and returns the container's plaintext length.  Failure paths return negative
codes; there is no infinite spin in the normal flow.

The container header (0x80 bytes) is shared by the loader and kernel images:

```
+0x00  0x00000080              magic
+0x08  24-byte digest          SHA1 + 4 bytes (engine-verified)
+0x40  0x00000050
+0x44  0x00008002
+0x45  0x80                    header length used by the loader
+0x48  16-byte IV
+0x58  4-byte value + zeros    header/CRC field
+0x7C  payload/container size
+0x80  encrypted payload
```

Both the loader (`boot0 + 0x10400`, size field `0x51298`) and the kernel
(`zImage`, size field `0x3d5a30`, file `0x3d5ab0`) use this format.

The engine command `0xFFFF0001`, the header field `0x8002`, and the fact that
the loader writes **no key and no IV registers** indicate that the key/IV
handling is inside the secure engine / OTP.  The key is not present
in the loader, the kernel, the DTB, or the SM firmware.  This confirms the
earlier conclusion: a custom kernel or loader cannot be made bootable without
the device's customer/OTP key or the engine's encryption service.

## 5. `mrvlsecure` and the production check

The loader keeps a pointer at `0x006D4F94`:

```
006D4F94: c8 08 cc f7   -> 0xF7CC08C8
```

`append_mrvlsecure` reads the hardware register at that pointer:

```
bit0 = (reg & 0xF0) == 0xD0
bit1 = (reg & 0x0F) == 0x0F
mrvlsecure = bit0 | (bit1 << 1)
```

The live cmdline says `mrvlsecure=1`, so the register is in the range
`0xD0..0xDE` (high nibble D, low nibble not F).  The production test is:

```
if ((reg & 0xFF) == 0xDF)   // production chip
```

Our box therefore reports **non-production secure state**.  Consequences:

- `verify_system_signature()` returns immediately; the `system` partition is
  not checked.
- A boot-image verification failure falls back to recovery instead of the
  production fatal path.
- The kernel container is still decrypted and digest-checked by the secure
  engine; `mrvlsecure=1` does not disable kernel decryption.

Suggested read-only confirmation on the box:

```
devmem 0xF7CC08C8 32
devmem 0xF7CC0000 32
devmem 0xF7CCD848 32
```

Do not write those registers on the live box.

## 6. System "signature" check

`verify_system_signature` is only reached when `reg & 0xFF == 0xDF`.  It:

1. Finds the `system` partition and reads its first 1 MiB.
2. Checks the squashfs magic `hsqs` at offset 0.
3. Uses the squashfs `bytes_used` field, aligns it to 0x1000, and reads a
   0x800-byte table appended after the filesystem.
4. Decrypts that table with the same secure engine (`image_decrypt`).
5. Interprets the first four bytes as an entry count; each entry is 20 bytes
   (five SHA1 words).
6. Picks 15 pseudo-random 1 MiB blocks from the partition, computes SHA1 of
   each, and compares against the table.

This is **SHA1 integrity sampling**, not a public-key signature.  The table is
encrypted with the same hardware key, so it still cannot be forged without the
engine.  On this non-production box the loader's check is skipped, so the
system partition can be modified without triggering the loader check (other
userspace checks may still exist).

Note: the official TOT OTA (`upgradeMPV110.img`) mounts `/dev/block/mmcblk0p10`
as **ext4**, and the GPT shows a 512 MiB `system` partition.  The squashfs
magic check above therefore describes the loader's production/squashfs path,
not this unit's actual ext4 system.  The check is skipped here because the
secure state is not `0xDF`; do not assume the squashfs signature path applies
to this TOT ext4 build.

The boot-image SHA1 routine (`0x006BD1A0`) similarly compares five SHA1 words
against the boot-image header at `+0x240`.  It is integrity-only and is not on
the normal kernel-loading path in this build; the secure engine's container
digest is the actual kernel authentication.

## 7. Boot image and DTB layout

The authoritative boot-image header is the **live** one the loader reads into
`0x006E6D88`.  It is a standard Android boot header with a 0x800-byte page:

```
+0x00  ANDROID!
+0x08  kernel size        0x3D5AB0
+0x0C  kernel_addr        0x01008000
+0x10  ramdisk size       0x2DE92
+0x14  ramdisk_addr       0x02000000
+0x18  second size        0
+0x1C  second_addr        0x01F00000
+0x20  tags_addr          0x01000100
+0x24  page size          0x800
+0x30  name               empty
+0x40  cmdline            live copy at 0x006E6DC8
+0x240 boot-image SHA1 id (five words)
```

This matches `parts/bootimg.cfg`:

```
bootsize = 0x1000000
pagesize = 0x800
kerneladdr = 0x1008000
ramdiskaddr = 0x2000000
secondaddr = 0x1f00000
tagsaddr = 0x1000100
cmdline = androidboot.console=ttyS0 console=ttyS0,115200 init=/init
          vmalloc=448M androidboot.hardware=mv88de3100 root=/dev/ram0
```

The top-level workspace `boot.img` does **not** match the live header: its
`+0x0C` contains `0x2DE92`, its `+0x10` is zero, and its `+0x14` is
`0x01000100`, i.e. the fields are shifted/missing the kernel address.  Treat
that file as a repacked or incorrectly generated image; use the live header at
`0x006E6D88` and `parts/bootimg.cfg` as ground truth.

Observed layout:

- kernel container at boot-image offset `0x800`, size `0x3D5AB0` (the same
  bytes as the top-level `zImage`); loaded to `0x01000800` and decrypted
  there, then copied to `kernel_addr = 0x01008000` for the zImage
  self-decompressor;
- ramdisk at boot-image offset `0x3D6800`, gzip (`1f 8b 08`), size `0x2DE92`,
  copied to `ramdisk_addr = 0x02000000`;
- second size is zero (second_addr is still `0x01F00000`);
- DTB template copied to `tags_addr = 0x01000100`, then patched with bootargs
  and `linux,initrd-start = 0x02000000`, `linux,initrd-end = 0x0202DE92`.

Final DTB (`dtb_kernel.bin`):

```
chosen {
    linux,initrd-end   = <0x202de92>;
    linux,initrd-start = <0x2000000>;
    bootargs = "nfc_shared androidboot.hardware=mv88de3100 root=/dev/ram0
                androidboot.console=ttyS0 console=ttyS0,115200 init=/init
                vmalloc=448M macaddr=98:bc:57:2e:4a:d6
                emmc_ts.dev_id=8 emmc_ts.size=16777216
                emmc_ts.erasesize=524288 emmc_ts.writesize=512 mrvlsecure=1";
};

memory {
    device_type = "memory";
    reg = <0x00 0x00>;
    linux,usable-memory = <0x1000000 0x25000000>;
};
```

The DTB template has only `bootargs = "console=ttyS0,115200"`; the full
bootargs/initrd properties are added by the loader.  The final DTB is 300
bytes larger than the template.

### Verified `p7.img` boot image

`parts/p7.img` is the real boot image in the user-area dump:

- 16 MiB, standard header, matching the live header above;
- kernel container at `0x800`, size `0x3D5AB0` (the same encrypted `zImage`);
- ramdisk at `0x3D6800`, size `0x2DE92`, gzip;
- boot-image SHA1 id at `+0x240` verifies against the image.

`parts/p4.img` and `parts/p5.img` are the larger recovery/recovery_backup
images (64 MiB, larger ramdisk); `parts/p3.img` is an ext4 factory-setting
partition; `p8` is zero-filled FTS; `p14` is MCID.  Do not overwrite the
factory/MCID partitions or boot0.

The boot-image SHA1 is:

```
SHA1(kernel_data + kernel_size_field +
     ramdisk_data + ramdisk_size_field +
     second_data + second_size_field)
```

and is stored as the raw 20-byte digest at header offset `0x240`.  For a custom
ramdisk, recompute it.  The normal-path loader we traced does not call the
boot-image SHA1 routine, but recovery/other paths may; keeping it valid costs
nothing.

## 8. SM CPU

The SM firmware is a separate ARM RTOS at `0x00684364` (50,076 bytes, reset
vector `0x006843C4`).  Its strings and code cover:

- power/warmup source handling (IR, WiFi/BT, WOL, VGA, CEC);
- CEC;
- IR key handling;
- temperature/ADC;
- watchdog;
- task scheduler ("task name", "task entry", "task run time").

It is **not** the secure-boot/key component.  The loader kicks it off and
communicates through a mailbox (`send_bootmode_to_sm` sends message 5).  The
Linux side has the matching `berlin_sm` driver (`berlin_sm_read/write`,
`bsm_msg_send/recv`, `shm_driver_open_secure`).  No OTP/efuse/secure-key
symbols are present in the kernel.

## 9. Security implications

1. **Recovery succeeded:** decrypted loader, DTB templates, SM firmware, and
   decompressed kernel are all recoverable from the live box's RAM.
2. **Kernel authenticity:** the kernel container is decrypted and
   digest-verified by the hardware secure engine.  A custom kernel or loader
   needs the OTP/customer key or the engine's encryption operation; the key is
   not in software.
3. **Non-production state:** `mrvlsecure=1` means the loader's system signature
   check and production fatal path are disabled.  The loader does not
   separately authenticate the ramdisk on the normal path, and its system
   check is skipped; userland/ramdisk/system modifications may therefore boot,
   although other userspace checks may still exist.  Kernel replacement still
   requires the secure engine.
4. **Hardware engine:** the interface is documented above.  It is a
   decrypt/verify command with an internal key; do not write its registers
   experimentally without a recovery path.
5. **No software key:** the kernel/loader boot path contains no software key
   material for the secure container; the only crypto code is SHA1 for the
   integrity sampling and the engine wrapper.

## 10. Reproducing the extraction

```bash
# low 16 MiB dump from /dev/mem via mmap (already pulled)
python3 - <<'PY'
from pathlib import Path
d = Path('ram_low_16m.bin').read_bytes()
Path('loader.bin').write_bytes(d[0x692820:0x692820+0x51218])
Path('sm_firmware.bin').write_bytes(d[0x684364:0x684364+50076])
Path('dtb_loader.bin').write_bytes(d[0x690708:0x690708+0x20fb])
k = Path('dtb_64k.bin').read_bytes()
size = int.from_bytes(k[0x104:0x108], 'big')
Path('dtb_kernel.bin').write_bytes(k[0x100:0x100+size])
PY

dtc -I dtb -O dts -o dtb_loader.dts dtb_loader.bin
dtc -I dtb -O dts -o dtb_kernel.dts dtb_kernel.bin

# Ghidra headless (JDK 21) import of the raw loader ELF:
JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
  /opt/ghidra/support/analyzeHeadless /tmp/opencode/ghidra_proj TotLoader \
  -import loader.elf -processor ARM:LE:32:v7
```

Ghidra headless decompilation outputs are in `loader_decomp/`.

## 11. Open items

- Read `0xF7CC08C8` on the box to confirm the exact secure-state byte.
- If the goal is a custom kernel, investigate whether the secure engine
  supports an encrypt operation and whether the OTP key usage allows it.
- The first-stage at boot0 `0x0` is still encrypted.  Its runtime copy is not
  present in the low dump (the `0x0` region contains display pixel data); it
  can only be recovered by the engine/BootROM or by analyzing the boot0
  container statically.
- The SM firmware can be analyzed further for power/CEC/IR behavior, but it is
  unrelated to secure boot.
- Kernel-side: `berlin_sm` and `shm_driver_open_secure` are the SM/shared-memory
  interfaces; `mrvlsecure` appears to be a bootarg consumed outside the kernel
  (userspace/SM), not a kernel secure-boot implementation.
