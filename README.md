# TOT MPV110 Firmware Recovery

Firmware recovery and analysis on a locked carrier IPTV box: **TOT MPV110**, built on Marvell's Armada 1500 / **Berlin BG2 CT** (88DE3100) platform (2014, ARMv7).

There is no exposed U-Boot menu, and the kernel is encrypted for a hardware secure engine, so the firmware cannot simply be unpacked and rebuilt. This project documents how the boot chain was recovered from the running device and what it revealed.

| | |
|---|---|
| **SoC** | Marvell Berlin BG2 CT (88DE3100) |
| **Full NAND backup** | 3.7 GiB |
| **Kernel symbols recovered** | 36,936 |
| **Tags** | ARMv7 · Secure boot · Live RAM · UART |

> Research was performed on a device I own. The kernel dump also contains stale userspace data (including Android log strings), so the raw artifacts are treated as sensitive and are not published here.

## How the firmware was obtained

1. **adb over LAN.** USB debugging was enabled in Android settings and a terminal app installed on the box. The daemon was already listening on TCP `5555`. Both USB ports are USB-A host ports (no device link to a PC), so adb was connected over the network.
2. **Rooted the box.** `KingRoot` was used to gain root, then the `su` binary and app from the extracted `UPDATE-SuperSU-v2.46` package were pushed over adb and installed to get a persistent, standard `su`-based root shell:

   ```sh
   adb push UPDATE-SuperSU-v2.46/armv7/su /system/xbin/su
   adb shell chmod 6755 /system/xbin/su
   adb push UPDATE-SuperSU-v2.46/common/Superuser.apk /data/local/tmp/SuperSU.apk
   adb shell pm install /data/local/tmp/SuperSU.apk
   ```
3. **Root shell and full eMMC dump.** With root available, the whole eMMC was written straight to a USB drive:

   ```sh
   adb shell su -c "dd if=/dev/block/mmcblk0 \
     of=/mnt/media/usb.3268-DF68/tot/tot_mpv110_full_backup.img \
     bs=1048576"
   ```

   This produced the 3.7 GiB `tot_mpv110_full_backup.img`, including the GPT and the boot image at `p7`.
4. **UART.** After opening the case, the TX, RX and GND pads were found. A CH341A with `picocom` at 115200 8N1 showed the loader's boot messages and confirmed the chain's load addresses.
5. **Live RAM dumps.** `boot0` and the loader are encrypted, so the NAND image only goes so far. `dd if=/dev/mem` is blocked below `0x01000000` (`valid_phys_addr_range` rejects it), but `mmap(/dev/mem)` is not, so a small static ARM dumper was used instead:
   - 10 MiB dump at `0x01008000`: the live, decrypted kernel
   - 16 MiB low-memory dump at `0x00000000`: decrypted loader, SM-CPU firmware and DTB templates

   Both were pulled over the same adb connection.
6. **Rebuilding what was possible.** The kernel was converted to an ELF with `vmlinux-to-elf` (36,936 symbols), and the recovered loader was disassembled in Ghidra (headless, ARM:LE:32:v7).

## What the dumps contained

| Artifact | Location | Notes |
|---|---|---|
| Decrypted loader | `0x00692820`, 332,312 bytes | Entry `0x006C53BC`; second near-identical copy at `0x00797280` |
| SM-CPU firmware | `0x00684364`, 50,076 bytes | RTOS for power, IR, CEC, temperature and watchdog; reset vector `0x006843C4` |
| DTB template | `0x00690708`, 8,443 bytes | Only `bootargs = "console=ttyS0,115200"` |
| Final kernel DTB | `0x01000100`, 8,743 bytes | Bootargs, initrd range and memory map patched in by the loader |
| Kernel | `0x01008000`, 10 MiB dump | Linux 3.4.60 `#2 SMP PREEMPT`, built 23 Jun 2014; ELF base `0x80008000` |
| Live boot header | `0x006E6D88` | Authoritative kernel and ramdisk load addresses |

### Boot image (live header)

Standard Android header, 0x800-byte pages:

- kernel `0x01008000` (container size `0x3D5AB0`)
- ramdisk `0x02000000` (gzip, size `0x2DE92`)
- tags / DTB `0x01000100`
- cmdline: `androidboot.console=ttyS0 console=ttyS0,115200 init=/init vmalloc=448M androidboot.hardware=mv88de3100 root=/dev/ram0`

The loader banner reads `RDKDMP BG2CT [Jul  1 2014 13:22:28]`.

## Findings

- **The kernel always goes through the hardware secure engine** at `0xF7CC0000` (`0xF7CC0004 <- 0xFFFF0001`). No key or IV is loaded by software; the key lives in OTP / the engine.
- **`kernel_is_encrypted()` always returns 1** in this build, so a custom or mainline kernel decrypts to garbage and cannot boot without the device key or the engine's encryption service.
- **Non-production secure state.** `mrvlsecure=1` means the register at `0xF7CC08C8` is not `0xDF`. The loader therefore skips its system signature sampling and falls back to recovery on a bad boot image instead of halting. (Userland, ramdisk and system changes may boot; kernel replacement still needs the engine.)
- **The boot-image SHA1 is integrity-only.** Actual kernel authentication is the secure engine's container digest.
- **No key material in software.** No OTP, eFuse or secure-boot key symbols exist in the kernel, and `sys_tee` / `trustee_thread` are ordinary Linux code, not a TrustZone interface. The SM firmware is power/IR/CEC/watchdog only, not the secure-boot component.
- **Practical takeaway:** the NAND image gives you the *encrypted* containers, while live memory gives you the plaintext loader and kernel. The running box, not the flash dump alone, is the useful analysis surface.

### Secure container format

Shared by the loader (`mmcblk0boot0 + 0x10400`) and the kernel `zImage`:

```
+0x00  0x00000080   magic
+0x08  24-byte digest (engine-verified)
+0x48  16-byte IV
+0x7C  payload size
+0x80  encrypted payload
```

## Reports

- [Kernel RAM dump analysis](kernel_analysis.md): memory layout, `/dev/mem` behaviour, security findings
- [Loader and secure-boot analysis](loader_analysis.md): boot flow, secure engine and DTB layout

## Open items

- Read `0xF7CC08C8` on the box (read-only) to confirm the exact secure-state byte.
- Investigate whether the secure engine supports an encrypt operation and whether OTP key usage allows it, if a custom kernel is the goal.
- The first-stage at `boot0 + 0x0` is still encrypted and has no runtime copy in the low dump; it can only come from the BootROM/engine or static analysis of the boot0 container.
