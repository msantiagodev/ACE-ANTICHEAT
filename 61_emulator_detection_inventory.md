# Emulator Detection — Full Signature Inventory

ACE's emulator detection in libanogs is comprehensive. Every Android emulator has a name, a fingerprint, and a set of special device files. ACE catalogs them all.

## Emulator product fingerprints (10 known)

These are matched as the result string of `ACE_QueryEmulatorName()`:

| Name | Source | Notes |
|---|---|---|
| `LeiDianX86` | LDPlayer (China) | Uses x86 instruction set |
| `NoxX86` | Nox Player | x86 |
| `NeteaseX86` | Netease MuMu Player | x86 |
| `XiaoYaoX86` | XiaoYao (碰 player) | x86 |
| `TianTianX86` | TianTian Player | x86 |
| `LuDaShiX86` | LuDaShi Player | x86 |
| `TencentX86` | TGPA / TGP / Tencent emulator | x86 |
| `BlueStacksX86` | BlueStacks | x86 |
| `Win11X86` | Windows 11 Subsystem for Android (WSA) | x86 |
| `GoogleX86` | Google Android Studio Emulator | x86 |
| `UnknownX86` | Generic x86 (catch-all) | |
| `NotEmulator` | Real device or undetected | |
| `builtin_nox`, `builtin_bluestacks` | Special markers (variants?) | |

These come from `decrypt(15754)` through `decrypt(16001)` and similar slots.

## System properties checked

ACE queries these `getprop` keys:

| Property | What it reveals |
|---|---|
| `ro.build.characteristics` | "emulator" or "tablet" → emulator hint |
| `ro.vendor.platform: cloudmatrix1/2/3` | Tencent's Cloud Matrix (Chinese cloud Android) |
| `ro.enable.native.bridge.exec` | x86 host translating ARM (Houdini/native_bridge) |
| `ro.dalvik.vm.isa.arm` | The Dalvik ISA — set on x86 if hosted ARM |
| `ro.dalvik.vm.isa.arm64` | Same for ARM64 |
| `ro.dalvik.vm.native.bridge` | Native bridge .so name (e.g., libhoudini.so) |
| `ro.boot.flash.locked` | 0 = unlocked bootloader → root concern |
| `ro.boot.vbmeta.device_state` | "orange" = unlocked, "green" = locked |
| `ro.boot.verifiedbootstate` | Same idea |
| `ro.build.fingerprint` | Full device fingerprint |
| `gsm.version.baseband` | Empty/missing on emulators |
| `ro.build.product` | Product name (e.g., "vbox86p" = VirtualBox) |
| `ro.build.flavor` | Build flavor |
| `ro.product.device` | Device identifier |

Emulators leak through almost any of these. ACE checks all of them.

## Special device files (`/dev/`)

These files only exist on specific emulator/cloud-phone platforms:

| File | Platform |
|---|---|
| `/dev/virtpipe-common-syzs` | Likely a cloud-phone "syzs" service |
| `/dev/virtpipe-common-yyb` | YYB (Tencent App Treasure) — cloud phone? |
| `/dev/virtpipe-common-syzsaow` | (Variant) |
| `/dev/virtpipe-sec` | **7 callers** — heavily used; cloud-phone secure pipe |
| `/dev/binder` | Standard Android IPC; checked for tampering |
| `/dev/random` | Standard; checked for entropy fingerprint |
| `/dev/com.koushikdutta.superuser.daemon` | **Koush SuperUser daemon** = root |

## Procfs files

| File | What ACE reads |
|---|---|
| `/proc/cpuinfo` | Hardware string (matches "ranchu" = Goldfish, "qemu" = QEMU) |
| `/proc/meminfo` | Total memory size (small = emulator) |

## CPU fingerprint parsing

ACE parses `/proc/cpuinfo` looking for the `Hardware` field. Emulators typically show:
- `Hardware : ranchu` (Google emulator)
- `Hardware : goldfish` (older Google emulator)
- `Hardware : qemu` (generic)
- `Hardware : Genymotion virtual device`

Real devices show:
- `Hardware : qcom` (Qualcomm)
- `Hardware : MT6XXX` (MediaTek)
- `Hardware : tegra` (Nvidia Tegra)
- etc.

## Strategy: `antiemulator` (master flag)

The master "antiemulator" strategy (string ID 16551) governs whether emulator detection runs. Plus:
- `is_x86` (7124)
- `is_x86_env` (7935)
- `x86` (46142)
- `scan_x86` (13130)
- `scan_x86_by_mem` (13141)
- `x86_module_cnt` (13177)
- `x86_bypass` (13295)
- `x86_sys_scan` (46123)

The presence of `x86_bypass` is interesting — does ACE have an INTERNAL bypass for known-good x86 environments (like authorized cloud servers)?

## ACE's full device fingerprint format

```
root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d
```

For our MuMu Pro 12 environment:
- `root=0` (or 1 if Magisk detected)
- `x86=1` (yes, x86 host running ARM via Houdini)
- `apk_cnt=N` (number of APKs installed)
- `adb=1` (likely yes, debugging is enabled)
- `machine=NeteaseX86` (MuMu = Netease)
- `sys_ver="Android 9"` etc.
- `root_record=N` (count of root tools detected)

This fingerprint is sent in detection reports.

## TenC vendor blobs (Tencent's vendor driver shims)

```
/vendor/lib/hw/audio.primary.tenc.so
/vendor/lib/hw/audio.primary.tenc_legacy.so
/vendor/lib/hw/gatekeeper.tenc.so
/vendor/lib/hw/gps.tenc.so
```

These are Tencent's vendor-level drivers used in TencentX86 cloud phones. ACE detects them to identify TenC environments.

## Sensor fingerprinting

`android/hardware/Sensor` and the sensor list — emulators typically have fewer/different sensors than real devices. ACE iterates them:

```c
// Java side
SensorManager mgr = (SensorManager)getSystemService(SENSOR_SERVICE);
List<Sensor> sensors = mgr.getSensorList(Sensor.TYPE_ALL);
// emulator: ~3-5 sensors (accelerometer, gyro, magnetometer)
// real device: 15-30+ sensors
```

## Camera fingerprinting (CameraCharacteristics)

ACE uses `android.hardware.camera2.CameraCharacteristics` to query camera capabilities. Emulators have very limited (or fake) cameras.

## Bypass implications

For our deployed MuMu setup, ACE WILL detect:
- `x86_env=1` (we're running on x86 host)
- `Hardware: ...` showing a non-real-device string
- Possibly `/dev/virtpipe-*` files
- Possibly some TenC vendor blobs

These together = "emulator detected" and various scanner bits get set in `g_anort_detection_flags`.

But ACE's response to "emulator detected" depends on the game's policy:
- For Division Resurgence (UE4 mobile), emulator play may be allowed (subject to limitations)
- The actual ban/kick decision is server-side

Our bypass strategy:
- We DON'T spoof emulator detection — let ACE see we're on emulator. The game allows it.
- We DO neutralize cheat detection (Tier 4 = drop scan results) so cheats don't leak.

If emulator detection becomes a real ban path, we'd need to spoof:
- `getprop` calls (return real-device values)
- `/proc/cpuinfo` (return real-device CPU string)
- `/dev/` listing (hide virtpipe files)
- Sensor enumeration (return realistic sensor count)

This would be Tier 12+ — currently not deployed.

## To-do

- Decompile `ACE_QueryEmulatorName` to see exact match logic
- Find IDA function for `/dev/virtpipe-sec` access — what's it used for?
- Cross-reference `cloudmatrix*` with Tencent's Cloud Matrix product (likely cloud Android instances)
- Document `x86_bypass` purpose (is there an authorization mechanism?)
