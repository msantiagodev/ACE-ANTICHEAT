# Master String Dictionary — All Decoded Strings by Category

A single-file reference for every interesting decoded string from libanort + libanogs. Organized by what they reveal about ACE.

## Tencent game packages ACE knows about

ACE has signatures for ~30+ Tencent games. This means ACE's detection runtime can identify which Tencent game is active and apply game-specific rules:

| String ID (libanogs) | Package | Game |
|---|---|---|
| 18812 | `com.tencent.weishi` | WeiShi (TikTok-clone) |
| 20794 | `com.tencent.mm` | WeChat |
| 20811 | `com.tencent.mobileqq` | QQ |
| 20847 | `com.tencent.gamestick` | Game Stick (controller app) |
| 33510 | `com.tencent.tptest` | TP test (TencentProtect dev) |
| 58961 | `com.tencent.pao` | Pao game |
| 58979 | `com.tencent.feiji` | Feiji game |
| 58999 | `com.tencent.tmgp.cf` | CrossFire Mobile |
| 59021 | `com.tencent.KiHan` | KiHan |
| 59041 | `com.tencent.gwgo` | GWGo |
| 59060 | `com.tencent.tmgp.speedmobile` | QQ Speed |
| 59091 | `com.tencent.tmgp.WePop` | WePop |
| 59116 | `com.tencent.tmgp.pubgmhd` | **PUBG Mobile HD / Game for Peace** |
| 59143 | `com.tencent.af` | AF |
| 59160 | `com.tencent.hyrzol` | HyRzol |
| 59181 | `com.tencent.ig` | **PUBG Mobile (international)** |
| 59237 | `com.tencent.mf.uam` | mf.uam |
| 59303 | `com.tencent.tmgp.dnf` | **Dungeon Fighter Mobile** |
| 59326 | `com.tencent.tmgp.sgame` | **Honor of Kings (Wangzhe Rongyao)** |
| 59351 | `com.tencent.tmgp.qqx5` | QQ X5 |
| 59375 | `com.tencent.tmgp.mt4` | MT4 |
| 59398 | `com.tencent.tmgp.gnyx` | GnYX |
| 59422 | `com.tencent.tmgp.dfm` | **Delta Force Mobile?** |
| 59486 | `com.tencent.iglite` | PUBG Mobile Lite |
| 59614 | `com.tencent.tmgp.codev` | **Call of Duty Mobile (Tencent)** |
| 59639 | `com.tencent.letsgo` | LetsGo |

## Heartbeat protocol strings

| ID | String |
|---|---|
| 11373 | `ObjVM_HBv2_%d` |
| 11389 | `ObjVM_HBv2_%d_%lx_%lx_%lx` |
| 12385 | `G_HB_ASK_K` (host → VM question) |
| 12398 | `G_HB_ASK_D` (host → VM question data) |
| 12411 | `G_HB_K_RESP` (VM → host response) |

## Magic config flags

| ID | String | Where used |
|---|---|---|
| 12015 | `enable_gp7_exit_group` | `JNI_ACE_CommandDispatch` "stop" kill criterion |
| 12086 | (string at JNI ProcessCommand) | command handler |
| 12117 | (string at validator chain) | validator |
| 12433 | (string at config validator) | validator |
| 11969 | `stop` | The "stop" command itself |
| 11935 | (version query) | first command compared in JNI |
| 11920 | (config query prefix) | partial-match prefix |

## VM module names

| ID | String | Purpose |
|---|---|---|
| 11259 | `vm_main.img` | Main detection VM module |
| 11273 | `vm_hb.img` | Heartbeat VM module |
| 11285 | `builtin` | Embedded source name |
| 11309 | `shell_rom.zip` | Filtered (skipped) module |
| 11325 | `a64.dat` | Inner ZIP entry |
| 11417 | `timeout_looper.img` | Timeout looper VM module |
| 11976 | `vm_gp7worker.img` | GP7 worker VM module |
| 11995 | `vm_gp7service.img` | GP7 service VM module |

## libart.so internals (runtime DEX loader)

| ID | C++ symbol (mangled) | Purpose |
|---|---|---|
| 9642 | `libart.so` | Library name |
| 9654 | `_ZN3art7DexFile4OpenEPKhjRKNSt3__1...EEjPKNS_10OatDexFileEbPS9_` | Open DEX from bytes (32-bit len, OatDexFile) |
| 9772 | (same with `m`) | 64-bit len variant |
| 9890 | `_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__1...EjPNS_6MemMapEPKNS_10OatDexFileEPS9_` | OpenMemory variant (OatDexFile) |
| 10026 | (same with `m`) | 64-bit len variant |
| 10162 | `_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__1...EjPNS_6MemMapEPKNS_7OatFileEPS9_` | OpenMemory (OatFile) |
| 10294 | (same with `m`) | 64-bit len variant |

## Frida detection paths

| ID | Path |
|---|---|
| 2173 | `frida-agent` (libanort) |
| 2889 | `/data/local/tmp/frida-server` |
| 2920 | `/data/local/tmp/re.frida.server` |
| 2954 | `/system/bin/frida-server` |
| 5267 | `frida` |
| 5288 | `frida-gadget` |
| 27374 (libanogs) | `/data/local/tmp/12re.34frida.56server78` (renamed Frida) |
| 27431 | `/data/local/tmp/re.frida.server` |
| 27492 | `/data/local/tmp/frida-server` |
| 27465 | `/system/bin/frida-server` |

## Root tools

| ID | Path/marker |
|---|---|
| 29135 | `/data/data/com.topjohnwu.magisk` |
| 35101 | `/data/data/eu.chainfire.supersu` |
| 35242 | `/data/data/com.topjohnwu.magisk` |
| 35276 | `/data/data/com.kingroot.kinguser` |
| 35566 | `/system/etc/init.d/99SuperSUDaemon` |
| 35603 | `/dev/com.koushikdutta.superuser.daemon` |
| 35759 | `/su/bin` |

## Emulator product fingerprints (libanogs)

| ID | Name | Emulator |
|---|---|---|
| 15754 | `LeiDianX86` | LDPlayer (China) |
| 15781 | `NoxX86` | Nox |
| 15809 | `NeteaseX86` | MuMu/Netease |
| 15840 | `XiaoYaoX86` | XiaoYao |
| 15872 | `TianTianX86` | TianTian |
| 15904 | `LuDaShiX86` | LuDaShi |
| 15935 | `TencentX86` | TencentTGB |
| 15969 | `BlueStacksX86` | BlueStacks |
| 16001 | `Win11X86` | WSA |
| 16029 | `GoogleX86` | Google AVD |

## TSS / TenC vendor strings

| ID | String |
|---|---|
| 33682 | `TssSDKInit` |
| 33695 | `TssSDKSetUserInfo` |
| 33715 | `TssSDKOnPause` |
| 33731 | `TssSDKOnResume` |
| 33748 | `TssSDKGetReportData` |
| 33770 | `TssSDKDelReportData` |
| 33792 | `TssSDKOnRecvData` |
| 33875 | `tss_sdk_init_start` |
| 33896 | `tss_sdk_init_finish` |
| 33971 | `tss_connect_count` |
| 1034 (libanort) | `tss_ano.dat` |
| 761 | `tss_cs2.dat` |
| 997 | `tss_tcj.dat` |
| 52615 | `tss_fap_info.dat` |
| 52634 | `tss_dev_info.dat` |
| 52653 | `tss_flag_info.dat` |

TSS = Tencent Safety SDK. ACE is one component; TSS is the broader anti-cheat framework.

## Detection report format strings (libanogs)

| ID | Format |
|---|---|
| 32413 | `root=%d\|x86=%d\|apk_cnt=%d\|adb=%d\|machine=%s\|sys_ver=%s\|root_record=%d` |
| 43543 | `%s\|emu=%d\|report=%d\|locale=%d` |
| 13027 | `TssIoCtl.emm:%d,n:%s,p:%s,b:%u` |
| 14876 | `TssIoCtl.uts:%d,n:%s,p:%s,b:%u` |
| 53946 | `TssIoCtl.emm_ex:%d,n:%s,p:files_dir=%s\|wait=%d,b:%u` |
| 1877 (libanort) | `tss_main:%s,0x%lx` |

## ACE persistent files

| ID | File |
|---|---|
| 6305 | `%s/xx_tmp_guard.dat` |
| 7035 | `%s/ace_shell_db.dat` |
| 7113 | `%s/SpeedUpCCH.dat` |
| 7153 | `%s/ace_shell_di.dat` |
| 7323 | `%s/ace_cache_db.dat` |
| 8768 | `%s/acecrh.dat` |
| 9573 | `%s/ano_tmp/%08x.xx.dat` |
| 9615 | `%s/ano_tmp/shell_foo.dat` |
| 10942 | `%s/h_rcd.dat` |
| 11747 | `%s/ms_%08X%08X_tmp.dat` |
| 1828 | `/data/data/%s/files/virap2.s.dat` |
| 2574 | `comm.dat` |
| 2585 | `comm.zip` (actually ELF inside) |

## Detection target libraries (libanort)

| ID | Library | Indicates |
|---|---|---|
| 475 | `libmono.so` | Unity Mono cheats |
| 5254 | `libjdwp.so` | Java debugger attached |
| 9642 | `libart.so` | Android Runtime (used for DEX backdoor) |
| 11862 | `SOBASE_libil2cpp.so` | Unity IL2CPP |
| 7202 | `libdrm.so.exagear` | Exagear emulator |
| 7234 | `ld-android.so.exagear` | Exagear linker |
| 8618 | `audio.primary.tenc.so` | TenC vendor blob |
| 8657 | `audio.primary.tenc_legacy.so` | TenC legacy |
| 8703 | `gatekeeper.tenc.so` | TenC gatekeeper |
| 8739 | `gps.tenc.so` | TenC GPS |

## /proc paths queried (libanort)

| ID | Path |
|---|---|
| 273 | `/proc/%d/cmdline` |
| 340 | `/proc/%u` |
| 351 | `/proc/%u/status` |
| 661 | `/proc/self/maps` (used by `ACE_ResolveDynFunc_NoDlsym`) |
| 1875 | `/proc/self/fd` |
| 1891 | `/proc/self/fd/%s` |
| 8887 | `/proc/self/status` |
| 8917 | `/proc/self/fd/%d` |
| 8936 | `/proc/self/./fd/%d` |
| 38230 (libanogs) | `/proc/cpuinfo` |
| 51335 (libanogs) | `/proc/meminfo` |

## getprop properties checked (libanogs)

| ID | Property |
|---|---|
| 13412 | `ro.build.characteristics` |
| 16314..16384 | `ro.vendor.platform: cloudmatrix1/2/3` |
| 38548 | `HARDWARE` |
| 38559 | `Hardware` (parsed from cpuinfo) |
| 45952 | `ro.enable.native.bridge.exec` |
| 45983 | `ro.dalvik.vm.isa.arm` |
| 46033 | `ro.dalvik.vm.native.bridge` |
| 46166 | `ro.dalvik.vm.isa.arm64` |
| 48806 | `ro.boot.flash.locked` |
| 48829 | `ro.boot.vbmeta.device_state` |
| 48868 | `ro.boot.verifiedbootstate` |
| 49006 | `ro.build.fingerprint` |
| 51214 | `gsm.version.baseband` |
| 55940 | `ro.build.product` |
| 55959 | `ro.build.flavor` |
| 55977 | `ro.product.device` |
| 56015 | `ro.build.fingerprint` |
| 56107 | `ro.odm.build.fingerprint` |
| 56186 | `ro.system.build.fingerprint` |
| 56268 | `ro.vendor.build.fingerprint` |
| 56320 | `ro.bootimage.build.fingerprint` |

## /dev/ files checked

| ID | Path |
|---|---|
| 16118 | `/dev/virtpipe-common-syzs` |
| 16146 | `/dev/virtpipe-common-yyb` |
| 16268 | `/dev/virtpipe-common-syzsaow` |
| 29169 | `/dev/virtpipe-sec` |
| 40398 | `/dev/binder` |
| 1607 | `/dev/random` |

## Strategy keys

| ID | Key |
|---|---|
| 16551 | `antiemulator` (master) |
| 31767 | `shell_checker` |
| 31817 | `scan_by_detect` |
| 7124 | `is_x86` |
| 7935 | `is_x86_env` |
| 13130 | `scan_x86` |
| 13141 | `scan_x86_by_mem` |
| 13177 | `x86_module_cnt` |
| 13295 | `x86_bypass` |
| 46123 | `x86_sys_scan` |
| 12365 | `scan_loop2` |
| 58596 | `attest_scan_objvm` |

## Bypass implications

The strings reveal ACE's full detection scope:
1. **Cross-game cheat detection** — knows which Tencent games run alongside ours
2. **DEX-side runtime updates** — backdoor for arbitrary Java code
3. **TSS framework integration** — anti-cheat is part of broader Tencent Safety SDK
4. **Server-side decision making** — many strings format reports for server analysis

For our specific bypass (Division Resurgence, MuMu Player):
- Game package isn't in the Tencent registry → no cross-game checks
- Emulator detection fires (we're MuMu/Netease) but game allows emulator
- Frida/root signals fire only if those tools are installed (they aren't on our setup)
- Heartbeat may or may not run (depends on Tier 8 timing)

This document serves as the reference for the next iteration of bypass hardening.
