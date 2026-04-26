# ACE Detection Targets — VERIFIED INVENTORY

All strings here are **decrypted with the explicit decoder ordinal from the disassembly**. False positives have been eliminated.

---

## 1. Hooking frameworks (highest priority)

### Frida (the killer category)
| Decoded string | Used as |
|---|---|
| `frida` | Generic identifier |
| `frida_agent_main` | Symbol in the loaded Frida agent |
| `frida-agent` | String search in `/proc/self/maps` |
| `libfrida-gadget.so` | Library name |
| `frida-agent-32.so` | 32-bit agent |
| `frida-agent-64.so` | 64-bit agent |
| `FRIDA_AGENT_1.0` | Agent version string |
| `frida_server` | Process name |
| `pool-frida` | Thread name (`/proc/self/task/<tid>/comm`) |
| `frida_scan` | Internal report name |
| `anti_frida` | Internal countermeasure ID |
| `/data/local/tmp/frida-server` | Default server path |
| `/data/local/tmp/re.frida.server` | Modern server path |
| `/data/local/tmp/12re.34frida.56server78` | Decoy/obfuscated server path |
| `/system/bin/frida-server` | System-installed server |

### Substrate (Cydia / Cydia Substrate, used by classic mod menus)
| `libsubstrate` | The native library |
| `anti_substrate` | Internal countermeasure |
| `libsandhook.edxp.so` | EdXposed's SandHook framework |

### Xposed family
| `anti_xposed` | Internal countermeasure |
| (other Xposed strings TBD; must verify) |

### Generic
| `hook` | Generic hook detection |
| `elf_hook_scan` | The actual scanner name |
| `inline_hook_opcode_dismatch` | Detection result type |
| `ms_hook_opcode` | Substrate-style opcode hook |
| `chk_elf_header2` | ELF header integrity check |

---

## 2. Root tools and superuser

### Root manager packages
- `com.topjohnwu.magisk` (Magisk)
- `com.kingroot.kinguser` (KingRoot)
- `com.kingo.root` (KingoRoot)
- `com.smedialink.oneclickroot` (OneClickRoot)
- `com.zhiqupk.root.global` (Zhiqu)
- `com.alephzain.framaroot` (Framaroot)
- `com.zachspong.temprootremovejb` (Temp Root)
- `com.ramdroid.appquarantine` (App Quarantine)
- `com.noshufou.android.su` (Superuser)
- `com.noshufou.android.su.elite` (Superuser Elite)
- `eu.chainfire.supersu` (SuperSU)
- `com.koushikdutta.superuser` (CWM Superuser)
- `com.thirdparty.superuser` (Generic)
- `com.yellowes.su` (yellowesSU)
- `me.weishu.kernelsu` (KernelSU)

### Root binaries / paths on disk
- `/system/app/Superuser.apk`
- `/system/etc/init.d/99SuperSUDaemon`
- `/dev/com.koushikdutta.superuser.daemon`
- `/system/xbin/daemonsu`
- `/system/sd/xbin`
- `/system/usr/we-need-root`
- `/system/bin/.ext`
- `/system/bin/failsafe`
- `/data/local`, `/data/local/bin`, `/data/local/xbin`
- `unlock_root` (string for known unlock_root tool)

### Zygisk (Magisk's modern injection)
- `/system/zygisk_magic`
- `/system/lib/libzygisk_loader.so`
- `/system/lib/libzygisk_injector.so`
- `/system/lib64/libzygisk_loader.so`
- `/system/lib64/libzygisk_injector.so`

### Internal flags
- `is_root`, `anti_root`, `gp4_no_root`, `mem_trap_no_root`, `unlock_root`
- `root_process_exists`

---

## 3. Cheat / script / automation apps

| Package | Notes |
|---|---|
| `pj.ishuaji.cheat` | "iShuaji" - mainland China cheating tool |
| `com.saitesoft.gamecheater` | Saitesoft Game Cheater |
| `com.muzhiwan.gamehelper` | Muzhiwan game helper |
| `com.www.gamespeeder` | Game speeder |
| `com.cih.game_cih` | "Game CIH" (Cheat Engine port) |
| `com.paojiao.youxia` | Paojiao game tool |
| `com.xiongmaoxia.gameassistant` | Xiongmao game assistant |
| `com.yx.youxia` | yx.youxia |
| `com.gmd.speedtime` | GMD speed time |
| `com.xiaojianjian.sw.app` | xiaojianjian |
| `com.cyjh.gundam` | CYJH Gundam |
| `com.cyjh.mobileanjian` | CYJH MobileAnjian |
| `com.cyjh.gundam.service.ScriptService.p` | Specific service detection |
| `com.jbbl.handjingling` | jbbl.handjingling |
| `com.scriptelf` | ScriptELF |
| `com.scriptelf.oneclickplay` | ScriptELF OneClickPlay |
| `com.diaobaosq` | diaobaosq |
| `com.kascend.chushou.lu` | kascend chushou |
| `com.leifeng.gametools` | Leifeng game tools |
| `com.dimonvideo.luckypatcher` | Lucky Patcher |
| `com.keramidas.TitaniumBackup` | Titanium Backup (re-signing) |
| `com.flamingo.xxrgplugin` | Flamingo XXRG plugin |
| `com.dragon.android.pandaspace` | Panda Space |
| `com.mf.guagua.ttfwks` | mf.guagua |
| `com.huluxia.gametools` | Huluxia game tools |
| `com.steady.autosimulate` | Steady AutoSimulate |
| `com.bayviewtech.game.roach` | Bayviewtech ROACH |
| `com.ifengwoo.zyjdkj` | ifengwoo |
| `com.dr.nr` | dr.nr |
| `com.zdnewproject` | zdnewproject |
| `com.tgp.autologin` | TGP AutoLogin |
| `com.uhaozu.autoapp`, `com.uhaozu.app` | UHaozu |
| `com.speed.chick` | speed.chick |
| `com.xh.kancn` | xh.kancn |
| `com.zx.a2_quickfox` | A2 QuickFox |

### Streaming / recording (anti-recording)
| `com.ss.android.ugc.aweme` (TikTok) |
| `com.ss.android.ugc.aweme.lite` |
| `com.ss.android.ugc.live` |
| `com.ss.android.ugc.trill` |
| `com.bilibili.bilibililive` |
| `com.bilibili.studio` |
| `com.duowan.live` / `com.duowan.kiwi` |
| `com.yy.huyaassist4game` |
| `com.kwai.livepartner` |
| `com.kuaishou.nebula` |
| `com.tencent.weishi` |
| `com.prism.live` |
| `com.streamlabs` |

### Account trading / rental (anti-trading)
| `com.zhanghaodaren.m_wzz` |
| `com.wuba.zhuanzhuan` |
| `com.bdkj.LightningGameRental` |
| `com.jj.jiasu` |
| `com.daofeng.zuhaowan` |
| `com.tsy.tsy` |
| `com.jym.mall` |
| `com.wanhaoba520.app` |

### Proxy / VPN (used to mask region for region-locked content)
| `com.github.shadowsocks` |
| `com.bige0.shadowsocksr` |
| `com.fobwifi.transocks` |
| `com.sticktoit` |

### File-system browsers (used to steal game files)
| `com.speedsoftware.rootexplorer` |

### Antivirus apps (run scans that interfere)
| `com.ijinshan.duba` (Kingsoft Duba) |
| `com.lbe.security` (LBE) |
| `com.qihoo` (Qihoo 360) |

---

## 4. Emulator / virtualization detection

### Files / device nodes (path-based)
| `/dev/virtpipe-common-syzs`, `/dev/virtpipe-common-yyb`, `/dev/virtpipe-common-syzsaow`, `/dev/virtpipe-sec` | BlueStacks/MuMu/Tencent emulator pipes |
| `vm_main.img`, `vm_x_task.img`, `vm_r4.img`, `vm_debug.img` | Virtual machine images |
| `/sys/module/kvm`, `/sys/module/kvm/parameters/halt_poll_ns` | KVM presence (almost always on cloud-emulator hosts) |
| `/sys/module/rockchip_*` (5 entries) | Rockchip-based ARM emulators (used by some BlueStacks variants) |
| `/system/lib*/libCPHIVmiAudio.so`, `/system/lib*/libCPHMediaServer.so`, `/system/lib*/libCPHTurboVideoEngine.so` | Cloud Phone (CPH) virtual phone services |
| `/system/vendor/bin/CloudAppEngine`, `/vendor/bin/CloudAppEngine`, `/system/app/CloudGaming` | Cloud gaming environments |
| `/system/lib/libnative-bridge.so` | Houdini (Intel x86 ARM translator) |
| `/system/lib/librknnhal_bridge.rockchip.so`, `/system/lib/librockit.so` | Rockchip emulator HAL |
| `/dev/qqgame-socket` | QQ game cloud platform socket |

### Virtual app frameworks (clone-app users)
| `com.vmos`, `com.vmos2` | VMOS virtual Android |

### Internal flags
| `emulator_name`, `NotEmulator`, `antiemulator`, `emu_crash`, `emu_crash_%s`, `emu_crash_all` |
| `scan_x86`, `scan_x86_by_mem` (x86 architecture detection — emulators are usually x86 hosts) |
| `TencentX86`, `TencentAoYYB`, `TencentAo` (Tencent's own emulator brands) |

---

## 5. Process / memory inspection paths

These are **how ACE inspects its own state** (and tries to detect tampering):

| `/proc/self/maps` | Loaded module list — checks for unauthorized libraries |
| `/proc/self/status` | Process state — checks for `TracerPid != 0` (anti-debug) |
| `/proc/self/fd` | File descriptor list — checks for unusual fds (frida server) |
| `/proc/self/task` / `/proc/self/task/%s/comm` | Thread enumeration + thread name (e.g. `pool-frida`) |
| `/proc/self/environ` | Env variables — checks for `LD_PRELOAD` etc. |
| `/proc/self/map_files` | Inverse maps — alternate enumeration |
| `/proc/self/root/proc/self/fd` | Bind-mount detection trick |
| `/proc/self/ns/mnt` | Mount namespace — detects Magisk's namespace separation |
| `/proc/%u/cmdline`, `/proc/%u/status`, `/proc/%u/task` | Generic /proc walking |
| `/proc/net/tcp`, `/proc/net/tcp6` | Open TCP sockets enumeration |
| `/proc/cpuinfo` | CPU info (architecture / virt detection) |
| `/proc/meminfo` | Memory layout |
| `/proc/sys/fs/inotify/max_user_watches` | inotify limits (sets up its own watches) |
| `/proc/sys/kernel/random/boot_id` | Boot ID for fingerprinting |
| `/dev/binder` | Binder IPC presence |
| `/sys/class/power_supply` | Battery info |

---

## 6. Sensor / token spoof detection

| `FakeToken` | Generic fake-token marker |
| `FakeToken_%x` | Format string for fake-token report |
| `fake_token_androidid` | Spoofed Android ID detection |
| `fake_token_sensor` | Spoofed sensor reading detection |
| `HANYCJLZOEUS_TOKEN2.dat` | Internal token cache file |
| `sensor_detect` | Sensor-detection module name |
| `report_apk` | APK reporting module |
| `ignore_sys_apk` | System-APK whitelist flag |

---

## 7. Permissions / system info

| `com.android.permission.GET_INSTALLED_APPS` | Permission ACE checks for |
| `report_apk` | When this is set, reports installed APKs |
| `device_info` | Device info gathering module |

---

## 8. Network exfiltration

### Server endpoints
- `https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me` — primary download endpoint (project ID 8899, build hash `71C1E6D7`)
- `https://%s/gamesafe/mobile/%s/%08X` — dynamic update template
- `gamesafe/mobile/ano_dfh.zip` — downloadable update archive

### Identifiers in payloads
- `TSS` (Tencent Security Solution prefix)
- `Tencent`, `TencentQQ`, `tencent_yyb_tp`, `tencent_tp`, `tencent_yyb` (project identifiers)
- `tencent` (lowercase)
- `gcloud`, `gcloud_log`, `gcloud_connector`, `gcloud_connector_t`, `GCloud`, `GCloudCore`, `GCloudCtrl`, `GCloudAppLifecycleWrapper` (gcloud SDK shell)
- `COREREPORT` (the data channel)
- `monitor` (the lifecycle-call category)

### Fingerprint payload
ACE's primary device-fingerprint format string:
```
root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d
```
And complementary:
```
name=%s|size=%d|crc=0x%08x|root=%d
reason=%s|root=%d|cert=%s
```

---

## 9. Internal subsystem / scan names

| Name | Meaning |
|---|---|
| `scan_loop2` | Main repeating scan loop |
| `scan_x86` / `scan_x86_by_mem` | Architecture / memory checks |
| `scan_by_detect` | Generic scan trigger |
| `opcode_scan` | Opcode integrity scanner |
| `opcode_scan2`, `opcode_scan3` | Variants |
| `opcode_crash` | Crash trigger when opcode mismatch found |
| `elf_hook_scan` | ELF hook detector |
| `module_crash` | Module-integrity crash trigger |
| `emu_crash` / `emu_crash_%s` / `emu_crash_all` | Emulator-detected crash |
| `frida_scan` | Frida scanner |
| `anoscan` | Generic ano-scan trigger |
| `chk_elf_header2` | ELF header check v2 |
| `cs_dl` | Code-section download verifier |
| `screenshot` | Screenshot detection |
| `super_white` | Whitelisted-superuser indicator |
| `anti_bm` | "Anti-bookmark"? (TBD) |
| `anti_virapp` | Anti virtual-app |
| `anti_cheat_open_id` | Open ID anti-cheat |
| `cheat_openid_crash` | Open-id crash trigger |
| `mrpcs1` | Module reverse-protection check 1 (TBD) |
| `tcj` | Unknown abbreviation (TBD) |
| `gp3_ext` / `gp4_2` | Generation 3/4 protection variants |

---

## 10. Bypass implications

This catalog lets us:

1. **Pre-rename detection** Build a list of strings to find in `/proc/self/maps` BEFORE ACE scans, and either rename our hook libraries to non-matching names or move them to non-`/data/local/tmp` paths.
2. **Spoof responses** Hook `open`/`fopen` to return ENOENT when ACE tries to read these paths.
3. **Mask process names** Set `/proc/self/task/<our_tid>/comm` to a benign value (we currently see `pool-frida` will get caught).
4. **Survive opcode_scan** Either patch the scanner to skip our regions, or stop hooking inline (use vtable swap instead).
5. **Survive elf_hook_scan** Use Dobby with the GOT/PLT path instead of `.text` injection — ELF section integrity stays intact.
6. **Defeat fingerprinting** Spoof the values feeding the `root=%d|x86=%d|...` format string.
7. **Network blackhole** Block `https://*.anticheatexpert.com` at DNS or with `setsockopt(SO_BROKEN)`. Server can't deliver new sigs, ACE keeps using stale ones.

---

*Source: `decoder_call_sites.txt` (3,200 verified call sites, 100% explicit-decoder.* Built by `ida_extract_decoder_calls.py`.)
