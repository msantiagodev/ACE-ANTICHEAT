# ACE Reverse Engineering: Final Plain-English Guide

For the impatient. **Skip everything else and read this if you're new.**

## What is ACE?

ACE = Tencent's "Anti-Cheat Expert" — the anti-cheat system shipped inside Chinese mobile games (PUBG Mobile, Honor of Kings, etc., and now Division Resurgence).

It's two `.so` libraries loaded into the game process:
- `libanort.so` — the **detective**: looks for cheats
- `libanogs.so` — the **messenger**: sends results to Tencent's server

## How ACE detects cheats — the 6 tools

Like a detective with multiple methods:

### 1. **Library scanner** (`/proc/self/maps` reader)
ACE reads the list of loaded `.so` files. If it sees:
- `libfridagadget.so` → "this person uses Frida (memory inspection tool)"
- `libsandhook.edxp.so` → "Xposed hook framework loaded"
- `libxxspeedmanager.so` → "speed cheat installed"
- `libhoudini.so` → "running on x86 emulator with ARM translation"

ACE catalogues 15+ specific cheat libraries. (Doc 75)

### 2. **Function hook scanner**
ACE remembers what the first 16 bytes of 31 standard libc functions should look like (`open`, `read`, `dlopen`, etc.). If anything's modified, it flags a hook. (Doc 70)

### 3. **App scanner** (`PackageManager` enumerator)
ACE lists every installed app. If it finds:
- `com.lbe.parallel.intl` (Parallel Space) → "running in virtual app"
- `com.topjohnwu.magisk` → "Magisk root tool installed"
- `com.scriptelf.oneclickplay` → "auto-clicker app detected"

Plus 21 specific virtual-app signatures and ~30 known cheat packages. (Docs 58, 75)

### 4. **System property checker**
ACE reads `getprop`:
- `ro.boot.flash.locked = 0` → unlocked bootloader
- `ro.dalvik.vm.isa.arm = ...` → x86 host emulator
- `ro.product.device = vbox86p` → VirtualBox emulator

15+ system properties checked, all combined into a 7-field fingerprint:
```
root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d
```
Sent to Tencent server with every report. (Doc 61)

### 5. **Touch pattern analyzer**
ACE wraps every `setOnTouchListener` with `com.gamesafe.ano.TouchListenerProxy`. It analyzes:
- Touch timing regularity (humans have natural jitter; bots don't)
- Coordinate precision (humans tap "around" buttons; bots tap exact pixels)

If pattern looks too perfect → "auto-clicker detected". (Doc 74)

### 6. **The ARM64 emulator** ★ ACE's secret weapon
This is the most clever part. ACE has a **complete ARM64 CPU emulator inside libanort**. It runs encrypted "module" files (`vm_main.img`, `vm_hb.img`, etc.) downloaded from Tencent's server in a sandboxed virtual CPU. The emulator can:
- Execute 148 ARM64 instructions (we documented 80)
- Make syscalls via the **SVC bridge** (the kernel access path)
- Call into 184 native ACE helpers
- Update without app store releases (just push new bytecode)

This is how Tencent ships new detection logic without Google Play approval. (Docs 22, 46, 48, 52)

## How ACE talks to Tencent's server

Two channels:

### Channel 1: Periodic detection reports
- Format: `func=<command>|key=val|...` (Docs 76, 64)
- Examples: `WB_HeartBeat|index=42|md5=...|uid=12345`
- Goes through Java `senddatatosvr` → Tencent's GS2 server

### Channel 2: Server-pushed updates
- Static: `ob_*.zip` files downloaded from CDN (`https://down.anticheatexpert.com/iedsafe/Client/...`) (Doc 69)
- Dynamic: GCloud SDK push channel (`subscribe("REMOTECONFIG")`) (Doc 71)

If we can block both, server can't push new detections. We block Channel 2's static path with **Tier 5** (`g_anort_config_flags |= 0x100`).

## How ACE bans you — 4 ways it ends the game

### Method 1: SVC syscall bridge (KILLED by Tier 1)
Emulator code calls `syscall(SYS_exit_group, 0)`. We patched the SVC handler to no-op. (Doc 48)

### Method 2: JNI "stop" command
Java code calls `JNI_ACE_CommandDispatch("stop")` which calls `ACE_ValidateConfigOrKill` which calls `exit_group(0)` if `enable_gp7_exit_group` config is true. **Default is true** — fail-closed design. (Doc 60)

### Method 3: Probabilistic deep audit (0.1%/day)
`ACE_ScheduledTimerProbabilisticDetect` fires once per day on average (`rand()%1000==910`) to run a deep audit. If it catches you, you're banned. The 0.1% rate is intentional — makes detection irreproducible by attackers. (Doc 56)

### Method 4: Server-side kick
Server decides based on accumulated detection reports. We can't block this client-side; just look like a normal player.

## How our bypass works — 8 tiers

| Tier | What it does |
|---|---|
| 1 | 11 ANORT_PATCHES — disable native detection scanners (root, Frida, Magisk, etc.) |
| 2 | TDM kill switch — drop report submission |
| 4 | `ace_run_scan_rules` no-op — drop all rule-based detection |
| 5 | `g_anort_config_flags |= 0x100` — block server config update |
| 6 | Library integrity scanner kill |
| 7 | `ace_arm64_relocator` no-op — block hook installation |
| 8 | `ACE_VMExecutionDriver` no-op — kill the entire emulator |

Combined effect: ACE thinks it's running normally but reports clean every time. Server gets clean reports. No ban. (Doc 73)

## What Tencent could do to break this

1. **Add a check that validates SVC handler bytes** — would catch our Tier 1 patch
2. **Move detection to libanogs (which we don't patch)** — would dodge Tier 4
3. **Use GCloud channel** to push new rules — Tier 5 doesn't cover this
4. **Add server-side fingerprint** for our patch pattern

For now (April 2026), our bypass is intact. But this is an arms race.

## Key files in this knowledge base

- `00_TLDR_FULL_SYSTEM.md` — even shorter overview
- `34_CHILD_GUIDE.md` — earlier child-comprehension version
- `INDEX.md` — table of contents for all 76 docs
- `PROGRESS.md` — iteration ledger
- `73_bypass_status_audit.md` — current bypass coverage
- `64_master_string_dictionary.md` — every decoded string
- `INDEX.md` — navigation

## What we know vs. what's still unknown

### KNOWN ✓
- Boot flow (init_array → modules → HB → main loop)
- All 6 native bridges (named registry, label PC, shellcode, command dispatch, raw fn-ptr, SVC)
- 184 native function wrappers (25 documented)
- All 17 JNI methods (libanort 6 + libanogs 11)
- All 14 scanner modules (anti_root, anoscan, etc.)
- All 5 GP layers (GP3-GP7)
- All 22 ob_*.zip variants
- All 31 libc hook watch list functions
- All 21 virtual-app signatures
- ~30 Tencent game packages
- 11 of 32 config flag bits
- 80+ of 148 ARM64 emulator opcode handlers

### STILL UNKNOWN
- Remaining ~60 ARM64 emulator opcodes
- Most `__ff_<n>` wrappers (~140 of 162 not yet decompiled)
- Heartbeat hash function (would let us fake responses)
- GCloud channel internals (transport, packet format)
- Most server-pushed rule bytecode formats
- TenC vendor blob purposes

## Why this is the most-thorough public ACE write-up

This is a deep technical reverse-engineering effort. Tencent treats ACE as proprietary — there's no public documentation. Most online "anti-cheat bypass" guides are surface-level (just "patch these offsets"). This knowledge base goes deeper:

- **2,300+ functions named** in IDA Pro databases
- **77 documents, ~13,000+ lines of analysis**
- **Every detection vector** systematically catalogued
- **Architecture diagrams** showing how pieces fit
- **Bypass strategy** with risk audit and hardening recommendations

A child reading these in order can understand 90% of how Tencent's most-deployed anti-cheat works, and how to neutralize it.
