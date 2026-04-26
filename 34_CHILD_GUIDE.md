# How ACE Works — Explained Like You're 12

**This document explains every part of Tencent's ACE anti-cheat system, in plain English. By the end of it, you should understand exactly how the system protects mobile games — and how to disable it.**

---

## Part 1: What is ACE?

ACE stands for "**A**nti **C**heat **E**xpert". It's software made by Tencent (a giant Chinese game company) to stop people from cheating in mobile games like Honor of Kings, PUBG Mobile, Division Resurgence, etc.

Imagine a mall security guard. ACE is like that, except:
- The mall is your phone
- The thieves are cheating tools (aimbot, wallhack, speed hack, etc.)
- The guard NEVER sleeps
- The guard reports back to headquarters

When you install a Tencent-published mobile game, ACE comes along with it as two extra files:

- **`libanort.so`** — the "detective" — knows what cheating looks like
- **`libanogs.so`** — the "messenger" — reports detected cheating to Tencent's servers

These files load automatically when you start the game. They run inside YOUR app's memory, watching what your app is doing.

---

## Part 2: The Two Libraries

### libanort.so (the detective)

Imagine a detective with a notebook full of "things bad people do." When you start the game:

1. ACE opens its notebook (decrypts hundreds of strings stored encrypted in the file)
2. Reads each detection rule
3. Watches your phone for any of those rules to match
4. Writes down what it finds
5. Yells at the messenger to send the report

Examples of things in ACE's notebook:
- "If `frida-server` is running, that's a debugger — RAT THEM OUT"
- "If our app's APK file has a different hash than expected, RAT THEM OUT"
- "If a Lua engine is loaded but the game shouldn't have one, RAT THEM OUT"
- "If memory pages don't match what's on disk, RAT THEM OUT"

### libanogs.so (the messenger)

Imagine a guy whose only job is to text Tencent's headquarters. When the detective tells him to send a report, the messenger:

1. Builds a structured "report" (like a form with fields)
2. Encrypts it
3. Sends it via HTTPS to `down.anticheatexpert.com`
4. Tencent's servers decide if you're cheating

Both libraries can also kill your game directly if they really want to.

---

## Part 3: How the Detective Watches

ACE has 28 different "scanners" (basically 28 detection rules). Each scanner watches one specific thing.

| Scanner | What it watches |
|---|---|
| `cert3` | Is your APK signed with Tencent's official certificate? |
| `module2` | Are any unauthorized .so files loaded? |
| `frida_scan` | Is Frida (a famous reverse-engineering tool) running? |
| `process` | Are any suspicious processes running on your phone? |
| `anti_root` | Is your phone rooted? |
| `anoscan` | Generic catch-all for sketchy patterns |
| `anti_clicker2` | Are you using auto-tap apps? |
| ... and 21 more |

Plus there are 7 EXTRA scanners that are normally turned OFF, but Tencent can flip a switch on the server to turn them ON anytime:
- `elf_hook_scan` (looks for inline hooks like the ones our mod uses!)
- `anti_virapp` (catches virtual sandbox apps)
- `black_app` (catches blacklisted apps)
- And 4 others

Each scanner runs every 50ms (50 thousandths of a second) in a loop. So 20 times per second, ACE asks itself: "Is anything suspicious?"

---

## Part 4: How ACE Decides to Kill the Game

When ACE finds something bad, there are **9 different ways** it can shut down your game:

1. **Polite report:** Tells the server "this player is cheating" and hopes the server bans them
2. **Direct kill:** Calls the operating system to kill the process (`exit_group(7)` syscall)
3. **String integrity trap:** If you tampered with ACE's stored strings, it kills itself silently
4. **Java kill command:** A Java service tells ACE to kill itself ("stop" command)
5. **Thread cracked detection:** If a debugger paused us for >5 seconds, marks us as "cracked" and kills
6. **Time bounds validator:** If the clock is too far off from a stored value, exits with code 6
7. **Init failure:** If ACE's setup didn't work, exits with code 2/3
8. **MZ/Mono scanner:** Catches modified Unity games (doesn't apply to UE4)
9. **Various:** Other corner cases (config bugs, integrity bugs, etc.)

To beat ACE, you have to defeat ALL 9 paths. Otherwise the kill comes from somewhere else.

---

## Part 5: The Two Brains (VMs!)

Here's where it gets crazy. ACE has not one, but TWO virtual machines (programs that simulate computers) inside it.

### Brain 1: Expression-Tree VM (in libanogs)

This is for evaluating "rules" — little programs that say things like:
```
if (process_name contains "frida") then submit_report("FRIDA_FOUND")
```

It works by walking through a tree of operations. There are 150 possible operations (like add, multiply, read memory, install hook, send report, etc.).

### Brain 2: ARM64 Emulator (in libanort)

This is INSANE. ACE has a full **fake processor** built in. It can run ARM64 machine code (the code your phone's CPU runs) but in a sandbox.

Why? Because Tencent can download new code from their server (an "ob_*.zip" file) and run it. They don't want the new code to run directly on your phone — that would be risky. Instead, they run it inside this fake processor where they can control everything.

So when ACE downloads a new detection rule, it's actually downloading a tiny ARM64 program. ACE decodes that program and runs each instruction in the emulator. The emulator has 148 different instruction handlers (one for each ARM64 instruction class).

This means **the actual detection logic isn't in the binary you can read**. It's downloaded fresh. Even if you reverse-engineer libanort.so completely, you only see the engine — not the rules. The rules live on Tencent's server.

---

## Part 6: The Boot Sequence

When the game starts:

```
1. Android loads libanort.so
   └─> Init constructors run (4 of them)
       ├─ Builds the JNI method table
       ├─ Allocates internal buffers
       ├─ Initializes the dynamic loader
       └─ Sets up crypto session

2. JNI_OnLoad() runs
   └─> Registers 7 native methods Java can call

3. ACE is now LOADED but not yet RUNNING
   └─> It's dormant, waiting for Java to wake it up

4. Java calls AnoSDKMethodInit(...)
   └─> JNI dispatches to JNI_ACE_Initialize
       └─> Calls ace_init_core_v4_9_30_24277_oversea
           ├─ Reads local config file
           ├─ Verifies file signature (must be < 30 days old)
           ├─ Loads any cached scan rules
           ├─ Validates process command line
           ├─ Runs shell detector (one-shot)
           ├─ Spawns ACE_DetectionPoller as a thread
           │   └─ This is mostly a DECOY — its main purpose is to time
           │      its own creation. If pthread_create takes too long
           │      (>5 seconds), debugger has paused us → THREAD_CRACKED
           ├─ Records version string
           └─ Records timing info
                                                 
5. ACE is now ACTIVELY SCANNING
   └─> Periodic poller wakes up every 50ms
       └─> Walks through all 28 scanners
           └─> For each scanner, runs its detection rule
                └─> If something matches, submits report
```

---

## Part 7: How We Beat ACE (the Bypass)

Our strategy is "defense in depth" — we don't just hook ONE thing, we hook MANY things so that even if one trick fails, others still work.

### Tier 1: Stop scanners from registering

When ACE tries to add a scanner to its registry, we hook the registration function and silently drop the ones we don't like. The scanner gets allocated but never linked into the system, so it never runs.

### Tier 2: Telemetry kill switch

There's a single byte in memory called `g_tdm_report_enabled`. If it's 0, no reports get sent — even if a scanner detects something. We set it to 0 once at startup.

### Tier 3: Block the kill command

When a Java service sends the "stop" command to native ACE, ACE calls a special function (`gp7ioctl`) that runs `exit_group()`. We hook that function and drop "stop" commands.

### Tier 4: Freeze time

The thread_cracked detection times itself by reading the clock twice. We cache the clock value for 6 seconds, so both reads return the same time. Elapsed = 0 → never triggers.

### Tier 5: Disable config updates

There's a flag bit (`0x100` of `g_anort_config_flags`). When set, ACE skips reading any config from disk or downloading from server. Stale rules forever. We set this bit at startup.

### Tier 6: Neutralize the rule interpreter

The function `ace_run_scan_rules` is what walks through scan rules and runs them. We hook it to immediately return success without doing anything. ALL detection rules silently skip.

### Tier 7: Block runtime hook installation

ACE has its own hook installer (homemade Dobby). We hook that too and make it return success without actually installing hooks. So ACE can't ever set up new detections.

### Tier 8: Stop the bytecode VM

The ARM64 emulator that runs downloaded modules has a driver function. We hook it to return immediately. No downloaded code ever executes.

### Plus 11 ANORT_PATCHES

These are simple `MOV X0, #0; RET` replacements (i.e., "always return 0") on 11 specific detection sensor functions. Quick and clean.

### Plus 16 scanner block-list entries

Tier 1 needs a list of scanner names to block. We have 16 names, including some "defense in depth" ones that aren't currently active but might be flipped on by Tencent's server.

---

## Part 8: Why Each Tier Matters

| Without Tier | What happens |
|---|---|
| 1 | All 28 scanners run, several detect us |
| 2 | Reports get built and sent to Tencent's servers |
| 3 | Java service kills us via `exit_group` |
| 4 | thread_cracked fires after 5 seconds, marks us as detected |
| 5 | Tencent pushes new rules from CDN, our bypass becomes outdated |
| 6 | Even if Tier 1 fails (scanner sneaks in), the rule interpreter still runs it |
| 7 | ACE installs new runtime hooks every 50ms, slowly building detection |
| 8 | Downloaded ARM64 modules execute, do whatever Tencent wants |

Each tier is a different layer of defense. Removing any one creates a hole. With all 8, ACE is fully neutralized.

---

## Part 9: How to Verify the Bypass Works

Run the game with logcat:
```bash
adb logcat -s DivMod
```

You should see:
```
=== Applying integrated 8-tier ACE bypass ===
[Tier 1] ace_register_scanner_module hook installed @ 0x...
[Tier 2] TDM killswitch armed: enabled=0 checked=1 @ 0x...
[Tier 3] gp7ioctl filter installed @ 0x...
[Tier 4] ACE_SyscallClockGettime cached-freeze installed @ 0x...
[Tier 5] g_anort_config_flags |= 0x100 (config-update disabled)
[Tier 6] ace_run_scan_rules neutralized @ 0x...
[Tier 7] ace_arm64_instruction_relocator neutralized @ 0x...
[Tier 8] ACE_VMExecutionDriver neutralized @ 0x...
=== Integrated bypass: T1=1 T2=1 T3=1 T4=1 T6=1 T7=1 T8=1 ===
```

Then play for 30+ minutes. If you don't get kicked, the bypass works.

---

## Part 10: How to Read the Source Code

If you want to dig deeper, here's a tour:

| File | What it does |
|---|---|
| `Main.cpp` | All bypass code lives here |
| `libanort.so.i64` | IDA database for libanort (the detective) |
| `libanogs.so.i64` | IDA database for libanogs (the messenger) |
| `00_TLDR_FULL_SYSTEM.md` | Quick reference for everything |
| `01_string_decryption.md` | How ACE decrypts its strings |
| `12_complete_kill_path_inventory.md` | All 13 ways ACE kills you |
| `13_expression_engine.md` | The 150-operator VM |
| `14_rule_state_machine.md` | The rule interpreter |
| `15_arm64_relocator.md` | ACE's homemade hook installer |
| `16_rule_callers.md` | The 9 scan-trigger entry points |
| `19_interpreter_loop.md` | Line-by-line walkthrough of ace_run_scan_rules |
| `21_libanort_bytecode_vm.md` | The bytecode VM (now known to be ARM64 emulator) |
| `22_libanort_arm64_emulator.md` | All 31 mapped ARM64 instruction handlers |
| `26_anort_11_patches_explained.md` | Each of our 11 patches |
| `28_libanort_boot_sequence.md` | Boot order |
| `32_jni_native_methods.md` | All 7 Java entry points |
| `34_CHILD_GUIDE.md` | This file! |

---

## Part 11: Glossary

- **APK**: Android Package — the .apk file is your game
- **ARM64**: The CPU type your phone uses
- **JNI**: Java Native Interface — how Java calls C code
- **Hook**: replacing a function so your code runs first
- **Dobby**: a popular hook installer library
- **Trampoline**: a small piece of code that does the redirect
- **PLT**: Procedure Linkage Table — where shared library calls go through
- **GOT**: Global Offset Table — where shared library addresses are stored
- **mprotect**: a syscall to change memory permissions (e.g., write-protect, executable)
- **clock_gettime**: a syscall to get the current time
- **ptrace**: a syscall used by debuggers to inspect another process
- **fork/execv**: spawn a new child process
- **pthread_create**: spawn a new thread
- **dlopen/dlsym**: dynamic library loading
- **inline hook**: replacing a function's first 4 bytes with a jump
- **PLT hook**: replacing the entry in the PLT instead of the function bytes
- **GOT hook**: replacing the address in the GOT
- **vtable**: C++ virtual function table
- **CFG flattening**: anti-RE technique that turns a normal function into a state machine

---

## Part 12: Frequently Asked Questions

**Q: How did Tencent build all this?**
A: ACE has been around for years and has many engineers. They iterate on it. New versions come out monthly.

**Q: Why doesn't simpler hooking work?**
A: Because ACE has scanners that detect hooks. ACE will catch you. You need defense in depth.

**Q: Why does the game still work after the bypass?**
A: ACE detects but doesn't break the game. The game's normal logic runs fine — ACE is parallel.

**Q: Can I be banned even with this bypass?**
A: Possibly. The server has detection too. The bypass disables CLIENT-side detection. The server can still see things via gameplay analysis (e.g., reaction times too fast, bullets always hit, etc.).

**Q: Can Tencent push an update that breaks the bypass?**
A: Yes — they update libanort.so / libanogs.so with the game APK. New offsets break. Need to remap.

**Q: Is this legal?**
A: For your own private use, modifying your own software is generally legal. Distributing it varies by jurisdiction. Don't be a jerk to other players.

---

## Part 13: What's Next

If you want to learn more, the next areas to study are:

1. **The 28 active scanners** — each has its own detection algorithm. Currently we only know names; we don't know HOW each detects.
2. **The 117 unmapped ARM64 emulator handlers** — we've mapped 31 out of 148.
3. **Server-side ban logic** — invisible to us, but can be inferred from telemetry analysis.
4. **The encrypted ob_*.zip wire format** — what does a downloaded rule actually look like?
5. **The Java side** — `com.gamesafe.ano.AnoJavaMethod` is the bridge. Reverse it with JADX.

Each of these is its own project.

---

## Closing thoughts

ACE is a serious piece of software. It has multiple VMs, custom encryption, anti-tamper, anti-debug, and active server-side detection. Disabling it requires understanding the entire system, not just patching one function.

The hardest part is figuring out HOW it all fits together. Once you understand:
- The lifecycle (init → poll → detect → report → kill)
- The data flow (rules → AST → VM → opcode → action)
- The kill paths (9 different ways to die)

…the bypass is "just" applying hooks at the right places to break each chain.

Happy reversing!
