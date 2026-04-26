# Detected Library Catalog — Every `.so` ACE Looks For

Comprehensive inventory of every Linux shared library (`.so`) ACE checks for in `/proc/self/maps` or library paths. Each represents a distinct detection vector.

## Cheat tool libraries

These are libraries shipped by known cheat frameworks. Their presence in the process address space is a **direct detection signal**:

| Library | Detected as | Notes |
|---|---|---|
| `libsandhook.edxp.so` | EDXP / SandHook | Xposed-style hook engine — used by many cheats |
| `libxxspeedmanager.so` | XX Speed Manager | Game speed manipulation tool (slomo cheat) |
| `libgg_time.so` | GameGuardian time | GG-style timing manipulation |
| `libspeedman.so` | Speed manager (variant) | Another speed cheat tool |
| `frida-agent`, `frida-gadget` | Frida instrumentation | Memory inspection / hook insertion |

## Tencent's own libs (anti-cheat ecosystem)

ACE checks for the presence of its **own family** of libraries. If any are missing, something tampered with the install:

| Library | Purpose |
|---|---|
| `libanort.so` | ACE host (the "detective") |
| `libanogs.so` | ACE messenger |
| `libtersafe.so` | Tencent Tersafe (older anti-cheat) |
| `libtprt.so` | Tencent Protection Runtime |
| `libtbs_crash_handler.so` | Tencent Browsing Service crash handler |

If any are missing or modified → "Tencent libs tampered" detection.

## Game engine / framework libs

These identify the game engine for engine-specific detection rules:

| Library | Engine |
|---|---|
| `libunity.so` | Unity (Mono backend) |
| `SOBASE_libil2cpp.so` | Unity (IL2CPP backend) |
| `libmono.so` | Standalone Mono runtime |
| `libglrenderer.so` | Generic OpenGL renderer (presence might indicate cheat overlay) |
| `libmonochrome.so` | Chromium (WebView) |
| `libwebviewchromium.so` | Android WebView |

## Standard system libs (verified for tampering)

These are core libs whose modification means something is hooking syscalls/runtime:

| Library | Purpose |
|---|---|
| `libc.so` | Standard C library |
| `libart.so` | Android Runtime (Java VM) |
| `libhoudini.so` | **ARM-on-x86 translator** (catches emulators running ARM apps) |
| `libbasic.so` | Common basic helper lib |
| `libcall.so` | Call/IPC helpers |

## Library check method

ACE uses `ACE_ResolveDynFunc_NoDlsym` (libanort+0x136650) which:
1. Reads `/proc/self/maps` line by line
2. For each loaded library, checks the library path
3. Filters by name match (e.g., `*libfridagadget*` substring or hash)
4. If found → set detection flag

Plus inline-hook checks on the 31 libc functions (see `70_libc_hook_watch_complete.md`).

## Houdini specifically

`libhoudini.so` is Intel's ARM-translation layer used by:
- BlueStacks (BlueStacks 4 had Houdini)
- LDPlayer (some versions)
- MuMu Pro 12 (uses Houdini for ARM apps on x86 host)
- Nox (varies)

ACE detecting `libhoudini.so` is a **dead giveaway** that we're on x86 emulator.

For our MuMu setup: Houdini IS loaded → ACE knows we're on emulator → game allows it (per its policy).

## Cross-reference with Java reflection

ACE also uses Java reflection to enumerate loaded native libs via `getDeclaredFields()` on classes. So even if we hide a lib from `/proc/self/maps` (via mount tricks), the Java side could still see it.

## Bypass implications

For our deployed bypass:
- **Tier 1 patches kill the scanners** that walk these lists
- Result: ACE can register libraries to look for, but the actual check never runs
- We don't currently use any cheat libs from this list (no Frida, no SandHook, no SpeedManager)

If a future version of our cheat used Frida or another flagged lib, the existing bypass would still work IF Tier 1 stays effective. To be safe, we could:
- Avoid loading any library named in this list
- Rename our hooks library (it's currently `libdivmod.so` which is unique)
- Use anti-detection techniques (mount-binding to hide files)

## To-do

- Add `libdivmod.so` and our injected libs to the "ignore" list (verify they don't match any detection pattern)
- Test if ACE has a "loaded library count" check that detects our extra `.so`
- Document the iteration loop in `ACE_ResolveDynFunc_NoDlsym` (does it scan ALL libraries every check or only specific ones?)
- Cross-reference with the libanort string list (libmono.so, libjdwp.so, libart.so, libil2cpp.so detection there)
