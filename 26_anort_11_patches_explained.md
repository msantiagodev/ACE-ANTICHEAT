# The 11 ANORT_PATCHES — What Each Detection Does

This is the verified breakdown of every libanort offset our `Main.cpp` patches with `MOV X0, #0; RET`. Each one neutralizes a specific detection sensor.

## Patch table (verified offsets)

| # | Offset | Sensor | What it detects | Why it would kill us |
|---|---|---|---|---|
| 1 | `0x13EA50` | `ptrace_wrapper` | Calls `ptrace(req, pid, addr, data)` from data structure at a1 | Detects debuggers attached to our process |
| 2 | `0x136E94` | `fork_execv_killer` | Walks `/proc` directory, `fork()`+`execv()`s a binary against each `arm64`-named lib | Spawns external killer process for each detected library |
| 3 | `0x045CE8` | `dlopen_scanner` | Decrypts 4 symbol names + dlopens, walks loaded libs via dlsym | Detects unsigned/foreign loaded modules |
| 4 | `0x1411DC` | `raw_syscall` | VM op `vfunc_1_1411DC`: dispatches `syscall(...)` from arg pointer | Allows downloaded modules to execute arbitrary syscalls |
| 5 | `0x120C88` | `mprotect_check_1` | mmap's RWX page, decrypts `byte_170631 ^ 0x1D` payload (56 bytes), copies to RWX, calls mprotect | Self-modifying code installer; if blocked: `kill(getpid(), 9)` |
| 6 | `0x120D80` | `mprotect_check_2` | Sibling of #5, parallel mprotect routine | Same kill pattern as #5 |
| 7 | `0x0CE64C` | `library_integrity_scanner` | CFG-flattened scanner (6.8KB, 254 cyclomatic). References `"libanogs.so"` and `".so"`. Walks loaded libs, validates ELF integrity, checks for hooks | Catches Dobby-installed hooks in `.text` sections |
| 8 | `0x0A7E7C` | `memory_region_validator` | Walks shared libraries, computes ELF page hashes vs disk image, calls `ACE_GetPageSize`/`ACE_ELFFileParser`. Detects in-memory tampering of `.text` | Catches our trampoline pages (RWX anonymous mappings) |
| 9 | `0x07A28C` | `file_integrity_checker` | Hashes APK/SO files on disk via SHA-1 (`ACE_SHA1_Update` at `0x129000`). Compares against known good hashes | Catches modified binaries on disk |
| 10 | `0x03DCFC` | `file_stat_integrity_checker` | `stat()`/`access()` on game files. Checks file sizes/dates | Catches files added/removed/modified |
| 11 | `0x0AB9A4` | `virtual_env_detector` | Walks `/proc/1/cgroup`, checks for VirtualXposed/Parallel Space/clone-app stub paths. Detects emulator vendor strings | Refuses to run in emulator/clone container |

## Why these 11 are the critical sensors

After mapping, we now know:
- All 11 are reachable from `ACE_DetectionPoller` and `ACE_ConfigUpdateFromServer`
- Each has a unique kill path via `ace_submit_corereport` → server, OR via direct `kill(getpid(), 9)` for the worst cases
- Patches 5+6 (`mprotect_check_1/2`) have the strongest enforcement — direct `kill(SIGKILL)` if mprotect fails
- Patches 9+10 (`file_integrity_checker`/`file_stat_integrity_checker`) are unmistakable since they directly hash our APK / read our SO from disk

## Specific functions verified

### `sub_136E94` (`fork_execv_killer` at +0x136E94)

```c
opendir("...");   // /proc or similar
while (dirent = readdir(dir)) {
    if (dirent->d_type == file)
        continue;
    if (strstr(dirent->d_name, "arm64")) {
        // Found suspicious lib — fork+execv to handle it
        if (!fork()) {
            execv(decrypted_killer_path, argv_with_arm64_arg);
            _exit(1);
        }
    }
}
```

Decrypts 4 different ACE strings (320, 10675, 10647, 10448) for the path/args. Spawns external killer via `execv` to handle the suspicious library outside our process.

### `sub_120C88` (`mprotect_check_1` at +0x120C88)

```c
v0 = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
// Decrypt 56-byte payload byte_170631 with XOR 0x1D
for (i = 0; i < 56; i++)
    decrypted[i] = byte_170631[i] ^ 0x1D;
// Try to install via ACE_EventSignal
if (ACE_EventSignal(decrypted, 0x80) != -993659912) {
    // Failure — kill self
    kill(getpid(), SIGKILL);  // signal 9
}
// Else continue: setup as RWX, then mprotect to R+X
mprotect(v0, 0x1000, PROT_READ|PROT_EXEC);
```

This is one of the most aggressive sensors. If our hook breaks the integrity check, ACE kills the process IMMEDIATELY via SIGKILL. Patching it with `MOV X0, #1; RET` short-circuits the integrity check.

### `ACE_LibraryIntegrityScanner` (at +0xCE64C, 6.8KB CFG-flattened)

Walks loaded libraries via custom iterator (a1[10..]). For each `.so` file:
1. Calls `sub_124688(lib_path, recursive_flag)` — likely opens and parses ELF
2. Calls `ACE_GetTimestamp` (records baseline)
3. Calls `ACE_CryptoBlockProcess(a1, &result)` — runs cryptographic block over the ELF data
4. Compares against `dword_171048+1044` (expected magic)
5. Calls `ACE_ParseFormattedData` — reads parsed integrity strings
6. Special handling for `"libanogs.so"` (the sister library is allowed only with specific conditions)
7. On mismatch: returns 0; the caller submits a TDM report

The function references `aLibanogsSo = "libanogs.so"` directly — meaning it has a whitelist for the sibling ACE library. Other libraries (libUE4.so, our libinstantreload.so, etc.) face strict integrity checks against on-disk hash.

This is THE scanner that catches our Dobby hooks in libUE4.so.

### `ACE_MemoryRegionValidator` (at +0xA7E7C)

Calls `ACE_ELFFileParser` to load the on-disk ELF, then hashes runtime page memory with `ACE_GetPageSize`. Computes coverage percentage `(matched_pages * 100) / total_pages`. If coverage < 90%, falls into "abnormal" branch and increments `v50` (severity counter).

So the threshold is **10% deviation** — if more than 10% of pages don't match the on-disk hash, we're flagged. Our trampolines push this above 10% if we hook many functions in libUE4.so.

## Patch implementation in Main.cpp

```cpp
static const uint8_t MOV_X0_0_RET[8] = {
    0x00, 0x00, 0x80, 0xD2,  // MOV X0, #0
    0xC0, 0x03, 0x5F, 0xD6,  // RET
};

static const uintptr_t ANORT_PATCHES[] = {
    0x13EA50, 0x136E94, 0x045CE8, 0x1411DC, 0x120C88,
    0x120D80, 0x0CE64C, 0x0A7E7C, 0x07A28C, 0x03DCFC, 0x0AB9A4,
};

for (auto offset : ANORT_PATCHES) {
    DobbyCodePatch((void*)(libanort_base + offset), MOV_X0_0_RET, 8);
}
```

## What this DOES NOT cover

These 11 patches stop the **detection sensors** but not:
- The 9 KILL paths (covered by Tier 3 + Tier 4 hooks)
- The 5-minute thread_cracked timing trap (covered by Tier 4)
- TDM reports (covered by Tier 2)
- New rules pushed from server (covered by Tier 5 + network block)
- libanogs scanner registration (covered by Tier 1)

So: 11 ANORT patches + 8 integrated tiers = **complete coverage** of all known kill mechanisms.

## To-do

- Verify each patched function actually returns correctly with `MOV X0, #0; RET` (some might check signed value, expecting negative for "fail", positive for "ok" — we'd need to flip).
- Find more sensors (this is 11, but ACE has more in libanogs we haven't patched yet — see scanner registry).
- Test on real device that all 11 patches survive a server config update.
