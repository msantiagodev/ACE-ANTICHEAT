# GP* Game Protection Layers — The Tencent ACE Tier System

ACE is built around **Game Protection layers** numbered 3 through 7. Each layer represents a generation/tier of detection technology with progressively stronger isolation and capabilities.

## The 5 known GP layers

| Layer | Status | Notes |
|---|---|---|
| GP3 | Legacy | Older Tencent anti-cheat tier; basic detection |
| GP4 | Active | Has variants: gp4_ignore, gp4_vp_ignore, gp4_no_root |
| GP5 | Active | Includes crash handling; has `gp5_crash` |
| GP6 | **Heavy** | Has its own VM module, separate process service, full syscall-like API |
| GP7 | **Latest** | Two VM modules: vm_gp7worker.img + vm_gp7service.img |

## GP6 — the powerful one

GP6 has a **full syscall-like API** exposed to its emulated code. This is the most evolved tier we've found:

| API Name | Purpose |
|---|---|
| `GP6_Stop` | Stop GP6 service |
| `GP6_Gettid` | Get thread ID |
| `GP6_Close` | Close FD |
| `GP6_Read` | Read from FD |
| `GP6_Lseek` | Seek FD |
| `GP6_Readlink` | Read symlink |
| `GP6_Access` | Check file access |
| `GP6_Stat` | File metadata |
| `GP6_GetRegister` | **Read CPU register** (live!) |
| `GP6_ReadMemory` | **Read process memory directly** |
| `GP6_SetEscapeMode` | Toggle sandbox escape (!) |
| `GP6_Dladdr` | Resolve address to symbol/lib |
| `GP6_GetHWBPStat` | Hardware breakpoint status |
| `GP6_VMFunc0` | Invoke native function 0 |
| `GP6_VMFunc1` | Invoke native function 1 |

`GP6_ReadMemory` and `GP6_GetRegister` mean GP6's emulated detection code can:
- Read any memory region in the host process (including the game's data)
- Read CPU registers (for hardware-based attestation)
- Read hardware breakpoint state (catches debug-register tricks)

## GP6Service (string 25664)

`GP6Service` — separate Android Service running GP6 detection in its own process. Communicates with the main game process via shared memory or Binder.

`RunningOnGP6Child` — flag set in the child process. ACE knows when it's running in the GP6 service vs. the game itself.

## GP7 — the future

GP7 has 2 modules:
- `vm_gp7worker.img` — runs in the main game process (worker thread)
- `vm_gp7service.img` — runs in `:GP7Service` separate process

The `GP7Service` is a **separate Android Service** declared in the manifest. Its activities run in a different process, providing process isolation for the most sensitive detection.

The `enable_gp7_exit_group` flag (string 12015) is the kill switch — when set, GP7 can call `exit_group()` to terminate the entire app process.

## Capability progression

```
GP3  → Basic API: GP3_Getpid (get process ID), basic checks
GP4  → Adds gp4_ignore (whitelist mechanism), gp4_no_root (root-relaxed mode)
GP5  → Adds gp5_crash (crash recovery)
GP6  → Major leap: full syscall API + ReadMemory + GetRegister + escape mode
GP7  → Adds out-of-process service + exit_group kill
```

## GP3 detection markers

| Marker | Meaning |
|---|---|
| `gp3` | GP3 layer active |
| `gp3_traced` | Process was being traced (ptrace detected) |
| `gp3_2022` | GP3 update v2022 |
| `gp3_incompat` | GP3 incompatible with environment |
| `gp3_ext` | GP3 extension |
| `gp3_cs`, `gp4_cs` | GP3/GP4 with crash-stack support |

## GP4 specific markers

| Marker | Meaning |
|---|---|
| `gp4_2` | GP4 v2 |
| `gp4_ignore` | Whitelist mode (skip detection) |
| `gp4_vp_ignore` | Whitelist for "VP" (Virtual Process?) |
| `gp4_no_root` | No-root variant (works without root) |
| `gp4_crash` | Crash recovery |

## How layers coexist

In a running ACE deployment:
- GP3 always runs (legacy compat)
- GP4 runs if Android compatible
- GP5 runs as crash handler
- GP6 runs if GP6Service available
- GP7 runs latest detection

Each layer reports independently. The orchestrator at `ace_detection_orchestrator_main` (libanort+0xF6B98) coordinates results.

## ACE strategy keys mapping to GP

| Strategy key | Likely GP layer |
|---|---|
| `root_strategy` | GP4 (with `gp4_no_root`) |
| `frida_strategy` | GP6 (uses GP6_Dladdr to enumerate libs) |
| `mem_watch_strategy` | GP6 (uses GP6_ReadMemory) |
| `ptrace_strategy` | GP3 (`gp3_traced`) |

## Bypass implications

For our deployed bypass:
- **GP3, GP4, GP5**: Less sophisticated — our Tier 1 patches catch most of these
- **GP6**: The most dangerous. `GP6_ReadMemory` could detect ANY of our hooks/changes. But it runs in the emulator (Tier 8 kills the VM driver), so it's neutralized.
- **GP7**: The kill-switch via `exit_group`. Tier 4+5 prevent the trigger condition.

If ACE adds a GP8 in the future, we'd need to re-audit. The current bypass relies on the assumption that all GP detection runs through the emulator (Tier 8 covers).

## To-do

- Decompile each `GP6_*` API to see what it actually exposes
- Find the GP6 service IPC protocol (Binder-based?)
- Cross-reference `vm_gp6.img` (referenced in GP6_VMFunc0/1)
- Document how GP6 transitions in/out of "escape mode" (sandbox bypass!)
- Audit `RunningOnGP6Child` for any process-fork detection
