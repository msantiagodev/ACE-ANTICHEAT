# SVC / Syscall Bridge — The Emulator's Kernel Door

This is **the** most important opcode in the ARM64 emulator. It bridges from emulated VM code directly to the host kernel via the `syscall()` libc function.

## The handler

`ace_vm_op_svc_syscall` (libanort+0x1411DC, dispatch table index 1):

```c
__int64 ace_vm_op_svc_syscall(__int64 insn, __int64 module) {
    if ((insn & 0xFFFC1F) == 1) {
        // ARM64 SVC #imm16 encoding: 0xD400_0001 + (imm16 << 5)
        // The mask 0xFFFC1F catches the lo bits (bit 0=1, bits 5-20=imm16)
        // We don't actually use imm16 — we use module->x16 (slot at +64)
        result = syscall(
            *(uint64_t*)(module + 64),    // x16 = sysno
            *(uint64_t*)(module +  0),    // x0  = arg0
            *(uint64_t*)(module +  8),    // x1  = arg1
            *(uint64_t*)(module + 16),    // x2  = arg2
            *(uint64_t*)(module + 24),    // x3  = arg3
            *(uint64_t*)(module + 32),    // x4  = arg4
            *(uint64_t*)(module + 40),    // x5  = arg5
            *(uint64_t*)(module + 48));   // x6  = arg6
        *(uint32_t*)(module + 288) = 0;   // clear flag
        *(uint64_t*)(module + 456) = result;  // store result at +456
    }
    return insn;
}
```

## What this means

The emulated code can invoke **any Linux syscall** by:
1. Loading the syscall number into X16 (i.e., the simulated register at offset +64).
2. Loading args into X0..X6.
3. Issuing an `SVC` instruction.

The handler calls the host process's libc `syscall()`, which executes a **real kernel syscall in the host process's context**.

## What syscalls are likely used

ACE's downloaded `ob_*.zip` modules contain emulated code. Without disassembling them, the most-likely syscalls are:

| Syscall | Use |
|---|---|
| `read(2)` | Read `/proc/self/maps`, `/proc/self/status`, `/proc/<pid>/cmdline` |
| `openat(2)` | Open detection paths (Frida-server, root tools) |
| `stat(2)` / `fstatat(2)` | Existence checks for jailbreak paths |
| `getpid(2)` / `gettid(2)` | Process introspection |
| `mmap(2)` / `mprotect(2)` | Memory inspection |
| `kill(2)` (with sig=0) | Probe for live processes |
| `socket(2)` / `connect(2)` | Network detection (debug ports) |
| `ptrace(2)` | Tracing detection (catch debuggers) |
| `prctl(2)` | Process options (anti-tamper) |
| `gettimeofday(2)` / `clock_gettime(2)` | Timing checks |

## Already neutralized in our deployed bypass

This is the **same function** we have at `ANORT_PATCHES[3] = 0x1411DC` in our Tier 1 bypass (renamed from `ACE_RawSyscall_PATCHED` after this discovery). Our existing patch `MOV X0, #0; RET` makes the SVC handler return 0 immediately — **no syscalls ever reach the kernel from the emulator**.

This was previously documented as "raw syscall" in `instant_reload_mod/mod.c` without understanding the full context. We now know it is the **single-point bridge** from ACE's downloaded emulated detection code to the kernel.

## Bypass implications — this is the critical chokepoint

If we hook `ace_vm_op_svc_syscall` to:
- **Always return 0** → all syscalls succeed silently with result 0. Detection paths look like "no debugger, no Frida, no root, etc."
- **Lie selectively per sysno** → return canned values for specific syscall numbers. E.g., `getpid()` returns expected PID, `kill(frida_pid, 0)` returns -1 (ESRCH).

Either way, this is a **single-point kill** for ALL emulator-driven detections that use kernel syscalls. It's tier-9 territory and complements our existing tier-8 (VM execution driver kill).

## Why ACE uses emulator-syscalls instead of native

By going through the emulator + `syscall()`:
1. **No PLT/GOT entry to hook**. The emulator calls libc `syscall` directly from its own .text — Dobby hooks on `read`, `open`, etc. don't fire.
2. **Syscall numbers can be obfuscated**. ACE can XOR the sysno or compute it at runtime in the VM, hiding which syscalls it makes from static analysis.
3. **Hard to detect with strace alone**. The strace shows the host process making syscalls, but doesn't reveal that they came from emulated VM code.

## How to find what ACE actually checks

To see what syscalls the emulated code makes, we'd need to:
1. Hook `ace_vm_op_svc_syscall` and log every (sysno, arg0..arg6) tuple.
2. Run the game in the modded environment.
3. Build a histogram of (sysno, args).

This would tell us exactly which paths/PIDs/files ACE is checking, by syscall.

## Encoding check

The handler tests `(insn & 0xFFFC1F) == 1`. ARM64 SVC opcode is:
```
SVC #imm16  →  0xD4_4_imm16_0_001
            =  binary: 11010100 0_imm16_00001
            =  hex:    D4 + (imm16 >> 13) ... + 01
```

Bits:
- 31:24 = `0xD4` (SVC opcode prefix)
- 23:21 = `010` (op2)
- 20:5  = `imm16`
- 4:2   = `000`
- 1:0   = `01`

So the bottom 5 bits = `0_0001` (binary 1). The mask `0xFFFC1F` catches:
- bits 31:18 (top 14 bits)
- bits 4:0 (bottom 5 bits)

Interesting: it ignores bits 17:5 (which is the imm16 field). So the SVC immediate is **not used** — the handler uses x16 (module+64) instead, which is the standard Linux syscall convention.

## Related opcodes (need investigation)

The emulator may have other "bridge to host" opcodes:
- `vfunc_0_1411D8` (nullsub) — opcode 0, doesn't do anything
- `vfunc_1_1411DC` — opcode 1 = **SVC syscall** (this one)
- `vfunc_2_141228` (nullsub) — opcode 2

Wait — opcodes 2-22 are all nullsubs in our table (we documented 25 nullsubs total). It looks like opcodes 1, 17, 18, 19, ... are the actual instructions, and the lower numbers are reserved/unused.

Actually, looking again — opcode 1 (SVC) is the ONLY "bridge to host" via syscall. The other bridges are via the BL/B branch handlers (0x142314, 0x141EB0) which use the special `0x48D958` opcode for `ace_vm_lookup_native_function`.

## To-do

- Hook `ace_vm_op_svc_syscall` in REPL bridge to log every syscall ACE's emulator makes
- Cross-reference observed sysnos with Linux syscall table
- Build a "lying syscall" hook that returns canned values for specific syscall+arg patterns
- Look for opcodes that bridge to **host memory** (read host process memory directly, bypassing the VM's 64KB sandbox)
