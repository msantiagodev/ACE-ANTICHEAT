---
iter: 69
title: vm_main.img — first disassembly + control-flow stats
status: 18,943 instructions decoded; 9 SVC syscalls + 1827 branches mapped
---

# vm_main.img Disassembly — First Pass

We treat `vm_main.img.bytecode` (152,332 bytes) as ARM64 machine code (since the VM is an ARM64 emulator that runs ARM64 instruction encodings) and disassemble with capstone. This iteration produces the first complete pass.

## Stats

```
152,332 bytes ÷ 4 = 38,083 candidate 4-byte instruction slots
18,943 valid ARM64 instructions decoded (~50%)
19,140 <invalid> + 2,598 udf = 21,738 non-instruction slots (~50%)
```

The 50% non-instruction rate confirms the bytecode interleaves **code with data** — likely:
- Constant pools (numbers, addresses, format strings)
- Per-function relocation tables (Type-A maps)
- Jump tables for switch statements
- Padding to align function boundaries

## Top opcode frequencies

These match expected detection-engine workload — heavy on memory access and branching:

| Rank | Opcode | Count | Note |
|---|---|---|---|
| 1 | `ldr` | 1,057 | Generic load (anything from memory) |
| 2 | `bl` | 1,013 | Function call |
| 3 | `b` | 814 | Unconditional branch |
| 4 | `str` | 781 | Generic store |
| 5 | `adrp` | 750 | Page-relative address (used for global var access) |
| 6 | `add` | 677 | Arithmetic |
| 7 | `adds` | 568 | Add + flags |
| 8 | `mov` | 531 | Move register |
| 9 | `stp` | 520 | Store pair |
| 10 | `adr` | 510 | PC-relative address |
| 11 | `cbnz` | 467 | Branch if non-zero (lots of "did this match?" checks) |
| 12 | `ldp` | 399 | Load pair |
| 13 | `tbnz` | 167 | Bit-test branch (more checks) |

## Branches: 1,827 total

| Type | Count |
|---|---|
| BL (function call) | 1,013 |
| B (unconditional jump) | 814 |
| → resolves to **type-B native import** | 97 |
| → resolves to **type-A intra-module symbol** | (not counted yet — many) |
| → other (intra-bytecode jump) | majority |

So **97 native-bridge call sites** where VM bytecode jumps directly into a native `__ff_<n>` (or named) function. The other 1,730 branches stay inside the VM bytecode.

## SVC syscalls — 9 sites in vm_main.img

These are direct kernel syscall sites — extremely sensitive!

| Offset | SVC instruction |
|---|---|
| `+0x004C4C` | svc #0x413 |
| `+0x007C20` | svc #0xb81f |
| `+0x00AAA0` | svc #0x1f |
| `+0x00C57C` | svc #0x401f |
| `+0x00F290` | svc #0x91d |
| `+0x010D94` | svc #0x65c1 |
| `+0x017A80` | svc #0x981f |
| `+0x01FCF8` | svc #0xb01f |
| `+0x025070` | svc #0x1f |

The immediate isn't the syscall number directly — ACE's VM passes the syscall number via x8 (per Linux ARM64 ABI). The `#imm16` in SVC is mostly metadata for ACE's VM dispatcher (`ace_vm_op_svc_syscall` at libanort+0x1411DC).

To identify each syscall: hook the SVC handler at runtime and log x8 values. The 9 sites likely hit:
- `getpid`, `gettid`, `prctl` — process introspection
- `read`, `write`, `open`, `close` — file ops on `/proc/self/maps`, `/proc/self/status`
- `mprotect`, `mmap` — memory permission queries (anti-Dobby)
- `kill` (with sig=0) — process existence check

## Native call site analysis

First 5 native call sites (B/BL → type-B import):

| VM offset | Insn | Target | Resolves to |
|---|---|---|---|
| `+0x000288` | `b` | `0x2EC` | `__ff_18` = `ACE_BytecodeEntryValidate` (bytecode entry validator) |
| (more in disasm) | | | |

`__ff_18` = `ACE_BytecodeEntryValidate` (libanort+0x13AE54): Calls `ACE_ValidateAndSendData` — sends a bytecode-validation packet via the network. So the VM's bytecode self-validates by calling back into native code.

## Key insight: VM bytecode interleaves code + data

The 50% "invalid" rate at first looks like a problem, but it's expected for compiled code:
- Constant tables (e.g., string offsets, lookup tables) live alongside code
- ARM64 LDR-literal can reference data within ±1 MB of PC — this is how the VM reads constants
- Type-A entries (2,004 in vm_main.img) are likely OFFSET pairs that point at intermixed data sections

To get a cleaner disassembly:
- Use the type-A entries to identify code regions (entries pointing to instructions) vs data regions
- Skip past `ldr literal`-referenced data
- Treat `udf` as data and re-sync at next likely instruction

## Module entry point — TBD

The first 64 instructions starting at offset 0 don't look like a function prologue. Possible explanations:
- The VM has a separate entry-point header (read from Type-A?)
- The entry is buried in the bytecode and needs to be discovered via control-flow analysis
- The entry might be the first `cbnz` we see at offset 0 (it's a tail-merge style)

To find the actual entry: look at the host-side caller of `ACE_VMExecutionDriver` to see what address it passes as the start PC.

## Bypass implications

### Surgical: hook the 9 SVC sites
If we patch the 9 SVC encoding bytes in vm_main.img to NOPs, the VM never makes kernel calls. Detection routines that need syscalls would fail silently. (Caveat: the bytecode is signed; we'd also need to bypass signature verify.)

### Substitute the entry point
With first-pass control-flow now visible, we can identify the main detection-loop function and replace its body with NOPs + return.

### Statically enumerate detection paths
With 1,013 BL call sites — each landing on either:
- A type-B native bridge (97 sites we now identify)
- An intra-VM function (~916 sites)

We can build a complete callgraph showing exactly which detection routines fire from which VM functions.

## Static artifacts

| File | Size | Description |
|---|---|---|
| `02_vm_main.img.bin.bytecode.disasm` | ~3 MB | Full disassembly of vm_main.img bytecode |
| `disasm_vm_main.py` | — | Disassembly script (re-runnable) |

## To-do

- Build callgraph from BL/B branch addresses
- Identify functions by walking from entry points (first-pass already started)
- Disassemble vm_hb.img, timeout_looper.img, gp7worker, gp7service the same way
- Cross-reference SVC sites to actual syscall numbers (need runtime hook)
- Map type-A entries to call sites for full address resolution
- Identify the actual entry-point address by examining `sub_138FA4` (entry point getter in ACE_VMModuleLoad)

## Cross-references

| Doc | Topic |
|---|---|
| `92_vm_module_bytecode_format.md` | Module file format + native import catalog |
| `91_vm_modules_catalog.md` | The 5 modules (sizes, MD5s) |
| `22_libanort_arm64_emulator.md` | The VM emulator itself |
| `46_arm64_emulator_handler_extension.md` | Opcode handler coverage (~80/122) |
| `48_svc_syscall_bridge.md` | The SVC handler that we'd hook |
