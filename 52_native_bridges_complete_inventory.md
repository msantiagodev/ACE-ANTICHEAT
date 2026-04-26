# Complete Inventory of Emulator → Native Bridges

The ACE ARM64 emulator has **multiple distinct mechanisms** for emulated code to invoke native (host) code. This is a complete catalog of every bridge we've found.

## Bridge #1 — Named Function Registry (`__ff_<n>` + named symbols)

- **Trigger**: Emulated `BL/B #0` with key `0` (i.e., the special opcode `0x48D958` set with offset 0)
- **Lookup**: `ace_vm_lookup_native_function(parser_ctx, current_pc)` (libanort+0x139118)
- **RB-tree root**: `parser+16` (per-module)
- **Key**: 32-bit value (typically the `key` field from the `.img` parse)
- **Population**: Module load → `ace_vm_module_parse_img` (libanort+0x1386B8) → `ace_lookup_native_function_by_name(name)` (libanort+0x13F41C) → returns ptr from global registry
- **Global registry**: `g_ace_native_function_registry` (libanort+0x1A84C0)
- **Source tables**: `g_ace_native_function_table_ff` (162 entries) + `g_ace_native_function_table_named` (22 entries)
- **Total exposed**: 184 functions
- **Argument convention**: `(module*)` — wrappers unpack X0..X7 from module struct

## Bridge #2 — Label PC Lookup

- **Trigger**: Emulated `BL/B #imm26` with magic `0x48D958`
- **Lookup**: `ace_vm_lookup_label_pc(parser_ctx, current_pc)` (libanort+0x1390E0)
- **RB-tree root**: `parser+0` (per-module)
- **Key**: 32-bit value (label key from `.img`)
- **Population**: Module load → `.img` v50 section
- **Returns**: New PC (uint32) — sets `module->PC = ret`
- **Used for**: Long branches to "named labels" inside the module that the assembler couldn't encode in 26 bits

## Bridge #3 — Shellcode Section Lookup

- **Trigger**: `__ff_14` wrapper (libanort+0x13B124)
- **Lookup**: `ACE_VMShellcodeLookup(parser_ctx, name_str, ...)` (libanort+0x139234)
- **RB-tree root**: `parser+120` (per-module)
- **Key**: hash of formatted string `.text.shellcode_<name_str>`
- **Returns**: Function pointer
- **Argument convention**: 7 args directly (X1..X7 from emulated)
- **Used for**: Modules that ship custom "shellcode" sections — alternative ABI to `__ff_<n>`

## Bridge #4 — Command Dispatch Tree (Hash Lookup)

- **Trigger**: `__ff_60` wrapper (libanort+0x13BCE8) — the init function doubles as the dispatcher
- **Lookup**: in-line BST search of `g_ace_command_dispatch_tree`
- **RB-tree root**: `g_ace_command_dispatch_tree` (libanort+0x1A84C8) — global
- **Key**: 32-bit hash from `ACE_EventSignal(in_data, ACE_GetTimestamp(in_data))`
- **Returns**: Offset (32..1856 step 8) — used as `*(parser_ctx[+52] + offset)` to dereference final function pointer
- **Population**: One-shot at first call to `__ff_60`. ~190 entries hardcoded into init.

## Bridge #5 — Function Pointer Direct Call

- **Trigger**: `__ff_<some_n>` (uses `sub_13DA54` = `ace_vm_call_native_funcptr`)
- **Lookup**: NONE — uses raw function pointer from `module->X0`
- **Argument convention**: 8 args (X1..X7 + 1 stack arg)
- **DANGER**: No pointer translation, no bounds check
- **Status**: Allowed — ACE's own modules legitimately use it

## Bridge #6 — SVC Syscall

- **Trigger**: `SVC #imm` instruction (handled by opcode 1 = `ace_vm_op_svc_syscall`)
- **Lookup**: NONE — uses `module->X16` as syscall number
- **Argument convention**: standard syscall(sysno, X0..X6)
- **DANGER**: Direct kernel access, no pointer translation
- **Status**: **KILLED** by Tier 1 (ANORT_PATCHES[3] = 0x1411DC patched to `MOV X0,#0; RET`)

## Bridge summary table

| # | Bridge | Trigger | Lookup mechanism | Allowed? | Notes |
|---|---|---|---|---|---|
| 1 | Named registry | BL/B #0 | RB-tree by 32-bit key | ✓ allowed | 184 functions, sandboxed |
| 2 | Label PC | BL/B #imm26 magic | RB-tree by 32-bit key | ✓ allowed | Just relocates PC |
| 3 | Shellcode section | `__ff_14` | RB-tree by string hash | ✓ allowed | Custom per-module ABI |
| 4 | Command dispatch | `__ff_60` | RB-tree by event hash | ✓ allowed | 190 entries, function-pointer-of-pointer |
| 5 | Direct fn-pointer | `__ff_?` | None (raw X0) | ✓ allowed (low risk) | Only ACE's own modules use |
| 6 | SVC syscall | `SVC #imm` | None | ✗ **KILLED** | Tier 1 patch |

## Why so many bridges?

Each bridge optimizes for a different use case:
- **Bridge 1** (named registry): Standard libc-style imports — emulated code links against named symbols.
- **Bridge 2** (label PC): Long-distance branches inside a module; relocation table.
- **Bridge 3** (shellcode): Modular extensibility — modules can ship their own native code in addressable sections.
- **Bridge 4** (command dispatch): Centralized command routing for "control plane" operations (config, reporting, etc.).
- **Bridge 5** (raw fn-pointer): Indirect dispatch within a module's data; internal callbacks.
- **Bridge 6** (SVC): Kernel access for system info collection (`getpid`, `read /proc`, etc.).

## Bypass posture

We have ONE bridge killed (SVC, the most dangerous). The rest run normally. This works because:

1. The non-SVC bridges all sandbox via VM↔host pointer translation.
2. ACE's own modules legitimately use bridges 1-5 for normal operation.
3. The kernel is the only resource that, if accessed unfiltered, can leak host state.

If we wanted to be paranoid, we could also kill bridges 5 (low-risk function pointer call) and patch the more-dangerous wrappers in bridge 1 (e.g., the proc/file readers). But our existing 8-tier bypass already neutralizes detection at higher levels.

## Cross-reference

| Bridge | Doc | Function |
|---|---|---|
| 1 | `49_native_function_registry.md` | `ace_vm_lookup_native_function` |
| 2 | (this doc) | `ace_vm_lookup_label_pc` |
| 3 | (this doc) | `ACE_VMShellcodeLookup` |
| 4 | `50_command_dispatch_tree.md` | `ace_init_command_dispatch_tree` |
| 5 | `50_command_dispatch_tree.md` | `ace_vm_call_native_funcptr` |
| 6 | `48_svc_syscall_bridge.md` | `ace_vm_op_svc_syscall` |
