# ACE Command Dispatch Tree — A Third Bridge

While exploring the `__ff_<n>` native function wrappers, we discovered a **third** mechanism for emulated code to call native code: a command-code → offset lookup tree.

## The structure

`g_ace_command_dispatch_tree` (libanort+0x1A84C8) is an RBTree initialized once by `ace_init_command_dispatch_tree` (libanort+0x13BCE8).

It maps **~190 magic 32-bit constants** to **offsets** stepping in 8-byte increments from 32 up to 1856.

```c
// pseudocode of the init function
g_ace_command_dispatch_tree = new RBTree;
RBTreeInsert(tree, key=0x4cc88e0f, value=32);    // command #1 → offset 32
RBTreeInsert(tree, key=0xb31bfb1c, value=40);    // command #2 → offset 40
RBTreeInsert(tree, key=0x265f7c41, value=48);    // command #3 → offset 48
... // 190 entries total
```

The keys appear to be hashed identifiers (probably `hash(command_name)` for some hash function).

## How emulated code uses it

The runtime invocation is in `__ff_60` = `sub_13BCE8` itself. The flow:

1. Emulated code calls `__ff_60` with X0/X1 set to (in_data, out_data) pointers
2. The function builds the tree if not yet built (lazy init)
3. Reads the input data (already in VM-translated form via `module[47] + ptr`)
4. Calls `ACE_GetTimestamp` then `ACE_EventSignal` on the input
5. The result of `ACE_EventSignal` is treated as a **lookup key** into the tree
6. If found, dereferences `*(parser_ctx[416] + offset_value + base)` to get the actual function pointer
7. Stores result in module->X0

## The really dangerous bit — `ace_vm_call_native_funcptr`

`sub_13DA54` (libanort+0x13DA54) — at most 8 args, **no pointer translation**:

```c
__int64 ace_vm_call_native_funcptr(__int64 module) {
    return ((fn_ptr)module[0])(             // X0 = function pointer (RAW)
        module[1], module[2], module[3],     // X1..X7 (RAW)
        module[4], module[5], module[6],
        module[7],
        *(parser_ctx[52] + module->SP)       // 8th arg from stack
    );
}
```

This wrapper takes **whatever** function pointer is in X0 and calls it directly. **No sandbox.** The function pointer can be a host process address.

Combined with `__ff_60` (which can return a host function pointer), emulated code can:
1. Call `__ff_60(command_hash)` → returns native function pointer
2. Set X0 = that pointer, set X1..X7 = args
3. Call `ace_vm_call_native_funcptr` → executes the native function with full control

## Bypass implications

This is a **third** chokepoint after:
- The named bridge (`ace_lookup_native_function_by_name`)
- The SVC syscall bridge (`ace_vm_op_svc_syscall`)
- The function pointer call (`ace_vm_call_native_funcptr`)

If we wanted to fully sandbox the emulator, we'd need to neutralize all three. Currently:
- SVC bridge → killed by Tier 1 (ANORT_PATCHES[3])
- Named bridge → not killed (we let it run, since it provides standard libc only)
- Function pointer call → not killed (let it run for now)

The function pointer call is currently low-risk because the actual function pointers are sourced from `parser_ctx[+52]` which is set up at module load. ACE's own modules legitimately use this for indirect dispatch (e.g., calling a callback table inside the module's data).

## The 190 magic constants

From the decompilation we have 190 keys → offsets. The keys are 32-bit signed integers (hex):

```
0x4CC88E0F → 32
0xB31BFB1C → 40
0x265F7C41 → 48
0x57F89AB3 → 56
0x4E2D9494 → 64
0x53A1ED27 → 72
0xC1D8B4D3 → 80
0x1A1F4A48 → 88
... (188 more)
```

These are most likely `hash("CommandName")` for some commonly-used hash. We could brute-force `crc32`, `fnv1a`, `murmur` etc. against known ACE command names to recover the mapping.

## To-do

- Brute-force the 190 key hashes against known ACE command name strings
- Decompile the 190 dispatched functions (whatever sits at `parser_ctx[+52] + offset`)
- Determine what subset of the dispatch is "safe" (sandbox-respecting) vs "dangerous" (host pointer escape)
