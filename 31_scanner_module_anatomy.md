# Scanner Module Anatomy — How Each Detector Works

## The C++ class hierarchy

ACE's scanners are C++ objects all derived from a base class with vtable `vtable_module_BASE` (libanogs+0x528BA0). Each scanner type has its own derived vtable that overrides `scan()` (slot 7) with detection-specific logic.

## vtable_module_BASE layout (32 slots)

| Slot | Address | Purpose |
|---|---|---|
| 0 | 0x1E64D0 | constructor / destructor |
| 1 | 0x1E64D4 | destructor 2 (multi-inheritance) |
| 2 | 0x504610 | default thunk |
| 3 | 0x1E6380 | get_name |
| 4 | NULL | reserved |
| 5 | 0x1EB2B8 | enable/disable getter |
| 6 | 0x1EB2BC | flag accessor |
| **7** | **0x1EB320** | **scan() — abstract, base = no-op** |
| 8 | 0x1EB324 | post_scan |
| 9-15 | 0x1EB328-0x1EB344 | pre/setup hooks |
| 16 | 0x1EB47C | initialization |
| 17-20 | 0x1EB480-0x1EB48C | result/state accessors |
| 21 | 0x1EB5C0 | report builder helper |
| 22-25 | 0x1EB5C4-0x1EB5D0 | report fields |
| 26 | 0x1EB734 | flush |
| 27 | 0x1EB7A8 | finalize |
| 28-30 | 0x1EB91C-0x1EB924 | misc |

The base scan() at slot 7 is `ace_module_base_scan_nop` — it does nothing. Derived scanners override this.

## Module struct layout (per scanner instance)

Allocated via `ace_calloc_wrapper(SIZE)` — sizes vary 0x48-0x150 bytes depending on scanner.

| Offset | Field | Notes |
|---|---|---|
| `+0` | vtable ptr | Initially `vtable_module_BASE`, then overwritten with derived (e.g., `vtable_module_anti_root`) |
| `+8` | linked-list-style fields (init via `ace_module_init_field_8`) |
| `+40` | another field (init via `ace_module_init_field_40`) |
| `+72` | enabled byte (set by ace_register_scanner_module) |
| `+80` | flag2 byte |
| varies | scanner-specific state |

## Init pattern (universal)

Every `ace_init_*_module` function:

```c
void ace_init_FOO_module(void* this) {
    *(qword*)this = vtable_module_BASE;          // base ctor
    ace_module_init_field_8(this+8, 0);          // init field at +8
    ace_module_init_field_40(this+40, 0);        // init field at +40
    *(qword*)this = vtable_module_FOO;           // override with derived vtable
    *(byte*)(this+72) = 0;                        // some flag
    // ... module-specific inits
}
```

So the constructor does:
1. Initialize the base class
2. Switch the vtable to the derived class
3. Initialize derived-class fields

## Verified scanner inventory (with vtables)

| vtable | Module | Purpose |
|---|---|---|
| `vtable_module_BASE` (0x528BA0) | abstract base | base scan() = no-op |
| `vtable_module_anti_cheat_open_id` (0x52A728) | anti_cheat_open_id | account-id-based anti-cheat |
| `vtable_module_trusted_scanner` (0x52A758) | trusted_scanner | check trust |
| `vtable_module_elf_hook_scan` (0x52A908) | elf_hook_scan | **catches our Dobby hooks** |
| `vtable_module_anti_virapp` (0x52AA98) | anti_virapp | anti-virtualized-app |
| `vtable_module_black_app` (0x52AB58) | black_app | blacklist check |
| `vtable_module_frida_scan` (0x52AC28) | frida_scan | Frida server detection |
| `vtable_module_cps_new` (0x52AC58) | cps_new | CPS variant |
| `vtable_module_cert3` (0x52ADE8) | cert3 | APK certificate v3 check |
| `vtable_module_cps_new3` (0x52B000) | cps_new3 | CPS variant 3 |
| `vtable_module_cps_new_alt` (0x52B050) | cps_new_alt | CPS variant alt |

## How to find what each scanner detects

1. Look up the scanner's vtable in IDA (via the table above)
2. Read slot 7 (byte offset 56) — that's the `scan()` method
3. Decompile it to see the detection algorithm

For example, to see what `frida_scan` does:
- Vtable at 0x52AC28
- Slot 7 = qword at 0x52AC28 + 56 = 0x52AC60
- Read that pointer → it's the address of the frida-specific scan() method

## Why this design helps us

Single-point bypass: hooking `ace_register_scanner_module` (libanogs+0x22D428) at registration drops the entire scanner before its `scan()` is ever called. This is what Tier 1 of our bypass does.

Alternatively, hooking `ace_module_base_scan_nop` (the BASE class's no-op) does nothing, but hooking the derived class's slot 7 directly silences a specific scanner. This is more surgical but requires knowing the vtable address.

## To-do

- For each derived vtable, decompile slot 7 (the scan method) and document the detection algorithm.
- Map all 37 scanner module init functions to their respective vtables (we have ~11).
- Build a script that automatically extracts each scanner's name + slot-7 ptr and produces an inventory.
