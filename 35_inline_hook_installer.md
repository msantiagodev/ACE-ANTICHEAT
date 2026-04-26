# ACE's Inline Hook Installer — Complete Pipeline

## Function: `ace_install_inline_hook` (libanogs+0x3F9944)

This is the high-level entry point that ACE uses to install ALL its inline hooks. It coordinates trampoline allocation, instruction relocation, and hook registration.

## Pipeline overview

```
ace_install_inline_hook(ctx, hook_obj, mode, ...)
   │
   ├─[1]─ Pre-checks (enabled? not already installed?)
   │
   ├─[2]─ ace_alloc_hook_trampoline(ctx, hook_obj, mode)
   │      │
   │      ├─ Switch on hook_obj.+1 (sub-type)
   │      │  - Case 0/8/12: setup PC-relative offset bytes
   │      │  - Case 2: 8-byte trampoline
   │      │  - Case 3/9: 16-byte trampoline
   │      │
   │      ├─ ace_hook_trampoline_validate
   │      │
   │      └─ Dispatch to one of 4 strategies:
   │         - ace_hook_install_default        (most common)
   │         - ace_hook_install_type_12        (type 12 hooks)
   │         - ace_hook_install_type_extended  (special trampolines)
   │         - ace_hook_install_special_offset (type 297==1/2)
   │
   ├─[3]─ ace_arm64_instruction_relocator(ctx, hook_obj)
   │      │  (See 15_arm64_relocator.md for full details)
   │      │  Rewrites each PC-relative instruction in the original prologue
   │      │  for execution from the trampoline location
   │
   ├─[4]─ Mark installed (hook_obj.+464 = 1)
   │      Increment g_ace_installed_hook_count
   │
   └─[5]─ ace_record_installed_hook(category, name, len, hook_ptr,
                                     trampoline_ptr, trampoline_addr,
                                     offset, prologue_len, inst_bytes)
          │
          └─ Allocates 0x70-byte audit record, copies metadata,
             links into category list (per-type bucket)
```

## Hook type categories (4 buckets)

The recording system groups installed hooks by type. The categories are stored at offsets +144, +152, +160 of an array at `unk_58DAC0`:

| Category | Type | Allocation | Sub-bucket |
|---|---|---|---|
| 1 | Type 1 hooks | 0x48 bytes | a1[18] |
| 2 | Type 3 hooks | 0x48 bytes | a1[19] |
| 3 | Default | 0x48 bytes | a1[20] |
| 4 | Type 4 (registry-bound) | from descriptor | descriptor.+440 |

The category determines which list the hook is appended to. This lets ACE inventory ALL installed hooks by type and remove them in batches if needed.

## Sub-type dispatch (in alloc_trampoline)

The descriptor's byte at +1 selects the install strategy:

| +1 | Strategy | Trampoline size | Notes |
|---|---|---|---|
| 0 | default | 16 bytes | Most common; sets PC-relative offset bytes at +232 (60-addr & 3) and +296 (12-addr & 3) |
| 2 | default | 8 bytes | Smaller trampoline |
| 3 | default | 16 bytes | Standard 16-byte |
| 8 | install_default with helper | 16 bytes | Uses `ace_hook_default_helper` callback |
| 9 | default | 16 bytes | |
| 12 | install_type_12 | 8 bytes | Special small variant; uses helper |

## Special-offset path (type 297)

If `hook_obj.+297 == 1 || hook_obj.+297 == 2`, the installer takes a special path: `ace_hook_install_special_offset`. This handles hooks that need precise placement (likely for cross-page or alignment-sensitive targets).

## Type-extended path

If `hook_obj.+393 == 1` (special flag set), it uses `ace_hook_install_type_extended`. This is for hooks with extended descriptors (more than just 64 bytes of state).

## Hook descriptor layout (relevant offsets)

| Offset | Field | Set by | Used for |
|---|---|---|---|
| `+0` | type | descriptor init | top-level hook type (1=inline, 3=PLT, 4=registry) |
| `+1` | sub-type | descriptor init | strategy selector for trampoline alloc |
| `+2` | name_id | descriptor init | for error logging |
| `+4` | hook_type_dword | descriptor init | controls record category |
| `+69` | enabled | runtime | 0=skip install |
| `+89` | operand counter | runtime | tracks operand vector usage |
| `+96` | operand vector | descriptor init | for AST-driven hooks |
| `+120` | hook target addr | runtime | the function being hooked |
| `+232` | byte offset 1 | alloc_trampoline | PC-relative bookkeeping |
| `+240` | prologue length | alloc_trampoline | 8 or 16 bytes typically |
| `+248` | original bytes | (after install) | inline copy of original prologue |
| `+296` | byte offset 2 | alloc_trampoline | PC-relative bookkeeping |
| `+297` | path selector | descriptor init | special offset path |
| `+304` | tail offset | runtime | trampoline tail address |
| `+393` | extended flag | runtime | force type_extended path |
| `+416` | name string | descriptor init | 32-byte name buffer |
| `+440` | trampoline addr | alloc_trampoline | RWX page address |
| `+448` | hook_ptr | descriptor init | replacement function pointer |
| `+456` | trampoline | alloc_trampoline | trampoline pointer (variant) |
| `+464` | installed flag | install (success) | 1 = installed |
| `+480` | descriptor id | descriptor init | for type-4 lookup |

## What `ace_record_installed_hook` actually records

For audit/inventory purposes, ACE keeps a 0x70-byte record per installed hook:

```c
struct ace_installed_hook_record {
    char     name[64];           // hook name (truncated to 49 chars)
    uint32_t hook_id;            // copied from a4
    uint32_t descriptor_id;      // copied from a5
    uint64_t trampoline_addr;    // a6
    uint64_t prologue_len;       // a7
    uint32_t offset;             // a8 (truncated to 25)
    char     orig_bytes[32];     // first ~25 bytes of original code (truncated)
};
```

This is a 0x70-byte struct with mixed name + addresses + a copy of the original instruction bytes. The list of these records is the "hook inventory" — ACE can iterate it later to verify all hooks are still in place.

## Bypass implications

We've already covered this in Tier 7 (hook `ace_arm64_instruction_relocator` to return true without doing anything). But now we know more attack surfaces:

1. **Hook `ace_alloc_hook_trampoline`** to return 0: trampoline allocation always fails, so install bails before reaching the relocator.

2. **Patch `g_ace_installed_hook_count`**: this is read by the integrity scanner to count installed hooks. If it stays at 0, the scanner sees "no hooks". (But changing it might trigger other anomaly checks.)

3. **Hook `ace_record_installed_hook`** to noop: the install completes but the hook is not added to the inventory. ACE believes hooks are installed but can't iterate them to verify.

4. **Hook one of the 4 install strategy functions**:
   - `ace_hook_install_default` (libanogs+0x3FC730)
   - `ace_hook_install_type_12` (libanogs+0x3FCD5C)
   - `ace_hook_install_type_extended` (libanogs+0x3FB9DC)
   - `ace_hook_install_special_offset` (libanogs+0x3FD698)
   Each returns bool — return false from each to make all installs "fail".

5. **Patch `unk_58DAC0`** (the hook category storage): if categories are NULL, no records get linked. ACE's hook inventory becomes empty.

Tier 7 is still the cleanest option since it short-circuits at the relocator stage, before anything else has happened.

## The "self-hosted Dobby" architecture

This is essentially Dobby (the popular open-source hooking library) reimplemented inside ACE:

| Dobby concept | ACE equivalent |
|---|---|
| `DobbyHook` | `ace_install_inline_hook` |
| `dobby_alloc_near_code` | `ace_alloc_hook_trampoline` |
| Instruction relocator | `ace_arm64_instruction_relocator` |
| Hook descriptor | The 1080+ byte struct |
| Hook list | Records via `ace_record_installed_hook` |

Why ACE has its own? Because:
1. Bundling Dobby would expose Tencent to its license
2. ACE wants control over allocation (anonymous-named VMA, stealthier)
3. ACE wants the INVENTORY for its own self-checking (catches if our Dobby hooks alter ACE's hooks!)

So we've been using Dobby to hook ACE, while ACE has its own Dobby-clone that could detect ours. The relocator is the chokepoint that makes everyone's hooks work.

## To-do (next)

- Decompile the 4 strategy functions (`install_default/_type_12/_type_extended/_special_offset`).
- Find what calls `ace_install_inline_hook` (probably `ace_install_hook_caller_1..6`).
- Verify our Tier 7 actually neutralizes ALL hook installations or just the relocator step.
- Map `g_ace_installed_hook_count` consumers (who reads this counter?).
