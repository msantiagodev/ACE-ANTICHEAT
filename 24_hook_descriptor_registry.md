# Hook Descriptor Registry — The Heart of Hook Tracking

## Singleton

`ace_get_hook_descriptor_registry` (libanogs+0x3C03B4) → `ace_get_hook_descriptor_registry_impl` (libanogs+0x3B8B6C) returns the singleton at `qword_58DAE8`.

The registry is **0x838 bytes (2104 bytes)**, lazily allocated on first call. Init via `sub_3B8C68`.

## Memory layout

Inferred from `sub_3B8C68` (init) and accesses across the codebase:

| Offset | Size | Field |
|---|---|---|
| `+0` | 8 | vtable ptr (`off_52DA18`) — the BIG registry vtable |
| `+8..+18` | bytes | flags array. `+10/+12/+14 = 1` (init); `+8/+9/+11/+13/+15/+16/+17/+18 = 0` |
| `+600` | 8 | `strdup`'d configuration name string (set by VM op `ace_expr_op_obstub_dispatch_4/9`) |
| `+608` | 24 | **hook chain 1** (dict-style structure, init via `sub_3B90F8`) |
| `+632` | 24 | **hook chain 2** (dict-style) |
| `+656` | 24 | **hook chain 3** (dict-style) |
| `+680` | 2 | magic word `0x8229` (-32215 signed) |
| `+682` | 1 | flag |
| `+688` | 800 | **hook chain 4** array of 100×8-byte slots (sub-tables) |
| `+1488` | 4 | hook chain 4 active count |
| `+1492` | 40 | dict (sub_3B8900 init) |
| `+1532` | 40 | dict |
| `+1572` | 40 | dict |
| `+1612` | 12 | counter dwords (3 × 4 bytes) |
| `+1624` | 1 | flag |
| `+1632` | 24 | qword[3] state |
| `+1656` | 4 | dword = 1 (enabled?) |
| `+1660` | 4 | dword = 1 |
| `+1664` | 4 | dword = 0 |
| `+1668` | 400 | **per-hook-id counter array** (100 × 4 bytes) |
| `+2068` | 4 | dword = 0 |
| `+2072` | 24 | another container (sub_3B9088 init) |
| `+2096` | 1 | flag |

## The 4 hook chains

VM op `ace_expr_op_install_all_hooks_for_chain` (libanogs+0x39C3E0) walks **4 hook chains** based on rule type:

| Chain | Storage | Type |
|---|---|---|
| 1 | `+608` | dict, single-level |
| 2 | `+632` | dict, single-level |
| 3 | `+656` | dict, single-level |
| 4 | `+688[0..99]` | array of pointers; each entry has its own dict at `*entry + 120` |

The first 3 are **flat** dicts: name → hook descriptor.

The 4th is a **2-level structure**: an array of sub-registries, each containing its own dict. Used for grouped/nested hook installations (e.g., per-module hook sets).

## The big vtable (`off_52DA18`)

The registry vtable has hundreds of entries. Sample:

| Slot | byte off | Address | Behavior |
|---|---|---|---|
| 0 | +0 | 0x3B9140 | constructor / init |
| 1 | +8 | 0x3B93D4 | ? |
| 2 | +16 | 0x3B9410 | **lookup by ID** (used by ace_rule_run_setup) |
| 3 | +24 | 0x3C0334 | typed accessor |
| 4 | +32 | 0x3C0354 | typed accessor |
| 5 | +40 | 0x3B9428 | dispatch helper |
| 6 | +48 | 0x3B9528 | dispatch helper |
| 7 | +56 | 0x3B9628 | another dispatch |
| 8 | +64 | 0x3BC12C | ? |
| 9 | +72 | 0x3C022C | ? |
| ... | | | ... |
| 16 | +128 | 0x3C02D4 | `return *(byte*)(this+15)` — flag getter |
| 17 | +136 | 0x3C02EC | flag getter |
| 18 | +144 | 0x3C0304 | flag getter |
| 19 | +152 | 0x3C031C | flag getter |
| 20 | +160 | 0x3BA670 | substantial work — likely registration |
| 21 | +168 | 0x3BFB04 | **find descriptor by ID** (used by VM ops) |
| 24 | +192 | 0x3C046C | another setter |
| 25 | +200 | 0x3C0650 | another |
| 26-31 | +208..+248 | 0x504610 | default thunk (multiple slots share) |

Then a third "chunk" of vtable at 0x52DC00+:

Looking at the dump after slot ~28, many entries are individual function pointers from various subsystems (0x3C84xx, 0x3F2D9C, 0x408D xx, etc.) — these are the implementations the registry exposes.

The 0x504610 entries (multi-shared default) suggest those slots are placeholder no-ops.

## How VM ops use this

Several VM operators query the registry:

- **`ace_expr_op_set_hook_target` (0x39BB50):** calls `vfn[21] (registry, *(uint*)a3+4, 0, v7, 0xFFFF, 0, 0)` to find the descriptor by ID, then writes the target address.
- **`ace_expr_op_set_hook_bytes` (0x39BCD4):** same lookup, then writes the byte sequence.
- **`ace_expr_op_set_hook_enabled` (0x39BF60):** sets descriptor's enabled flag.
- **`ace_expr_op_install_all_hooks_for_chain` (0x39C3E0):** walks one of the 4 chains, recursively installs every hook.

## Hook descriptor (the 1080+ byte object)

When a single hook descriptor is allocated, it has:

| Offset | Field | Notes |
|---|---|---|
| `+0` | type ('1' = inline, '3' = libc-PLT) | controls install method |
| `+1` | sub-type | further classification |
| `+8` | hook obj/handle | set by ace_install_or_query_hook |
| `+24` | flag (0/1/3) | descriptor type indicator |
| `+25` | sub-flag (1/2/3) | |
| `+32` | qword | "id1+id2" for descriptor lookup (lower 32-bit = id, upper 32-bit = subid) |
| `+69` | enabled byte | 0/1 |
| `+88` | active hook flag | |
| `+96` | byte sequence (32 bytes) | hex bytes for inline patch |
| `+120` | hook target address | written by `ace_expr_op_set_hook_target` |
| `+232..+248` | original prologue bytes | for restoration |
| `+240` | prologue length | |
| `+260` | name field offset | accessed by VM "str" prefix lookup |
| `+280` | padding bytes | header size |
| `+288` | trampoline pointer | RWX page |
| `+296` | byte offset into descriptor | for relocator scratch |
| `+393` | special flag | |
| `+416` | name string (32-byte) | |
| `+440` | trampoline_addr | |
| `+448` | hook_ptr | |
| `+456` | trampoline | |
| `+464` | installed flag | 1 = active |
| `+1022` | predicate id | for if-statement rules |
| `+1024` | jump target id | for type 6/7 rules |
| `+1032` | AST tree ptr | actual rule body |

## Hook engine descriptor (separate object)

`ace_get_hook_engine_descriptor` (libanogs+0x494274) returns a DIFFERENT singleton at `qword_58EE38`, allocated to **0x1048 bytes**. This is the one used by `ace_rule_run_setup`. Its vfns:

- vfn[2] (byte off 16) = lookup-by-id (returns descriptor handle or NULL)
- vfn[7] (byte off 56) = create-or-upgrade descriptor

The hook ENGINE manages descriptors; the hook DESCRIPTOR REGISTRY tracks installation state. Different roles, different objects.

## Bypass implications

The registry is a **central choke point**. Hooking key vfns disables specific subsystems:

1. **Hook vfn[21] (0x3BFB04 — descriptor lookup-by-id)** to return NULL: any VM op that tries to install/modify a hook fails because it can't find the target descriptor.

2. **Patch the registry struct directly**: 
   - Set `+1656 = 0` and `+1660 = 0` to disable hook installation.
   - Set every `+688[i] = 0` to empty hook chain 4.
   - Patch `+682 = 0` to flag-disable.

3. **Hook the registry singleton getter** (`ace_get_hook_descriptor_registry_impl`) to return a known-empty struct: the entire hook system runs against an empty registry, so no descriptors exist to install.

4. **Hook the hook ENGINE descriptor's vfn[16]** (lookup) to return NULL: ace_rule_run_setup fails to find/create descriptors, so no rules run. (This is essentially Tier 6 from a different angle.)

## To-do (remaining)

- Decompile each of the 200+ vfns in `off_52DA18` to give them human names.
- Map the dict structure at `+608/+632/+656` (probably uses `ace_dict_*` from libanogs).
- Document hook chain 4's per-slot sub-registry layout.
- Find what calls each vfn — gives us a "vfn → caller" cross-reference.
