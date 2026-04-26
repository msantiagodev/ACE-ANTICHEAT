# ACE Has a Downloaded Scripting Language

## The discovery

The cluster of 100+ functions in `0x395478 – 0x399E50` of libanogs.so are NOT hook descriptor accessors as I initially thought. They are **operators in an expression-evaluation engine**.

Each operator follows the pattern:
```c
__int64 ace_expr_op_NAME(__int64 *self) {
    operand_a = *ace_expr_get_operand(self + 8, 0);
    operand_b = *ace_expr_get_operand(self + 8, 1);
    *self = OP(operand_a, operand_b);  // store result back into self
    return 1;
}
```

Where `self+8` is the operand vector (start_ptr, end_ptr pair).

## Verified operators

### Arithmetic
| Address | Operator | Type |
|---|---|---|
| `0x395478` | `ace_expr_op_add_int` | A + B (int64) |
| `0x39554C` | `ace_expr_op_sub_int` | A - B |
| `0x3955F4` | `ace_expr_op_mul_int` | A * B |
| `0x39569C` | `ace_expr_op_div_int` | A / B (guards /0) |
| `0x395750` | `ace_expr_op_add_float` | A + B (float) |
| `0x395824` | `ace_expr_op_sub_float` | A - B (float) |
| `0x3958F8` | `ace_expr_op_mul_float` | A * B (float) |
| `0x3959CC` | `ace_expr_op_div_float` | A / B (float, /0 guard) |

### Bitwise
| Address | Operator |
|---|---|
| `0x395AAC` | `ace_expr_op_and_bit` |
| `0x395B54` | `ace_expr_op_or_bit` |
| `0x395BFC` | `ace_expr_op_xor_bit` |
| `0x395CA4` | `ace_expr_op_shr` |
| `0x395D4C` | `ace_expr_op_shl` |

### Comparison
| Address | Operator |
|---|---|
| `0x395DF4` | `ace_expr_op_eq` (==) |
| `0x395EAC` | `ace_expr_op_ne` (!=) |
| `0x395F64` | `ace_expr_op_lt` (<) |
| `0x39601C` | `ace_expr_op_le` (≤) |
| `0x3960D4` | `ace_expr_op_gt` (>) |
| `0x39618C` | `ace_expr_op_ge` (≥) |

### Side-effecting / dangerous operators
| Address | Renamed | Effect |
|---|---|---|
| `0x39C9EC` | `ace_install_hook_caller_1` | INSTALLS an inline hook (with name lookup) |
| `0x3B0EEC` | `ace_install_hook_caller_2` | INSTALLS an inline hook (lookup by ID) |
| `0x3FAD70` | `ace_install_hook_caller_3` | INSTALLS hook (variant 3) |
| `0x494610` | `ace_install_hook_caller_4` | INSTALLS hook (variant 4) |
| `0x496BEC` | `ace_install_hook_caller_5` | INSTALLS hook (variant 5) |
| `0x497EC8` | `ace_install_hook_caller_6` | INSTALLS hook (variant 6) |
| `0x396694` | `ace_expr_op_read_memory_sized` | READ MEMORY (byte/word/dword/qword based on config byte) |
| `0x396910` | `ace_expr_op_indirect_load` | TRIPLE-DEREF LOAD (`*self = ***ptr`) |
| `0x39699C` | `ace_expr_op_call_func_8arg` | CALL FUNCTION POINTER (int return, 8 args) |
| `0x396B6C` | `ace_expr_op_call_func_float` | CALL FUNCTION POINTER (float return) |
| `0x396D54` | `ace_expr_op_call_func_double` | CALL FUNCTION POINTER (double return) |
| `0x396FE4` | `ace_expr_op_string_intern` | INTERN STRING in pool (max 61 entries) |
| `0x397488` | `ace_expr_op_string_remove` | REMOVE INTERNED STRING |
| `0x39761C` | `ace_expr_op_register_report` | REGISTER detection report builder |
| `0x3976A4` | `ace_expr_op_load_field_at_32` | LOAD FIELD at +32 of object |
| `0x397B40` | `ace_expr_op_dlopen_test` | TEST IF LIBRARY LOADABLE (dlopen+dlclose) |
| `0x397C38` | `ace_expr_op_dlsym_cached` | DLSYM with cached handles |
| `0x3981F4` | `ace_expr_op_compute_a` | Hash/CRC computation |
| `0x398374` | `ace_expr_op_call_variadic` | VARIADIC FUNCTION CALL (any N args) |
| `0x39866C` | `ace_expr_op_scan_range` | SCAN MEMORY RANGE for pattern |

### Logical
| Address | Renamed | Effect |
|---|---|---|
| `0x39625C` | `ace_expr_op_assign` | Result := operand[0] (with side metadata) |
| `0x396330` | `ace_expr_op_logical_and` | A && B |
| `0x396408` | `ace_expr_op_logical_or` | A \|\| B |
| `0x39656C` | `ace_expr_op_mod` | A % B |
| `0x39661C` | `ace_expr_op_bitwise_not` | ~A (one-operand) |

So **executing the right expression can install an inline hook on any libc function**. The script can also presumably:
- Submit detection reports
- Read memory
- Hash byte regions
- Do file I/O
- Walk loaded modules
- ... and more (TBD)

## The expression-tree node layout

Each node is a struct with at least:
- offset 0: result slot (or first 8 bytes of result)
- offset 8: ??? (next field)
- offset +96: operand vector header (start_ptr at +0, end_ptr at +8)
  - Each operand is a pointer to another expression-tree node OR a literal value

Calling `node->op(node)` executes the operator, evaluating sub-expressions through `ace_expr_get_operand(node+8, idx)`.

## How ACE uses this

The downloaded ZIP rule packages (`ob_cdn2.zip`, `ob_cs2.zip`, `ob_gs2.zip` + 64-bit variants) likely contain:
- Expression trees encoded in some format (binary/protobuf/JSON?)
- The trees are deserialized into in-memory nodes at runtime
- The scanner walks the trees to evaluate detection rules

This explains why ACE_ConfigUpdateFromServer is so important — without it, ACE runs only baked-in rules. WITH it, ACE can deploy new detection scripts on the fly.

## Implications for our bypass

1. **Static reverse-engineering is incomplete.** The detection logic in the SDK binary is just the runtime engine; the actual rules live in downloaded scripts. We can't see all detections by reading the binary alone.
2. **Tier 5 (disable config update via `dword_171118 |= 0x100`) is critical.** Without it, the server can push a new rule that specifically targets us.
3. **Network-level blocking is the strongest defense.** If we firewall `*.anticheatexpert.com` at DNS/iptables level, ACE never updates rules.
4. **For full emulation, we don't need to reproduce the engine** — a stub libanogs.so that returns "no rules to evaluate" defeats the script engine entirely.

## Expanded operator inventory (iteration 16-17 additions)

### Type-conversion and bit-cast
| Address | Operator |
|---|---|
| `0x39961C` | `ace_expr_op_int_to_float_bits` (int reinterpreted as float bits) |
| `0x3996AC` | `ace_expr_op_int_to_float_trunc` (int truncated to float) |

### Hashing
| Address | Operator |
|---|---|
| `0x399738` | `ace_expr_op_hash_bytes` (rolling XOR hash over operand bytes) |

### Guarded memory
| Address | Operator |
|---|---|
| `0x399A8C` | `ace_expr_op_memread_dword_guarded` (locked 4-byte read, returns `0xBAD00BAD` on validation fail) |
| `0x399D44` | `ace_expr_op_nop_zero` |
| `0x39A8AC` | `ace_expr_op_nop_zero_v2` |
| `0x39B70C` | `ace_expr_op_nop_true` |

### Embedded dictionary (slua_unreal-style hashmap)
ACE has a built-in dict/map type: `ace_dict_create` (calloc 0x18), opens 32-byte hash buckets.

| VM op | Native impl | Effect |
|---|---|---|
| `ace_expr_op_dict_create` (0x399D80) | `ace_dict_create` | calloc 0x18, init |
| `ace_expr_op_dict_set` (0x399DD0) | `ace_dict_set` | dict[key]=value |
| `ace_expr_op_dict_size` (0x399EA0) | `ace_dict_size` | returns count |
| `ace_expr_op_dict_destroy` (0x399F18) | `ace_dict_destroy` | frees |
| `ace_expr_op_dict_remove` (0x399F8C) | `ace_dict_remove` | removes key |
| `ace_expr_op_dict_remove_at` (0x39A030) | `ace_dict_remove_at_index` | iter-walk to N, remove |
| `ace_expr_op_dict_get` (0x39A0D4) | `ace_dict_get` | dict[key] |
| `ace_expr_op_dict_value_at` (0x39A17C) | `ace_dict_value_at_index` | iter-walk to N, return value |
| `ace_expr_op_dict_key_at` (0x39A224) | `ace_dict_key_at_index` | iter-walk to N, return key |

### Loaded module / scanner singleton (0x58E100, 0x1B40 bytes)
Tracks loaded libraries; entries at +3600, 32-byte each `{name, ?, +16:dword, +20:dword}`.

| VM op | Effect |
|---|---|
| `ace_expr_op_module_lookup_field20` (0x39A2CC) | name → entry.+20 dword |
| `ace_expr_op_module_lookup_field16` (0x39A370) | name → entry.+16 dword |
| `ace_expr_op_module_format_namelist` (0x39A4BC) | builds `;`-separated module name list (filter via N args) |
| `ace_expr_op_descriptor_query_3arg` (0x39A614) | dual-singleton query (hook engine + module scan) |
| `ace_expr_op_descriptor_query_4arg` (0x39A744) | dual-singleton query (4-arg) |

### Variadic native function call (the C-FFI of ACE script)
| VM op | Backend | Args |
|---|---|---|
| `ace_expr_op_call_variadic_a` (0x39A8FC) | `ace_expr_variadic_dispatch_a` (0x4F46DC) | 2 fixed + N variable, max 16 |
| `ace_expr_op_call_variadic_b` (0x39AAD4) | `ace_expr_variadic_dispatch_b` (0x4FD214) | 1 fixed + N variable |
| `ace_expr_op_call_resolved_int` (0x39AED8) | resolved via `ace_resolve_func_cached` (sub_3E881C) | up to 8 args, returns int |
| `ace_expr_op_install_or_query_hook` (0x39AC80) | `ace_install_or_query_hook` (0x4FC46C) | dispatches based on rule type 1 (install) or 8 (query service) |

### Hook descriptor manipulation (rule scripts read/write hook state)
| VM op | Effect |
|---|---|
| `ace_expr_op_install_hook_2arg` (0x39B078) | shorthand install via descriptor name |
| `ace_expr_op_install_hook_caller_4` (0x39CBE8) | wrapper around `ace_install_hook_caller_4` |
| `ace_expr_op_set_hook_target` (0x39BB50) | descriptor[+120] = operand[1] (with optional trampoline-relative addressing) |
| `ace_expr_op_set_hook_bytes` (0x39BCD4) | parses hex string, writes byte sequence into descriptor[+96] |
| `ace_expr_op_set_hook_enabled` (0x39BF60) | descriptor[+69] = bool |
| `ace_expr_op_install_all_hooks_for_chain` (0x39C3E0) | walks all rules in chain (1/2/3/4), recursively installs every hook in their AST trees |
| `ace_expr_op_descriptor_name_lookup` (0x39B2F8) | name lookup with `"str"` prefix special-case |
| `ace_expr_op_submit_finding` (0x39B168) | submit detection via `ace_submit_rule_finding` |
| `ace_expr_op_submit_finding_hook` (0x399C1C) | submit via hook engine descriptor |
| `ace_expr_op_load_operand_uint` / `_value` / `_value_b` | helpers |

### Filesystem / process scanning
| VM op | Effect |
|---|---|
| `ace_expr_op_dir_match_count` (0x39AD04) | counts dir entries matching pattern (decrypted target: `"touchEvent"`) |
| `ace_expr_op_inotify_dispatch` (0x39AE98) | calls `sub_3E8AB0` |
| `ace_inotify_watch_from_params` (0x39AE40) | creates inotify watcher |
| `ace_expr_op_inotify_register` (0x39B764) | registers a watch |

### Configuration / detection setup (calls obfuscated stub at 0x1CC0C0)
| VM op | Stub op | Effect |
|---|---|---|
| `ace_expr_op_obstub_dispatch_4` (0x39B800) | op=4 | strdup name into hook_descriptor_registry+600, set 1 bool |
| `ace_expr_op_obstub_dispatch_9` (0x39B8F4) | op=9 | strdup name + 4 dwords + 2 bools |

### libUE4.so (target module) introspection
ACE pre-decrypts `"libUE4.so"` and parses its ELF, populating offset constants `qword_5903C0..0x5905C8` (60 offsets). Once `byte_5923D8=1`, these queries work:

| VM op | Backend | Args |
|---|---|---|
| `ace_expr_op_libUE4_offset_setup` (0x39CC80) | `ace_load_libUE4_offsets` | initializes parser |
| `ace_expr_op_libUE4_query_a..e` (0x39CD8C..0x39D04C) | `ace_libUE4_query_a..d` (0x5035BC..0x5039A0) | 2-arg lookups |
| `ace_expr_op_libUE4_query_3arg` (0x39D0FC) | `sub_503F64` | 3-arg with index |
| `ace_expr_op_call_indexed_func` (0x39D1D8) | `sub_503CE4` (max 0x42 indices) | indexed function table |

### Generic registry lookup (`qword_58D3A8` global module list)
The big multi-module registry. Each entry has 4 sub-tables at +16, +40, +64, +112.

| VM op | Lookup |
|---|---|
| `ace_expr_op_subtable_lookup` (0x39D2E0) | wraps `ace_subtable_lookup` (0x39D398) |
| Cases 1/2/3/5 → searches subtable +16/+40/+64/+112 by id, returns +12 dword |

### Boolean / state queries
`ace_expr_op_query_state_a..g` (0x39D6FC..0x39D934) — each returns a single byte from a different ACE subsystem's state (poller status, hook count, report builder state, scanner state, etc.).

### Typed memory access (the "VM as machine code" feature)
The opcode reads `node+28` (WORD) as the access size. Same opcode handles 1/2/4/8-byte access.

| VM op | Effect |
|---|---|
| `ace_expr_op_typed_store` (0x39D990) | `*(typed*)operand[0] = operand[1]` |
| `ace_expr_op_array_index_load` (0x39DC28) | `result = *(typed*)(operand[0] + (node+28)*operand[1])` |
| `ace_expr_op_calloc` (0x39DF58) | allocates `(node+28)`-sized zeroed buffer |
| `ace_expr_op_set_node_typesize` (0x39E074) | sets the +28 type-size field of another node |

### String interning (61-entry pool at qword_58E198, 0x78 bytes)
| VM op | Backend | Effect |
|---|---|---|
| `ace_expr_op_string_intern_by_name` (0x39E0FC) | `ace_compute_string_hash` + `ace_string_intern_get_by_id` | interns by string |
| `ace_expr_op_dlopen_check` (0x39E274) | `ace_dlopen_check` | tests if library can be loaded |
| `ace_expr_op_string_alloc_by_id` (0x39E2F4) | `ace_string_intern_alloc` | allocates 0x100-byte slot for hash |
| `ace_expr_op_get_intern_count` (0x39E364) | `ace_string_intern_count` | returns interned count |
| `ace_expr_op_set_intern_string` (0x39E3AC) | `ace_string_intern_set_path` | stores 49-byte string |
| `ace_expr_op_intern_pool_init` (0x39E428) | `sub_3FF2F4` | re-initializes the pool |

### Anti-dump / region naming (the prctl trick)
| VM op | Effect |
|---|---|
| `ace_expr_op_prctl_set_vma_name` (0x39E7BC) | `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, name)` — renames an anonymous VMA so it appears with a custom string in /proc/self/maps. **This is how ACE makes its trampoline pages disguise themselves.** |

### Report enrichment
| VM op | Effect |
|---|---|
| `ace_expr_op_report_add_section9` (0x39EC48) | append section ID 9 to current detection report |

## Statistics

- **150+ VM operators** mapped and named
- **3 dispatch tables** (4 AST node types)
- **3 levels of indirection**: rule → AST root → opcode table → handler
- **2 major data types**: dict (0x18) and string-intern pool (0x78)
- **1 special case**: target module (libUE4.so) gets dedicated parser

## To-do (next iteration)

- Find where the expression-tree is *deserialized* from the downloaded ZIP. That tells us the wire format.
- Find xrefs to `ace_arm64_instruction_relocator` to confirm it's only invoked via the script engine.
- Capture an `ob_*.zip` from the device's filesystem to see the actual rule format.
- Decode the obfuscated stub at `loc_1CC0C0` (multiple VM ops dispatch through it).
- Map the predicate vector — ace_eval_rule_predicate(ctx, id) walks a separate AST list.
