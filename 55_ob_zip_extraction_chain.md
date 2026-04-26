# `ob_*.zip` Extraction → VM Execution Chain (Boot)

The boot path that takes a downloaded encrypted ZIP and turns it into running emulated ACE detection code. Documented end-to-end.

## Boot call chain

```
ace_init_core_v4_9_30_24277_oversea  (libanort+0xC3A6C)
   │
   │  (after config update + cache load + cmdline check + sig verify + dlopen + shell detect)
   │
   ▼
ace_get_boot_module_singleton  (libanort+0x137C2C)
   │   pthread_once init → sub_137C84 populates singleton
   │   Returns singleton with vtable off_163E60
   ▼
ace_boot_extract_and_run_modules  (libanort+0x137CC0)
   │
   │  1. Calls (*singleton)[0](singleton, &payload_buf)  → fills v14 with boot ZIP data
   │  2. DecryptString(11285) = "builtin"   (ZIP archive name in singleton)
   │  3. DecryptString(11325) = "a64.dat"   (entry to extract)
   │
   ▼
ACE_ZipExtractAndProcess(out_module_list, "builtin", payload, "a64.dat", payload_data, payload_size, tree, mode)
   (libanort+0x137204)
   │
   │  ACE_ZipArchiveExtract_2(payload_data, payload_size, key="a64.dat", &extracted_buf)
   │      └─ extracts the "a64.dat" entry from the embedded ZIP
   │
   ▼
ace_parse_module_zip_entries("builtin", tree, extracted_data, extracted_size, mode, out_list, ?)
   (libanort+0x1372FC)
   │
   │  walks each module entry inside the extracted data, calls
   │
   ▼
ACE_VMModuleLoad(parser, magic_str_a, magic_str_b, count, module_struct, ?)
   (libanort+0x13761C)
   │  alloc 0xE8-byte module ctx, 0x10000 (64KB) VM memory
   │  parse .img module via ace_vm_module_parse_img
   │  module ready for execution
   │
   ▼
ACE_VMExecutionDriver(module_list)  (libanort+0x137804)
   │  walks the module list
   │  for each module: ACE_VMRunModules → ACE_VMExecuteLoop
   │  each ARM64 instruction → handler from g_ace_vm_opcode_table
   │  emulator runs the detection code
```

## Static archive name: `"builtin"`

The string `"builtin"` (decrypted from string-ID 11285) tells us this is the **first-load** module — embedded in libanort itself, not downloaded from server. The structure at `qword_1A8480` (singleton) holds a `vtable` (off_163E60) where `vtable[0]` is a callback that fills a buffer with the embedded ZIP data.

This means even if we block ALL network traffic, ACE still has its initial detection code from the `builtin` blob inside libanort.so.

## Inner archive name: `"a64.dat"`

String 11325 = `"a64.dat"`. The ZIP archive contains a file called `a64.dat` which is the **actual ARM64 emulator bytecode** for the boot detection module.

## Boot module is "always available"

Unlike server-pushed modules (which can be blocked by killing config update), the `builtin/a64.dat` module is shipped inside libanort.so. It always runs at boot.

This means our bypass cannot prevent the boot module from loading. It can only:
1. Prevent the module from doing anything useful (Tier 4: kill `ace_run_scan_rules`)
2. Prevent the emulator from running at all (Tier 8: kill `ACE_VMExecutionDriver`)

## ZIP extraction internals

`ACE_ZipArchiveExtract_2` (libanort+0x11561C) is the ZIP-format extractor. Given a byte-buffer (the ZIP archive contents), an entry name (e.g., `"a64.dat"`), it:
1. Parses ZIP local file headers
2. Finds the entry matching the name
3. Decompresses (DEFLATE)
4. Optionally decrypts (AES?) — likely uses ACE's `ACE_DecryptModule` flow with the per-module S-box

This is documented in `17_ob_zip_format.md` for downloaded modules; `builtin` follows the same format but is embedded.

## Module count and structure (from `ace_vm_module_parse_img`)

Each `.img` entry inside the extracted data has format:
```
[u32 magic = 0x12345678]   (different from cache's 0x20218115)
[N_sections counts]
[v50 list — generic data]
[v49 list — native function bridge entries (key, fn_name)]
[v48 list — label PC entries (key, target_pc)]
[byte init data]
[code blob (length-prefixed)]
```

See `49_native_function_registry.md` for the per-module RB-tree population details.

## After boot

After `ACE_VMExecutionDriver` runs the boot module:
1. The boot module (a64.dat) initializes ACE's detection state
2. It registers periodic scan rules with the `ace_run_scan_rules` callback
3. Returns control to `ace_init_core` which then calls `ACE_ConditionalTimingReporter` (we documented in `43_timing_reporter_chain.md`)
4. Init complete — periodic scan thread can now spawn (`44_periodic_scan_thread.md`)

## Bypass cleanup chain

After the module runs, the boot function carefully frees:
1. `v14` linked list (boot ZIP buffer entries)
2. `v16` tree (intermediate parser tree)
3. `v17` module list (each entry is 0x1E0 bytes)

This is just resource cleanup — doesn't affect bypass.

## Tier 8 — `ACE_VMExecutionDriver` neutralization

Our bypass already includes Tier 8: hooking `ACE_VMExecutionDriver` (libanort+0x137804) to return immediately:

```cpp
static int64_t hooked_ace_vm_exec_driver(void*) { return 0; }
```

This means the call chain runs to here, then the actual emulator dispatch is no-op'd. The boot module's detection code never executes.

**This is the most upstream kill point** for ALL emulator-based detection (boot module + downloaded modules). Highly effective.

## Inner ZIP wire format (verified via decompilation)

`ace_parse_module_zip_entries` (libanort+0x1372FC) parses the **decrypted ZIP outer payload**:

```
[u32 magic = 0x20218998 (539099416)]   ← outer ZIP magic
[u32 entry_count]                       ← N
[N × {                                  ← per-entry record
    [length-prefixed string name]       ← module name e.g. "vm_main.img"
    [length-prefixed body]              ← encrypted module body
}]
```

For each entry:
1. Read entry name string (length-prefixed).
2. Read entry body (length-prefixed) into a buffer.
3. **Decrypt body in-place** using:
   ```c
   for (i = 0; i < body_len; i++)
       body[i] = g_ace_module_sbox[body[i] ^ 0x23];
   ```
4. **Filter check**: skip the entry if name matches `shell_rom.zip` (string ID 11309).
5. **Special flag check**: if name matches `vm_main.img` (string ID 11259), set special flag in module's struct (offset +393 = 1).
6. Pass to `ACE_VMModuleLoad` to allocate a 0xE8-byte module ctx + 64KB VM memory.
7. If load OK, prepend to module list via `ACE_VMModuleListPrepend`.

## Three magic numbers in the ACE wire format

ACE uses different magic constants for each layer:

| Magic | Value | Where | Purpose |
|---|---|---|---|
| `0x20211215` | 539038229 | `ace_cache_db.dat` first u32 | Cache file marker |
| `0x20218998` | 539099416 | Outer ZIP magic | Module-archive marker |
| `0x12345678` | 305419896 | Inner `.img` magic | Per-module marker |
| `0x20218923` | 539100707 | Running module ctx | "Module is active" |

The shared `0x2021_xxxx` prefix suggests these were all assigned by the same year/version (`2021_xxxx`). Specifically `0x20211215` (Aug 1) and `0x20218998` (some date in late 2021).

## Confirmed strings in the decompilation

| String ID | Decrypted Value |
|---|---|
| `11259` | `vm_main.img` |
| `11285` | `builtin` |
| `11309` | `shell_rom.zip` |
| `11325` | `a64.dat` |

These tell the full story: the boot code reads from `builtin` source, extracts `a64.dat`, parses module entries (filtering out `shell_rom.zip`, marking `vm_main.img` as special), decrypts each module body via S-box, and runs them.

## To-do

- ~~Decrypt strings 11285 and 11325 — confirmed via `decoder_call_sites_libanort.txt`:~~ ✓ DONE
  - `11285` → `"builtin"`
  - `11325` → `"a64.dat"`
  - `11259` → `"vm_main.img"`
  - `11309` → `"shell_rom.zip"`
- Trace `sub_137C84` (the pthread_once init) — what does it populate in the singleton?
- Determine ZIP encryption used (AES? Per-install key? Or just compression?)
- Look for the "extra" module names — server-pushed updates might have different inner-file names than `a64.dat`
