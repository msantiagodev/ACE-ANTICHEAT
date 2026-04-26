# ob_*.zip Wire Format — What We Know

## Overview

ACE downloads detection rules at runtime from `*.anticheatexpert.com` CDN. The rule packages live in 6 files (3 channels × 2 architectures):

| Filename | Channel | Arch |
|---|---|---|
| `ob_cdn2.zip` | CDN-direct | 32-bit |
| `ob_cdn2_64.zip` | CDN-direct | 64-bit |
| `ob_cs2.zip` | Client-server | 32-bit |
| `ob_cs2_64.zip` | Client-server | 64-bit |
| `ob_gs2.zip` | Game-server | 32-bit |
| `ob_gs2_64.zip` | Game-server | 64-bit |

These are decrypted (XOR-100 family) into globals `g_ob_*_filename` at init_array time by `ace_init_ob_zip_filenames` (libanogs+0x1E6F88).

## Top-level deserializer

`sub_1E3378` (libanogs+0x1E3378) is the entry point:

```c
sub_1E3378(out_a, out_b, filename, flags) {
    ZipHandle h = sub_2228E0(open_zip_archive(), filename);
    if (!h) {
        h = decrypt_signed_payload();   // fallback for signed config
        if (!h) return -1;
    }
    
    void* data = h->data;     // +64
    size_t len = h->size;     // +72  
    if (len < 0xF) return -1;
    
    bool is_signed = (strcmp(filename, decrypted_special_name(45215)) == 0);
    
    return sub_1E31A0(out_a, out_b, filename, flags,
                      data, len, is_signed, 0, 0);
}
```

The actual parser is `sub_1E31A0` (libanogs+0x1E31A0). It's heavily CFG-flattened with state machine dispatch (state values like `0xBD053F3`, `0xFF1021F3`, `0xF71F2AB5`, etc.) — making it expensive to fully decompile statically.

## What we know about the format

From cross-referencing with the rule struct layout (see `14_rule_state_machine.md`), the parser must produce:

- **Rule list** at `ruleset+16`
- **Predicate vector** at `ruleset+368` (separate AST list)
- **9 hook chains** at `registry+608/+632/+656/+688[N]`
- **String intern pool** entries for constant strings

Each rule struct (after deserialization) has:
- `+0`: rule_type (4/5/6/7/8)
- `+4`: rule_id
- `+232`: hash/flags byte
- `+240`: prologue_len
- `+248`: bytes (instructions)
- `+288`: trampoline pointer
- `+297`: handler type (1/2/3)
- `+1022`: predicate_id (for if-statements)
- `+1024`: jump_target_id (for type 6/7)
- `+1032`: ast_tree_ptr (root of expression-tree)
- `+1040`: visited_flag
- `+1048`: cached result

So the wire format must encode:
1. A header (probably with version, count, channel ID)
2. A flat list of rule entries
3. A flat list of predicate entries (separately typed)
4. A blob of expression-tree nodes (AST), cross-referenced by ID
5. A string table (interned constants)

## Why we haven't decoded the wire format yet

`sub_1E31A0` is one of the most heavily obfuscated functions in libanogs:
- 100+ state values used as a computed-goto dispatch
- The state variables encode multiple bits worth of program state
- Each state transition decrypts/decompresses partial data
- Constants have ASCII patterns that encode opcode tables

Manual reverse engineering would take 50-100 hours. The fastest path is **dynamic analysis**: capture an actual `ob_*.zip` from the device at runtime, then trace the parser with a debugger or instrumented breakpoints.

## How to capture an ob_*.zip on a real device

ACE downloads these files into the app's private cache directory. They are encrypted on disk but can be intercepted at the network layer. Two approaches:

### Approach 1: Filesystem dump
```bash
# After app has run a few minutes, files exist in:
adb shell "ls -la /data/data/com.ubisoft.../files/ace/"
adb shell "cat /data/data/com.ubisoft.../files/ace/ob_cdn2.zip" > /tmp/ob_cdn2.zip
```

But these files are encrypted with a per-install key — capturing them is not enough; we'd also need the key (stored in `g_anort_config_flags` related globals).

### Approach 2: Network MITM
Intercept the HTTPS request to `*.anticheatexpert.com` with mitmproxy:
```
*.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me
```

The downloaded file is the same encrypted blob. Same problem with the key.

### Approach 3: Memory dump after parse (BEST)
Once `sub_1E31A0` finishes, the deserialized rule list lives in memory at known offsets via the registry singleton. Hook `ace_dispatch_rule_run` and dump the rule list parameter:
```cpp
DobbyHook(ace_dispatch_rule_run, [](ctx, ruleset, args) {
    dump_to_file("/sdcard/Android/data/.../files/rules.bin",
                 (void*)ruleset, 4096);
    return original(ctx, ruleset, args);
});
```

Then we can inspect the post-deserialization layout directly without ever decoding the wire format.

## Bypass implications

Even without understanding the wire format, we have leverage:

1. **`g_anort_config_flags |= 0x100`** (libanort+0x171118) — disables config update entirely. ACE never calls the deserializer for downloaded rules; only baked-in rules run.

2. **Hook `sub_1E3378`** to return -1 — fakes "rule package missing", same outcome.

3. **Hook `sub_1E31A0`** to return without parsing — also same.

4. **Network DNS/iptables block** of `*.anticheatexpert.com` — prevents the download in the first place.

The cleanest defense is option 1 + option 4 combined. We've already integrated option 1 into `Main.cpp` Tier 5.

## To-do

- Static-analyze the state machine dispatch table at `off_537650` to recover the FSM transitions.
- Build a custom IDA script that resolves the state-table pattern automatically.
- Capture a live rule package and write a parser around what we see.
- Cross-reference field offsets with the deserialized output struct.
