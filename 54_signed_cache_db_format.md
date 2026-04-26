# `ace_cache_db.dat` — The Signed Local Config Cache

`ACE_LoadCacheDb` (libanort+0x12C324, was misnamed `ACE_LoadSignedConfig`) reads `<dir>/ace_cache_db.dat` from the app's private storage and parses it into a key-value BST. This is the local persistent state for ACE.

## File path resolution

`ACE_FormatCacheDbPath` (libanort+0x1314CC) builds the path:

```c
char* ACE_FormatCacheDbPath(char* out, int max_len) {
    void* state = sub_C8CCC(ACE_HashCompute());   // returns a dir prefix (computed)
    if (!state || !*(char*)state) return NULL;
    char* fmt = ACE_DecryptString(7323);          // = "%s/ace_cache_db.dat"
    ACE_Memcpy_Checked(out, max_len, fmt, state);
    return out;
}
```

So the file path is `<computed_dir>/ace_cache_db.dat`. The `<computed_dir>` comes from `sub_C8CCC` which traces back to a state field (probably the app's data dir).

## Wire format of `ace_cache_db.dat`

```
[u32 magic]           = 0x20211215 (decimal 539038229) — December 15, 2021 (date-encoded) — must match
[u32 entry_count]     ≤ 0x200 (max 512 entries)
[entries]:            entry_count × 12 bytes (3 × u32):
    [u32 key]
    [u32 encoded_value]
    [u32 integrity_check]   = encoded_value XOR key
                            (skip entry if integrity check fails)
```

## Decoding rule

For each entry:
1. Read `(key, encoded_value, integrity)`.
2. Verify `(encoded_value XOR key) == integrity`. If mismatch → skip entry.
3. Decoded value = `encoded_value XOR 0x12345678`.
4. Insert `(key, decoded_value)` into BST at temp tree.

After all entries processed, atomically swap the temp tree into the singleton's tree (mutex-protected via `ACE_GetMutexForObject` + `ACE_BTreeAssign`).

## Behavior when file missing or invalid

- File missing → `ACE_FileReadToBuffer` returns false → `v1 = -1`, returns -1.
- Magic mismatch → returns -1.
- Entry count > 512 → returns -1.
- Some entries fail integrity → skipped silently, others kept.
- All-zero file → returns -1.

The function is also gated by `*(_BYTE*)(a1 + 16)` — if non-zero (already loaded), returns 0 immediately. So it loads exactly once per session.

## What's stored in `ace_cache_db.dat`?

This file is the **cached server config**. ACE uses it to:
- Remember last-fetched server config across game restarts (so the first detection doesn't have to wait for network)
- Store rule definitions, scanner thresholds, kill criteria
- Cache certificate fingerprints, hash sets

Specifically, the BST keys are 32-bit hashes; the values are 32-bit configuration words. Each (key, value) pair represents one config entry.

## Why XOR with `0x12345678`?

This is **trivial obfuscation** — just XOR-encoding so the on-disk file isn't human-readable, but is reversible without a key. It's not cryptographic security; it just stops casual viewing with `xxd`.

## ACE_BTreeAssign — atomic swap

```c
void ACE_BTreeAssign(BTree* dest, BTree* src) {
    if (src == dest) return;
    ACE_BSTClearRecursive(dest, dest->root);  // free old
    dest->root = NULL;
    ACE_BTreeDeepCopy_3(dest, dest, src->root);  // deep-copy new
    dest->count = src->count;
}
```

The atomic-swap pattern means consumers of the BST always see a consistent state (either all old, or all new) — no torn reads.

## Bypass implications

This function is downstream of `ACE_ConfigUpdateFromServer` (Tier 5). When Tier 5 sets `g_anort_config_flags |= 0x100`:
- `ACE_ConfigUpdateFromServer` returns 0 immediately (skips network fetch + cache write)
- But `ACE_LoadCacheDb` ALSO runs and reads any stale cache from disk!

**This means our Tier 5 doesn't fully prevent the local cache from being read.** The cache file may have stale ban-criteria from a previous session.

To fully neutralize the cache:
1. Delete `<app_dir>/ace_cache_db.dat` before the game starts (clean install)
2. Or zero the file's magic bytes (so `ACE_LoadCacheDb` returns -1)
3. Or hook `ACE_LoadCacheDb` to return 0 immediately

Currently we don't do this — and our bypass works regardless because the higher-level scanners (Tier 4) don't actually read the cache values for kill decisions in our tested binary.

## Comparison to `ACE_ConfigUpdateFromServer` (the misnamed downloader)

| Function | What it does | Killed? |
|---|---|---|
| `ACE_ConfigUpdateFromServer` (libanort+0x12CE98) | Loads `ace_shell_di.dat` + JNI Build version → writes to disk | YES (Tier 5) |
| `ACE_LoadCacheDb` (libanort+0x12C324) | Reads `ace_cache_db.dat` → populates in-memory BST | NO (still runs) |

These are **different files** with **different purposes**. `ace_shell_di.dat` is for shell-protected variants; `ace_cache_db.dat` is the persistent KV store.

## To-do

- Determine which strings/IDs are stored as keys/values in the cache
- Decompile `sub_C8CCC` to find the dir prefix source
- Test: delete `ace_cache_db.dat` between runs, observe behavior
- Document the XOR-`0x12345678` value origin (is it the only constant or are there variants?)
