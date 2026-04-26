# `ACE_ValidateConfig` — The Kill-Switch Validator

`JNI_ACE_CommandDispatch` (the JNI method that receives "stop" commands) calls `ACE_ValidateConfig` and **terminates the host process via `exit_group(0)` if validation returns true**. This is the most direct kill path in ACE.

## The chain

```
Server / IPC sends "stop" command via Java
        ↓
JNI_ACE_CommandDispatch(JNIEnv*, jobject, jstring="stop")
        ↓
strcmp(input, decrypt(11969)="stop") → match
        ↓
config = ACE_GetConfigSingleton()      // libanort+0x12A2B0 — alloc 0x68 bytes
        ↓
result = ACE_ValidateConfigOrKill(config, decrypt(12015), 1)
        ↓ if result is true
syscall(__NR_exit_group, 0)            // PROCESS DIES
```

## `ACE_GetConfigSingleton` (libanort+0x12A2B0)

```c
__int64 ACE_GetConfigSingleton(void) {
    if (!g_ace_config_singleton) {
        v0 = operator new(0x68);
        // Layout (104 bytes):
        //   +0    : initialized_flag (1 byte)
        //   +8    : list_head (16 bytes — head of config entry linked list)
        //   +24   : padding (16 bytes)
        //   +40   : padding (16 bytes)
        //   +56   : qword
        //   +64   : pthread_mutex_t (init via sub_11C7B8)
        memset(v0, 0, 0x68);
        sub_11C7B8(v0 + 64);            // init mutex
        g_ace_config_singleton = v0;
    }
    return g_ace_config_singleton;
}
```

This is a singleton holding the parsed `comm.zip` config.

## `ACE_LoadConfigFromCommZip` (libanort+0x12A404) — first-run loader

```c
void ACE_LoadConfigFromCommZip(config_obj* obj) {
    char path[1024];
    char* zip_name = ACE_DecryptString(2585);   // "comm.zip"
    char* full_path = sub_12B2A4(zip_name, path, 1024);   // resolve full path
    
    if (full_path) {
        Buffer buf;
        ACE_Buffer_Init(&buf);
        if (sub_12A4D0(buf, &buf, full_path)) {
            // Failed to read/validate the file
            access(full_path, F_OK);    // touch (timestamp side-effect?)
        } else {
            // Read OK — parse as ELF
            entry = new(0x10);
            entry[0] = 0;
            entry[1] = 0;
            ACE_ELFSectionEnumerator(obj, &buf, entry);   // parse ELF sections
            mutex_lock(obj+64);
            sub_11BE78(obj+8, &entry);    // append to linked list
            mutex_unlock(obj+64);
        }
        ACE_Buffer_Reset(&buf);
    }
}
```

So `comm.zip` is **actually an ELF file** despite the name (or contains an ELF). ACE enumerates its sections and stores entries in the config's linked list.

## `ACE_ValidateConfigOrKill` (libanort+0x12A308) — the kill validator

```c
bool ACE_ValidateConfigOrKill(config_obj* a1, char* param_string, bool default_result) {
    // Step 1: Lazy-init from comm.zip
    if (!*(byte*)a1) {
        ACE_LoadConfigFromCommZip(a1);
        *(byte*)a1 = 1;
    }
    
    // Step 2: Snapshot the linked list under mutex
    LinkedList working_list = {};
    mutex_lock(obj_mutex_for(a1));
    for (entry = a1->list_head; entry; entry = entry->next)
        list_append(&working_list, entry+16);   // copy pointer to BST root at +16
    mutex_unlock(obj_mutex_for(a1));
    
    // Step 3: For each entry, search its BST for the encoded param_string
    bool result = default_result;   // start with caller's default
    for (item = working_list.head; item; item = item->next) {
        BST* bst = (BST*)item->data;
        EncodedKey key = ACE_DataEncoder(param_string);
        Node* node = ACE_BSTStringSearchObfuscated(bst, &key);
        ACE_Free(key);
        
        if (node) {
            result = (*(uint32_t*)(node + 40) == 100);   // "100" is the magic value
            break;
        }
    }
    
    // Step 4: Free working_list, return
    return result;
}
```

## The kill condition (revisited)

In `JNI_ACE_CommandDispatch`:

```c
result = ACE_ValidateConfigOrKill(obj, decrypt(12015), 1);
                                                       ^^^
                                                       default = TRUE
if ((result & 1) != 0) {
    syscall(__NR_exit_group, 0);
}
```

**The default is TRUE.** This means:
- Config NOT loaded / param NOT in BST: returns default = TRUE → KILL
- Config loaded, param IN BST with value == 100: returns TRUE → KILL
- Config loaded, param IN BST with value != 100: returns FALSE → DON'T KILL

So **by default, "stop" command kills the process**. The only way to NOT kill is if `comm.zip` has an entry for the encoded param-string-12015 with value 99 (or any non-100).

This is a **fail-closed** design: ACE assumes the config is unreliable, so a stop command always kills unless the config explicitly says otherwise.

## CONFIRMED: param-string 12015 = `"enable_gp7_exit_group"`

Verified via `decoder_call_sites_libanort.txt`:
```
off= 12015  dec=0x0F  callers=  1  first=0x00025F0C  -> 'enable_gp7_exit_group'
```

So the validator is asking: "is the config flag `enable_gp7_exit_group` set?". With default = TRUE, the answer is YES unless config explicitly says otherwise.

The "gp7" prefix matches the `vm_gp7worker.img` and `vm_gp7service.img` modules — this is the **Game Protection layer 7** (Tencent's anti-cheat tier system).

## Bypass tactics

### Hook `ACE_ValidateConfigOrKill` to always return false
```cpp
bool hooked_ACE_ValidateConfigOrKill(void* obj, char* param, bool default_) {
    return false;  // never kill
}
```
Single-point fix that prevents the JNI kill path entirely. Tier 11 candidate.

### Hook `JNI_ACE_CommandDispatch` to drop "stop"
```cpp
jint hooked_JNI_ACE_CommandDispatch(JNIEnv* env, jobject obj, jstring input) {
    return 0;   // ignore everything
}
```
Stops ALL command dispatch (including legitimate ones). More invasive but simpler.

### Lower-level: hook `exit_group` in libc
```cpp
ssize_t hooked_syscall(int sysno, ...) {
    if (sysno == __NR_exit_group) return 0;   // ignore the exit
    return real_syscall(sysno, ...);
}
```
Catches exit_group regardless of which path triggers it. But also breaks legitimate exit (e.g., user-initiated shutdown).

### Currently deployed
None of the above. We rely on:
- The cache DB never has a "kill-criteria" entry by default
- The "stop" command is rarely sent (only when server explicitly invokes it)

This means our bypass would FAIL if the server ever sent the JNI "stop" command. To harden, we should add Tier 11.

## To-do

- Decrypt string 12015 to know the exact param being validated
- Trace `sub_11BE78` (linked list append) to understand the entry structure
- Document `ACE_BSTStringSearchObfuscated` algorithm — how is the obfuscation reversed during search?
- Test in REPL bridge: hook `ACE_ValidateConfigOrKill` to log every call's args
- Add Tier 11 to the bypass: kill the validator
