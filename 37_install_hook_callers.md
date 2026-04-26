# The 6 ace_install_hook_caller_N Functions — Hook Installation Entry Points

ACE has 6 different "caller" functions that each install hooks for a specific scenario. They all call `ace_install_inline_hook` (libanogs+0x3F9944) but feed it different descriptors.

## Caller 1: `ace_install_hook_caller_1` (libanogs+0x39C9EC)

**Purpose:** VM op-level single descriptor install.

```c
ace_install_hook_caller_1(self, ?, hook_id_struct):
    name = *(*(*(self+8))[0])                                  // operand[0] from VM op
    descriptor = registry->vfn[168](registry, *(uint*)(hid+4), 0, name, 0xFFFF, 0, 0)
    if descriptor:
        v6 = (descriptor->type == 3 || descriptor->type == 4)  // PLT or registry-based
        ctx = ace_hook_engine_get_context()
        ace_install_inline_hook(ctx, descriptor, v6, 0, 0, 0)
        *self = 1  // success
```

This is what an expression-tree VM op uses: pass a name, look it up, install. Used for **single-target hooks** (e.g., "hook function `dlopen`").

## Caller 2: `ace_install_hook_caller_2` (libanogs+0x3B0EEC)

**Purpose:** Install a hook by descriptor ID alone (no operand resolution).

```c
ace_install_hook_caller_2(rule):
    if rule == NULL: return 0
    descriptor = registry->vfn[168](registry, *(uint*)(rule+4))
    if descriptor:
        v4 = (descriptor->type == 3 || descriptor->type == 4)
        ctx = ace_hook_engine_get_context()
        ace_install_inline_hook(ctx, descriptor, v4, 0, 0, 0)
    return 1
```

Simpler than caller_1 — used by other ACE code paths that already know the descriptor's id and just want to install.

## Caller 3: `ace_install_hook_caller_3` (libanogs+0x3FAD70)

**Purpose:** Bulk install for a rule's entire descriptor list.

```c
ace_install_hook_caller_3(state_byte_addr, rule, force):
    if !force && (*state_byte_addr & 1): return 0  // already installed
    if sub_3BF6E0(rule): return 1                  // disabled rule
    
    iter = rule_iterator_begin(rule)
    while iter_neq(iter, rule_iterator_end(rule)):
        descriptor = iter_get(iter)
        ace_install_inline_hook(state_byte_addr, descriptor, force, 0, 0, 0)
        iter_advance(iter)
    
    if !force: *state_byte_addr = 1                // mark installed
```

Walks all descriptors in a rule's vector and installs each. Used at boot time to initialize all hooks for a rule chain.

## Caller 4: `ace_install_hook_caller_4` (libanogs+0x494610)

**Purpose:** VM eval-result based hook install (the "dynamic" version).

```c
ace_install_hook_caller_4(this, rule, arg3, arg4, arg5):
    // Read 3 operands from rule's operand vector at +64
    this+64 = *(rule.operand[0])  // typically the function pointer
    this+72 = *(rule.operand[1])
    this+80 = *(rule.operand[2])
    this+88 = arg4
    this+96 = arg3
    
    if all three operands non-NULL:
        ace_vm_eval_node(scope, this+64, arg3, arg4, arg5)
        this+4000 = *(this+64)                     // capture result
        
        if sub_49435C(this) success:
            store result + arg refs at this+3736..3776
            if !this+3784:
                this+3440 = this+4000              // hook target = eval result
                this+3321 = 0
                this+3328 = 1                       // descriptor flags
                ctx = ace_hook_engine_get_context()
                ace_install_inline_hook(ctx, this+3320, 0, 0, 0, sub_49486C)
                                                   //                    ^
                                                   // sub_49486C = the hook handler
```

This is the **most powerful caller**. It:
1. Evaluates a VM expression to compute the target address
2. Stores the result + arguments in a descriptor at offset +3320
3. Installs a hook on that target with `sub_49486C` as the handler

This means **rules can dynamically compute what to hook**. Useful for: "hook the function pointed to by global X" or "hook the address resolved from this string lookup".

## Caller 5: `ace_install_hook_caller_5` (libanogs+0x496BEC) ★ **UNITY MONO HOOK**

**Purpose:** Hook methods in `Assembly-CSharp.dll` (Unity Mono).

```c
ace_install_hook_caller_5(this, rule, force):
    mono_ctx = this->vfn[4032]()                   // returns Mono runtime singleton
    if !mono_ctx: return 0
    
    target_dll = "Assembly-CSharp.dll"             // decrypted from "Ykk}uzta5[Kpyjh6|tt"
    
    iter = rule_iterator_begin(rule)
    while iter_neq:
        method_name = descriptor.+72.+8
        type_flags = descriptor.+72.+1
        
        // Look up Mono method by name in target DLL
        method = sub_496728(this, "Assembly-CSharp.dll", method_name, type_flags)
        if method:
            // Call mono runtime function via vfn[4056]
            method_addr = mono_ctx->vfn[4056](mono_ctx, method)
            if method_addr:
                // Install hook for each operand offset
                for j in 0..descriptor.+88:
                    offset = descriptor.operand[j]
                    target = method_addr + 16 + offset
                    descriptor.+128 = offset
                    descriptor.+89 = j
                    descriptor.+120 = target
                    if ace_install_inline_hook(ctx, descriptor, force, 0, 0, 0):
                        break
```

This is **direct Unity Mono hooking**. The decrypted string `"Assembly-CSharp.dll"` confirms the target. ACE can hook arbitrary C# methods if the rule names them.

For our **UE4 game**, this caller never fires because there's no Assembly-CSharp.dll loaded. But for Unity-based games (PUBG Mobile, Honor of Kings on some platforms), this is a major detection vector.

## Caller 6: `ace_install_hook_caller_6` (libanogs+0x497EC8)

**Purpose:** Symbol-resolution-based hook with deduplication.

```c
ace_install_hook_caller_6(this, op, rule, force):
    if !this+72 || !this+80 || !this+96 || !this+88: return
    
    // Lock dedup mutex
    pthread_mutex_lock(this+3960)
    
    // Resolve target symbol via VM eval
    symbol = ace_vm_eval_node(scope, this+72, this+96, this+88, scope_args)
    
    // Check if already in dedup RBT at this+3936
    found = walk_rbt(this+3936, symbol)
    if !found:
        // Strcmp against expected symbol name
        if !strcmp(*(symbol+72), *(this+3928)):
            // Add to dedup RBT
            sub_3F6FA8(this+3936, &symbol)
    
    pthread_mutex_unlock(this+3960)
    
    // Now iterate rule operands and install
    iter = rule_iterator_begin(rule)
    while iter_neq:
        if sub_4973C4(this, ...):
            // install hook with computed address
            for k in 0..descriptor.+88:
                offset = descriptor.operand[k]
                target = base_addr + offset
                descriptor.+128 = offset
                descriptor.+120 = target
                if ace_install_inline_hook(...):
                    break
```

This is the **library-symbol hook installer with deduplication**. It:
1. Resolves a symbol from a loaded library
2. Compares its name against an expected name (probably to avoid false matches)
3. Maintains a deduplication RBT so the same library symbol isn't hooked twice
4. Walks rule operands and installs at each offset

Used for: "hook every load of `libfoo.so` and patch its `bar` function" — deduplicates if the same library is loaded multiple times.

## Summary table

| Caller | Use case | Multiple targets? | Mono support? | Dedup? |
|---|---|---|---|---|
| 1 | VM op single hook by name | No | No | No |
| 2 | Direct ID-based install | No | No | No |
| 3 | Bulk install for rule | Yes | No | No |
| 4 | VM eval result hook | Computed | No | No |
| 5 | Unity Mono assembly | Yes | **YES** | No |
| 6 | Library symbol with dedup | Yes | No | **YES** |

## Bypass implications

All 6 callers eventually call `ace_install_inline_hook` (libanogs+0x3F9944), which calls the relocator. **Tier 7** (hook the relocator) catches all 6 in one shot.

For belt-and-suspenders, hooking each caller individually:
- Caller 1: 138 bytes — hook it to immediately set `*a1 = 0; return 1`
- Caller 2: 118 bytes — hook to `return 0`
- Caller 3: 124 bytes — hook to `return 0`
- Caller 4: 25C bytes — too complex, just rely on relocator hook
- Caller 5: 350 bytes — hook to `return 0` (would skip Unity Mono hooks; for our UE4 game this is irrelevant anyway)
- Caller 6: 6BC bytes — too complex, rely on relocator hook

## To-do

- Decode the `vfn[4032]` and `vfn[4056]` of the Mono context (caller 5) — these are likely Mono API wrappers
- Find what calls each caller (probably specific scanner modules)
- Map `sub_4973C4` (the symbol comparator in caller 6) — this might tell us what symbol names ACE specifically watches for
