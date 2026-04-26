# ACE's Rule Interpreter — Line-by-Line Walkthrough

The interpreter is the heart of ACE. It takes a deserialized rule list (from `ob_*.zip`) and walks it like a state machine, evaluating embedded expression trees, jumping forward/backward by ID, and submitting findings.

This doc walks through every line.

## Top-level entry: `ace_dispatch_rule_run` (0x3ECB40)

```c
ace_dispatch_rule_run(ctx, rule_set, args) {
    ace_rule_run_setup(ctx, rule_set);
    if (rule_set.+68 & 1)             // alt-mode flag
        ace_run_scan_rules_alt(ctx, rule_set, args);
    else
        ace_run_scan_rules(ctx, rule_set, args);
    ace_rule_run_teardown(ctx, rule_set);
    return 1;
}
```

Two interpreter implementations, picked by a flag at `rule_set+68`. The "alt" version is simpler — used for one-shot rule lists. The main version is for chained/persistent rule sets.

### Setup (`ace_rule_run_setup`, 0x3ECBDC)

```c
v5 = *(rule_set.+400 + 1);                        // sub-mode byte
if (v5 == 1 || v5 == 2) {
    if (rule_set.+400.+4) {
        descriptor = ace_hook_engine_get_descriptor();
        if (!descriptor->vfn[16](descriptor, rs.+2, rs.+4, rs.+480)) {
            // Descriptor not found — install it
            descriptor->vfn[56](descriptor,
                                rs.+2, rs.+400.+4,
                                /*upgrade=*/v5 == 2,
                                rs.+408.+4, rs.+4, rs.+480);
        }
    }
}
```

Pre-creates the hook engine descriptor (used by AST evaluation later). vfn[16] = lookup, vfn[56] = create.

### Teardown (`ace_rule_run_teardown`, 0x3ED598)

```c
if (rule_set.+408.+1 == 1 && !rule_set.+408.+4) {
    v6 = sub_4B72F4();
    descriptor = ace_hook_engine_get_descriptor();
    desc_handle = descriptor->vfn[16](descriptor, rs.+2, rs.+4, rs.+480);
    v6->vfn[16](v6, rs.+2, desc_handle);          // submit completed scope
}
```

Cleans up the hook engine descriptor — submits it to the report queue if `+408.+4` is zero (no errors).

## Main interpreter: `ace_run_scan_rules` (0x3ECFF8)

This is the canonical interpreter. Pseudocode:

```c
ace_run_scan_rules(ctx, rule_set, args) {
    ok = 1;
    i = 0;
    while (i < ace_rule_count(rule_set + 368)) {     // rule_vector at +368
        rule = ace_rule_at_index(rule_set + 368, i);
        
        // === STAGE 1: Predicate check ===
        if (rule.+1022)                             // has predicate?
            ok_predicate = ace_eval_rule_predicate(ctx, rule.+1022, rule_set);
        else
            ok_predicate = 1;
        
        if (!ok_predicate) { i++; continue; }       // skip rule
        
        // === STAGE 2: Jump dispatch ===
        target_idx = -1;
        if (rule.+1024) {                           // has jump target?
            switch (rule.+0) {                      // rule_type
                case 6:                             // forward jump
                    if (rule.+1024 == 0xFFFF) goto FINALIZE;
                    for (j = i+1; j < count; j++) {
                        if (rules[j].+4 == rule.+1024) {
                            target_idx = j;
                            break;
                        }
                    }
                    break;
                case 7:                             // backward jump
                    for (j = i-1; j >= 0; j--) {
                        if (rules[j].+4 == rule.+1024) {
                            target_idx = j;
                            break;
                        }
                    }
                    break;
                case 8:                             // eval AST + submit
                    if (rule.+1027 != 1 && rule.+1032)  {
                        if (ace_vm_eval_node(ctx, rule.+1032, rule, rs, args)) {
                            rule.+1048 = *(rule.+1032);    // cache result
                            ace_submit_rule_finding(*args, 0, rule.+1048,
                                                    ace_get_rule_run_severity(rs));
                        }
                    }
                    goto FINALIZE;
            }
        }
        
        // === STAGE 3: Type-4/5 leaf rule eval ===
        if (target_idx == -1) {
            // Check parent type for if-statement context
            in_if_block = (rule.+0 != 4 && rule.+0 != 5
                          && (rule.+1021 == 4 || rule.+1021 == 5));
            
            if (!in_if_block || !(rule.+1040 & 1)) {  // not visited yet
                rule.+1040 = 1;                       // mark visited
                
                if (rule.+1027 == 1) {
                    // Special scanner flag → built-in file-integrity scanner
                    ace_file_integrity_scanner(ctx, rule, rs, args, ...);
                    ace_rule_continue_chain(ctx, rule, rs, args);
                    ace_rule_save_result(ctx, rule);
                    if (rule.+0 == 4 || rule.+0 == 5)
                        ok = ace_rule_post_process(ctx, rule);
                } else {
                    // Standard AST evaluation
                    if (!ace_vm_eval_node(ctx, rule.+1032, rule, rs, args))
                        break;                         // hard break on failure
                    if (rule.+1032)
                        rule.+1048 = *(rule.+1032);    // cache result
                }
            }
            i++;
        } else {
            i = target_idx;                            // jump
        }
    }
    
FINALIZE:
    ace_finalize_rule_run(ctx, rule_set);
    return ok;
}
```

### Critical fields decoded

| Offset | Type | Meaning |
|---|---|---|
| `+0` | byte | rule_type (4=leaf, 5=leaf-variant, 6=fwd jump, 7=bwd jump, 8=eval+submit) |
| `+4` | uint16 | rule_id (used as jump target) |
| `+1021` | byte | parent_type (for if-block detection) |
| `+1022` | uint16 | predicate_id (0 = no predicate) |
| `+1024` | uint16 | jump_target_id (or 0xFFFF = "exit loop") |
| `+1027` | byte | special_scanner_flag (1 = use file_integrity_scanner; else AST) |
| `+1032` | qword | ast_tree_ptr (root of expression tree) |
| `+1040` | byte | visited_flag (set to 1 first time rule executes) |
| `+1048` | qword | last_result (cache of `*ast_tree_ptr` after eval) |

### Why type 6/7 jumps make this Turing-complete

- **Type 6 (forward jump):** unconditional `goto N` where N comes after current rule
- **Type 6 + 0xFFFF:** "exit interpreter" — graceful early termination
- **Type 7 (backward jump):** `goto N` where N is earlier — creates loops!

Combined with predicates (`+1022`) on each rule, you get conditional execution and loops. Combined with `ace_vm_eval_node` invoking VM operators that can mutate dict state and read/write memory, the rule scripts can do everything a real program can.

### The "if block" optimization

The check `rule.+0 != 4 && rule.+0 != 5 && (rule.+1021 == 4 || rule.+1021 == 5)` detects: "this rule is inside an if-block (parent is type 4/5) and is itself a non-leaf rule".

If the rule has already been visited (`+1040 & 1`), skip it. This prevents repeated re-evaluation of "child rules" inside an if-block when the loop iterates back through them.

It's a memoization trick the rule compiler uses — once you've eval'd the body of an if, don't re-eval it on subsequent loop iterations.

## Alt interpreter: `ace_run_scan_rules_alt` (0x3ECCDC)

The alt mode uses a different rule list structure (at `rule_set+16` instead of `+368`) and a slightly simpler dispatch:

```c
if (rule_set.+64 & 1) return 0;              // already running, abort
rule_set.+64 = 1;                            // lock
v13 = rule_count(rule_set+16);               // count from a different vector
*(uint16*)(rule_set + 66) = 0;               // reset state

for (i = 1; i <= v13; ) {
    rule = lookup(rule_set+16, i);           // 1-indexed!
    if (!rule) break;
    
    if (rule.+1024) {                        // has jump?
        switch (rule.+0) {
            case 4 or 5:
                ace_run_single_rule(...);
                if (rule.+1048) i++;
                else            i = rule.+1024;   // result-conditional jump!
                break;
            case 6: i = rule.+1024; break;        // unconditional jump
            case 7: i = rule.+1024; break;        // ditto
            case 8:
                i = rule.+1024;                    // jump THEN
                if (rule.+1027 != 1 && rule.+1032) {
                    ace_run_single_rule(...);
                    ace_submit_rule_finding(...);
                }
                break;
            default: i++; break;
        }
    } else {
        ace_run_single_rule(...);             // no jump, just eval
        i++;
    }
}
sub_3EDCD0(ctx, rule_set);                   // cleanup
rule_set.+64 = 0;                            // unlock
return 1;
```

**Key differences from main interpreter:**
1. **1-indexed rules** (i starts at 1).
2. **No predicate check** — every rule just runs.
3. **Type 4/5 with jump:** if eval result is "non-truthy" (`+1048 == 0`), JUMP TO `+1024`. Otherwise advance. This is **conditional control flow inside the interpreter**.
4. **Reentrancy lock** (`+64`) — alt mode prevents recursion.

So the alt interpreter is "imperative-style with if/else jumps", while the main interpreter is "declarative with predicates + memoization".

## VM eval entry: `ace_vm_eval_node` (0x3EFEFC)

The dispatcher into our 150 VM operators:

```c
ace_vm_eval_node(ctx, ast_node, parent, rule_set, args) {
    if (!ast_node) return 0;
    switch (ast_node.+24) {                   // node type byte
        case 1: return ace_vm_eval_caller_1(...);   // simple ops (8 opcodes)
        case 2: return ace_vm_eval_caller_2(...);   // arithmetic/logic (26 opcodes)
        case 3: return ace_vm_eval_caller_3(...);   // complex/dangerous (120+ opcodes)
        case 4: return ace_vm_eval_type4(...);      // unknown type 4
        default:
            log_error(69, rule_set.+2, parent.+4);  // log unknown node type
            return 0;
    }
}
```

Each caller looks up the opcode at `ast_node.+25` in its dispatch table and invokes the operator function (one of the 150 we mapped in `13_expression_engine.md`).

The operator gets called as `op_fn(ast_node)` and returns 1 on success, 0 on failure. It can:
- Read operands from `ast_node.+96` (operand vector start/end pointers)
- Write its result back into `*(ast_node)` (the result slot at offset 0)
- Recursively invoke `ace_vm_eval_node` on operands to get sub-expression values
- Mutate global state (install hooks, write memory, submit findings, etc.)

## How a rule actually runs — concrete example

Imagine a downloaded rule says: "If process is debugger-attached, install a hook on `dlopen`, then submit finding."

In rule terms:
- Rule 1: type=8, predicate=42 (debugger-attached?), AST=install_hook(dlopen)
- Predicate 42: AST = `(read_proc_status_line("TracerPid") != 0)`

Execution:
1. Interpreter at i=0 sees rule[0].+1022 = 42 (predicate ID).
2. Calls `ace_eval_rule_predicate(ctx, 42, rule_set)`.
3. Predicate eval calls `ace_vm_eval_node` on the predicate's AST → reads `/proc/self/status`, parses TracerPid line, returns boolean.
4. If true: rule.+0 == 8 → calls `ace_vm_eval_node` on rule.+1032 → invokes `ace_install_hook_caller_1` op → installs hook on `dlopen`.
5. Calls `ace_submit_rule_finding(args, 0, result, severity)` → builds TDM report → sends home.

That's the entire flow.

## Bypass attack surface (ranked by effectiveness)

1. **`ace_run_scan_rules` (0x3ECFF8)** — replace with `MOV X0, #1; RET`. Both interpreter loops stop entirely. **Cleanest single-point bypass.**
2. **`ace_run_scan_rules_alt` (0x3ECCDC)** — needed only if some triggers use alt mode (some do, per dispatch_rule_run flag check).
3. **`ace_dispatch_rule_run` (0x3ECB40)** — same effect as #1, slightly higher.
4. **`ace_vm_eval_node` (0x3EFEFC)** — let setup/teardown work normally, just skip eval. Returns 0 = "rule failed" → no findings submitted.
5. **`ace_submit_rule_finding`** — let rules run, drop findings.
6. **`ace_eval_rule_predicate`** — make all predicates return 0 → no rule ever fires.

**Most surgical:** hook `ace_vm_eval_caller_3` (the dangerous opcodes — install_hook, dlopen_test, etc.) and selectively allow safe opcodes through. This lets ACE *think* it's running rules without actually doing detection.

## To-do

- Decode `ace_run_single_rule` (0x3EDF48) — the alt-mode rule executor.
- Map `ace_finalize_rule_run` (0x3F024C) — what does cleanup do?
- Verify the predicate vector layout (currently inferred to be at `rule_set + 368` like rules; could be a separate vector).
