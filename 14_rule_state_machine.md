# ACE Rule Interpreter — The Complete State-Machine Engine

## The discovery

Beyond the expression-tree VM (see `13_expression_engine.md`), ACE has an OUTER state-machine layer that runs scripted **scan rules**. Rules can:
- Conditionally execute based on predicates
- Jump forward or backward by ID
- Embed a complete expression-tree script (the AST)
- Trigger hardcoded scanners (e.g., file integrity)

## Architecture

```
RuleSet (downloaded from ob_*.zip)
   │
   └─ rule_vector at +368
        ├─ rule[0]: { type, id, predicate, ast_tree, ... }
        ├─ rule[1]: ...
        └─ rule[N]
        
ace_dispatch_rule_run (0x3ECB40)              ← scan trigger calls this
   │
   ├─ ace_rule_run_setup
   ├─ ace_run_scan_rules (0x3ECFF8)            ← THE INTERPRETER LOOP
   │     │
   │     for each rule:
   │     ├─ predicate check (rule+1022)
   │     ├─ rule.type=6  → forward jump to rule with matching id
   │     ├─ rule.type=7  → backward jump
   │     ├─ rule.type=8  → eval AST + submit finding
   │     └─ default      → ace_file_integrity_scanner OR ace_vm_eval_node(rule.ast)
   │
   └─ ace_rule_run_teardown
```

## Rule struct layout (verified)

| Offset | Field | Description |
|---|---|---|
| `+0` | `rule_type` | 4/5 = leaf rules; 6 = forward jump; 7 = backward jump; 8 = eval+submit |
| `+4` | `rule_id` | jump-target identifier (used by type 6/7) |
| `+1021` | `parent_type` | (in if-statements) parent rule's type |
| `+1022` | `predicate_id` | predicate-tree ID; runs `ace_eval_rule_predicate(ctx, id)` |
| `+1024` | `jump_target_id` | rule ID to jump to (for type 6/7) |
| `+1027` | `is_special_scanner` | if 1: run hardcoded `ace_file_integrity_scanner` |
| `+1032` | `ast_tree_ptr` | pointer to root AST node (the script) |
| `+1040` | `visited_flag` | set to 1 after first execution |
| `+1048` | `last_result` | cached result of last evaluation |

## Rule types

| Type | Purpose |
|---|---|
| 4 | "leaf" rule — runs scanner once, no jump |
| 5 | "leaf" rule (variant) |
| 6 | **forward jump** — find next rule with `id == self.jump_target_id`, jump there |
| 7 | **backward jump** — find previous rule with `id == self.jump_target_id`, jump there |
| 8 | **eval + submit** — evaluate `ast_tree`, store result, call `ace_submit_rule_finding` |

The jump rules (6/7) make this Turing-complete: rules can form loops via backward jumps and conditional branches via predicates.

## Scan triggers

`ace_dispatch_rule_run` is called from **9 different sites**, each representing a scan trigger:
- `ace_rule_run_caller_1..9` — different scan modules invoke their own rule sets
- Each callsite passes a different `RuleSet` (rule list + context)

So ACE has 9+ independent rule chains. Each downloaded `ob_*.zip` likely populates one or more of these.

## How the AST gets evaluated

For type-8 rules and default rules without the special-scanner flag:

```c
ace_vm_eval_node(ctx, rule.ast_tree, rule, ruleset, ...)
```

Inside `ace_vm_eval_node`:
1. Read `ast_node.type` (byte +24): 1/2/3/4
2. Look up dispatch table for that type
3. Read `ast_node.opcode` (byte +25)
4. Find handler via `ace_vm_lookup_opcode_handler`
5. Invoke handler — handler may recursively call `ace_vm_eval_node` for sub-expressions

## The full ACE detection pipeline

```
1. Init  (libanort.so loaded)
   │   ace_init_core_v4_9_30_24277_oversea
   │   - reads /proc/self/cmdline (ACE_ProcessCmdlineCheck)
   │   - downloads config from server (ACE_ConfigUpdateFromServer)
   │   - loads signed config (ACE_LoadSignedConfig)
   │   - runs shell detector (ACE_ShellDetector)
   │   - spawns ACE_DetectionPoller as detached pthread
   │
2. Periodic scan
   │   ACE_DetectionPoller (or other thread)
   │   triggers one of 9 rule-run callers
   │   │
   │   └─ ace_dispatch_rule_run
   │       └─ ace_run_scan_rules
   │           └─ for each rule: ace_vm_eval_node
   │               └─ opcode handlers (read /proc, dlopen test, etc.)
   │
3. On detection
   │   ace_submit_rule_finding -> 
   │   ace_create_tdm_report (libanogs.so) -> 
   │   ace_submit_corereport -> network
```

## Bypass implications

The full rule pipeline gives us **multiple choke points**:

1. **`ace_run_scan_rules` (libanogs+0x3ECFF8)** — replace with no-op `MOV X0, #1; RET`. ALL rule chains stop running. Cleanest single-point disable.

2. **`ace_dispatch_rule_run` (libanogs+0x3ECB40)** — same effect, one level higher.

3. **Hook `ace_submit_rule_finding`** — let rules run but drop findings.

4. **Hook `ace_vm_eval_node`** — return success without evaluating, or selectively skip dangerous opcodes (148 = install hook, 50 = verify hook integrity, etc.).

5. **Disable rule downloads** — set `g_anort_config_flags |= 0x100` (already in our Tier 5).

## What we don't know yet

- The **exact format of `ob_*.zip`**. We know it's a serialized rule list; need to capture one from the device's filesystem to decode.
- The **predicate evaluation** — `ace_eval_rule_predicate(ctx, predicate_id)` looks up by id; the predicates themselves are also AST trees but in a separate vector.
- The **special hardcoded scanners** — `ace_file_integrity_scanner` is one; there are likely 2-3 more named handlers triggered by specific flag values.
