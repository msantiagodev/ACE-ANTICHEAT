# The 9 ACE Rule Callers — Where Detection Actually Triggers

`ace_dispatch_rule_run` is called from 9 different sites in libanogs. Each site represents an entry point into the rule interpreter from a different scan trigger or context. Together they make ACE's detection pipeline.

## Family overview

| Caller | Address | Size | Pattern | When it runs |
|---|---|---|---|---|
| `ace_rule_run_caller_1` | `0x3BD140` | 276 bytes | simple list walk | scanner module hooked into init flow |
| `ace_rule_run_caller_2` | `0x3BD4F8` | 276 bytes | **identical to #1** | second instance of same scanner pattern |
| `ace_rule_run_caller_3` | `0x3E83C4` | 664 bytes | event handler dispatch | hook fired with `"handler"` lookup |
| `ace_rule_run_caller_4` | `0x3FDCA8` | 848 bytes | targeted match by ID | specific rule lookup (e.g., from a hook handler matching a function pointer) |
| `ace_rule_run_caller_5` | `0x4B4288` | 1076 bytes | **PERIODIC POLLER** | the throttle-paced detection loop (50ms/rule) |
| `ace_rule_run_caller_6` | `0x4C4038` | 300 bytes | sub-list walk (a1+352) | secondary trigger (in same module as 5) |
| `ace_rule_run_caller_7` | `0x4C5240` | 300 bytes | sub-list walk (a1+304) | secondary trigger |
| `ace_rule_run_caller_8` | `0x4C8204` | 848 bytes | filter+dispatch | similar to 5 but with stop semantics (break on result=3) |
| `ace_rule_run_caller_9` | `0x4E2214` | 424 bytes | **REENTRANCY-GUARDED** | re-entry from inside another rule eval |

## The unified inner loop

Every caller follows the same shape:

```
v18[0] = list_begin(ruleset);
v17 = list_end(ruleset);
while ( !iter_neq(v18, v17) ) {
    rule_ptr = iter_get(v18);
    if ( rule_ptr ) {
        sub_3ECB20(ctx);               // begin run scope
        memset(args, 0, sizeof(args));
        ace_dispatch_rule_run(ctx, rule_ptr, args);
        sub_3ECB30(ctx);               // end run scope
    }
    iter_advance(v18);
}
```

The `sub_3ECB20` / `sub_3ECB30` pair is the rule-run scope (allocates per-rule scratch, releases on exit).

## Caller 5 is the heart of detection

`ace_rule_run_caller_5` (0x4B4288) is by far the most complex. It implements the **periodic poller** that runs detection rules in batches, with throttling between rules. Behaviorally:

```
for each rule in ruleset:
    rule_type = rule.+4   // (1, 2, 3, or 4)

    // Tier check: read different vfn slots based on rule type
    if rule_type == 1: result = registry->vfn[88]   // tier 1 check
    if rule_type == 2: result = registry->vfn[120]  // tier 2 check
    if rule_type == 3: result = registry->vfn[104]  // tier 3 check
    if result == 2: BREAK loop

    // Skip rules whose AST root opcode is 6 or 7 (= jumps)
    if rule.ast.opcode in {6, 7}: continue

    // Modulo divider: only run every Nth time, where N is at rule.+408+4
    divider = rule.+408->+4
    if divider != 0 and (counter % divider != 0): continue

    // Dispatch by rule.+297 (handler type)
    switch (rule.+297) {
        case 1, 2: 
            handler = string_intern_pool[rule.+344]
            if rule.+297 == 1: handler += rule.+320   // relative offset
            handler(rule.+336, NULL)
        case 3:
            sub_404634(sub_403BA0(), rule, NULL)     // alternative dispatch
        default:
            ace_dispatch_rule_run(ctx, rule, args)   // standard VM eval
    }

    iter_advance()
    if (ctx.+10 & 1) sleep_microseconds(50000)  // 50ms throttle
```

So caller 5 has:

- **3 tier checks** per rule (depending on rule.+4) — these are the gating bits ACE uses to disable scanners by tier.
- **Jump-rule skipping** (opcode 6/7 = forward/backward jumps, only meaningful inside rule chains).
- **Divider counter** — some rules only fire every Nth poll.
- **Handler-type dispatch** — type 1/2/3 = direct C function call (resolved via string-intern); default = VM eval.
- **50ms throttle** — between rules to avoid thermal/battery impact.

## Caller 9 is the recursive entry point

`ace_rule_run_caller_9` is invoked from inside another rule's evaluation (via the VM op at 0x39CB50, `ace_expr_op_rule_eval_helper`). It guards against infinite recursion:

```c
if (rule.+192 == 1) {  // already running!
    return rule.+288  // bail with cached result
}
rule.+192 = 1
ace_dispatch_rule_run(ctx, rule, args)
rule.+192 = 0
```

This means rules can call other rules, but circular references are detected and short-circuited.

## What kind of triggers map to which caller

Based on caller signatures and xrefs:

| Trigger | Caller | Notes |
|---|---|---|
| TSS init phase | 1 | first scanner module to run |
| TSS resume phase | 2 | identical impl, called from a different lifecycle hook |
| Hook handler fired | 3 | resolves "handler" function from context, then dispatches |
| Hook handler fired (with target) | 4 | matches by target function address, dispatches the matching rule |
| **Periodic detection poller** | **5** | the main detection loop (throttle-paced) |
| init_array post-hook | 6/7 | secondary detection triggers |
| Detection feedback / re-eval | 8 | break on result==3 (stop scanning) |
| Cross-rule recursion | 9 | reentrancy-guarded helper |

## The predicate vector (separate from rule vector)

`ace_eval_rule_predicate(ctx, predicate_id, ruleset)` walks a separate predicate list at `ruleset+368`. Each predicate has:
- `+4`: predicate_id
- `+1022`: parent_predicate_id (0 = root)
- `+1048`: cached result

If `parent_id != 0`, the predicate is conditional on its parent: recursively evaluate parent, then return parent's result. If `parent_id == 0`, just return whether `+1048` is non-null (the result has been computed).

So the predicate engine is a **lazy boolean tree** — predicates can chain, and evaluation is depth-first.

## Bypass implications

Each caller is a separate hook target:

1. **Hook caller 5** — kills the periodic poller. **Highest impact**: stops 90% of detection.
2. **Hook caller 1+2** — kills init-time scanners.
3. **Hook caller 3+4** — kills hook-handler-driven detection (the "fired when our hook runs" path).
4. **Hook caller 6/7** — kills secondary triggers.
5. **Hook caller 8** — kills feedback-loop detection.
6. **Hook caller 9** — kills cross-rule eval (rare).

OR a single point: `ace_dispatch_rule_run` (0x3ECB40) — replace with `MOV X0, #1; RET`. ALL 9 callers stop dispatching.

OR even cleaner: `ace_run_scan_rules` (0x3ECFF8) — same effect but spares the setup/teardown work, leaving caller-side state consistent.
