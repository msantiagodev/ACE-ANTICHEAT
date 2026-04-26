# The Central Configuration Dispatcher at 0x1CC0C0

## What it is

Code blob `loc_1CC0C0` (libanogs+0x1CC0C0) — **NOT marked as a function** in IDA, called via `BL` from anywhere needing config/detection ops. Contains a jump table with **85 op codes** (1-85), each routing to a different ACE subsystem call.

Multiple expression-tree VM ops dispatch through it: at minimum op=4 and op=9 are confirmed (used by `ace_expr_op_obstub_dispatch_4` and `_9`).

## Calling convention

```c
__int64 obstub_dispatch(int op_code, X1, X2, X3, X4)
```

Where X1-X4 are op-specific arguments.

## Initial fast path

Before the switch, it checks for an alternate dispatcher (vtable replacement):

```c
ace_string_util_singleton ssu = ace_string_util_core();
if (ssu->cfg_set_at_4AC) {
    // Anti-disasm: dummy arithmetic on stack to confuse static analysis
    // Then load 3 hardcoded qwords and check qword_5792E0
}
if (qword_5792E0) {
    // Override: call vfn at +0x18 of the singleton
    return (*qword_5792E0)->vfn[0x18](op, X1, X2, X3, X4);
}
// Otherwise fall into 85-case switch...
```

The dummy stack arithmetic in `loc_1CC0C0` is anti-static-analysis padding — it computes intermediate values that go nowhere (e.g., `W8 = W0 * W1 ; if (W1+1 <= W1) ... `), but their effect is to fool decompilers into adding fake control flow.

## The 85-case switch

The op code dispatcher (`loc_1CC22C`) is built on `ADR + LDRSW + ADD + BR X10` — a classic indirect jump table.

| Case | What it calls | Likely meaning |
|---|---|---|
| 1 | `sub_2E7294` then `sub_22B644` | string init + dispatch |
| 3 | `sub_349C80` then `sub_349FB0` | scanner module pair init |
| 14 | `ace_copy_property_value(name, "7.8.7.54221", out)` | **set version string** |
| 16 | `ace_validate_and_dispatch` on operand[0]/+8 | feature flag write-back |
| 17 | `sub_1CA1F8` + `sub_219B04` + `sub_219F6C` | triple-init |
| 26 | `sub_33724C` then `sub_337F60` | conditional register |
| 27 | `sub_337210` then `sub_337F38` | sibling of 26 |
| 30 | `sub_1CDF08` | single-call op |
| 31 | timestamp + `sub_238E40(time, X1, X2)` | record event with timestamp |
| 32 | `string_util_core` + `sub_244510(util, X1)` | string-keyed register |
| 34 | `sub_225F80` then `sub_226118` | sibling of 26/27 |
| 37 | `sub_22DFAC` then `sub_22E4A8` | sibling pair |
| 42 | `sub_367E14` + `sub_368300`, sets `byte_5791EC=1` | **enable some flag globally** |
| 49 | `string_util_core` + `sub_2451AC` | string-keyed register |
| 54 | strcmp against decrypted strings (0xABCD, 0xABDF, 0xABF0) | named registry lookup |
| 56 | timestamp + `decrypt_xor51(0x1695)` + `validate_and_dispatch` + scope reg | feature gate by name |
| 58 | parses "default"/"true"/"false" strings with `decrypt_xor21(0x85)` | parse boolean config |
| 70 | `ace_get_global_singleton()` + `sub_1E5864` | singleton dispatch |
| 72 | check `*X1 == 0x50` ('P'), then `sub_20E660(X1+0x10, X1+0x14)` | parse "P" record header |
| 77 | timestamp + `decrypt_xor20(0xD6F8)` + `validate_and_dispatch(force=1)` | timed feature gate |
| 79 | `ace_get_global_singleton()` + `ace_vtable_dispatch` | virtual call |

The default branch (cases 11-13, 19-22, 29, 43-45, 48, 50, 52, 53, 55, 57, 61-69, 71, 78, 80-84) goes to `def_1CC22C` (0x1CC988) — these are unimplemented op codes that fall through to a no-op return.

## Decrypted string fragments seen

The dispatcher uses several decoder calls to look up its own constant strings:
- `decrypt_xor20(0xD6F8)` — feature flag name (op 77)
- `decrypt_xor51(0x1695)` — feature flag name (op 56)
- `decrypt_xor21(0x85)` — config key prefix (op 56, 58)
- `decrypt_xor43(0x1687)` — sub-key name (op 56, 58)
- `decrypt_xor4A(0x168E)` — value field name (op 56)
- `decrypt_xor51(0xABCD)` — registry name 1 (op 54)
- `decrypt_xor63(0xABDF)` — registry name 2 (op 54)
- `decrypt_xor10(0xABF0)` — registry name 3 (op 54)

These strings can be decoded using the standalone decryptor (`scripts/decrypt_ace_standalone.py`) — but they require running the decoder against the in-binary table. Future work: integrate decoder.

## Architecture: this is a "configuration backplane"

Looking at the case actions — set version, enable flag, register module, parse config, dispatch by name — `loc_1CC0C0` is essentially ACE's **service registry / configuration broker**. Different parts of ACE (VM ops, init code, scanners) call into it with op codes to:
- Enable/disable features
- Look up configurations
- Dispatch to scanner modules
- Record events with timestamps
- Register components

The reason it's not a named function in IDA is likely because:
1. It's called from indirect addresses (loaded into registers, then `BLR`).
2. Its prologue is hidden behind the anti-disasm dummy arithmetic.

## Bypass implications

Hooking `loc_1CC0C0` to filter specific op codes lets us neutralize specific subsystems:
- **Filter op 14** → break version reporting.
- **Filter op 42** → prevent global flag set.
- **Filter ops 56, 58, 77** → all "feature flag" gates default-deny.
- **Filter op 70/79** → singleton dispatches no-op.

Or replace the entire function with `MOV W0, #0; RET` — disables all 85 op codes. Likely breaks ACE's bootstrapping but that's the point.

## To-do

- Decode all referenced XOR strings to identify feature flag names (likely "tdm_enabled", "scanner_X_enabled", etc).
- Cross-reference each case to find its callers — that tells us which ACE subsystem owns it.
- Map the alternate dispatcher (vfn+0x18 of qword_5792E0) — it could be used to neuter loc_1CC0C0 entirely by setting that pointer.
