# COREREPORT Singleton vtables — vfn-by-vfn Decoded

## The two vtables

The COREREPORT singleton (`g_corereport_singleton` at libanogs+0x57E0D0) is a 32-byte struct laid out for C++ multi-inheritance:

```
offset  0: ptr to vtable_corereport_singleton_a (off_52D628)
offset  8: ptr to vtable_corereport_singleton_b (off_52D688)
offset 16: ?? (object state)
offset 24: gcloud module link (set after CSSCRIPT lookup)
```

This is C++ multiple inheritance: the singleton inherits from two base classes, each with its own vtable. When code calls through `vtable_b`, the offset adjuster `-8` (the `0xFFFFFFFFFFFFFFF8` qword at the end of vtable_b) puts the implicit `this` pointer back at `obj+0` rather than `obj+8`.

## vtable_corereport_singleton_a (off_52D628)

| Slot | byte off | Address | Behavior |
|---|---|---|---|
| 0 | +0 | 0x346344 | `RET` — no-op |
| 1 | +8 | 0x346348 | `B sub_51DF6C` — **destructor (delete)** |
| 2 | +16 | 0x34634C | `MOV X0, "TSS"; RET` — **returns SDK name "TSS"** |
| 3 | +24 | 0x346324 | `B ace_format_report_payload` — **format payload** |
| 4 | +32 | 0x346358 | `RET` — no-op |
| 5 | +40 | 0x34635C | `RET` — no-op |
| 6 | +48 | 0x346360 | `RET` — no-op |
| 7 | +56 | 0x346364 | `RET` — no-op |
| 8 | +64 | 0x3462EC | `if (a1 == "CSSCRIPT") return singleton; else NULL` — **module lookup** |
| 9 | +72 | 0x34632C | `if (this+0x18 == 0) this+0x18 = a1` — **setter for state slot** |
| (10) | +80 | 0xFFFFFFFFFFFFFFF8 | -8 offset adjuster (multi-inheritance) |
| (11) | +88 | 0x00 | typeinfo NULL |

## vtable_corereport_singleton_b (off_52D688)

| Slot | byte off | Address | Behavior |
|---|---|---|---|
| 0 | +0 | 0x346368 | `RET` — no-op |
| 1 | +8 | 0x34636C | `SUB X0, X0, #8; B sub_51DF6C` — **destructor (with -8 adj)** |
| 2 | +16 | 0x346374 | `MOV X0, "TSS"; RET` — **returns SDK name "TSS"** |
| 3 | +24 | 0x346328 | `B ace_format_report_payload` — **format payload** |
| 4 | +32 | 0x346380 | `RET` — no-op |
| 5 | +40 | 0x346384 | `RET` — no-op |
| 6 | +48 | 0x346388 | `RET` — no-op |
| 7 | +56 | 0x34638C | `RET` — no-op |
| 8 | +64 | 0x346320 | `B sub_3462EC` — **module lookup (delegates to vtable_a vfn[8])** |
| 9 | +72 | 0x00 | NULL |
| 10 | +80 | 0x00 | NULL |
| 11 | +88 | 0x346390 | `RET` — no-op |

## What ace_create_tdm_report actually does

Tracing the calls in `ace_create_tdm_report` against these vtables:

```c
gcloud = singleton[3];                      // singleton+24 (the gcloud_regist module)

// gcloud has its OWN vtable (different singleton). vfn[32] of the gcloud module
// returns the channel object for the given decrypted name.
channel_obj = gcloud->vfn[32](gcloud, decrypt_xor02(49902));
//            ^                       ^
//            different vtable        decrypts to channel name (probably "GCloudCtrl" or similar)

// channel_obj.vfn[64] — looks up "COREREPORT" sub-channel
corereport_chan = channel_obj->vfn[64](channel_obj, "COREREPORT");

// corereport_chan.vfn[32] — creates a report builder
report = corereport_chan->vfn[32](corereport_chan, severity, 2004, rule_args);

// report.vfn[24] = add_string_field(report, field_id, str, len)
// report.vfn[32] = add_int_field(report, field_id, value)
report->vfn[24](report, 110100, "TSS", strlen("TSS"));
report->vfn[24](report, 110101, payload_str, strlen(payload));
report->vfn[24](report, 110102, raw_value, strlen(raw_value));
report->vfn[32](report, 100100, event_code);
report->vfn[32](report,  40004, 5);
```

So the COREREPORT singleton's own vtables are NOT what's calling the field-add methods. **The field-add methods belong to the report builder** (returned by corereport_chan vfn[32]).

The COREREPORT singleton is mainly a **factory** that owns the channel registry. Its own vtables are mostly RET-stubs because it's just a passthrough to gcloud module.

## What the trailing 0xFFFFFFFFFFFFFFF8 means

It's the **base offset** for the secondary inheritance. When code does:

```c
((Class_b*)this+8)->some_method(this+8)
```

…the C++ runtime needs to recover `this` from `this+8`. The vtable_b stores `-8` so dispatch can adjust the pointer back: `real_this = this - (-8) = this - 8 + 8 = this`. (Actually the math is `this -= adj`.) This is C++'s standard Itanium ABI for multi-inheritance.

## What "TSS" does

vfn[2] in both vtables returns the constant string "TSS" (Tencent Security Services). This is the SDK identity. ACE (the **A**nti-**C**heat **E**xpert) is one of several Tencent SDKs (TSS, TP2, ACE, AnoSDK). The same binary shells out under different names depending on which SDK was selected at integration. Our build identifies as "TSS".

## To-do (other vtables to map)

The interesting vtables aren't on the COREREPORT singleton — they're on:

1. **gcloud module** (whatever singleton[3] points to) — has vfn[32] for channel-by-name. This is the master channel router.
2. **Channel object** (returned by gcloud.vfn[32]) — has vfn[64] for sub-channel lookup, vfn[40] for submit.
3. **Report builder** (returned by channel.vfn[32]) — has vfn[24] for add_string_field, vfn[32] for add_int_field. **This is where the actual field encoding lives.**
4. **Hook descriptor registry** (libanogs+0x3C03B4) — vfn[88/104/120/168] used for hook-chain queries.
5. **Hook engine descriptor** (libanogs+0x4942F4) — vfn[16/56] used by rule_run_setup.

Each of these singletons sits behind a different vtable. Mapping them all gives complete control of every cross-component call inside ACE.
