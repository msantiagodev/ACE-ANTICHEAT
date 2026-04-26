# TDM (Tencent Data Management) Report Chain — Complete Flow

When ACE detects a violation, it builds a structured TDM report and submits it to a server. This doc maps the complete chain from detection callback to network send.

## Entry: `ace_submit_rule_finding` (0x4E24C4)

Called from the rule interpreter and many VM ops. Tiny wrapper:

```c
ace_submit_rule_finding(rule_args, event_id, value, severity_bool) {
    void* report = NULL;
    sub_4E256C(rule_args, event_id, &report, severity_bool);
    if (report)
        *report = value;        // store the actual finding value at offset 0
    return ...;
}
```

`sub_4E256C` is the report builder. It looks up the rule's metadata, calls `ace_create_tdm_report` to build the report struct, then returns it for the caller to fill in fields.

## Builder: `ace_create_tdm_report` (0x345C54)

This is where the report is actually constructed.

```c
ace_create_tdm_report(rule_args, payload, event_code, severity_bool) {
    // === STAGE 1: Lazy feature-flag check ===
    if (!g_tdm_report_checked) {
        g_tdm_report_checked = 1;
        g_tdm_report_enabled = ace_validate_and_dispatch(
            ace_get_timestamp_leaf(), "tdm_report", default=1, force=1) & 1;
    }
    if (!g_tdm_report_enabled) return NULL;     // disabled — silent drop
    
    // === STAGE 2: Singleton lookup ===
    severity = severity_bool ? 1 : 3;           // 1=high, 3=normal
    if (!g_corereport_singleton) {
        g_corereport_singleton = ace_calloc(0x20);
        g_corereport_singleton[0] = &vtable_corereport_singleton_a;
        g_corereport_singleton[1] = &vtable_corereport_singleton_b;
        g_corereport_singleton[2] = NULL;
        g_corereport_singleton[3] = NULL;       // gcloud_regist link, set up on init
    }
    
    // === STAGE 3: Channel resolution chain ===
    gcloud = g_corereport_singleton[3];         // the gcloud_regist module
    if (!gcloud) goto fail;
    
    channel_name = decrypt_xor02(49902);        // probably "GCloudCtrl" or "iedsafe"
    channel_obj = gcloud->vfn[32](gcloud, channel_name);
    if (!channel_obj) goto fail;
    
    corereport_channel = channel_obj->vfn[64](channel_obj, "COREREPORT");
    if (!corereport_channel) goto fail;
    
    // === STAGE 4: Create report builder ===
    report = corereport_channel->vfn[32](corereport_channel,
                                          severity, 2004, rule_args);
    if (!report) {
fail:
        if (++g_tdm_report_fail_count >= 3) {
            g_tdm_report_enabled = 0;            // self-disable after 3 fails
            return NULL;
        }
        return NULL;
    }
    
    // === STAGE 5: Populate report fields ===
    // Field IDs are TDM protocol constants
    report->vfn[24](report, 110100, "TSS",       strlen("TSS"));   // source SDK
    report->vfn[24](report, 110101, payload_str, strlen(payload)); // formatted payload
    report->vfn[24](report, 110102, payload,     strlen(payload)); // raw value
    report->vfn[32](report, 100100, event_code);                   // event ID
    report->vfn[32](report,  40004, 5);                            // report type=5
    
    return report;
}
```

### Decoded constants

| Constant | Meaning |
|---|---|
| `g_tdm_report_enabled` (`byte_57E31C`) | 1=submit reports, 0=silent drop |
| `g_tdm_report_checked` (`byte_57E31D`) | 1=feature flag has been checked once |
| `g_tdm_report_fail_count` (`dword_57E320`) | Increments on submit failure; auto-disables at 3 |
| `g_corereport_singleton` (`qword_57E0D0`) | The COREREPORT subsystem singleton (32 bytes) |
| `vtable_corereport_singleton_a` (`off_52D628`) | Methods table A (lookup, create-by-name) |
| `vtable_corereport_singleton_b` (`off_52D688`) | Methods table B (channel dispatch) |
| `2004` | Channel-creation magic constant for COREREPORT |
| `110100` | TDM field: source-SDK name |
| `110101` | TDM field: formatted payload string |
| `110102` | TDM field: raw payload value |
| `100100` | TDM field: event/error code |
| `40004` | TDM field: report category (5 = security) |

### vtable layout (deduced)

`vtable_corereport_singleton_a` at offset:
- `+24`: `add_string_field(report, field_id, str, len)`
- `+32`: `add_int_field(report, field_id, int_val)` OR `lookup_module(name)` (overloaded)
- `+40`: `submit(report, ctx)` — used by ace_submit_corereport
- `+64`: `get_channel(name)` — looks up "COREREPORT", "REMOTECONFIG", etc.

## Submit: `ace_submit_corereport` (0x345E60)

Tiny submitter that sends the completed report:

```c
ace_submit_corereport(report, ctx) {
    if (!report) return;
    gcloud = report[2];                            // the gcloud module
    if (!gcloud) return;
    
    channel = gcloud->vfn[32](gcloud, decrypt_xor02(49902));
    if (!channel) return;
    
    corereport_chan = channel->vfn[64](channel, "COREREPORT");
    if (!corereport_chan) return;
    
    return corereport_chan->vfn[40](corereport_chan, ctx);  // send!
}
```

`vfn[40]` is the actual network send. After this call, the report flies to the Tencent server via HTTPS.

## Server endpoints (decrypted)

```
POST https://%s/gamesafe/mobile/huiwan/android/%s/test/%s         (test)
POST https://%s/gamesafe/mobile/huiwan/android/%s/%08X/%s          (production)
GET  https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me  (config)
```

The `%s` placeholders are filled with: hostname (e.g., `down.anticheatexpert.com`), device-id, install-key, channel-token. The endpoint name `donot_delete_me` is real — it's a server-side marker for "this is the official ACE config endpoint, don't garbage-collect".

## Pipeline visualization

```
[Detection Site]
       │
       ▼
ace_submit_rule_finding(args, event, value, severity)
       │
       ▼
sub_4E256C (builder helper)
       │
       ▼
ace_create_tdm_report(args, payload, code, severity)
       │
       ├─ check g_tdm_report_enabled → if 0: DROP
       ├─ resolve gcloud_regist[3] → "GCloudCtrl" channel → "COREREPORT"
       ├─ build report via vfn[32](..., 2004, ctx)
       ├─ add fields 110100/110101/110102/100100/40004
       │
       ▼
ace_submit_corereport(report, ctx)
       │
       ▼
COREREPORT.vfn[40](report)     ← network send
       │
       ▼
HTTPS POST → *.anticheatexpert.com
```

## Bypass implications

The chain has multiple kill switches, in order of preference:

1. **`g_tdm_report_enabled = 0`** (single byte at libanogs+0x57E31C). Blocks ALL findings silently. **Cleanest. Already in our Tier 2 bypass.**

2. **`g_tdm_report_checked = 1` + `g_tdm_report_enabled = 0`**: makes the lazy-init check think it's already disabled. Persistent across resets.

3. **Hook `ace_create_tdm_report` to return NULL**: callers handle gracefully.

4. **Hook `ace_submit_corereport`**: let everything build, then drop at network send.

5. **Hook the channel lookup `vfn[64]("COREREPORT")` to return NULL**: rare side effects on other channels.

6. **Network DNS/iptables block** of `*.anticheatexpert.com`: defense in depth — even if all hooks fail, the report can't fly home.

7. **The 3-strike auto-disable**: ACE itself disables submission after 3 failures. We can trigger this artificially by hooking the channel lookup to fail 3+ times.

## Verification

Tested in Main.cpp Tier 2: setting bytes `g_tdm_report_enabled = 0; g_tdm_report_checked = 1` immediately silences ALL findings. Confirmed via logcat — no `submit_corereport` calls observed after the bypass installs.

## To-do

- Decode `vtable_corereport_singleton_a/b` field-by-field.
- Find the network send implementation (corereport channel's vfn[40]).
- Map the encryption used on the wire (AES key setup is in libanogs).
- Document the REMOTECONFIG and CONNECTOR channels (parallel to COREREPORT).
