# GCloud Remote Config — ACE's Live Update Pipeline

ACE uses Tencent's **GCloud SDK** as its delivery channel for remote configuration, server-pushed rules, and on-the-fly detection updates. This is separate from the `ob_*.zip` static packages — GCloud is for real-time control.

## What is GCloud?

GCloud is Tencent's gaming cloud service. It's a SDK embedded in Tencent games that provides:
- Real-time configuration delivery
- Player analytics
- Crash reporting
- A/B testing
- **And in ACE's case: live anti-cheat rules**

## Discovery in libanogs

`ace_init_remoteconfig_channel` (libanogs+0x345080) sets up the connection:

```c
__int64 ace_init_remoteconfig_channel(void* this) {
    if (this->initialized) return 0;
    this->initialized = 1;
    
    // Step 1: Feature-flag gate
    char* gcloud_ctrl_name = ace_decrypt_xor59(49889);   // = "GCloudCtrl"
    if (!ace_validate_and_dispatch(ctx, gcloud_ctrl_name, 1, 1))
        return 0;   // GCloud feature flag disabled
    
    // Step 2: Get/create the CoreReport singleton (the data conduit)
    if (!g_corereport_singleton) {
        g_corereport_singleton = ace_calloc(32);
        g_corereport_singleton->vtable_a = &vtable_corereport_singleton_a;
        g_corereport_singleton->vtable_b = &vtable_corereport_singleton_b;
    }
    
    // Step 3: Look up GCloudCore module
    void* gcloud_core_module = g_corereport_singleton->vtable_b
        ->lookup(ace_decrypt_xor02(49902));   // = "GCloudCore"
    
    if (!gcloud_core_module) return 0;
    
    // Step 4: Get the version string
    char* version_str = gcloud_core_module->vtable->get_version();
    int v_a, v_b, v_c, v_d;
    sscanf(version_str, "%d.%d.%d.%d", &v_a, &v_b, &v_c, &v_d);
    
    // Step 5: Require GCloud >= 1.0.0.74
    if (1000000*v_a + 10000*v_b + 100*v_c + v_d < 1000074)
        return 0;
    
    // Step 6: Subscribe to "REMOTECONFIG" events on the GCloud channel
    void* subscription = gcloud_core_module->vtable->subscribe("REMOTECONFIG");
    if (subscription)
        this->remoteconfig_handle = subscription;
}
```

## The two GCloud namespaces

| Namespace | Purpose |
|---|---|
| `GCloudCtrl` (49889) | Feature flag — "is GCloud control plane available?" |
| `GCloudCore` (49902) | The actual GCloud SDK core module |
| `gcloud` (49827) | Lowercase namespace marker (general-purpose) |

ACE checks GCloudCtrl as a feature flag before initializing GCloudCore. This lets the game disable GCloud entirely and ACE will skip remote config setup.

## Version requirement: 1.0.0.74

ACE requires GCloud SDK version >= `1.0.0.74`. Older GCloud lacks the `subscribe("REMOTECONFIG")` API. So if the game ships with old GCloud, ACE silently falls back to no remote config.

## "REMOTECONFIG" event subscription

The `subscribe("REMOTECONFIG")` registers a callback. When server pushes new config, GCloud:
1. Receives the message via long-poll or push notification
2. Decodes the payload
3. Fires the registered callback (in ACE's CoreReport module)
4. ACE applies the new config

This is the **back-channel** for ACE detection updates — separate from the `ob_*.zip` static download.

## What kinds of remote config are pushed?

Without runtime sniffing, we can only guess based on what's adjacent:
- Threshold tweaks (e.g., "ban after N detections")
- Whitelist updates (e.g., "this device fingerprint is OK now")
- Feature flag toggles (e.g., "enable JNI scan on Android 12+")
- Rule pushes (compact rule format, applied to scanner runtime)
- Force-scan triggers (e.g., "force_emu_scan now on these device IDs")

## ace_validate_and_dispatch — feature flag pattern

This function is called everywhere ACE checks a feature flag:

```c
__int64 ace_validate_and_dispatch(ctx, name, default_yes, force_dispatch) {
    bool result = false;
    
    if (ace_validate_module_call(ctx, name, &result) && force_dispatch) {
        // Validation passed AND force-dispatch requested
        // → dispatch the actual module call
        ace_dispatch_prepare(ctx);
        if (ace_dispatch_module_call(ctx, name) != -1)
            return ace_dispatch_finalize();
    } else if (ace_validate_module_call(ctx, name, &result)) {
        return result;   // Just return validation result
    }
    
    return default_yes;
}
```

Used to gate features like:
- `GCloudCtrl` (does the game support GCloud?)
- `frida_strategy` (is Frida detection enabled?)
- `cps_light_scan` (run lightweight CPS?)

## Bypass implications

### To block remote config entirely:
1. Hook `ace_init_remoteconfig_channel` to return 0 immediately
2. Or: hook GCloud's network layer (kill the long-poll socket)
3. Or: block DNS for GCloud endpoints

The simplest is probably hooking `ace_validate_and_dispatch` to return 0 when the name decrypts to "GCloudCtrl".

### Currently NOT deployed
We rely on:
- `g_anort_config_flags |= 0x100` (Tier 5) blocks `ACE_ConfigUpdateFromServer` — but this is a different path (`ace_shell_di.dat` reading, not GCloud)
- DNS block at user discretion

The GCloud path is **NOT covered** by Tier 5. New rules CAN still be pushed via GCloud if the game uses it. Future bypass hardening should add a Tier for GCloud.

## CoreReport singleton

`g_corereport_singleton` (libanogs+0x57E0D0) is the central event/IPC hub. It uses C++ multi-inheritance (vtable_a + vtable_b) and serves as the bus for:
- GCloud subscriptions
- Internal event publishing
- Cross-module callbacks

This is a critical infrastructure piece — many subsystems hook into it.

## To-do

- Decompile `vtable_corereport_singleton_a` and `_b` to know all methods
- Hook the subscribe callback to log every REMOTECONFIG message ACE receives
- Determine the GCloud transport (HTTPS? gRPC? Custom protocol?)
- Find what server endpoint GCloud talks to (likely Tencent's gcloud.tencent.com or similar)
