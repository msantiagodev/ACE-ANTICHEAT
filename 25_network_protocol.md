# ACE Network Protocol — How Reports Fly Home

## Discovery

ACE doesn't use native HTTP. It calls Java's `URL` / `URLConnection` via JNI to send HTTPS requests. This means **all of ACE's network traffic uses the JVM's TLS stack and cert store** — not a bundled libcurl/openssl.

Evidence:
- Decoded libanort strings include `java/net/URL` and `()Ljava/net/URLConnection;`
- No `libcurl` / `libssl` symbols in the import tables of either ACE binary
- Multiple references to `getInputStream()`, `setRequestMethod()` JNI signatures (we'd need to dig further to confirm)

## Endpoints

Three URL templates were decoded (see `anort_decrypted_strings.txt`):

| Decoded template | Purpose |
|---|---|
| `https://%s/gamesafe/mobile/huiwan/android/%s/test/%s` | Test/staging endpoint |
| `https://%s/gamesafe/mobile/huiwan/android/%s/%s` | Default/no-key endpoint |
| `https://%s/gamesafe/mobile/huiwan/android/%s/%08X/%s` | **Production** (with 32-bit install key) |
| `https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me` | Config download |

The `%s` placeholders fill in (in order): `hostname`, `device_id`, `key_or_token`. The `%08X` is the 32-bit hexadecimal install key.

The strange filename `donot_delete_me` is real — server-side it's a marker that says "this is an official ACE config endpoint, don't garbage collect from CDN".

The `huiwan` (慧玩 — "smart play") path component is the **project codename** for ACE inside Tencent. All server APIs live under `/gamesafe/mobile/huiwan/android/`.

## Report payload format

Decoded from `anort_decrypted_strings.txt[6509]`:

```
model=%s;pkgname=%s;platid=%d;manufactuer=%s;release=%s;api=%s;cpu=%s;
apk_hash=%08X;apk_ver=%s;shell_ver=%s;is_x86=%d;sdk_ver=%s;bt=%lld;
unpackerinfo=%s;is_aab=%d;dt=%d;iscompatiblemode=%d;cs=%s;cdn=%s
```

(Joined onto one line for transmission, but for readability shown as multi-line.)

This is **semicolon-separated key=value**, not JSON, not protobuf. Each report's body is just a long string.

| Field | Meaning |
|---|---|
| `model` | Device model (Build.MODEL) |
| `pkgname` | App package name (com.ubisoft.thedivision...) |
| `platid` | Platform identifier (number) |
| `manufactuer` | Build.MANUFACTURER (typo "manufactuer" is intentional) |
| `release` | Android release version |
| `api` | API level |
| `cpu` | CPU architecture |
| `apk_hash` | 32-bit hash of APK contents |
| `apk_ver` | App version string |
| `shell_ver` | Shell-protector version |
| `is_x86` | 1 if running on x86 emulator |
| `sdk_ver` | ACE SDK version (e.g., 4.9.30.24277_oversea) |
| `bt` | Boot time (uptime in milliseconds, signed 64-bit) |
| `unpackerinfo` | Info about any unpackers detected |
| `is_aab` | 1 if APK was installed as Android App Bundle |
| `dt` | Detection type identifier |
| `iscompatiblemode` | 1 if running in scoped storage compatibility mode |
| `cs` | Client signature/checksum |
| `cdn` | CDN configuration identifier |

This is the **device-fingerprint payload**. Every report includes it as boilerplate.

## Detection-specific payload (additive)

Beyond the device fingerprint, each report adds detection-specific fields. From `ace_create_tdm_report` (libanogs+0x345C54):

```c
report->vfn[24](report, 110100, "TSS",  3);            // SDK identity
report->vfn[24](report, 110101, payload_str, strlen);  // formatted payload
report->vfn[24](report, 110102, raw_value, strlen);    // raw value
report->vfn[32](report, 100100, event_code);           // event/error code
report->vfn[32](report, 40004, 5);                     // report category=5 (security)
```

| Field ID | Type | Content |
|---|---|---|
| `110100` | string | SDK identity (`TSS`) |
| `110101` | string | Formatted payload (semicolon-separated kv pairs) |
| `110102` | string | Raw detected value (e.g., process name caught, file path) |
| `100100` | int | Event/error code (which detection triggered) |
| `40004` | int | Report category (5 = security finding) |

## Module integrity payload format

When reporting a hooked module, libanort uses this format (decoded):

```
module_base=%llu|section_enctype=%u|vaddr=%u|memsz=%u|md5_crc32=%u|begin=%u|end=%u
```

Pipe-separated key=value. So integrity reports have their own format different from the main fingerprint.

## Lookup chain at submit time

```
1. ace_submit_corereport(report, ctx) called by detector
2.    └─> gcloud = report[2]
3.        └─> channel = gcloud->vfn[32](decrypted_xor02_49902)
                                          ↓
                                          (decoded: probably "GCloudCtrl" or "iedsafe")
4.            └─> corereport = channel->vfn[64]("COREREPORT")
5.                └─> corereport->vfn[40](report, ctx)        // SEND!
```

The `vfn[40]` of the COREREPORT channel is the actual sender. We haven't traced through to see if it directly calls Java JNI or hands off to a worker thread, but the `java/net/URL` references in the string corpus suggest direct JNI dispatch.

## How TLS works

Since ACE uses Java's URLConnection:
1. JVM uses Android's system TrustStore (cert store).
2. TLS handshake done by JVM.
3. Server cert validation depends on Android's CA store at the time of TLS.

This means **certificate pinning** (if any) would happen in the JVM layer. We haven't confirmed if ACE pins its server certs — if NOT, then our existing TLS interception via Frida/Charles would work. If pinned, we'd need to bypass the pin specifically.

## Authentication

The `%08X` install-key in the production URL is the per-install token. It's:
- Generated on first launch (deterministic from device_id)
- Stored locally for subsequent reports
- Used by server to dedupe reports per-install
- NOT a strong authentication token — server still validates payload via signed config check

There's no obvious HMAC or request signing in the URL/headers (would need to trace the JNI sends to confirm). The payload itself is semicolon-separated, presumably TLS does the integrity protection.

## Data exfil per report

A single TDM report sent to the server contains:
- HTTP POST URL: `https://down.anticheatexpert.com/gamesafe/mobile/huiwan/android/<device_id>/<install_key>/<token>`
- POST body: pipe-separated TDM fields with the device fingerprint + the specific detection details
- TLS protected by Android system cert store
- Sent via Java JVM URLConnection

## Bypass implications

Multiple kill points:

1. **Block at network level** (most reliable):
   - DNS sinkhole `*.anticheatexpert.com` → `127.0.0.1`
   - iptables drop port 443 to those hostnames
   - VPN routing rules
   - Pi-hole / Adblock list

2. **Hook the JNI URL.openConnection() Java side**: refuse to connect to anticheatexpert.com hostnames.

3. **Hook the libanort native code that builds the URL**: corrupt the hostname so requests fail.

4. **Hook ace_submit_corereport** (libanogs+0x345E60): drop reports before sender is invoked.

5. **Tier 2 (already deployed)**: `g_tdm_report_enabled = 0`. Reports never get built.

## To-do

- Find and decode the JNI bridge for URL.openConnection.
- Trace `vfn[40]` of COREREPORT channel to see the actual sender code path.
- Check for certificate pinning by patching the `java/security/cert/X509Certificate` JNI calls.
- Capture an actual TDM POST request via mitmproxy on a test device to confirm format.
