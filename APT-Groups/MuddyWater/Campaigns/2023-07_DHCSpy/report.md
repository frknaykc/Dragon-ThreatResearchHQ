# DHCSpy: Discovering the Iranian APT MuddyWater's Android Spyware

> **Published:** September 29, 2025
> **Authors:** Paul (R3dy) Viard — Randorisec / Shindan
> **Source:** [shindan.io](https://shindan.io/blog/dhcspy-discovering-the-iranian-apt-muddywater)

---

## Table of Contents

1. [Introduction](#introduction)
2. [Overview](#overview)
3. [Manifest Analysis](#manifest-analysis)
4. [First Launch Behavior](#first-launch-behavior)
5. [C2 Communication](#c2-communication)
6. [VPN Configuration](#vpn-configuration)
7. [Runtime Permissions](#runtime-permissions)
8. [Permissions and Capabilities](#permissions-and-capabilities)
9. [Exfiltration](#exfiltration)
10. [Xiaomi Autostart Bypass](#xiaomi-autostart-bypass)
11. [Under Development Evidence](#under-development-evidence)
12. [IOCs](#iocs)

---

## Introduction

DHCSpy is an Android spyware family attributed to **MuddyWater**, a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS). The malware was first discovered by Lookout on July 16, 2023. A potential developer identifier, `hossein`, was found in the compilation traces of the APK's libraries.

The analyzed sample, **Earth VPN** (`com.earth.earth_vpn` v1.3.0), was downloaded from `hxxps://www[.]earthvpn[.]org`, which is now offline.

---

## Overview

DHCSpy is a malicious spyware disguised as a VPN application, built on edited open-source **OpenVPN** code ([ics-openvpn](https://github.com/schwabe/ics-openvpn)). This design allows it to automatically run whenever the victim activates the VPN. Once active, the malware operates in the background, secretly collecting:

- WhatsApp conversation databases
- Contact lists
- Call logs
- Camera files, screenshots, recordings
- Device fingerprinting data

### Variant Timeline

| Variant | First Seen | Notes |
|---------|-----------|-------|
| (Development traces) | 2022-08-10 | Earliest C2 test response found in Comodo VPN variant |
| Hide VPN | 2023-07-16 | First discovery by Lookout |
| Hazrat Eshq | — | Subsequent variant |
| Earth VPN | 2024-03 (site active) / 2025-07-20 (sample) | Distribution via `earthvpn[.]org`, Wayback Machine confirms site active since March 2024 |
| Comodo VPN | — | Distribution via `comodo-vpn[.]com` |

---

## Manifest Analysis

### Package & SDK Targeting

```xml
<manifest package="com.earth.earth_vpn"
    android:versionCode="4"
    android:versionName="1.3.0"
    android:compileSdkVersion="33">
    <uses-sdk android:minSdkVersion="22" android:targetSdkVersion="26"/>
```

`targetSdkVersion="26"` is intentionally low to avoid stricter permission enforcement introduced in later Android versions.

### Requested Permissions

**Data theft permissions:**

| Permission | Purpose |
|-----------|---------|
| `READ_PHONE_STATE` | Device IMSI, SIM, phone numbers |
| `READ_PHONE_NUMBERS` | Phone number access |
| `READ_CALL_LOG` | Call history |
| `READ_CONTACTS` | Contact list |
| `GET_ACCOUNTS` | Device accounts |
| `READ_EXTERNAL_STORAGE` | WhatsApp DBs, photos, recordings |

**Persistence permissions:**

| Permission | Purpose |
|-----------|---------|
| `RECEIVE_BOOT_COMPLETED` | Auto-start after reboot |
| `WAKE_LOCK` | Keep CPU active when screen is off |
| `POST_NOTIFICATIONS` | Show notifications to maintain foreground |
| `REQUEST_INSTALL_PACKAGES` | Self-update capability |

### Key Activities

- **`SplashActivity`** — Main launcher, handles C2 config retrieval
- **`MainActivity`** — VPN toggle UI, permission requests, deep linking handler (registered for `https://www.google.com/*` but unused in current version)

---

## First Launch Behavior

On first execution, DHCSpy performs:

1. **VPN Service Initialization** — Binds to `OpenVPNService` via AIDL IPC
2. **C2 Config Request** — Contacts C2 server to retrieve VPN configuration and command orders
3. **Permission Requests** — Dynamically requests permissions based on C2 command code
4. **VPN Tunnel Establishment** — Parses OpenVPN config and starts tunnel
5. **Data Theft** — Begins collecting data according to granted permissions

---

## C2 Communication

### Config Server Selection

The C2 URL is randomly selected from a hardcoded JSON array:

```java
public static String configUrlsJson = "{\"array\" : [
    \"https://r1.earthvpn.org:3413/\",
    \"https://r2.earthvpn.org:3413/\"
]}";
```

### Request Structure

A POST request is sent to `/api/v1` with device fingerprint:

```json
{
  "android_id": "<ANDROID_ID>",
  "body": {
    "app_version": "1.3.0",
    "client_info": {
      "language": "en",
      "model": "<MODEL_NAME>",
      "network_info": "<WIFI|MOBILE_DATA>",
      "os_name": "Android",
      "os_ver": "<SDK_VERSION>",
      "timezone": "<TIMEZONE>"
    },
    "IMSI_1": null, "IMSI_2": null,
    "SIM_1": null, "SIM_2": null,
    "package_name": "com.earth.earth_vpn",
    "publicIP": "-1", "privateIP": "",
    "connectedTime": "0", "upTime": "0",
    "inputByteCount": "0", "outputByteCount": "0"
  },
  "date": "<ISO_8601_TIMESTAMP>",
  "label": "3007",
  "request_code": "100"
}
```

**User-Agent:** `okhttp/3.14.9`

### Response Structure

```json
{
  "response": "ok",
  "body": {
    "mode": "ovpn",
    "data": {
      "ovpn_list": [{
        "title": "Pf2-aroid vpn4",
        "content": "<base64_encoded_ovpn_config>",
        "priority": "0"
      }],
      "ovpn_id": "//",
      "expiration_date": ""
    }
  },
  "order": [{
    "code": "0000000000010000",
    "id": 8383515,
    "des": "sftp://<username>:<pass>@5.255.118.39:4793",
    "pass": "<zip_password>"
  }]
}
```

**Response modes:**

| Mode | Action |
|------|--------|
| `ovpn` | Deliver VPN configuration |
| `update` | Download and install APK update (`Catalog.apk`) |
| `msg` | Display message |
| `url` | Open URL |
| `error` | Error handling |

---

## VPN Configuration

The `order` field contains four critical values stored in an SQLite database (`dsbc.db`):

| Field | Description |
|-------|-------------|
| `code` | 16-character binary string controlling permissions and capabilities |
| `pass` | 32-character password for ZIP archives |
| `des` | SFTP destination URL with credentials |
| `id` | Order identifier |

The base64-encoded OpenVPN config is decoded and parsed for:
- `remote <ip> <port>` — VPN server address
- `cipher <algorithm>` — Encryption cipher
- `# country <name>` — Server country

---

## Runtime Permissions

The `code` field (16-bit binary string) controls which permissions to request at runtime. Each bit position maps to a specific Android permission. The malware iterates backwards through the string, requesting only the permissions indicated by `1` bits.

Permissions are requested via `ActivityResultContracts.RequestMultiplePermissions` — the VPN only starts once all permissions are granted.

---

## Permissions and Capabilities

| Bit (MSB→LSB) | Permission | Capability | Handler |
|----------------|-----------|------------|---------|
| 16 (MSB) | READ_PHONE_STATE / READ_PHONE_NUMBERS | Device info collection | `getClientInfo` |
| 15 | READ_CONTACTS | Contact list theft | `getContact` |
| 14 | READ_CALL_LOG | Call history theft | `getCallog` |
| 13 | GET_ACCOUNTS | Account enumeration | `getAccount` |
| 12 | — | Installed apps list | `getAppList` |
| 11 | READ_EXTERNAL_STORAGE | WhatsApp database theft | `WhatsAppFile.getFile` |
| 10 | READ_EXTERNAL_STORAGE | Screenshots theft | `getFile` (Screenshots) |
| 9 | READ_EXTERNAL_STORAGE | Camera photos theft | `getFile` (Camera) |
| 8 | READ_EXTERNAL_STORAGE | Audio recordings theft | `getFile` (Recordings) |
| 7 | READ_EXTERNAL_STORAGE | Downloads folder theft | `getFile` (Download) |

### WhatsApp Targeting

The malware searches four paths for encrypted WhatsApp databases:

```
/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt14
/storage/emulated/0/WhatsApp/Databases/msgstore.db.crypt14
/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases/msgstore.db.crypt14
/storage/emulated/0/WhatsApp Business/Databases/msgstore.db.crypt14
```

---

## Exfiltration

All stolen data is:
1. Collected by capability-specific classes (`WhatsAppFile`, `Contact`, `CallLog`, etc.)
2. Compressed into **password-protected ZIP archives** (password from C2 `pass` field)
3. Uploaded via **SFTP** to the exfiltration server specified in `des` field

Observed exfiltration endpoint:

```
sftp://<username>:<pass>@5.255.118.39:4793
```

After successful upload, the malware clears local files and re-contacts the C2 for new orders via `getConfig()`.

---

## Xiaomi Autostart Bypass

DHCSpy includes special handling for **Xiaomi/MIUI** devices (2nd most popular brand in Iran):

1. Detects Xiaomi devices via `Build.MANUFACTURER`
2. Uses the **MIUI-Autostart** library (`xyz.kumaraswamy.autostart`) to check autostart permission state
3. Employs **AndroidHiddenApiBypass** to access MIUI's private APIs:
   - `android.miui.AppOpsUtils.getApplicationAutoStart`
4. Bypasses Android 9+ non-SDK API restrictions using `Unsafe` class to modify ART hidden API policy
5. If autostart is disabled, shows an alert dialog redirecting user to MIUI Security Center:
   - Component: `com.miui.securitycenter` / `com.miui.permcenter.autostart.AutoStartManagementActivity`

```java
HiddenApiBypass.addHiddenApiExemptions("");
// Disables all non-SDK API filtering (empty prefix matches everything)
```

---

## Under Development Evidence

Several indicators suggest DHCSpy is actively being developed:

### Unused Code (Dead Code)

| Feature | Description |
|---------|-------------|
| **Connectivity Test** | `ping()` — Executes `/system/bin/ping -c 1 8.8.8.8` (never called) |
| **External IP Lookup** | `getMyOwnIP()` — Queries `https://icanhazip.com` (never called) |
| **Geolocation** | `GeoIpService` — Uses `https://ipapi.co/` API via Retrofit (never called) |
| **Usage Database** | `vsbc.db` — Table for network traffic statistics (never created) |
| **Deep Linking** | `MainActivity` registered for `https://www.google.com/*` (never utilized) |

### Update Mechanism

The C2 can send `mode: "update"` to trigger:
1. Download of `Catalog.apk` from server
2. Display notification to user
3. Install via `installApk` using `REQUEST_INSTALL_PACKAGES` permission

---

## IOCs

See [iocs.csv](iocs.csv) for the complete machine-readable list.

### File Hashes

| SHA256 | Description |
|--------|-------------|
| `a4913f52bd90add74b796852e2a1d9acb1d6ecffe359b5710c59c82af59483ec` | DHCSpy sample |
| `48d1fd4ed521c9472d2b67e8e0698511cea2b4141a9632b89f26bd1d0f760e89` | DHCSpy sample |

### C2 Infrastructure

| Indicator | Description |
|-----------|-------------|
| `r1[.]earthvpn[.]org:3413` | Earth VPN C2 config server |
| `r2[.]earthvpn[.]org:3413` | Earth VPN C2 config server |
| `r1[.]earthvpn[.]org:1254` | Earth VPN C2 (alternate port) |
| `r2[.]earthvpn[.]org:1254` | Earth VPN C2 (alternate port) |
| `it1[.]comodo-vpn[.]com:1953` | Comodo VPN C2 |
| `it1[.]comodo-vpn[.]com:1950` | Comodo VPN C2 |
| `5[.]255[.]118[.]39:4793` | SFTP exfiltration server |
| `www[.]earthvpn[.]org` | Distribution site |

### On-Device Artifacts

| Path | Description |
|------|-------------|
| `/data/data/com.earth.earth_vpn/databases/dsbc.db` | Command/order database |
| `/data/data/com.earth.earth_vpn/databases/vsbc.db` | Unused usage tracking DB |

---

*Source: [Shindan / Randorisec — DHCSpy Analysis](https://shindan.io/blog/dhcspy-discovering-the-iranian-apt-muddywater)*
