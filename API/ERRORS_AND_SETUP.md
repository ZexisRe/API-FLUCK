# KeyAuth API – Errors Found & Package Setup

## Errors Fixed

| File | Issue | Fix |
|------|-------|-----|
| **Import paths** | `API/`, `Esp/` prefixes | Standardized to local `"SecureMap.h"` etc. for standalone build |
| **PackageValidator** | Hardcoded ENC_* values | Now uses `KeyAuthConfig.h` |
| **titleLabel** | Hardcoded `@"Free Fire MAX"` | Uses `KEYAUTH_APP_DISPLAY_NAME` from config |
| **packagemanager** | Depends on menuUIKIT/Vars | Added `VarsStub.h` for standalone; use `-DKEYAUTH_STANDALONE` |

## Known Issue – Requires Your Action

### lisense.mm line 24
```objc
bool Vars.ewid = false;
```
**Problem:** Invalid syntax. You cannot declare a variable like `Vars.ewid` in C/ObjC.

**Fix options:**
- **If Vars is defined in menuUIKIT/Vars.h:** Remove this line. Initialize in `application:didFinishLaunching`:
  ```objc
  Vars.ewid = false;
  ```
- **Or** ensure `Vars_t Vars = {0};` is defined in one .mm file (e.g. Vars.mm in menuUIKIT).

### infosystem.h
- Imports `"API/common.h"` which is not in the API folder. Copy `common.h` from your main project or remove InfoSystem if unused.

---

## Packaging to Single .a

### 1. User configuration
Edit **`KeyAuthConfig.h`** and set:
- `KEYAUTH_APP_DISPLAY_NAME` – e.g. `@"Free Fire MAX"`
- `KEYAUTH_ENC_VERSION`, `KEYAUTH_ENC_APP_ID`, `KEYAUTH_ENC_CHECK_URL`
- `KEYAUTH_ENC_AES_KEY`, `KEYAUTH_ENC_AES_IV`

Use `encodeSecureToHexString(@"your_text")` (from SecureMap) to generate encrypted bytes.

### 2. Build on macOS
```bash
cd /path/to/API
./build_lib.sh
```
Or create an Xcode static library target and add the `.mm` sources.

### 3. Files to distribute
- **Library:** `libKeyAuth.a`
- **Headers:** `KeyAuth.h`, `KeyAuthConfig.h`, `PackageValidator.h`, `SecureMap.h`

### 4. Auto-run
- `packagemanager.mm` uses `__attribute__((constructor))` so the integrity checker starts automatically after ~5 seconds.
- Call `[[KeyAuthSystem shared] start]` in `application:didFinishLaunchingWithOptions:` for the full UI flow.

---

## How It Works
1. User edits `KeyAuthConfig.h` with their package data.
2. `PackageValidator` reads config, validates against your server.
3. `getAppDisplayName` returns `KEYAUTH_APP_DISPLAY_NAME` for UI (e.g. titleLabel).
4. Constructor in `packagemanager` auto-starts validation; `Vars.ewid` is set when valid.
