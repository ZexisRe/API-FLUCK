# Build libKeyAuth.a with GitHub Actions

## Setup

1. **Create a GitHub repo** (e.g. `KeyAuth-iOS`)

2. **Push your API folder**:
   - Either push the whole API folder as repo root (recommended)
   - Or push a parent folder so `API/` is a subfolder

3. **Ensure `.github/workflows/build.yml` exists** in the repo

## Trigger Build

- **Auto**: Push to `main` or `master`
- **Manual**: Repo → Actions → "Build libKeyAuth" → Run workflow

## Get the .a

1. Go to **Actions** → click the latest run
2. Scroll to **Artifacts**
3. Download **KeyAuth-iOS** (zip with `libKeyAuth.a` + headers)

## Repo structure (recommended)

```
your-repo/
├── .github/workflows/build.yml
├── Makefile
├── KeyAuth.h
├── KeyAuthConfig.h
├── KeyAuthConfigExample.m
├── PackageValidator.mm
├── SecureMap.mm
├── ... (rest of API files)
```
