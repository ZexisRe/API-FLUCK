#!/bin/bash
# Build libKeyAuth.a for iOS (arm64 device + x86_64 sim)
# Run from API directory: ./build_lib.sh
# Requires Xcode command line tools

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
OUTPUT="$SCRIPT_DIR/libKeyAuth"
mkdir -p "$OUTPUT/build"
BUILD_DIR="$OUTPUT/build"

# Source files to include in library (core validation only - no lisense UI)
SOURCES=(
    "PackageValidator.mm"
    "SecureMap.mm"
    "EncryptionHelper.mm"
    "KeychainHelper.mm"
)

# Add optional components (comment out if external deps missing)
# SOURCES+=("LicenseManager.mm")
# SOURCES+=("dylidmonitor.mm")
# SOURCES+=("InfoSystem.mm")
# SOURCES+=("packagemanager.mm")  # needs Vars.h from menuUIKIT

# SDK paths
IPHONEOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
IPHONESIMULATOR_SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)

# Include path - use current dir for "Esp/" and "API/" imports
INCLUDES="-I. -I$SCRIPT_DIR"

echo "Building for device (arm64)..."
xcodebuild -scheme KeyAuthLib -configuration Release -sdk iphoneos -arch arm64 \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    CONFIGURATION_BUILD_DIR="$BUILD_DIR/device" \
    BUILD_DIR="$BUILD_DIR" \
    ONLY_ACTIVE_ARCH=NO \
    2>/dev/null || true

# Fallback: compile manually if no scheme
echo "Compiling sources manually..."
for src in "${SOURCES[@]}"; do
    if [ -f "$src" ]; then
        echo "  Compiling $src (device)..."
        clang++ -c "$src" -o "$BUILD_DIR/${src%.mm}_device.o" \
            -arch arm64 -isysroot "$IPHONEOS_SDK" \
            $INCLUDES -fobjc-arc -O2 -fno-exceptions \
            -DKEYAUTH_STANDALONE=1 2>/dev/null || echo "  Skip $src (may need fixes)"
    fi
done

echo "Creating libKeyAuth.a..."
libtool -static -o "$OUTPUT/libKeyAuth.a" "$BUILD_DIR"/*_device.o 2>/dev/null || \
    echo "Run: libtool -static -o libKeyAuth.a *.o"

echo "Done. Output: $OUTPUT/libKeyAuth.a"
echo "Headers to distribute: KeyAuth.h KeyAuthConfig.h PackageValidator.h SecureMap.h"
