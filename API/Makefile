# Build libKeyAuth.a for iOS (run on macOS with Xcode)
# Usage: make

SDK_DEVICE   := $(shell xcrun --sdk iphoneos --show-sdk-path)
SDK_SIM      := $(shell xcrun --sdk iphonesimulator --show-sdk-path)
CC           := clang++
CFLAGS       := -fobjc-arc -O2 -I. -DKEYAUTH_STANDALONE
FRAMEWORKS   := -framework Foundation -framework UIKit -framework Security -framework QuartzCore -framework CoreTelephony -framework SystemConfiguration

SRCS := PackageValidator.mm SecureMap.mm EncryptionHelper.mm KeychainHelper.mm \
        LicenseManager.mm dylidmonitor.mm InfoSystem.mm common.mm \
        packagemanager.mm VarsStub.mm lisense.mm

OBJ_DEVICE   := $(SRCS:%.mm=build/device/%.o)
OBJ_SIM      := $(SRCS:%.mm=build/sim/%.o)

all: libKeyAuth.a

build/device/%.o: %.mm
	@mkdir -p build/device
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)

build/sim/%.o: %.mm
	@mkdir -p build/sim
	$(CC) $(CFLAGS) -c $< -o $@ -arch x86_64 -isysroot $(SDK_SIM)

libKeyAuth.a: $(OBJ_DEVICE) $(OBJ_SIM)
	libtool -static -o $@ $(OBJ_DEVICE)
	@echo "Built libKeyAuth.a (device arm64)"
	@echo "Headers to ship: KeyAuth.h KeyAuthConfig.h"

clean:
	rm -rf build libKeyAuth.a

.PHONY: all clean
