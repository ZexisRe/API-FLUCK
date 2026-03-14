# Build libKeyAuth.a for iOS (run on macOS with Xcode)
# Usage: make

SDK_DEVICE   := $(shell xcrun --sdk iphoneos --show-sdk-path)
SDK_SIM      := $(shell xcrun --sdk iphonesimulator --show-sdk-path)
CC           := clang++
CFLAGS       := -fobjc-arc -O2 -I. -DKEYAUTH_STANDALONE
FRAMEWORKS   := -framework Foundation -framework UIKit -framework Security -framework QuartzCore -framework CoreTelephony -framework SystemConfiguration

# Obfuscated .o names (ar -x shows these, not source names)
SRCS := PackageValidator.mm SecureMap.mm EncryptionHelper.mm KeychainHelper.mm \
        LicenseManager.mm dylidmonitor.mm InfoSystem.mm common.mm \
        packagemanager.mm VarsStub.mm fluckcheck.mm lisense.mm
OBF := _a7f2 _b3e1 _c9d4 _e2f8 _k1m5 _n4p0 _q6r3 _s8t2 _u1v7 _w9x5 _y0z4 _h2j6
OBJ_DEVICE := $(addprefix build/device/,$(addsuffix .o,$(OBF)))

all: libKeyAuth.a

build/device/_a7f2.o: PackageValidator.mm
	@mkdir -p build/device
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_b3e1.o: SecureMap.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_c9d4.o: EncryptionHelper.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_e2f8.o: KeychainHelper.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_k1m5.o: LicenseManager.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_n4p0.o: dylidmonitor.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_q6r3.o: InfoSystem.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_s8t2.o: common.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_u1v7.o: packagemanager.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_w9x5.o: VarsStub.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_y0z4.o: fluckcheck.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)
build/device/_h2j6.o: lisense.mm
	$(CC) $(CFLAGS) -c $< -o $@ -arch arm64 -isysroot $(SDK_DEVICE)

libKeyAuth.a: $(OBJ_DEVICE)
	libtool -static -o $@ $(OBJ_DEVICE)
	@echo "Built libKeyAuth.a (device arm64)"
	@echo "Headers to ship: KeyAuth.h KeyAuthConfig.h"

clean:
	rm -rf build libKeyAuth.a

.PHONY: all clean
