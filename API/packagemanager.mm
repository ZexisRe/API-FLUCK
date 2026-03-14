#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import "PackageValidator.h"
#import "SecureMap.h"
#ifdef KEYAUTH_STANDALONE
#import "VarsStub.h"
#else
#import "menuUIKIT/Vars.h"
#endif

// ============================================
// SILENT CONTINUOUS INTEGRITY CHECKER
// Runs every frame via CADisplayLink
// Crashes on validation failure
// No logging - operates silently
// ============================================

@interface ContinuousIntegrityChecker : NSObject
@property (nonatomic, strong) CADisplayLink *displayLink; // Kept for compatibility but not used
@property (nonatomic, strong) NSTimer *checkTimer; // Added timer for 2-second interval checks
@property (atomic, assign) BOOL isValidated;
@property (atomic, assign) BOOL isValidating;
@property (atomic, assign) NSInteger frameCount; // Deprecated - kept for compatibility
@property (atomic, assign) NSInteger checkInterval; // Deprecated - kept for compatibility
@property (atomic, strong) NSDate *lastCheckTime;
@property (atomic, strong) NSDictionary *cachedPackageData;
@property (atomic, assign) BOOL hasGracePeriodPassed;


+ (instancetype)shared;
- (void)start;
- (void)stop;
@end

@implementation ContinuousIntegrityChecker

+ (instancetype)shared {
    static ContinuousIntegrityChecker *instance = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        instance = [[ContinuousIntegrityChecker alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _isValidated = NO;
        _isValidating = NO;
        _frameCount = 0;
        _checkInterval = 300;
        _lastCheckTime = nil;
        _cachedPackageData = nil;
        _hasGracePeriodPassed = NO;
        
        // CRITICAL: Disable features until validated
        Vars.ewid = false;
        
        // Add initial grace period (10 seconds)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            self.hasGracePeriodPassed = YES;
        });
    }
    return self;
}

- (void)start {
    // Initial validation before starting timer
    [self performPackageCheck];
    
    // Changed: Use NSTimer with 2.0 second interval instead of CADisplayLink (every frame)
    // This reduces CPU load and prevents crashes from checking every frame
    self.displayLink = nil; // Clear displayLink reference
    
    // Stop existing timer if any
    if (self.checkTimer) {
        [self.checkTimer invalidate];
        self.checkTimer = nil;
    }
    
    // Create timer that checks every 2 seconds
    __weak ContinuousIntegrityChecker *weakSelf = self;
    self.checkTimer = [NSTimer scheduledTimerWithTimeInterval:2.0
                                                       repeats:YES
                                                         block:^(NSTimer *timer) {
        ContinuousIntegrityChecker *strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf performPackageCheck];
            // Verify Vars.ewid matches validation state (now only every 2s instead of every frame)
            if (strongSelf.isValidated) {
                if (!Vars.ewid) {
                    // Should be enabled but isn't - tampering detected
                    [strongSelf crashSilently];
                }
            } else {
                if (Vars.ewid) {
                    // Shouldn't be enabled but is - illegal modification
                    [strongSelf crashSilently];
                }
            }
        }
    }];
}

- (void)stop {
    // Stop timer if exists
    if (self.checkTimer) {
        [self.checkTimer invalidate];
        self.checkTimer = nil;
    }
    // Clear displayLink reference (kept for compatibility)
    self.displayLink = nil;
}

// Removed frameUpdate method - now using timer-based checking instead of frame-based
// This reduces CPU load from checking every frame (60 FPS) to every 2 seconds
- (void)performPackageCheck {
    // Prevent multiple simultaneous checks
    if (self.isValidating) return;
    
    self.isValidating = YES;
    self.lastCheckTime = [NSDate date];
    
    [[PackageValidator shared] validatePackageWithCompletion:^(BOOL valid, NSString *error, NSDictionary *packageData) {
        
        self.isValidating = NO;
        
        // During grace period, allow failures
        if (!self.hasGracePeriodPassed) {
            if (valid) {
                self.isValidated = YES;
                self.cachedPackageData = packageData;
                Vars.ewid = true;
            }
            return; // Don't crash during grace period
        }
        
        if (!valid) {
            // PACKAGE VALIDATION FAILED - CRASH IMMEDIATELY
            Vars.ewid = false;
            [self crashSilently];
            return;
        }
        
        // Verify package data hasn't changed
        if (self.cachedPackageData) {
            // Encrypted: "app_id"
            static const uint8_t ENC_APP_ID[] = {0x01, 0x10, 0x10, 0x55, 0x09, 0x04};
            // Encrypted: "version"
            static const uint8_t ENC_VERSION[] = {0x16, 0x05, 0x12, 0x13, 0x09, 0x0F, 0x0E};
            // Encrypted: "status"
            static const uint8_t ENC_STATUS[] = {0x13, 0x14, 0x01, 0x14, 0x15, 0x13};
            
            NSString *appIdKey = decodeSecureBytes(ENC_APP_ID, sizeof(ENC_APP_ID));
            NSString *versionKey = decodeSecureBytes(ENC_VERSION, sizeof(ENC_VERSION));
            NSString *statusKey = decodeSecureBytes(ENC_STATUS, sizeof(ENC_STATUS));
            
            // Check if critical data changed
            if (![self.cachedPackageData[appIdKey] isEqualToString:packageData[appIdKey]]) {
                [self crashSilently];
                return;
            }
            
            if (![self.cachedPackageData[versionKey] isEqualToString:packageData[versionKey]]) {
                [self crashSilently];
                return;
            }
            
            if (![self.cachedPackageData[statusKey] isEqualToString:packageData[statusKey]]) {
                [self crashSilently];
                return;
            }
        }
        
        // VALIDATION SUCCESSFUL
        self.isValidated = YES;
        self.cachedPackageData = packageData;
        Vars.ewid = true; // ✅ ENABLE FEATURES
    }];
}

- (void)crashSilently {
    // Don't crash during grace period
    if (!self.hasGracePeriodPassed) {
        return;
    }
    
    Vars.ewid = false;
    
    // Clear displayLink reference (may be nil if using timer)
    self.displayLink = nil;
    
    // Crash immediately without logging
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        exit(0);
    });
}
@end

// ============================================
// AUTO-START ON LOAD
// ============================================
__attribute__((constructor))
static void initContinuousIntegrityChecker() {
    // CRITICAL: Disable features immediately on load
    Vars.ewid = false;
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [[ContinuousIntegrityChecker shared] start];
    });
}